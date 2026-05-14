#!/usr/bin/env node
/**
 * MCP server discovery pipeline.
 *
 * Three sources, deduplicated by repo URL:
 *   1. modelcontextprotocol/servers README — official curated list
 *   2. GitHub topic search — `topic:mcp-server`, `topic:mcp`, popular orgs
 *   3. npm search — keyword "mcp-server"
 *
 * For each candidate:
 *   - skip if already in tools_database.json (matched by source_url or name)
 *   - fetch stars / last_commit_days / open_issues / license via `gh api`
 *   - apply the same scoring formula as calculate_health.cjs
 *   - apply reject heuristics:
 *       <10 stars              → reject (low signal)
 *       last_commit > 365 days → reject (unmaintained)
 *       archived               → reject
 *       fork                   → reject
 *       no license             → flag, not reject (LLM-readable)
 *
 * Output: candidates JSON with the tools_database.json schema (minus
 * pkg_integrity — fill via `verify_integrity.cjs --update` after merge).
 * The human reviews and cherry-picks entries to merge.
 *
 * Usage:
 *   node scripts/discover.cjs --limit 50 [--out candidates.json]
 *                              [--source readme,gh,npm]   default: all
 *                              [--include-existing]       don't skip DB matches
 *                              [--max-health-checks N]    cap gh api calls
 *
 * Prerequisites:
 *   - `gh` CLI authenticated (`gh auth login`); rate limits are higher
 *   - `npm` CLI in PATH for the npm-search source
 *
 * Exit codes:
 *   0  ran to completion, candidates written
 *   1  no candidates passed filters (likely a network or auth issue)
 *   2  bad arguments
 */

'use strict';

const fs    = require('fs');
const https = require('https');
const path  = require('path');
const { execFileSync } = require('child_process');

const DB_PATH      = path.resolve(__dirname, '../assets/tools_database.json');
const CALC_HEALTH  = path.resolve(__dirname, 'calculate_health.cjs');

const argv = process.argv.slice(2);
const ARG  = (flag, def) => {
  const i = argv.indexOf(flag);
  return i !== -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : def;
};

const LIMIT         = parseInt(ARG('--limit', '50'), 10);
const MAX_HEALTH    = parseInt(ARG('--max-health-checks', '200'), 10);
const OUT           = ARG('--out', null);
const SOURCES       = (ARG('--source', 'readme,gh,npm') || '').split(',').map(s => s.trim()).filter(Boolean);
const INCL_EXISTING = argv.includes('--include-existing');

// ── helpers ────────────────────────────────────────────────────────────────

function ghJson(args) {
  try {
    return JSON.parse(execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }));
  } catch (e) {
    process.stderr.write(`gh ${args.join(' ')} failed: ${e.message.split('\n')[0]}\n`);
    return null;
  }
}

function httpsGet(url, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const u   = new URL(url);
    const req = https.get(
      { hostname: u.hostname, path: u.pathname + u.search, headers: { 'User-Agent': 'mcp-skills-vault/discover.cjs' } },
      (res) => {
        if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end',  ()  => resolve(data));
      },
    );
    req.on('error', () => resolve(null));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve(null); });
  });
}

function normalizeRepoUrl(url) {
  if (!url) return null;
  let u = url.trim()
    .replace(/^git\+/, '')
    .replace(/\.git$/, '')
    .replace(/\/$/, '')
    .replace(/^http:/, 'https:');
  // Strip /tree/branch/path suffixes — collapse to bare repo.
  const m = u.match(/^(https:\/\/github\.com\/[^/]+\/[^/]+)/);
  return m ? m[1] : u;
}

function ownerRepoFromUrl(url) {
  const m = url && url.match(/github\.com\/([^/]+)\/([^/]+)/);
  return m ? { owner: m[1], repo: m[2] } : null;
}

// ── sources ────────────────────────────────────────────────────────────────

async function fromMcpServersReadme() {
  // The canonical curated list — links live in "Reference Servers", "Official
  // Integrations", and "Community Servers" sections.
  const readme = await httpsGet('https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md');
  if (!readme) return [];
  const seen = new Set();
  const out  = [];
  for (const line of readme.split('\n')) {
    // Markdown list items pointing to a github repo.
    const m = line.match(/-\s*\*\*\[([^\]]+)\]\((https:\/\/github\.com\/[^)]+)\)\*\*/)
            || line.match(/-\s*\[([^\]]+)\]\((https:\/\/github\.com\/[^)]+)\)/);
    if (!m) continue;
    const repo = normalizeRepoUrl(m[2]);
    if (seen.has(repo)) continue;
    seen.add(repo);
    out.push({ name: m[1].trim(), source_url: repo, source: 'mcp-servers-readme' });
  }
  return out;
}

function fromGhSearch() {
  const out = [];
  const queries = [
    ['repos', '--topic', 'mcp-server', '--limit', '100'],
    ['repos', '--topic', 'modelcontextprotocol', '--limit', '100'],
  ];
  const seen = new Set();
  for (const q of queries) {
    const res = ghJson(['search', ...q, '--json', 'fullName,description,url,stargazersCount,language,isArchived,isFork,license']);
    if (!Array.isArray(res)) continue;
    for (const r of res) {
      if (r.isArchived || r.isFork) continue;
      const repo = normalizeRepoUrl(r.url);
      if (seen.has(repo)) continue;
      seen.add(repo);
      out.push({
        name:           r.fullName.split('/')[1],
        full_name:      r.fullName,
        source_url:     repo,
        description:    r.description,
        stars:          r.stargazersCount,
        language:       r.language?.name || null,
        license_pre:    r.license?.key || null,
        source:         'gh-topic',
      });
    }
  }
  return out;
}

function fromNpmSearch() {
  let raw;
  try {
    raw = execFileSync('npm', ['search', 'mcp-server', '--searchlimit=250', '--json'],
                       { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  } catch (e) {
    process.stderr.write(`npm search failed: ${e.message.split('\n')[0]}\n`);
    return [];
  }
  let arr;
  try { arr = JSON.parse(raw); } catch { return []; }
  const out  = [];
  const seen = new Set();
  for (const p of arr || []) {
    // npm search results: { name, description, links: { repository } }.
    const repo = normalizeRepoUrl(p.links?.repository || p.repository);
    if (!repo || !repo.startsWith('https://github.com/')) continue;
    if (seen.has(repo)) continue;
    seen.add(repo);
    out.push({
      name:        p.name,
      source_url:  repo,
      description: p.description,
      source:      'npm-search',
      npm_package: p.name,
    });
  }
  return out;
}

// ── enrichment ─────────────────────────────────────────────────────────────

function annotateHealthFromGh(cand) {
  const ownerRepo = ownerRepoFromUrl(cand.source_url);
  if (!ownerRepo) return null;
  const data = ghJson(['api', `repos/${ownerRepo.owner}/${ownerRepo.repo}`,
                       '--jq', '{stars: .stargazers_count, pushed_at, open_issues_count, license: .license.spdx_id, archived, fork, default_branch}']);
  if (!data) return null;
  if (data.archived || data.fork) return null;
  const days = data.pushed_at ? Math.floor((Date.now() - new Date(data.pushed_at).getTime()) / 86400000) : 9999;
  return {
    stars:             data.stars ?? 0,
    last_commit_days:  days,
    open_issues:       data.open_issues_count ?? 0,
    license:           data.license || null,
    default_branch:    data.default_branch || 'main',
  };
}

// Same formula as calculate_health.cjs, kept inline so we don't shell out
// once per candidate.
function scoreHealth({ stars, last_commit_days, has_install_cmd, in_registry, open_issues, license }) {
  let s = 0;
  s += Math.min(20, 10 * Math.log10((stars || 0) + 1));
  if      (last_commit_days < 30)  s += 40;
  else if (last_commit_days < 90)  s += 20;
  else if (last_commit_days < 180) s += 10;
  if (in_registry)     s += 30;
  if (has_install_cmd) s += 15;
  if (((open_issues || 0) / 10) < 5) s += 5;
  const ok = ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0', 'LGPL-2.1', 'LGPL-3.0', 'GPL-2.0', 'GPL-3.0', 'AGPL-3.0'];
  if (!license || !ok.includes(license)) s -= 10;
  return Math.round(s * 10) / 10;
}

function classifyScore(score) {
  if (score >= 85) return 'Core';
  if (score >= 65) return 'Recommended';
  if (score >= 40) return 'Experimental';
  return 'Deprecated';
}

// ── reject heuristics ──────────────────────────────────────────────────────

// gh topic-search picks up unrelated projects that just tagged themselves
// "mcp" or "modelcontextprotocol" for discoverability. Require the candidate
// to *look* like an MCP server in its name or description; npm-search and the
// readme source are already curated and bypass this check.
function looksLikeMcpServer(cand) {
  if (cand.source && cand.source.includes('mcp-servers-readme')) return true;
  if (cand.source && cand.source.includes('npm-search'))         return true;
  const hay = `${cand.name || ''} ${cand.description || ''}`.toLowerCase();
  return /\bmcp\b/.test(hay)
      || /model[\s-]context[\s-]protocol/.test(hay)
      || /mcp[\s-]server/.test(hay);
}

function rejectReason(cand) {
  if (!looksLikeMcpServer(cand))             return 'not-mcp-server';
  if ((cand.stars || 0) < 10)                return 'low-stars';
  if ((cand.last_commit_days ?? 9999) > 365) return 'unmaintained';
  return null;
}

// ── main ───────────────────────────────────────────────────────────────────

async function main() {
  const db        = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  const existing  = new Set();
  for (const t of db.tools) {
    if (t.source_url) existing.add(normalizeRepoUrl(t.source_url));
    if (t.name)       existing.add(t.name.toLowerCase());
  }

  process.stderr.write(`Sources: ${SOURCES.join(', ')}\n`);

  const seedLists = [];
  if (SOURCES.includes('readme')) seedLists.push(await fromMcpServersReadme());
  if (SOURCES.includes('gh'))     seedLists.push(fromGhSearch());
  if (SOURCES.includes('npm'))    seedLists.push(fromNpmSearch());

  // Merge and dedupe by repo URL.
  const merged = new Map();
  for (const list of seedLists) {
    for (const c of list) {
      const key = c.source_url;
      if (!key) continue;
      if (merged.has(key)) {
        const prev = merged.get(key);
        prev.source = `${prev.source}+${c.source}`;
        if (!prev.description && c.description) prev.description = c.description;
        if (!prev.npm_package  && c.npm_package)  prev.npm_package  = c.npm_package;
        continue;
      }
      merged.set(key, { ...c });
    }
  }

  process.stderr.write(`Raw candidates (merged across sources): ${merged.size}\n`);

  // Skip already-in-DB.
  let kept = [...merged.values()];
  if (!INCL_EXISTING) {
    kept = kept.filter(c => !existing.has(c.source_url) && !existing.has(c.name.toLowerCase()));
    process.stderr.write(`After dropping existing DB entries:    ${kept.length}\n`);
  }

  // Soft pre-rank by initial stars (from gh-topic source if present) so the
  // --max-health-checks cap takes the most promising entries first.
  kept.sort((a, b) => (b.stars || 0) - (a.stars || 0));
  const toEnrich = kept.slice(0, MAX_HEALTH);
  process.stderr.write(`Enriching health metrics for top ${toEnrich.length} (cap --max-health-checks)\n`);

  const enriched = [];
  let i = 0;
  for (const cand of toEnrich) {
    i++;
    if (i % 25 === 0) process.stderr.write(`  enriched ${i}/${toEnrich.length}\n`);
    const health = annotateHealthFromGh(cand);
    if (!health) continue;                              // archived/fork/api-error
    Object.assign(cand, health);
    const score = scoreHealth({
      stars:            cand.stars,
      last_commit_days: cand.last_commit_days,
      has_install_cmd: !!cand.npm_package,              // we know it ships on npm
      in_registry:     !!cand.npm_package,
      open_issues:     cand.open_issues,
      license:         cand.license,
    });
    cand.health_score   = score;
    cand.classification = classifyScore(score);
    enriched.push(cand);
  }

  // Apply reject heuristics.
  const candidates = [];
  const rejected   = [];
  for (const c of enriched) {
    const reason = rejectReason(c);
    if (reason) { rejected.push({ ...c, reject_reason: reason }); continue; }
    candidates.push(c);
  }
  candidates.sort((a, b) => (b.health_score || 0) - (a.health_score || 0));
  const top = candidates.slice(0, LIMIT);

  process.stderr.write(`After reject heuristics:               ${candidates.length}\n`);
  process.stderr.write(`Returning top ${top.length} by health_score (--limit)\n`);

  // Shape into tools_database.json schema. install_cmd is best-effort —
  // verify_integrity.cjs --update will refresh version + pkg_integrity.
  const shaped = top.map(c => ({
    name:            c.npm_package || c.name,
    category:        null,                              // human picks category at merge time
    install_cmd:     c.npm_package ? `npx -y ${c.npm_package}` : null,
    source_url:      c.source_url,
    version:         null,                              // filled by --update
    pkg_integrity:   null,                              // filled by --update
    trust:           'candidate',
    license:         c.license || 'Unknown',
    health_score:    c.health_score,
    classification:  c.classification,
    est_tools_count: null,                              // human estimate
    toolsets:        null,
    notes:           c.description || null,
    _discovery: {
      source:           c.source,
      stars:            c.stars,
      last_commit_days: c.last_commit_days,
      open_issues:      c.open_issues,
    },
  }));

  const out = {
    generated_at: new Date().toISOString(),
    sources:      SOURCES,
    raw_count:    merged.size,
    kept_count:   top.length,
    rejected_count: rejected.length,
    candidates:   shaped,
    rejected:     rejected.slice(0, 50).map(r => ({
      name: r.name, source_url: r.source_url, reason: r.reject_reason,
      stars: r.stars, last_commit_days: r.last_commit_days,
    })),
  };

  const json = JSON.stringify(out, null, 2) + '\n';
  if (OUT) {
    fs.writeFileSync(OUT, json);
    process.stderr.write(`\nWrote candidates → ${OUT}\n`);
  } else {
    process.stdout.write(json);
  }

  process.exit(top.length ? 0 : 1);
}

if (require.main === module) {
  main().catch((e) => { console.error(e.message); process.exit(1); });
}

module.exports = {
  normalizeRepoUrl,
  ownerRepoFromUrl,
  scoreHealth,
  classifyScore,
  looksLikeMcpServer,
  rejectReason,
};
