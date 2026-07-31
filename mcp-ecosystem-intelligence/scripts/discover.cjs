#!/usr/bin/env node
/**
 * MCP server discovery pipeline.
 *
 * Five sources, deduplicated by repo URL (or name when repo unknown):
 *   1. modelcontextprotocol/servers README — official curated list
 *   2. GitHub topic search — `topic:mcp-server`, `topic:mcp`, popular orgs
 *   3. npm search — keyword "mcp-server"
 *   4. MCP registry — registry.modelcontextprotocol.io/v0/servers (paginated)
 *   5. PyPI — `uvx`-installable servers (probe by name from /simple/ index)
 *
 * For each candidate:
 *   - skip if already in tools_database.json (matched by source_url or name)
 *   - fetch stars / last_commit_days / open_issues / license via `gh api`
 *     (only when source_url is a github.com repo; pypi/registry-only
 *     entries without a repo URL fall through to the reject filter)
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
 *                              [--source readme,gh,npm,registry,pypi | all]
 *                                                          default: readme,gh,npm
 *                              [--include-existing]        don't skip DB matches
 *                              [--max-health-checks N]     cap gh api calls
 *                              [--pypi-probe-limit N]      cap PyPI /json probes
 *                                                          (default 80)
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
const PYPI_PROBES   = parseInt(ARG('--pypi-probe-limit', '80'), 10);
const OUT           = ARG('--out', null);
const SOURCES_RAW   = ARG('--source', 'readme,gh,npm') || '';
const SOURCES       = SOURCES_RAW === 'all'
  ? ['readme', 'gh', 'npm', 'registry', 'pypi']
  : SOURCES_RAW.split(',').map(s => s.trim()).filter(Boolean);
const INCL_EXISTING = argv.includes('--include-existing');

// URLs are env-overridable so tests can stub them without monkey-patching.
const REGISTRY_BASE = process.env.MCP_DISCOVER_REGISTRY_URL
  || 'https://registry.modelcontextprotocol.io/v0/servers';
const PYPI_BASE     = process.env.MCP_DISCOVER_PYPI_URL || 'https://pypi.org';

// ── helpers ────────────────────────────────────────────────────────────────

// Deterministic tiebreaker for every ranked list this script writes. Ranking
// keys here (stars, health_score) are coarse and volatile; without a stable
// second key the output order tracks whichever source answered first, so a
// re-run reshuffles the file even when nothing was discovered or dropped.
// Locale-independent on purpose — the file is a git artifact, not UI.
function cmpName(a, b) {
  const x = String(a && a.name || '');
  const y = String(b && b.name || '');
  return x < y ? -1 : x > y ? 1 : 0;
}

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

// ── MCP registry (registry.modelcontextprotocol.io) ────────────────────────
//
// Parses one /v0/servers page into our candidate shape. Pure function — given
// a parsed JSON body, returns candidates + nextCursor. Network-free so tests
// hit it with a fixture.
//
// Real registry shape (verified 2026-05): each entry is
//   { server: { name, title?, description?, repository?: {url,source,subfolder?},
//               packages?: [{ registryType, identifier, version, ... }],
//               remotes?: [...] }, _meta: {...} }
// SKILL.md's documented `packages[].installCommand` field isn't actually
// present on live responses — we synthesize the install_cmd from registryType
// + identifier + version below.
function parseRegistryPage(body) {
  if (!body || !Array.isArray(body.servers)) return { entries: [], nextCursor: null };
  const entries = [];
  for (const item of body.servers) {
    const srv = item && item.server;
    if (!srv || !srv.name) continue;
    const repoRaw = srv.repository && srv.repository.url;
    const repo    = repoRaw ? normalizeRepoUrl(repoRaw) : null;
    const pkg     = Array.isArray(srv.packages) && srv.packages[0];
    let install   = null;
    let npmPkg    = null;
    let pypiPkg   = null;
    if (pkg && pkg.identifier) {
      const ver = pkg.version ? `@${pkg.version}` : '';
      if (pkg.registryType === 'npm') {
        install = `npx -y ${pkg.identifier}${ver}`;
        npmPkg  = pkg.identifier;
      } else if (pkg.registryType === 'pypi') {
        install = `uvx ${pkg.identifier}${pkg.version ? `==${pkg.version}` : ''}`;
        pypiPkg = pkg.identifier;
      } else if (pkg.registryType === 'oci') {
        install = `docker run --rm -i ${pkg.identifier}`;
      }
    }
    entries.push({
      name:         srv.title || srv.name,
      registry_id:  srv.name,
      description:  srv.description || null,
      source_url:   repo,
      install_cmd:  install,
      npm_package:  npmPkg,
      pypi_package: pypiPkg,
      source:       'mcp-registry',
    });
  }
  const nextCursor = body.metadata && body.metadata.nextCursor;
  return { entries, nextCursor: nextCursor || null };
}

async function fromMcpRegistry(opts = {}) {
  const fetcher   = opts.fetcher || (async (url) => {
    const raw = await httpsGet(url);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  });
  const maxPages  = opts.maxPages != null ? opts.maxPages : 20;   // ~600 entries cap
  const base      = opts.base || REGISTRY_BASE;
  const out       = [];
  const seen      = new Set();   // dedupe registry-internal duplicates (versions)
  let cursor      = null;
  for (let i = 0; i < maxPages; i++) {
    const url = cursor
      ? `${base}?cursor=${encodeURIComponent(cursor)}`
      : base;
    const body = await fetcher(url);
    if (!body) break;
    const { entries, nextCursor } = parseRegistryPage(body);
    for (const e of entries) {
      // Dedupe by registry name (multiple versions appear as separate entries).
      if (seen.has(e.registry_id)) continue;
      seen.add(e.registry_id);
      out.push(e);
    }
    if (!nextCursor || nextCursor === cursor) break;
    cursor = nextCursor;
  }
  return out;
}

// ── PyPI (uvx-installable servers) ─────────────────────────────────────────
//
// PyPI deprecated its JSON search endpoint and the HTML /search/ now returns
// a bot-challenge page (verified 2026-05). Strategy: pull the /simple/ index
// (one HTML page listing every package on PyPI, ~6MB, no auth, cacheable),
// regex out names matching MCP-server prefixes, then probe per-package
// /pypi/<name>/json for description + repo URL.
//
// Limitations:
//   - prefix-based ⇒ misses packages that don't start with "mcp-" or
//     "*-mcp-server" (rare in practice; the convention is strong).
//   - capped to --pypi-probe-limit to avoid hammering /pypi/<>/json.
// If PyPI changes the /simple/ format the regex just stops returning
// candidates — the source silently degrades rather than crashing.
function parsePypiSimpleIndex(html) {
  if (typeof html !== 'string' || !html) return [];
  const names = new Set();
  // /simple/ entries look like: <a href="/simple/mcp-foo/">mcp-foo</a>
  // Match either the anchor text or the href to be robust to format tweaks.
  const re = /<a[^>]*>([a-z0-9][a-z0-9._-]*)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const n = m[1].toLowerCase();
    // Accept either prefix; later filtering keeps real MCP servers.
    if (/^mcp[-_.]/.test(n) || /[-_.]mcp[-_.]?server/.test(n)) names.add(n);
  }
  return [...names].sort();
}

function parsePypiJson(body) {
  if (!body || typeof body !== 'object') return null;
  const info = body.info;
  if (!info || typeof info !== 'object' || !info.name) return null;
  const urls = info.project_urls || {};
  // Common keys in the wild: Source, Repository, Homepage, Source Code, Code.
  const repoCandidates = [
    urls.Source, urls.Repository, urls['Source Code'], urls.Code,
    urls.Homepage, info.home_page,
  ].filter(Boolean);
  let repo = null;
  for (const u of repoCandidates) {
    if (typeof u === 'string' && /github\.com/.test(u)) {
      repo = normalizeRepoUrl(u);
      break;
    }
  }
  return {
    name:         info.name,
    description:  info.summary || null,
    version:      info.version || null,
    source_url:   repo,
    install_cmd:  info.version ? `uvx ${info.name}==${info.version}` : `uvx ${info.name}`,
    pypi_package: info.name,
    source:       'pypi',
  };
}

async function fromPyPI(opts = {}) {
  const fetcherText = opts.fetcherText || ((url) => httpsGet(url));
  const fetcherJson = opts.fetcherJson || (async (url) => {
    const raw = await httpsGet(url);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  });
  const probeLimit  = opts.probeLimit != null ? opts.probeLimit : PYPI_PROBES;
  const base        = opts.base || PYPI_BASE;

  const html  = await fetcherText(`${base}/simple/`);
  const names = parsePypiSimpleIndex(html);
  // Pre-rank: names containing "mcp-server-" probably are servers; bare "mcp-"
  // mixes in SDKs/utilities. Probe servers first so probe cap hits high-signal
  // entries before noise.
  names.sort((a, b) => {
    const aServer = /mcp[-_]server/.test(a) ? 0 : 1;
    const bServer = /mcp[-_]server/.test(b) ? 0 : 1;
    return aServer - bServer || a.localeCompare(b);
  });
  const toProbe = names.slice(0, probeLimit);
  const out = [];
  for (const n of toProbe) {
    const body = await fetcherJson(`${base}/pypi/${encodeURIComponent(n)}/json`);
    const cand = parsePypiJson(body);
    if (cand) out.push(cand);
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
  if (cand.source && cand.source.includes('mcp-registry'))       return true;
  if (cand.source && cand.source.includes('pypi'))               return true;
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
  if (SOURCES.includes('readme'))   seedLists.push(await fromMcpServersReadme());
  if (SOURCES.includes('gh'))       seedLists.push(fromGhSearch());
  if (SOURCES.includes('npm'))      seedLists.push(fromNpmSearch());
  if (SOURCES.includes('registry')) seedLists.push(await fromMcpRegistry());
  if (SOURCES.includes('pypi'))     seedLists.push(await fromPyPI());

  // Merge and dedupe by repo URL when known, else by name+source-tag. Entries
  // from registry/pypi without a github repo still flow downstream so the
  // human reviewer sees them (annotateHealthFromGh just returns null for
  // those, and the reject filter handles the rest).
  const merged = new Map();
  for (const list of seedLists) {
    for (const c of list) {
      const key = c.source_url || `noref::${c.source}::${(c.name || '').toLowerCase()}`;
      if (merged.has(key)) {
        const prev = merged.get(key);
        prev.source = `${prev.source}+${c.source}`;
        if (!prev.description  && c.description)  prev.description  = c.description;
        if (!prev.npm_package  && c.npm_package)  prev.npm_package  = c.npm_package;
        if (!prev.pypi_package && c.pypi_package) prev.pypi_package = c.pypi_package;
        if (!prev.install_cmd  && c.install_cmd)  prev.install_cmd  = c.install_cmd;
        continue;
      }
      merged.set(key, { ...c });
    }
  }

  process.stderr.write(`Raw candidates (merged across sources): ${merged.size}\n`);

  // Skip already-in-DB.
  let kept = [...merged.values()];
  if (!INCL_EXISTING) {
    kept = kept.filter(c => {
      if (c.source_url && existing.has(c.source_url)) return false;
      if (c.name && existing.has(c.name.toLowerCase())) return false;
      if (c.npm_package && existing.has(c.npm_package.toLowerCase())) return false;
      if (c.pypi_package && existing.has(c.pypi_package.toLowerCase())) return false;
      return true;
    });
    process.stderr.write(`After dropping existing DB entries:    ${kept.length}\n`);
  }

  // Soft pre-rank by initial stars (from gh-topic source if present) so the
  // --max-health-checks cap takes the most promising entries first. Ties break
  // on name: without it the cap would keep a different subset run to run,
  // depending on the order the sources happened to answer in.
  kept.sort((a, b) => (b.stars || 0) - (a.stars || 0) || cmpName(a, b));
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
      // registry/pypi entries already carry install_cmd; npm-search implies one.
      has_install_cmd: !!(cand.install_cmd || cand.npm_package || cand.pypi_package),
      // True if the candidate is published in the official registry, or if it
      // ships through any package registry we already trust.
      in_registry:     !!(cand.source && cand.source.includes('mcp-registry'))
                       || !!cand.npm_package
                       || !!cand.pypi_package,
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
  // Rank for triage — highest health first — but break ties on name, so the
  // stored order is a function of the data and not of network timing.
  // health_score is coarse: measured on the current inbox, 45 of 50 entries
  // share a score with at least one other, so without a tiebreaker almost the
  // whole file reshuffles every week. That turned a ~41-entry change into a
  // 1755-line diff (PR #71) and made the reviewer checklist unusable.
  candidates.sort((a, b) => (b.health_score || 0) - (a.health_score || 0) || cmpName(a, b));
  const top = candidates.slice(0, LIMIT);

  process.stderr.write(`After reject heuristics:               ${candidates.length}\n`);
  process.stderr.write(`Returning top ${top.length} by health_score (--limit)\n`);

  // Shape into tools_database.json schema. install_cmd is best-effort —
  // verify_integrity.cjs --update will refresh version + pkg_integrity.
  const shaped = top.map(c => ({
    name:            c.npm_package || c.pypi_package || c.name,
    category:        null,                              // human picks category at merge time
    install_cmd:     c.install_cmd
                       || (c.npm_package  ? `npx -y ${c.npm_package}` : null)
                       || (c.pypi_package ? `uvx ${c.pypi_package}`   : null),
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
      registry_id:      c.registry_id || null,
    },
  }));

  const out = {
    generated_at: new Date().toISOString(),
    sources:      SOURCES,
    raw_count:    merged.size,
    kept_count:   top.length,
    rejected_count: rejected.length,
    candidates:   shaped,
    // Rejects carry no ranking at all, so they were stored in raw discovery
    // order — the noisiest part of the diff. Name order makes the truncation
    // to 50 reproducible too.
    rejected:     [...rejected].sort(cmpName).slice(0, 50).map(r => ({
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
  cmpName,
  normalizeRepoUrl,
  ownerRepoFromUrl,
  scoreHealth,
  classifyScore,
  looksLikeMcpServer,
  rejectReason,
  parseRegistryPage,
  fromMcpRegistry,
  parsePypiSimpleIndex,
  parsePypiJson,
  fromPyPI,
};
