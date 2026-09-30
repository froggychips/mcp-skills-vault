#!/usr/bin/env node
/**
 * mcp-vault badge — a "vetted by mcp-vault" badge for an entry, and the pages
 * it points at.
 *
 * Two modes:
 *
 *   badge <name>   prints the Markdown / HTML snippet an author pastes into a
 *                  README, and what the badge says today. Offline; reads the DB.
 *   badge --write  renders every entry's badge into a site root (--out):
 *                    badges/<slug>.svg    flat SVG, rendered here
 *                    badges/<slug>.json   shields.io endpoint format
 *                    badges/index.json    name → slug, state, date
 *                    entry/<slug>.html    the evidence behind it
 *                  `site-registry` calls this with its own --out/--base-url,
 *                  so the badges are rebuilt whenever the registry page is.
 *
 * The public site (mcp.froggychips.xyz) is assembled in froggychips/mcp-site
 * from the npm release: that repo runs these generators with --out pointed at
 * its own root. Nothing generated here is committed to the vault.
 *
 * A badge is a claim made on somebody else's README, so it says what the DB
 * says and nothing warmer: the derived tier, the date of the newest evidence,
 * and `stale` instead of the tier once a required check is past its shelf life
 * (lib/badge.cjs has the rules). The page it links to lists every dimension
 * with its date, and how to dispute it.
 *
 * Usage:
 *   node scripts/badge.cjs <name> [--json] [--base-url <url>]
 *   node scripts/badge.cjs --write [--out <dir>] [--base-url <url>] [--now YYYY-MM-DD] [--json]
 *
 * Exit codes:
 *   0  printed / written
 *   2  no such entry, bad arguments, or two entries would share a badge file
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb } = require('./lib/db_io.cjs');
const { evalIndex } = require('./lib/tiers.cjs');
const { DEFAULT_MAX_AGE_DAYS, staleDimensions } = require('./lib/evidence.cjs');
const {
  badgeState, renderSvg, endpointJson, slugFor, badgeUrls, snippet, escXml, SITE,
} = require('./lib/badge.cjs');

const ROOT      = path.resolve(__dirname, '..', '..');
const DB_PATH   = path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json');
const EVAL_PATH = path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'eval_results.json');
const SITE_DIR  = path.join(ROOT, 'docs', 'site');
const REPO      = 'https://github.com/froggychips/mcp-skills-vault';

const HELP = `badge — a "vetted by mcp-vault" badge for an entry

USAGE
  mcp-vault badge <name> [--json] [--base-url <url>]
  mcp-vault badge --write [--out <dir>] [--base-url <url>] [--now YYYY-MM-DD] [--json]

  <name>      print the README snippet (Markdown, HTML, shields endpoint)
              and what the badge says today
  --write     render every entry's badges/<slug>.svg, badges/<slug>.json and
              entry/<slug>.html under the site root
  --out       the site root to write into (default: docs/site in this checkout)
  --base-url  URL the site root is served at; every link and snippet is built
              from it (default: ${SITE})
  --now       the date staleness is judged against (default: today)
  --json      machine-readable output
`;

function parseArgs(argv) {
  const opts = { name: null, json: false, write: false, out: SITE_DIR, now: null, base: SITE, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--write') opts.write = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--out') { const v = argv[++i]; if (!v) return { ...opts, error: '--out needs a directory' }; opts.out = path.resolve(v); }
    else if (a === '--base-url' || a === '--base') {
      opts.base = (argv[++i] || '').replace(/\/+$/, '');
      if (!/^https?:\/\/[^\s"'<>]+$/i.test(opts.base)) return { ...opts, error: '--base-url needs an http(s) URL' };
    }
    else if (a === '--now') {
      const v = argv[++i];
      if (!/^\d{4}-\d{2}-\d{2}$/.test(v || '') || Number.isNaN(Date.parse(`${v}T00:00:00Z`))) {
        return { ...opts, error: '--now takes a date, YYYY-MM-DD' };
      }
      opts.now = Date.parse(`${v}T00:00:00Z`);
    }
    else if (a.startsWith('--')) return { ...opts, error: `unknown flag ${a}` };
    else if (!opts.name) opts.name = a;
    else return { ...opts, error: 'badge takes one entry name' };
  }
  if (!opts.help && !opts.write && !opts.name) return { ...opts, error: 'which entry? `mcp-vault badge <name>`, or --write for all' };
  if (opts.write && opts.name) return { ...opts, error: '--write renders every entry; drop the name' };
  return opts;
}

function loadEvals(evalPath = EVAL_PATH) {
  // Behavioural results may be absent; an empty file is not an empty claim.
  try { return evalIndex(JSON.parse(fs.readFileSync(evalPath, 'utf8')).results); }
  catch { return new Map(); }
}

// Midnight UTC of the day, so that every run on one day renders the same bytes.
const dayOf = (ms) => Date.parse(`${new Date(ms).toISOString().slice(0, 10)}T00:00:00Z`);

/** One entry's evidence page. Minimal on purpose: the facts, their dates, and how to argue. */
function renderEntryPage(tool, state, evalResult, { now, base = SITE }) {
  const dims = (tool.trust_evidence && tool.trust_evidence.dimensions) || {};
  const staleSet = new Set(staleDimensions(tool.trust_evidence || null, DEFAULT_MAX_AGE_DAYS, now).map((s) => s.dimension));
  const rows = Object.keys(dims).sort().map((k) => {
    const v = dims[k] || {};
    const limit = DEFAULT_MAX_AGE_DAYS[k];
    return `        <tr><td>${escXml(k)}</td><td>${escXml(v.status)}</td><td>${escXml(v.checked_at || 'unknown')}</td>`
      + `<td>${Number.isFinite(limit) ? `${limit} d` : '—'}</td><td>${staleSet.has(k) ? 'stale' : 'current'}</td></tr>`;
  }).join('\n');
  const smoke = evalResult
    ? `${escXml(evalResult.status)}${evalResult.tool_count != null ? `, ${escXml(evalResult.tool_count)} tools` : ''} (as of ${escXml(String(evalResult.checked_at || '').slice(0, 10) || 'unknown')})`
    : 'never run';
  const s = snippet(tool.name, base);
  const dispute = `${REPO}/issues/new?title=${encodeURIComponent(`Evidence dispute: ${tool.name}`)}`;
  const asOf = new Date(now).toISOString().slice(0, 10);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escXml(tool.name)} — mcp-vault</title>
  <meta name="description" content="What mcp-vault checked about ${escXml(tool.name)}, and when.">
  <link rel="canonical" href="${escXml(badgeUrls(tool.name, base).page)}">
  <link rel="stylesheet" href="../style.css">
</head>
<body>
  <header>
    <nav>
      <a href="../index.html">home</a>
      <a href="../registry.html">registry</a>
      <a href="${REPO}">github</a>
    </nav>
  </header>
  <main>
    <h1>${escXml(tool.name)}</h1>
    <p><img alt="vetted by mcp-vault: ${escXml(state.message)}" src="../badges/${escXml(state.slug)}.svg"></p>
    <p class="lede">Tier <strong>${escXml(state.tier)}</strong>: ${escXml(state.why)}.</p>
    <p>${state.stale
      ? `Past its shelf life: ${escXml(state.stale_dimensions.join(', '))}. ${state.state === 'Deprecated'
        ? 'A failed check outranks that, so the badge says <em>blocked</em> until a re-run finds otherwise.'
        : 'The badge says <em>stale</em> until the check is re-run.'}`
      : 'Every check the tier depends on is within its shelf life.'} Judged as of ${escXml(asOf)}; the tier is derived from the evidence below, never stored.</p>
    <dl>
      <dt>Source</dt><dd>${/^https?:\/\//i.test(tool.source_url || "") ? `<a href="${escXml(tool.source_url)}">${escXml(tool.source_url)}</a>` : escXml(tool.source_url || "unknown")}</dd>
      <dt>Install</dt><dd><code>${escXml(tool.install_cmd)}</code></dd>
      <dt>Artifact</dt><dd><code>${escXml((tool.trust_evidence && tool.trust_evidence.artifact_id) || 'not recorded')}</code></dd>
      <dt>Smoke</dt><dd>${smoke}</dd>
    </dl>
    <h2>Evidence</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Dimension</th><th>Status</th><th>Checked</th><th>Shelf life</th><th>Now</th></tr></thead>
        <tbody>
${rows || '        <tr><td colspan="5">no evidence recorded</td></tr>'}
        </tbody>
      </table>
    </div>
    <h2>Reproduce</h2>
    <pre><code>npx -y @froggychips/mcp-vault explain ${escXml(tool.name)}
npx -y @froggychips/mcp-vault verify --entry ${escXml(tool.name)}</code></pre>
    <h2>Wrong?</h2>
    <p>If any of this is inaccurate, <a href="${escXml(dispute)}">open an issue</a> with what you see instead — the evidence is re-checked, not argued.</p>
    <h2>Badge</h2>
    <pre><code>${escXml(s.markdown)}</code></pre>
  </main>
</body>
</html>
`;
}

/**
 * Render every entry. Returns the manifest; `write` false returns the files as
 * a map instead of touching the disk (used by tests).
 */
function buildAll(tools, evals, { now, base = SITE } = {}) {
  const files = new Map();
  const bySlug = new Map();
  const index = [];
  const sorted = [...tools].sort((a, b) => (String(a.name) < String(b.name) ? -1 : String(a.name) > String(b.name) ? 1 : 0));
  for (const t of sorted) {
    const slug = slugFor(t.name);
    if (bySlug.has(slug)) {
      throw new Error(`"${bySlug.get(slug)}" and "${t.name}" would share the badge file ${slug}.svg`);
    }
    bySlug.set(slug, t.name);
    const ev = evals.get(t.name) || null;
    const st = badgeState(t, ev, { now });
    files.set(`badges/${slug}.svg`, renderSvg({ label: st.label, message: st.message, color: st.color, title: `${st.label}: ${st.message} — ${st.why}` }));
    files.set(`badges/${slug}.json`, `${JSON.stringify(endpointJson(st), null, 2)}\n`);
    files.set(`entry/${slug}.html`, renderEntryPage(t, st, ev, { now, base }));
    index.push({
      name: st.name, slug, state: st.state, tier: st.tier, stale: st.stale,
      stale_dimensions: st.stale_dimensions, latest_evidence: st.latest_evidence,
      ...badgeUrls(t.name, base),
    });
  }
  const as_of = new Date(now).toISOString().slice(0, 10);
  files.set('badges/index.json', `${JSON.stringify({ schema: 'mcp-vault/badges@1', as_of, count: index.length, entries: index }, null, 2)}\n`);
  return { files, index, as_of };
}

function writeAll(outDir, files) {
  // Clear what a previous run wrote, so a removed entry's badge does not keep
  // vouching for it. Only these two generated directories.
  for (const sub of ['badges', 'entry']) {
    fs.rmSync(path.join(outDir, sub), { recursive: true, force: true });
    fs.mkdirSync(path.join(outDir, sub), { recursive: true });
  }
  for (const [rel, body] of files) fs.writeFileSync(path.join(outDir, rel), body);
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.help) { process.stdout.write(HELP); return 0; }
  if (opts.error) { process.stderr.write(`badge: ${opts.error}\n\n${HELP}`); return 2; }

  const { db } = readDb(DB_PATH);
  const tools = db.tools || [];
  const evals = loadEvals();
  const now = dayOf(opts.now ?? Date.now());

  if (opts.write) {
    let built;
    try { built = buildAll(tools, evals, { now, base: opts.base }); }
    catch (e) { process.stderr.write(`badge: ${e.message}\n`); return 2; }
    writeAll(opts.out, built.files);
    const counts = {};
    for (const e of built.index) counts[e.state] = (counts[e.state] || 0) + 1;
    if (opts.json) {
      process.stdout.write(`${JSON.stringify({ schema: 'mcp-vault/badges@1', as_of: built.as_of, out: opts.out, count: built.index.length, states: counts }, null, 2)}\n`);
    } else {
      process.stdout.write(`Wrote ${built.index.length} badges to ${path.join(opts.out, 'badges')} (as of ${built.as_of}: `
        + `${Object.keys(counts).sort().map((k) => `${counts[k]} ${k}`).join(', ')})\n`);
    }
    return 0;
  }

  const tool = tools.find((t) => t.name === opts.name);
  if (!tool) {
    process.stderr.write(`badge: no entry named "${opts.name}" — \`mcp-vault list --query ${opts.name}\`\n`);
    return 2;
  }
  const st = badgeState(tool, evals.get(tool.name) || null, { now });
  const urls = badgeUrls(tool.name, opts.base);
  const snip = snippet(tool.name, opts.base);
  if (opts.json) {
    process.stdout.write(`${JSON.stringify({ schema: 'mcp-vault/badge@1', ...st, urls, snippet: snip }, null, 2)}\n`);
    return 0;
  }
  process.stdout.write(`${tool.name}: ${st.message}${st.stale ? `  (stale: ${st.stale_dimensions.join(', ')})` : ''}\n`);
  process.stdout.write(`  ${st.why}\n\n`);
  process.stdout.write(`Markdown\n  ${snip.markdown}\n\nHTML\n  ${snip.html}\n\nshields.io endpoint\n  ${snip.shields_markdown}\n\n`);
  process.stdout.write(`The badge is rebuilt with the registry page, and says "stale" once a check it rests on\n`
    + `is past its shelf life. Evidence: ${urls.page}\n`);
  return 0;
}

if (require.main === module) exitAfterFlush(main(process.argv.slice(2)));

module.exports = { parseArgs, buildAll, writeAll, renderEntryPage, main };
