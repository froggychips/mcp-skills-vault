#!/usr/bin/env node
/**
 * mcp-vault export-registry — the DB as a static sub-registry of the official
 * MCP Registry (API v0.1), servable from GitHub Pages as it is.
 *
 * Writes, under <out>/v0.1/ (<out> is the site root, served at --base-url):
 *
 *   servers/index.html                         GET /v0.1/servers   (one page, no cursor)
 *   servers/<name>/versions/index.html         GET …/versions
 *   servers/<name>/versions/latest             GET …/versions/latest
 *   servers/<name>/versions/<version>          GET …/versions/<version>
 *   servers.json, …/versions.json, …/latest.json, …/<version>.json
 *                                              the same bytes, as application/json
 *   x/<namespace>/toolhive.json                ToolHive upstream-format registry file
 *   x/<namespace>/export.json                  manifest: as-of instant, skips, sha256 per file
 *
 * <name> is written twice, URL-encoded (`io.github.o%2Fr`) and decoded
 * (`io.github.o/r`), because static hosts disagree about `%2F` — see
 * lib/subregistry.cjs.
 *
 * What a static host cannot do, and so this export does not pretend to:
 *   - `?search=`, `?updated_since=`, `?version=`, `?include_deleted=` are
 *     ignored — every request for /v0.1/servers gets the whole list;
 *   - `?limit=` / `?cursor=` are ignored — there is one page, and no
 *     `nextCursor`, so a client paginating correctly stops after it;
 *   - on GitHub Pages the API paths are served as `text/html` (list
 *     endpoints are `index.html`) and `application/octet-stream` (single
 *     versions have no extension). The bodies are JSON, and the clients
 *     checked (VS Code's gallery, ToolHive) parse the body without looking at
 *     the Content-Type; for anything that does, each endpoint has a `.json`
 *     twin served as `application/json` — see jsonTwin in lib/subregistry.cjs.
 *
 * Offline: no network. Each entry's verdict is the Decision `decide()` makes
 * over its stored evidence (the model `explain` renders), under the policy
 * that applies to --cwd, as of one instant: the clock read once here, or
 * --as-of (lib/clock.cjs, docs/adr/0001). Same DB, policy and instant: same
 * bytes.
 *
 * Usage:
 *   node scripts/export_subregistry.cjs [--out <dir>] [--base-url <url>]
 *                                       [--as-of <date|instant>] [--cwd <dir>]
 *                                       [--min-tier Core|Recommended|Experimental]
 *                                       [--check] [--json]
 *
 *   --out       site root to write under (default: docs/site, git-ignored)
 *   --base-url  where that root is served; every absolute URL written is built
 *               from it (default: https://mcp.froggychips.xyz)
 *   --as-of     judge as of YYYY-MM-DD or an ISO-8601 instant (default: now;
 *               with --check, the instant the export on disk was made at)
 *   --cwd       the project whose policy applies (default: the working directory)
 *   --check     write nothing; exit 1 if the files on disk differ from a fresh export
 *   --json      print the manifest (schema mcp-vault/subregistry-export@1),
 *               with every entry's findings and Decision under `findings`
 *               (mcp-vault/findings@1)
 *
 * Exit codes:
 *   0  export written (or --check: on-disk export is current)
 *   1  --check: the on-disk export differs from the data
 *   2  bad arguments, unreadable DB, or an export that could not be built
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { buildExport, normalizeBaseUrl, jsonTwin, API_PREFIX, NAMESPACE, DEFAULT_BASE_URL } = require('./lib/subregistry.cjs');
const { asOfFromArgv, parseAsOf } = require('./lib/clock.cjs');
const { loadEffectivePolicy } = require('./lib/policy_rules.cjs');

const ROOT      = path.resolve(__dirname, '..', '..');
const DB_PATH   = path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json');
const EVAL_PATH = path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'eval_results.json');
const DEFAULT_OUT = path.join(ROOT, 'docs', 'site');

const HELP = `export-registry — the vault as a static MCP sub-registry (API v0.1)

  --out <dir>        site root to write under (default: docs/site)
  --base-url <url>   where that root is served (default: ${DEFAULT_BASE_URL})
  --as-of <date>     judge as of YYYY-MM-DD or an ISO-8601 instant (default: now;
                     with --check, the instant the export on disk was made at)
  --cwd <dir>        the project whose policy applies (default: .)
  --min-tier <t>     Core | Recommended | Experimental (default: Experimental)
  --check            write nothing; exit 1 if the on-disk export is stale
  --json             print the manifest, with findings and decisions (findings@1)
`;

function parseArgs(argv) {
  const opts = { out: DEFAULT_OUT, baseUrl: DEFAULT_BASE_URL, cwd: process.cwd(), minTier: 'Experimental', check: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => {
      const v = argv[++i];
      if (!v || v.startsWith('--')) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === '--out') opts.out = path.resolve(val());
    else if (a === '--base-url') opts.baseUrl = val();
    else if (a === '--as-of') val();                 // read by asOfFromArgv
    else if (a.startsWith('--as-of=')) { /* read by asOfFromArgv */ }
    else if (a === '--cwd') opts.cwd = path.resolve(val());
    else if (a === '--min-tier') opts.minTier = val();
    else if (a === '--check') opts.check = true;
    else if (a === '--json') opts.json = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  opts.baseUrl = normalizeBaseUrl(opts.baseUrl);
  // The one clock read for this run (lib/clock.cjs).
  const clock = asOfFromArgv(argv);
  if (clock.error) throw new Error(clock.error);
  opts.clock = clock;
  if (!['Core', 'Recommended', 'Experimental'].includes(opts.minTier)) {
    throw new Error('--min-tier must be Core, Recommended or Experimental');
  }
  return opts;
}

/** Every file currently under the directories this export owns. */
function ownedFiles(out) {
  const found = [];
  const walk = (rel) => {
    const abs = path.join(out, rel);
    let entries;
    try { entries = fs.readdirSync(abs, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const r = path.posix.join(rel, e.name);
      if (e.isDirectory()) walk(r);
      else if (e.isFile()) found.push(r);
    }
  };
  walk(`${API_PREFIX}/servers`);
  walk(`${API_PREFIX}/x/${NAMESPACE}`);
  const listTwin = jsonTwin(`${API_PREFIX}/servers/index.html`);
  if (fs.existsSync(path.join(out, listTwin))) found.push(listTwin);
  return found.sort();
}

/** Files to add, change and remove to make <out> match `files`. */
function diffAgainstDisk(out, files) {
  const onDisk = new Set(ownedFiles(out));
  const changed = [];
  for (const [rel, body] of files) {
    let cur = null;
    try { cur = fs.readFileSync(path.join(out, rel), 'utf8'); } catch { /* absent */ }
    if (cur !== body) changed.push(rel);
    onDisk.delete(rel);
  }
  return { changed: changed.sort(), removed: [...onDisk].sort() };
}

function writeExport(out, files) {
  // Only the two directories this export owns are cleared: the rest of the
  // site belongs to other generators.
  fs.rmSync(path.join(out, API_PREFIX, 'servers'), { recursive: true, force: true });
  fs.rmSync(path.join(out, API_PREFIX, 'x', NAMESPACE), { recursive: true, force: true });
  fs.rmSync(path.join(out, jsonTwin(`${API_PREFIX}/servers/index.html`)), { force: true });
  for (const rel of [...files.keys()].sort()) {
    const abs = path.join(out, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, files.get(rel));
  }
}

function run(argv, { dbPath = DB_PATH, evalPath = EVAL_PATH } = {}) {
  let opts;
  try { opts = parseArgs(argv); } catch (e) {
    process.stderr.write(`export-registry: ${e.message}\n\n${HELP}`);
    return 2;
  }
  if (opts.help) { process.stdout.write(HELP); return 0; }

  let db;
  try { db = JSON.parse(fs.readFileSync(dbPath, 'utf8')); } catch (e) {
    process.stderr.write(`export-registry: cannot read the DB: ${e.message}\n`);
    return 2;
  }
  // No eval snapshot is "nothing has run yet", not an error.
  let evals = { results: [] };
  try { evals = JSON.parse(fs.readFileSync(evalPath, 'utf8')); } catch { /* none shipped */ }

  // The same loader every command uses; the effective policy is recorded in
  // the findings document, so the verdicts can be recomputed from it.
  const loaded = loadEffectivePolicy(opts.cwd);
  if (!loaded.ok) {
    process.stderr.write(`export-registry: policy ${loaded.path}: ${(loaded.errors || []).join('; ')}\n`);
    return 2;
  }

  // --check without --as-of replays the instant the export on disk was made
  // at: "is it stale" means "does the data still produce these files", not
  // "would today's clock produce them".
  let asOf = opts.clock.asOf;
  if (opts.check && opts.clock.source !== 'as-of') {
    try {
      const onDisk = JSON.parse(fs.readFileSync(path.join(opts.out, API_PREFIX, 'x', NAMESPACE, 'export.json'), 'utf8'));
      asOf = parseAsOf(onDisk.as_of);
    } catch { /* nothing (readable) on disk: stale at any instant */ }
  }

  let built;
  try { built = buildExport(db, evals, { asOf, policy: loaded.policy, minTier: opts.minTier, baseUrl: opts.baseUrl }); } catch (e) {
    process.stderr.write(`export-registry: ${e.message}\n`);
    return 2;
  }
  const { files, manifest, findings } = built;

  if (opts.check) {
    const { changed, removed } = diffAgainstDisk(opts.out, files);
    const stale = changed.length + removed.length > 0;
    if (opts.json) {
      process.stdout.write(`${JSON.stringify({ ...manifest, check: { stale, changed, removed }, findings }, null, 2)}\n`);
    } else if (stale) {
      process.stdout.write(`export is stale: ${changed.length} file(s) differ, ${removed.length} should not exist\n`);
      for (const f of [...changed, ...removed].slice(0, 20)) process.stdout.write(`  ${f}\n`);
      process.stdout.write('regenerate with: mcp-vault export-registry\n');
    } else {
      process.stdout.write(`export is current (${manifest.exported} servers, as of ${manifest.as_of})\n`);
    }
    return stale ? 1 : 0;
  }

  writeExport(opts.out, files);
  if (opts.json) {
    process.stdout.write(`${JSON.stringify({ ...manifest, findings }, null, 2)}\n`);
  } else {
    process.stdout.write(`Exported ${manifest.exported} servers as of ${manifest.as_of} → ${path.join(opts.out, API_PREFIX)}\n`);
    process.stdout.write(`${files.size} files; ${manifest.skipped.length} entries not exported:\n`);
    for (const s of manifest.skipped) process.stdout.write(`  ${s.name}: ${s.reason}\n`);
  }
  return 0;
}

if (require.main === module) exitAfterFlush(run(process.argv.slice(2)));

module.exports = { run, parseArgs, writeExport, diffAgainstDisk, ownedFiles };
