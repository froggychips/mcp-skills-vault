#!/usr/bin/env node
/**
 * mcp-vault export-registry — the DB as a static sub-registry of the official
 * MCP Registry (API v0.1), servable from GitHub Pages as it is.
 *
 * Writes, under <out>/v0.1/:
 *
 *   servers/index.html                         GET /v0.1/servers   (one page, no cursor)
 *   servers/<name>/versions/index.html         GET …/versions
 *   servers/<name>/versions/latest             GET …/versions/latest
 *   servers/<name>/versions/<version>          GET …/versions/<version>
 *   x/xyz.froggychips.mcp/toolhive.json        ToolHive upstream-format registry file
 *   x/xyz.froggychips.mcp/export.json          manifest: as-of date, skips, sha256 per file
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
 *   - list endpoints are served as `text/html` (they are `index.html`) and
 *     single versions as `application/octet-stream` (no extension). The bodies
 *     are JSON; a client that insists on the Content-Type needs a real server.
 *
 * Offline and deterministic: no clock, no network. The tier is computed as of
 * the newest evidence date in the data (or --as-of), and the same DB produces
 * the same bytes.
 *
 * Usage:
 *   node scripts/export_subregistry.cjs [--out <dir>] [--as-of YYYY-MM-DD]
 *                                       [--min-tier Core|Recommended|Experimental]
 *                                       [--check] [--json]
 *
 *   --out       site root to write under (default: docs/site)
 *   --check     write nothing; exit 1 if the files on disk differ from a fresh export
 *   --json      print the manifest (schema mcp-vault/subregistry-export@1)
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
const { buildExport, API_PREFIX, NAMESPACE } = require('./lib/subregistry.cjs');

const ROOT      = path.resolve(__dirname, '..', '..');
const DB_PATH   = path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json');
const EVAL_PATH = path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'eval_results.json');
const DEFAULT_OUT = path.join(ROOT, 'docs', 'site');

const HELP = `export-registry — the vault as a static MCP sub-registry (API v0.1)

  --out <dir>        site root to write under (default: docs/site)
  --as-of <date>     compute tiers as of YYYY-MM-DD (default: newest evidence date)
  --min-tier <t>     Core | Recommended | Experimental (default: Experimental)
  --check            write nothing; exit 1 if the on-disk export is stale
  --json             print the manifest
`;

function parseArgs(argv) {
  const opts = { out: DEFAULT_OUT, asOf: null, minTier: 'Experimental', check: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => {
      const v = argv[++i];
      if (!v || v.startsWith('--')) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === '--out') opts.out = path.resolve(val());
    else if (a === '--as-of') opts.asOf = val();
    else if (a === '--min-tier') opts.minTier = val();
    else if (a === '--check') opts.check = true;
    else if (a === '--json') opts.json = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  if (opts.asOf && !/^\d{4}-\d{2}-\d{2}$/.test(opts.asOf)) throw new Error('--as-of must be YYYY-MM-DD');
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

  let built;
  try { built = buildExport(db, evals, { asOf: opts.asOf, minTier: opts.minTier }); } catch (e) {
    process.stderr.write(`export-registry: ${e.message}\n`);
    return 2;
  }
  const { files, manifest } = built;

  if (opts.check) {
    const { changed, removed } = diffAgainstDisk(opts.out, files);
    const stale = changed.length + removed.length > 0;
    if (opts.json) {
      process.stdout.write(`${JSON.stringify({ ...manifest, check: { stale, changed, removed } }, null, 2)}\n`);
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
    process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
  } else {
    process.stdout.write(`Exported ${manifest.exported} servers as of ${manifest.as_of} → ${path.join(opts.out, API_PREFIX)}\n`);
    process.stdout.write(`${files.size} files; ${manifest.skipped.length} entries not exported:\n`);
    for (const s of manifest.skipped) process.stdout.write(`  ${s.name}: ${s.reason}\n`);
  }
  return 0;
}

if (require.main === module) exitAfterFlush(run(process.argv.slice(2)));

module.exports = { run, parseArgs, writeExport, diffAgainstDisk, ownedFiles };
