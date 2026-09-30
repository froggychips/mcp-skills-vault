#!/usr/bin/env node
/**
 * mcp-vault registry-ingest — what the official MCP Registry says about this
 * DB, from a saved snapshot.
 *
 * Two steps, deliberately separate:
 *
 *   --fetch --out <file>   the only networked step: page through
 *                          registry.modelcontextprotocol.io/v0.1/servers
 *                          (include_deleted=true) and save the result. All or
 *                          nothing — a failed page writes no file.
 *   --snapshot <file>      offline: compare the DB with a saved snapshot and
 *                          report entries whose server the registry marks
 *                          `deprecated` or `deleted` (latest version, or the
 *                          exact version the DB pins), and how many listed
 *                          servers the DB does not have.
 *
 * The DB is never changed. Withdrawals are a report for a human; new servers
 * go to the discovery inbox through
 *   mcp-vault discover --source registry-snapshot --snapshot <file>
 * which scores and filters them like every other source.
 *
 * Usage:
 *   node scripts/registry_ingest.cjs --fetch --out <file> [--registry <url>]
 *                                    [--latest-only] [--max-pages N]
 *   node scripts/registry_ingest.cjs --snapshot <file> [--json]
 *
 * Exit codes:
 *   0  report produced, no DB entry is withdrawn upstream (or: snapshot written)
 *   1  at least one DB entry's server is deprecated or deleted upstream
 *   2  bad arguments, an unreadable snapshot, or a fetch that did not complete
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { fetchSnapshot, ingestReport, REGISTRY, DEFAULT_MAX_PAGES } = require('./lib/registry_snapshot.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');

const HELP = `registry-ingest — the official MCP Registry's view of this DB, from a saved snapshot

  --fetch --out <file>   download a snapshot (network; nothing else here uses it)
  --registry <url>       registry base URL for --fetch (default: ${REGISTRY})
  --latest-only          fetch one record per server (fast; cannot see a
                         withdrawn pinned version that is not the latest)
  --max-pages <n>        page cap for --fetch (default: ${DEFAULT_MAX_PAGES}; hitting it writes nothing)
  --snapshot <file>      compare the DB with a saved snapshot (offline)
  --json                 machine-readable report (mcp-vault/registry-ingest@1)
`;

function parseArgs(argv) {
  const o = { fetch: false, out: null, snapshot: null, registry: REGISTRY, json: false, latestOnly: false, maxPages: DEFAULT_MAX_PAGES };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => {
      const v = argv[++i];
      if (!v || v.startsWith('--')) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === '--fetch') o.fetch = true;
    else if (a === '--out') o.out = val();
    else if (a === '--snapshot') o.snapshot = val();
    else if (a === '--registry') o.registry = val().replace(/\/+$/, '');
    else if (a === '--json') o.json = true;
    else if (a === '--latest-only') o.latestOnly = true;
    else if (a === '--max-pages') {
      o.maxPages = Number(val());
      if (!Number.isInteger(o.maxPages) || o.maxPages < 1) throw new Error('--max-pages must be a positive integer');
    }
    else if (a === '-h' || a === '--help') o.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  if (o.help) return o;
  if (o.fetch && !o.out) throw new Error('--fetch needs --out <file>: a snapshot is only useful saved');
  if (!o.fetch && !o.snapshot) throw new Error('give --fetch --out <file> or --snapshot <file>');
  if (o.fetch && o.snapshot) throw new Error('--fetch and --snapshot are separate steps');
  if (!/^https:\/\//.test(o.registry)) throw new Error('--registry must be an https:// URL');
  return o;
}

function printHuman(r) {
  const out = [];
  out.push(`Official registry snapshot: ${r.snapshot.count} records (${r.snapshot.scope || 'unknown scope'}), fetched ${r.snapshot.fetched_at || 'unknown'}`);
  if (r.snapshot.scope === 'latest') out.push('  latest versions only: a withdrawn pinned version that is not the latest is not visible');
  out.push(`${r.matched} DB entr${r.matched === 1 ? 'y' : 'ies'} matched to a registry server (of ${r.db_entries})`);
  if (r.withdrawn.length) {
    out.push('', `Withdrawn upstream (${r.withdrawn.length}) — review; the DB was not changed:`);
    for (const w of r.withdrawn) {
      const parts = [];
      if (w.latest && w.latest.status !== 'active') parts.push(`latest ${w.latest.version} is ${w.latest.status}`);
      if (w.pinned && w.pinned.status !== 'active') parts.push(`pinned ${w.pinned.version} is ${w.pinned.status}`);
      const msg = (w.pinned && w.pinned.statusMessage) || (w.latest && w.latest.statusMessage);
      out.push(`  ${w.name}  →  ${w.server_id} (by ${w.matched_by}): ${parts.join('; ')}${msg ? ` — "${msg}"` : ''}`);
    }
  } else {
    out.push('', 'No matched entry is deprecated or deleted upstream.');
  }
  out.push('', `${r.new_servers_count} listed server(s) with a package are not in the DB.`);
  for (const s of r.new_servers.slice(0, 20)) out.push(`  ${s.name}  (${s.package.registryType}: ${s.package.identifier})`);
  if (r.new_servers_count > 20) out.push(`  … ${r.new_servers_count - 20} more (--json)`);
  out.push('Triage them with: mcp-vault discover --source registry-snapshot --snapshot <file>');
  process.stdout.write(`${out.join('\n')}\n`);
}

async function run(argv, { get, dbPath = DB_PATH } = {}) {
  let o;
  try { o = parseArgs(argv); } catch (e) {
    process.stderr.write(`registry-ingest: ${e.message}\n\n${HELP}`);
    return 2;
  }
  if (o.help) { process.stdout.write(HELP); return 0; }

  if (o.fetch) {
    const res = await fetchSnapshot({
      base: o.registry, latestOnly: o.latestOnly, maxPages: o.maxPages,
      onPage: (n, count) => { if (n % 50 === 0) process.stderr.write(`  ${n} pages, ${count} records\n`); },
      ...(get ? { get } : {}),
    });
    if (!res.ok) {
      process.stderr.write(`registry-ingest: snapshot not written — ${res.error}\n`);
      return 2;
    }
    fs.writeFileSync(o.out, `${JSON.stringify(res.snapshot, null, 2)}\n`);
    process.stderr.write(`Wrote ${res.snapshot.count} records (${res.snapshot.pages} pages) → ${o.out}\n`);
    return 0;
  }

  let snapshot;
  let db;
  try { snapshot = JSON.parse(fs.readFileSync(o.snapshot, 'utf8')); } catch (e) {
    process.stderr.write(`registry-ingest: cannot read the snapshot: ${e.message}\n`);
    return 2;
  }
  try { db = JSON.parse(fs.readFileSync(dbPath, 'utf8')); } catch (e) {
    process.stderr.write(`registry-ingest: cannot read the DB: ${e.message}\n`);
    return 2;
  }
  let report;
  try { report = ingestReport(db, snapshot); } catch (e) {
    process.stderr.write(`registry-ingest: ${e.message}\n`);
    return 2;
  }
  if (o.json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else printHuman(report);
  return report.withdrawn.length ? 1 : 0;
}

if (require.main === module) {
  run(process.argv.slice(2)).then(exitAfterFlush, (e) => { console.error(e.message); exitAfterFlush(2); });
}

module.exports = { run, parseArgs };
