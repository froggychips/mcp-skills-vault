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
 * What the snapshot says about an entry is a finding (lib/finding.cjs:
 * `registry/deleted-upstream`, `registry/deprecated-upstream`,
 * `registry/pinned-unseen`); the exit code is the Decision's, from
 * `decide()` over the table in lib/policy_rules.cjs (docs/adr/0001). A
 * project's policy file has no rule about upstream withdrawals, so only the
 * gate's own rows apply; --strict / --fail-unverified set the threshold.
 *
 * The DB is never changed. Withdrawals are a report for a human; new servers
 * go to the discovery inbox through
 *   mcp-vault discover --source registry-snapshot --snapshot <file>
 * which scores and filters them like every other source.
 *
 * Usage:
 *   node scripts/registry_ingest.cjs --fetch --out <file> [--registry <url>]
 *                                    [--latest-only] [--max-pages N]
 *   node scripts/registry_ingest.cjs --snapshot <file> [--json] [--as-of <date>]
 *                                    [--strict] [--fail-unverified]
 *
 * Exit codes (--snapshot: the decisions' — lib/finding.cjs exitCode):
 *   0  nothing fails at the threshold (or: snapshot written)
 *   1  a decision fails: a pinned or latest version deleted upstream always;
 *      deprecated under --strict; a pin a latest-only snapshot could not see
 *      under --fail-unverified
 *   2  bad arguments, an unreadable snapshot, a snapshot fetched after
 *      --as-of, or a fetch that did not complete
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { fetchSnapshot, ingestReport, ingestFindings, REGISTRY, DEFAULT_MAX_PAGES } = require('./lib/registry_snapshot.cjs');
const { asOfFromArgv } = require('./lib/clock.cjs');
const { decide, exitCode, findingsDocument, toJson } = require('./lib/finding.cjs');
const { loadEffectivePolicy, flagsFromArgv } = require('./lib/policy_rules.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');

const HELP = `registry-ingest — the official MCP Registry's view of this DB, from a saved snapshot

  --fetch --out <file>   download a snapshot (network; nothing else here uses it)
  --registry <url>       registry base URL for --fetch (default: ${REGISTRY})
  --latest-only          fetch one record per server (fast; cannot see a
                         withdrawn pinned version that is not the latest)
  --max-pages <n>        page cap for --fetch (default: ${DEFAULT_MAX_PAGES}; hitting it writes nothing)
  --snapshot <file>      compare the DB with a saved snapshot (offline)
  --json                 machine-readable report (mcp-vault/registry-ingest@1), with
                         findings and decisions under \`findings\` (mcp-vault/findings@1)
  --as-of <date>         decide as of YYYY-MM-DD or an ISO-8601 instant (--snapshot
                         only; a snapshot fetched later did not exist then)
  --strict               a deprecation upstream fails the run too
  --fail-unverified      a pin a latest-only snapshot could not see fails the run
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
    else if (a === '--strict' || a === '--fail-unverified') { /* policy flags: flagsFromArgv */ }
    else if (a === '--as-of') val();                 // read by asOfFromArgv
    else if (a.startsWith('--as-of=')) { /* read by asOfFromArgv */ }
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
  // The one clock read for this run (lib/clock.cjs). --fetch observes the
  // registry now, and a replayed instant must never date an observation.
  const clock = asOfFromArgv(argv);
  if (clock.error) throw new Error(clock.error);
  if (o.fetch && clock.source === 'as-of') throw new Error('--as-of replays a saved snapshot; --fetch observes the registry now');
  o.clock = clock;
  o.flags = flagsFromArgv(argv);
  return o;
}

function printHuman(r, doc) {
  const out = [];
  out.push(`Official registry snapshot: ${r.snapshot.count} records (${r.snapshot.scope || 'unknown scope'}), fetched ${r.snapshot.fetched_at || 'unknown'}`);
  if (r.snapshot.scope === 'latest') out.push('  latest versions only: a withdrawn pinned version that is not the latest is not visible');
  out.push(`${r.matched} DB entr${r.matched === 1 ? 'y' : 'ies'} matched to a registry server (of ${r.db_entries}), decided as of ${doc.as_of}`);
  // The decisions, rendered: each subject that is not a plain allow, with the
  // rule that decided and the findings behind it.
  const byId = new Map(doc.findings.map((f) => [f.id, f]));
  const notAllow = doc.decisions.filter((d) => d.effect !== 'allow');
  if (notAllow.length) {
    out.push('', `Withdrawn upstream, or not checkable (${notAllow.length}) — review; the DB was not changed:`);
    for (const d of notAllow) {
      out.push(`  ${d.effect.toUpperCase()}${d.fails ? ' (fails)' : ''}  ${d.subject.entry}  — ${d.decided_by}`);
      for (const id of d.findings) if (byId.has(id)) out.push(`      ${byId.get(id).rule}: ${byId.get(id).message}`);
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

async function run(argv, { get, dbPath = DB_PATH, cwd = process.cwd() } = {}) {
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
  // A look dated after the instant decided at did not exist then.
  const fetchedAt = Date.parse(report.snapshot.fetched_at || '');
  if (o.clock.source === 'as-of' && Number.isFinite(fetchedAt) && fetchedAt > o.clock.asOf) {
    process.stderr.write(`registry-ingest: the snapshot was fetched ${report.snapshot.fetched_at}, after --as-of ${o.clock.iso}\n`);
    return 2;
  }

  // The project's policy file has no rules about upstream withdrawals
  // (noPolicy drops the file's rows, the gate's stay); the flags set fail_on.
  const loaded = loadEffectivePolicy(cwd, { flags: o.flags, noPolicy: true });
  const { subjects, observations, findings } = ingestFindings(db, report);
  const facts = Object.fromEntries(subjects.map((s) => [s.id, { mode: 'gate' }]));
  const decisions = decide(findings, loaded.policy, o.clock.asOf, { subjects, facts });
  const doc = toJson(findingsDocument({
    asOf: o.clock.asOf, observations, findings, decisions, scope: 'database', policy: loaded.policy, facts,
  }));

  if (o.json) {
    // The envelope keeps what is not a finding: the snapshot it read, the
    // match count and the discovery candidates.
    process.stdout.write(`${JSON.stringify({
      schema:            'mcp-vault/registry-ingest@1',
      as_of:             doc.as_of,
      snapshot:          report.snapshot,
      db_entries:        report.db_entries,
      matched:           report.matched,
      new_servers_count: report.new_servers_count,
      new_servers:       report.new_servers,
      findings:          doc,
    }, null, 2)}\n`);
  } else printHuman(report, doc);
  return exitCode(decisions);
}

if (require.main === module) {
  run(process.argv.slice(2)).then(exitAfterFlush, (e) => { console.error(e.message); exitAfterFlush(2); });
}

module.exports = { run, parseArgs };
