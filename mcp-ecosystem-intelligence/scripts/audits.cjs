#!/usr/bin/env node
/**
 * mcp-vault audits — record, export and import audits (the cargo-vet model).
 *
 *   list   [<entry>]              your audits and the imported ones in force,
 *                                 matched against the DB (offline)
 *   add    <entry> --criteria C --who W [--notes N]
 *                                 record your audit of the entry's *current*
 *                                 artifact: version and integrity come from the
 *                                 DB, so you cannot audit bytes you did not pin
 *   export [--out <file>]         your audits as a signed bundle; the key from
 *                                 $MCP_VAULT_AUDIT_KEY or --key-file
 *   fetch                         the only command that touches the network:
 *                                 fetch each source in .mcp-vault.imports.json,
 *                                 verify its signature, write the lock
 *   check                         re-verify the lock offline; exit 1 on any
 *                                 source that does not verify
 *   keygen <path>                 a new Ed25519 key for signing your exports
 *
 * Common: --cwd <path> (project; default .), --json.
 *
 * lib/audits.cjs has the formats and the reasons. The short version: imports
 * are not transitive, every imported bundle is verified against the key named
 * in *your* config, and an audit never changes `trust` — it is shown beside the
 * evidence in `explain`, with its source.
 *
 * Exit codes: 0 ok, 1 something did not verify / could not be done, 2 bad arguments.
 */

'use strict';

const fs    = require('fs');
const https = require('https');
const path  = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb } = require('./lib/db_io.cjs');
const { generateKeyPair, keyringEntry } = require('./lib/signing.cjs');
const { readKey, writeNewKey } = require('./sign_db.cjs');
const { readWallClock, isoDay } = require('./lib/clock.cjs');
const { decide, findingsDocument, toJson, exitCode } = require('./lib/finding.cjs');
const { effectivePolicy } = require('./lib/policy_rules.cjs');
const A = require('./lib/audits.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
const KEY_ENV = 'MCP_VAULT_AUDIT_KEY';
const MAX_BYTES = 5 * 1024 * 1024;

const HELP = `audits — record, export and import audits (cargo-vet style)

  mcp-vault audits list   [<entry>] [--json]
  mcp-vault audits add    <entry> --criteria safe-to-run|safe-to-deploy --who "Name <mail>" [--notes "…"]
  mcp-vault audits export [--out <file>] [--key-file <pem>]     (key: $${KEY_ENV})
  mcp-vault audits fetch  [--json]                              (network: configured sources only)
  mcp-vault audits check  [--json]                              (offline)
  mcp-vault audits keygen <path>

  --cwd <path>   the project holding ${A.AUDITS_FILE}, ${A.IMPORTS_FILE}, ${A.LOCK_FILE}
`;

function parseArgs(argv) {
  const opts = { sub: argv[0] || null, args: [], cwd: process.cwd(), json: false, criteria: null, who: null, notes: null, out: null, keyFile: null, db: DB_PATH };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    try {
      if (a === '--json') opts.json = true;
      else if (a === '--cwd') opts.cwd = path.resolve(val());
      else if (a === '--criteria') opts.criteria = val();
      else if (a === '--who') opts.who = val();
      else if (a === '--notes') opts.notes = val();
      else if (a === '--out') opts.out = path.resolve(val());
      else if (a === '--key-file') opts.keyFile = val();
      else if (a === '--db') opts.db = path.resolve(val());
      else if (a === '-h' || a === '--help') opts.sub = 'help';
      else if (a.startsWith('--')) return { error: `unknown flag ${a}` };
      else opts.args.push(a);
    } catch (e) { return { error: e.message }; }
  }
  return opts;
}

/**
 * GET over https, nothing clever: no redirects (a redirect is a different
 * location than the one the config names), a size cap and a timeout.
 */
function fetchText(url, { timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    if (!/^https:\/\//.test(url)) { reject(new Error('only https:// sources are fetched')); return; }
    const req = https.get(url, { headers: { 'user-agent': 'mcp-vault-audits', accept: 'application/json' } }, (res) => {
      if (res.statusCode !== 200) { res.resume(); reject(new Error(`HTTP ${res.statusCode}${res.headers.location ? ` (redirect to ${res.headers.location} not followed)` : ''}`)); return; }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BYTES) { req.destroy(new Error(`larger than ${MAX_BYTES} bytes`)); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`timed out after ${timeoutMs} ms`)));
    req.on('error', reject);
  });
}

function out(opts, json, text) {
  process.stdout.write(opts.json ? `${JSON.stringify(json, null, 2)}\n` : text);
}

function findTool(db, name) {
  return (db.tools || []).find((t) => t.name === name) || null;
}

function cmdList(opts) {
  const { db } = readDb(opts.db);
  const local = A.readLocalAudits(opts.cwd);
  const imported = A.loadImportedAudits(opts.cwd);
  const tools = opts.args[0] ? [findTool(db, opts.args[0])].filter(Boolean) : (db.tools || []);
  if (opts.args[0] && !tools.length) { process.stderr.write(`audits: no entry named "${opts.args[0]}"\n`); return 2; }

  const rows = [];
  for (const t of tools) {
    const matched = A.auditsFor(t, { local: local.audits, imported: imported.audits });
    if (matched.length || opts.args[0]) rows.push({ name: t.name, subject: A.subjectOf(t), audits: matched });
  }
  // Audits that name something the DB no longer pins: the version moved, and
  // an audit of the old bytes says nothing about the new ones.
  const subjects = (db.tools || []).map(A.subjectOf).filter(Boolean);
  const orphaned = [...local.audits.map((a) => ({ ...a, source: 'local' })), ...imported.audits]
    .filter((a) => !subjects.some((s) => A.auditMatches(a, s)));

  const errors = [...local.errors.map((e) => ({ source: 'local', code: 'local', error: e })), ...imported.errors];
  out(opts, { schema: 'mcp-vault/audit-list@1', entries: rows, orphaned, ignored: imported.ignored, errors },
    [
      ...rows.map((r) => `${r.name}${r.subject ? `  ${r.subject.ecosystem}:${r.subject.package}@${r.subject.version}` : '  (no pinned artifact to audit)'}\n`
        + (r.audits.length
          ? r.audits.map((a) => `  ✓ ${a.accepted_criteria.join(', ')}  by ${a.who}  on ${a.date}  [${a.source}${a.key_id ? ` ${a.key_id}` : ''}]${a.notes ? `\n      ${a.notes}` : ''}\n`).join('')
          : '  · no audit of this artifact\n')),
      orphaned.length ? `\n${orphaned.length} audit(s) name an artifact the DB does not pin (version or integrity moved).\n` : '',
      imported.ignored.length ? `\nIgnored:\n${imported.ignored.map((i) => `  · [${i.source}] ${i.reason}\n`).join('')}` : '',
      errors.length ? `\nErrors:\n${errors.map((e) => `  ✗ [${e.source || 'config'}] ${e.error}\n`).join('')}` : '',
    ].join('') || 'No audits recorded or imported.\n');
  return errors.length ? 1 : 0;
}

function cmdAdd(opts) {
  const name = opts.args[0];
  if (!name || !opts.criteria || !opts.who) { process.stderr.write(`audits add: <entry>, --criteria and --who are required\n\n${HELP}`); return 2; }
  const { db } = readDb(opts.db);
  const tool = findTool(db, name);
  if (!tool) { process.stderr.write(`audits add: no entry named "${name}"\n`); return 2; }
  const subject = A.subjectOf(tool);
  if (!subject) { process.stderr.write(`audits add: ${name} has no pinned artifact with an integrity value — there is nothing definite to audit\n`); return 1; }
  const audit = {
    who: opts.who, ...subject, criteria: opts.criteria,
    // When you looked: an observation, so the wall clock (lib/clock.cjs).
    date: isoDay(readWallClock()),
    ...(opts.notes ? { notes: opts.notes } : {}),
  };
  let res;
  try { res = A.addLocalAudit(opts.cwd, audit); }
  catch (e) { process.stderr.write(`audits add: ${e.message}\n`); return 1; }
  out(opts, { schema: 'mcp-vault/audit-add@1', ...res, audit }, `${res.added ? 'Recorded' : 'Already recorded'}: ${opts.criteria} for ${subject.package}@${subject.version} in ${res.path}\n`);
  return 0;
}

function cmdExport(opts) {
  const local = A.readLocalAudits(opts.cwd);
  if (!local.ok) { process.stderr.write(`audits export: ${local.errors.join('; ')}\n`); return 1; }
  if (!local.audits.length) { process.stderr.write(`audits export: no audits in ${local.path}\n`); return 1; }
  let pem;
  try { pem = readKey({ keyFile: opts.keyFile }, { MCP_VAULT_SIGNING_KEY: process.env[KEY_ENV] }); }
  catch (e) { process.stderr.write(`audits export: could not read the key: ${e.message}\n`); return 1; }
  if (!pem) { process.stderr.write(`audits export: no key — set ${KEY_ENV} or pass --key-file (make one with \`mcp-vault audits keygen <path>\`)\n`); return 1; }
  let bundle;
  try { bundle = A.exportBundle(local.audits, { privateKeyPem: pem, now: readWallClock() }); }
  catch (e) { process.stderr.write(`audits export: ${e.message}\n`); return 1; }
  const text = `${JSON.stringify(bundle, null, 2)}\n`;
  if (opts.out) {
    fs.writeFileSync(opts.out, text, 'utf8');
    process.stderr.write(`Exported ${local.audits.length} audit(s), signed by ${bundle.signature.key_id}, to ${opts.out}\n`);
  } else {
    process.stdout.write(text);
  }
  return 0;
}

/**
 * The import check's verdict: findings per source, decided by the
 * `audits/import` row (lib/policy_rules.cjs). `--json` is the findings@1
 * document; the lock path and what was ignored ride along as facts.
 */
function importDecision({ rows, global = [], configPath, facts }) {
  // The decision does not depend on the instant; the document says when.
  const asOf = readWallClock();
  const policy = effectivePolicy(null, {}, { policyRules: false });
  const { subjects, findings, facts: f } = A.importFindings({ rows, global, configPath, facts });
  const decisions = decide(findings, policy, asOf, { subjects, facts: f });
  const doc = toJson(findingsDocument({ asOf, findings, decisions, scope: 'audit-imports', policy, facts: f }));
  return { doc, decisions, exit: exitCode(decisions) };
}

const mark = (d) => (d.fails ? '✗' : '✓');
const lineOf = (doc, d) => {
  const byId = new Map(doc.findings.map((x) => [x.id, x]));
  return d.findings.map((id) => byId.get(id)).filter(Boolean).map((x) => x.message).join('; ');
};

async function cmdFetch(opts) {
  const config = A.readImportsConfig(opts.cwd);
  if (!config.ok) { process.stderr.write(`audits fetch: ${config.errors.join('; ')}\n`); return 1; }
  if (!config.found) { process.stderr.write(`audits fetch: no ${A.IMPORTS_FILE} in ${opts.cwd}\n`); return 1; }
  const res = await A.fetchImports(config, { fetchText, now: readWallClock() });
  let lockPath = null;
  if (res.ok) lockPath = A.writeLock(opts.cwd, res.lock);
  const facts = Object.fromEntries(res.report.map((r) => [r.source, { lock: lockPath, rejected: r.rejected || [] }]));
  const { doc, decisions, exit } = importDecision({ rows: res.report, configPath: config.path, facts });
  out(opts, doc,
    decisions.map((d) => `${mark(d)} ${lineOf(doc, d)}\n`).join('')
    + (res.ok ? `\nLock written: ${lockPath}\n` : '\nNothing written: the lock is updated all at once or not at all.\n'));
  return exit;
}

function cmdCheck(opts) {
  const config = A.readImportsConfig(opts.cwd);
  const imported = A.loadImportedAudits(opts.cwd, { config });
  const rows = Object.keys(config.sources).sort().map((name) => {
    const err = imported.errors.find((e) => e.source === name);
    const mine = imported.audits.filter((a) => a.source === name);
    return err
      ? { source: name, ok: false, code: err.code, error: err.error }
      : { source: name, ok: true, audits: mine.length, key_id: config.sources[name].key_id };
  });
  const global = imported.errors.filter((e) => !e.source);
  const facts = Object.fromEntries(rows.map((r) => [r.source, {
    ignored: imported.ignored.filter((i) => i.source === r.source).map((i) => i.reason),
  }]));
  const { doc, decisions, exit } = importDecision({ rows, global, configPath: config.path, facts });
  out(opts, doc,
    [
      ...decisions.map((d) => `${mark(d)} ${lineOf(doc, d)}\n`),
      imported.ignored.length ? `${imported.ignored.map((i) => `  · [${i.source}] ${i.reason}\n`).join('')}` : '',
    ].join('') || `No imports configured (${A.IMPORTS_FILE}).\n`);
  return exit;
}

function cmdKeygen(opts) {
  const target = opts.args[0] ? path.resolve(opts.args[0]) : null;
  if (!target) { process.stderr.write('audits keygen: <path> for the private key is required\n'); return 2; }
  const pair = generateKeyPair();
  const refused = writeNewKey(target, pair.privateKeyPem);
  if (refused) { process.stderr.write(`audits keygen: ${refused}\n`); return 1; }
  const entry = keyringEntry(pair.publicKey, { validFrom: isoDay(readWallClock()) });
  out(opts, { schema: 'mcp-vault/keygen@1', private_key_file: target, key_id: pair.keyId, public_key: pair.publicKey, keyring_entry: entry },
    `Private key written to ${target} (mode 0600).\n\nPublish this public key; importers put it in their ${A.IMPORTS_FILE}:\n\n  "public_key": "${entry.public_key}"   (key id ${entry.key_id})\n`);
  return 0;
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`audits: ${opts.error}\n\n${HELP}`); return 2; }
  switch (opts.sub) {
    case 'list':   return cmdList(opts);
    case 'add':    return cmdAdd(opts);
    case 'export': return cmdExport(opts);
    case 'fetch':  return cmdFetch(opts);
    case 'check':  return cmdCheck(opts);
    case 'keygen': return cmdKeygen(opts);
    case 'help':   process.stdout.write(HELP); return 0;
    default:
      process.stderr.write(`audits: ${opts.sub ? `unknown subcommand "${opts.sub}"` : 'which subcommand?'}\n\n${HELP}`);
      return 2;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then(exitAfterFlush, (e) => {
    process.stderr.write(`audits: ${e.stack || e.message}\n`);
    exitAfterFlush(1);
  });
}

module.exports = { main, parseArgs, fetchText };
