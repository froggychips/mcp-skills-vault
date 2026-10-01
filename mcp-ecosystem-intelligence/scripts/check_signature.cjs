#!/usr/bin/env node
/**
 * mcp-vault signature — is this DB the one the maintainers signed?
 *
 * The CLI already runs this check before every command that reads the DB
 * (bin/mcp-vault.cjs); this is the same check on its own, with its evidence,
 * for a person who wants to see it and for a pipeline that wants `--json`.
 * Offline: the keyring ships in the package, the signature sits next to the
 * file, and nothing is fetched.
 *
 * It decides nothing itself: each file is a set of `db/signature-*` findings
 * (lib/db_signature.cjs), `decide()` applies the `db/signature` row, and this
 * prints the Decision. `--json` is an `mcp-vault/findings@1` document.
 *
 * Usage:
 *   node scripts/check_signature.cjs [file ...] [--json] [--allow-unsigned-db]
 *                                    [--strict | --fail-unverified] [--as-of <date>]
 *     default file: the bundled assets/tools_database.json
 *     any other JSON artifact is checked against `<file>.sig` the same way
 *     (the site's registry.json, a DB passed around with --db)
 *
 * Where it runs matters for one case only — a missing `.sig`: an installed
 * package requires one, a git checkout does not (lib/db_signature.cjs
 * `signatureContext`). A signature that is present must verify everywhere.
 *
 * Exit codes (the decisions', lib/finding.cjs exitCode):
 *   0  nothing fails: verified, not required here, or the keyring is empty
 *      (`unknown`, never `verified`; --fail-unverified makes it fail)
 *   1  at least one file is refused (--strict: or only allowed by the override)
 *   2  bad arguments
 */

'use strict';

const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { loadTrustedKeys, TRUSTED_KEYS_PATH } = require('./lib/signing.cjs');
const { signatureDocument, signatureContext, signaturePolicy, allowUnsignedFromEnv, ALLOW_FLAG } = require('./lib/db_signature.cjs');
const { flagsFromArgv } = require('./lib/policy_rules.cjs');
const { asOfFromArgv, stripAsOf } = require('./lib/clock.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
const KNOWN = new Set(['--json', ALLOW_FLAG, '--strict', '--fail-unverified']);

const HELP = `signature — check published JSON against its .sig and the shipped keyring

  mcp-vault signature [file ...] [--json] [--allow-unsigned-db] [--strict | --fail-unverified]
`;

function main(argv, { keyringPath = TRUSTED_KEYS_PATH, env = process.env } = {}) {
  const clock = asOfFromArgv(argv);
  if (clock.error) { process.stderr.write(`signature: ${clock.error}\n`); return 2; }
  const rest = stripAsOf(argv);
  const files = [];
  for (const a of rest) {
    if (a === '-h' || a === '--help') { process.stdout.write(HELP); return 0; }
    if (KNOWN.has(a)) continue;
    if (a.startsWith('--')) { process.stderr.write(`signature: unknown flag ${a}\n`); return 2; }
    files.push(path.resolve(a));
  }
  if (!files.length) files.push(DB_PATH);
  const json = rest.includes('--json');
  const allowUnsigned = rest.includes(ALLOW_FLAG) || allowUnsignedFromEnv(env);
  const context = signatureContext({ env });

  const keyring = loadTrustedKeys(keyringPath);
  const { doc, decisions, exit } = signatureDocument(files, {
    keyring, keyringPath, context, allowUnsigned, asOf: clock.asOf, policy: signaturePolicy(flagsFromArgv(rest)),
  });

  if (json) {
    process.stdout.write(`${JSON.stringify(doc, null, 2)}\n`);
    return exit;
  }
  const byId = new Map(doc.findings.map((f) => [f.id, f]));
  for (const d of decisions) {
    const facts = doc.facts[d.subject.id] || {};
    const name = path.basename(facts.file || d.subject.path);
    const mark = d.fails ? '✗' : (d.effect === 'allow' ? '✓' : (d.effect === 'warn' ? '!' : '·'));
    const detail = d.rules.map((r) => r.detail).find(Boolean)
      || d.findings.map((id) => byId.get(id)).filter(Boolean).map((f) => f.message)[0] || '';
    process.stdout.write(`${mark} ${name}  ${d.effect}${d.fails ? ' (fails)' : ''} — ${detail}  [${d.decided_by}]\n`);
  }
  process.stdout.write(`  context: ${context.context} — ${context.reason}${context.required ? '; a signature is required' : '; a missing signature is allowed, a bad one is not'}\n`);
  return exit;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { main };
