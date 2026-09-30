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
 * Usage:
 *   node scripts/check_signature.cjs [file ...] [--json]
 *     default file: the bundled assets/tools_database.json
 *     any other JSON artifact is checked against `<file>.sig` the same way
 *     (the site's registry.json, a DB passed around with --db)
 *
 * Exit codes:
 *   0  every file verified — or the shipped keyring is empty, which is
 *      reported as `not-configured`, never as `verified`
 *   1  at least one file did not verify
 *   2  bad arguments / unreadable keyring
 */

'use strict';

const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { loadTrustedKeys, TRUSTED_KEYS_PATH } = require('./lib/signing.cjs');
const { verifyFile } = require('./lib/db_signature.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');

function main(argv, { keyringPath = TRUSTED_KEYS_PATH } = {}) {
  const files = [];
  let json = false;
  for (const a of argv) {
    if (a === '--json') json = true;
    else if (a === '-h' || a === '--help') {
      process.stdout.write('signature — check published JSON against its .sig and the shipped keyring\n\n  mcp-vault signature [file ...] [--json]\n');
      return 0;
    } else if (a.startsWith('--')) { process.stderr.write(`signature: unknown flag ${a}\n`); return 2; }
    else files.push(path.resolve(a));
  }
  if (!files.length) files.push(DB_PATH);

  const keyring = loadTrustedKeys(keyringPath);
  if (!keyring.ok) {
    process.stderr.write(`signature: the keyring is invalid: ${keyring.errors.join('; ')}\n`);
    return 2;
  }

  const rows = files.map((file) => {
    if (!keyring.keys.length) return { file, state: 'not-configured', ok: null, detail: 'the shipped keyring has no key; nothing is checked' };
    const r = verifyFile(file, { keys: keyring.keys });
    return r.ok
      ? { file, state: 'verified', ok: true, key_id: r.key_id, signed_at: r.signed_at, sha256: r.sha256 }
      : { file, state: 'refused', ok: false, code: r.code, detail: r.error, key_id: r.key_id || null };
  });
  const failed = rows.some((r) => r.ok === false);

  if (json) {
    process.stdout.write(`${JSON.stringify({
      schema: 'mcp-vault/signature-check@1',
      keyring: { path: keyringPath, keys: keyring.keys.map((k) => ({ key_id: k.key_id, valid_from: k.valid_from, valid_until: k.valid_until, revoked: k.revoked })) },
      files: rows,
      ok: !failed,
    }, null, 2)}\n`);
  } else {
    for (const r of rows) {
      const name = path.basename(r.file);
      if (r.state === 'verified') process.stdout.write(`✓ ${name}  signed by ${r.key_id} at ${r.signed_at}\n`);
      else if (r.state === 'not-configured') process.stdout.write(`· ${name}  not checked — ${r.detail}\n`);
      else process.stdout.write(`✗ ${name}  ${r.detail} [${r.code}]\n`);
    }
  }
  return failed ? 1 : 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { main };
