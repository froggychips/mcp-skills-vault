'use strict';
/**
 * The DB's signature, as the CLI sees it: a file next to a file, checked before
 * anything reads the DB, refusing when it does not hold.
 *
 * `lib/signing.cjs` is the mechanism; this is the policy around it, which has
 * exactly three outcomes:
 *
 *   verified        the canonical DB matches `tools_database.json.sig`, signed
 *                   by a key in the shipped keyring, inside that key's window
 *   refused         anything else — missing, malformed, unknown key, revoked
 *                   key, tampered bytes. The command does not run.
 *   not-configured  the shipped keyring is empty. That is a property of the
 *                   *build* (a release made before a signing key existed, or a
 *                   fork that has not made one), not something a tampered DB
 *                   can cause: removing the `.sig` next to a DB whose package
 *                   carries a key is `refused`.
 *
 * The escape hatch is for development and forks, and it is loud on purpose:
 * `--allow-unsigned-db` or `MCP_VAULT_ALLOW_UNSIGNED_DB=1`. A git checkout has
 * no `.sig` (signing happens at release), so a developer running `bin/` from a
 * clone needs it; `npm test` does not, because the tests call the libraries.
 * The warning is printed on every run it applies to — a flag that goes quiet
 * after the first time becomes a setting nobody remembers turning on.
 *
 * API:
 *   sigPathFor(file)                          -> `${file}.sig`
 *   verifyFile(file, { keys, artifact? })     -> verifyCanonical result (+ code 'unreadable')
 *   signFile(file, { privateKeyPem, now? })   -> envelope (written to sigPathFor(file))
 *   allowUnsignedFromEnv(env)                 -> boolean
 *   checkDb({ dbPath, keys, allowUnsigned })  -> { proceed, state, message, result }
 */

const fs   = require('fs');
const path = require('path');
const { canonicalBytes, signCanonical, verifyCanonical } = require('./signing.cjs');

const ALLOW_ENV  = 'MCP_VAULT_ALLOW_UNSIGNED_DB';
const ALLOW_FLAG = '--allow-unsigned-db';

const sigPathFor = (file) => `${file}.sig`;

function readCanonical(file) {
  try { return { ok: true, bytes: canonicalBytes(fs.readFileSync(file, 'utf8')) }; }
  catch (e) { return { ok: false, error: e.message }; }
}

function verifyFile(file, { keys, artifact = path.basename(file) } = {}) {
  const content = readCanonical(file);
  if (!content.ok) return { ok: false, code: 'unreadable', error: `could not read ${file} as JSON: ${content.error}` };
  let envelope = null;
  const sigFile = sigPathFor(file);
  if (!fs.existsSync(sigFile)) return { ok: false, code: 'no-signature', error: `no signature file (${path.basename(sigFile)})` };
  try { envelope = JSON.parse(fs.readFileSync(sigFile, 'utf8')); }
  catch (e) { return { ok: false, code: 'malformed', error: `could not read ${path.basename(sigFile)}: ${e.message}` }; }
  return verifyCanonical(content.bytes, envelope, keys, { artifact });
}

function signFile(file, { privateKeyPem, now = Date.now() } = {}) {
  const content = readCanonical(file);
  if (!content.ok) throw new Error(`could not read ${file} as JSON: ${content.error}`);
  const envelope = signCanonical(content.bytes, { privateKeyPem, artifact: path.basename(file), now });
  fs.writeFileSync(sigPathFor(file), `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
  return envelope;
}

function allowUnsignedFromEnv(env = process.env) {
  const v = String(env[ALLOW_ENV] || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
}

function checkDb({ dbPath, keys, allowUnsigned = false }) {
  const name = path.basename(dbPath);
  if (!keys || !keys.length) {
    return {
      proceed: true, state: 'not-configured', result: null,
      message: `${name}: this build ships no trusted signing key, so the DB signature is not checked`,
    };
  }
  const result = verifyFile(dbPath, { keys });
  if (result.ok) {
    return { proceed: true, state: 'verified', result, message: `${name}: signature verified (key ${result.key_id}, signed ${result.signed_at})` };
  }
  const why = `${name}: ${result.error} [${result.code}]`;
  if (allowUnsigned) {
    return {
      proceed: true, state: 'unsigned-allowed', result,
      message: [
        '!!! ─────────────────────────────────────────────────────────────── !!!',
        `!!! DB SIGNATURE NOT VERIFIED — ${why}`,
        `!!! Running anyway because ${ALLOW_FLAG} / ${ALLOW_ENV} is set.`,
        '!!! Every recommendation and install below trusts a DB nobody vouched for.',
        '!!! ─────────────────────────────────────────────────────────────── !!!',
      ].join('\n'),
    };
  }
  return {
    proceed: false, state: 'refused', result,
    message: [
      `mcp-vault: refusing to use the DB — ${why}`,
      '',
      'The DB decides what `install` writes into your config, so it has to be the one',
      'the maintainers signed. If you are developing on a checkout or running a fork',
      `with its own DB, pass ${ALLOW_FLAG} or set ${ALLOW_ENV}=1 — knowingly.`,
      'Check it on its own: mcp-vault signature --json',
    ].join('\n'),
  };
}

module.exports = {
  ALLOW_ENV, ALLOW_FLAG,
  sigPathFor, verifyFile, signFile, allowUnsignedFromEnv, checkDb,
};
