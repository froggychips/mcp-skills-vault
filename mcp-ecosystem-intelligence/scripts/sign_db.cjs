#!/usr/bin/env node
/**
 * sign_db — sign the DB (or any published JSON artifact) with the release key.
 *
 * Writes `<file>.sig` next to each file: an Ed25519 signature over the file's
 * canonical JSON, in the envelope described in lib/signing.cjs. The CLI checks
 * that signature before it reads the DB (lib/db_signature.cjs).
 *
 * The private key never touches the repository. It comes from the environment
 * (`MCP_VAULT_SIGNING_KEY`, PKCS#8 PEM — or that PEM base64-encoded, for
 * secret stores that mangle newlines) or from a file given with `--key-file`.
 *
 * Usage:
 *   node scripts/sign_db.cjs [file ...]          sign (default: assets/tools_database.json)
 *   node scripts/sign_db.cjs --release           what release.yml runs — see below
 *   node scripts/sign_db.cjs --keygen <path>     new key: private PEM to <path> (0600),
 *                                                keyring entry for trusted_keys.json on stdout
 *   node scripts/sign_db.cjs --public-entry      keyring entry for the configured key
 *
 * `--release` is the fail-closed mode:
 *   - the shipped keyring (assets/trusted_keys.json) is empty → nothing to
 *     sign against; a warning, exit 0. Publishing an unsigned DB from a build
 *     that trusts no key is the state before signing existed, not a regression.
 *   - the keyring has a key and the secret is missing → exit 1. A build whose
 *     clients will demand a signature must not ship without one.
 *   - after signing, the result is verified against the shipped keyring, so a
 *     secret that holds a key the keyring does not list — an old key, a typo'd
 *     rotation — stops the release instead of shipping a DB every client refuses.
 *
 * Other options:
 *   --key-file <path>   read the private key from a file instead of the env
 *   --json              machine-readable output
 *
 * Exit: 0 signed (or nothing to do under --release), 1 refused, 2 bad arguments.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { generateKeyPair, publicKeyFromPrivate, keyringEntry, loadTrustedKeys } = require('./lib/signing.cjs');
const { signFile, verifyFile, sigPathFor } = require('./lib/db_signature.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
const KEY_ENV = 'MCP_VAULT_SIGNING_KEY';

const HELP = `sign_db — sign published JSON artifacts with the release key

  node scripts/sign_db.cjs [file ...] [--key-file <pem>] [--json]
  node scripts/sign_db.cjs --release
  node scripts/sign_db.cjs --keygen <path>
  node scripts/sign_db.cjs --public-entry [--key-file <pem>]

  The key comes from $${KEY_ENV} (PKCS#8 PEM, or its base64) unless --key-file is given.
`;

function parseArgs(argv) {
  const opts = { files: [], keyFile: null, release: false, keygen: null, publicEntry: false, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--release') opts.release = true;
    else if (a === '--public-entry') opts.publicEntry = true;
    else if (a === '--key-file') { opts.keyFile = argv[++i] || null; if (!opts.keyFile) return { error: '--key-file needs a path' }; }
    else if (a === '--keygen') { opts.keygen = argv[++i] || null; if (!opts.keygen) return { error: '--keygen needs a path' }; }
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('--')) return { error: `unknown flag ${a}` };
    else opts.files.push(path.resolve(a));
  }
  return opts;
}

/** The private key, from --key-file or the environment; null when neither. */
function readKey(opts, env = process.env) {
  let text = null;
  if (opts.keyFile) text = fs.readFileSync(opts.keyFile, 'utf8');
  else if (env[KEY_ENV]) text = env[KEY_ENV];
  if (!text) return null;
  text = text.trim();
  if (!text.startsWith('-----BEGIN')) text = Buffer.from(text, 'base64').toString('utf8').trim();
  return text;
}

function keygen(target, out) {
  if (fs.existsSync(target)) {
    out.err(`sign_db: ${target} exists — refusing to overwrite a key`);
    return 1;
  }
  const pair = generateKeyPair();
  // `wx`: fail rather than follow a file that appeared in the meantime.
  fs.writeFileSync(target, pair.privateKeyPem, { mode: 0o600, flag: 'wx' });
  const entry = keyringEntry(pair.publicKey, { comment: 'release key' });
  out.result({ schema: 'mcp-vault/keygen@1', private_key_file: target, key_id: pair.keyId, public_key: pair.publicKey, keyring_entry: entry },
    `Private key written to ${target} (mode 0600). Keep it out of the repository.\n\n`
    + 'Add this to mcp-ecosystem-intelligence/assets/trusted_keys.json "keys":\n\n'
    + `${JSON.stringify(entry, null, 2)}\n`);
  return 0;
}

function main(argv, { env = process.env, keyringPath } = {}) {
  const opts = parseArgs(argv);
  const out = {
    err: (s) => process.stderr.write(`${s}\n`),
    result: (json, text) => process.stdout.write(opts.json ? `${JSON.stringify(json, null, 2)}\n` : text),
  };
  if (opts.error) { process.stderr.write(`sign_db: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }
  if (opts.keygen) return keygen(opts.keygen, out);

  let pem = null;
  try { pem = readKey(opts, env); }
  catch (e) { out.err(`sign_db: could not read the signing key: ${e.message}`); return 1; }

  if (opts.publicEntry) {
    if (!pem) { out.err(`sign_db: no key — set ${KEY_ENV} or pass --key-file`); return 1; }
    const { publicKey } = publicKeyFromPrivate(pem);
    const entry = keyringEntry(publicKey);
    out.result({ schema: 'mcp-vault/keygen@1', key_id: entry.key_id, public_key: entry.public_key, keyring_entry: entry }, `${JSON.stringify(entry, null, 2)}\n`);
    return 0;
  }

  const files = opts.files.length ? opts.files : [DB_PATH];
  const keyring = loadTrustedKeys(keyringPath);
  if (!keyring.ok) { out.err(`sign_db: the shipped keyring is invalid: ${keyring.errors.join('; ')}`); return 1; }

  if (opts.release && !keyring.keys.length) {
    const msg = 'the shipped keyring has no key, so clients do not check a DB signature yet; publishing unsigned';
    if (env.GITHUB_ACTIONS) process.stdout.write(`::warning::${msg}\n`);
    out.result({ schema: 'mcp-vault/sign@1', signed: [], skipped: 'no-trusted-key', message: msg }, `sign_db: ${msg}\n`);
    return 0;
  }
  if (!pem) {
    out.err(`sign_db: no signing key — set ${KEY_ENV} (a repository secret in CI) or pass --key-file`);
    return 1;
  }

  const signed = [];
  for (const file of files) {
    let envelope;
    try { envelope = signFile(file, { privateKeyPem: pem }); }
    catch (e) { out.err(`sign_db: ${e.message}`); return 1; }
    const row = { file, signature: sigPathFor(file), key_id: envelope.key_id, sha256: envelope.sha256, signed_at: envelope.signed_at };
    if (opts.release) {
      // The same check a client runs, before anything is published.
      const check = verifyFile(file, { keys: keyring.keys });
      if (!check.ok) {
        out.err(`sign_db: ${path.basename(file)} does not verify against the shipped keyring: ${check.error} [${check.code}]. Nothing should be published.`);
        return 1;
      }
      row.verified = true;
    }
    signed.push(row);
  }
  out.result({ schema: 'mcp-vault/sign@1', signed }, signed.map((r) => `signed ${r.file}\n  → ${r.signature} (key ${r.key_id}, sha256 ${r.sha256.slice(0, 16)}…)${r.verified ? ' — verified against the shipped keyring' : ''}\n`).join(''));
  return 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { main, parseArgs, readKey };
