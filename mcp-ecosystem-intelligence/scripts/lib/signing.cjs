'use strict';
/**
 * Ed25519 signatures over canonical JSON — for the DB we publish, and for the
 * audits people exchange.
 *
 * Until this existed the client trusted `tools_database.json` because of where
 * it came from: the npm tarball, a copy passed with `--db`, a download from the
 * site. Every one of those is a transport, and a transport is not a signer. The
 * DB is the trust anchor for every `install` (SECURITY.md), so it gets the same
 * treatment we ask of the packages in it: a signature, checked, failing closed.
 *
 * Modelled on minisign / signify in what it leaves out: one algorithm, one key
 * type, no certificate chain, no options. Two things differ, on purpose:
 *
 *   - What is signed is the *canonical* form of the JSON, not the file's bytes.
 *     A checkout with `core.autocrlf`, a pretty-printer or a re-escaping of
 *     non-ASCII must not turn a good signature into a bad one — and a
 *     formatting change must not be able to smuggle anything, because a
 *     formatting change does not reach the canonical bytes at all.
 *   - The envelope is JSON, and the date, key id and artifact name are *inside*
 *     the signed message (minisign's "trusted comment"), so none of them can be
 *     edited after signing.
 *
 * minisign compatibility was considered and not taken: it signs file bytes, so
 * `minisign -V` would need the canonical bytes written to disk first, which is
 * one more artifact to keep in sync for a verifier nobody here runs.
 *
 * Canonical form (`mcp-vault-jcs/1`): RFC 8785 in the parts this data uses —
 * object keys sorted by UTF-16 code unit, no insignificant whitespace, strings
 * and numbers as ECMAScript `JSON.stringify` writes them, UTF-8. Non-finite
 * numbers are refused rather than turned into `null`.
 *
 * Signature envelope (`<file>.sig`, or inline under `signature`):
 *
 *   {
 *     "format":           "mcp-vault-signature/1",
 *     "algorithm":        "ed25519",
 *     "key_id":           "3f9c0a1b2c3d4e5f",        // sha256(raw public key)[0..8], hex
 *     "canonicalization": "mcp-vault-jcs/1",
 *     "artifact":         "tools_database.json",
 *     "sha256":           "<hex of the canonical bytes>",
 *     "signed_at":        "2026-09-30T12:00:00.000Z",
 *     "signature":        "<base64, Ed25519 over canonical(envelope minus signature)>"
 *   }
 *
 * Trusted keys (`assets/trusted_keys.json`, shipped in the package):
 *
 *   { "keys": [ { "key_id", "algorithm": "ed25519", "public_key": "<base64 raw 32 bytes>",
 *                 "valid_from": "YYYY-MM-DD", "valid_until": null | "YYYY-MM-DD",
 *                 "revoked": false, "comment": "…" } ] }
 *
 * Rotation: a new key is added with its `valid_from`, the old one gets a
 * `valid_until`, and a signature is accepted when its `signed_at` falls in the
 * window of the key that made it. `signed_at` is chosen by the signer, so a
 * window protects against a retired key being *used by mistake*, not against a
 * *stolen* one backdating — that is what `revoked: true` is for: a revoked key
 * verifies nothing, whatever date it claims.
 *
 * API:
 *   canonicalize(value)                    -> string
 *   canonicalBytes(value | jsonText)       -> Buffer
 *   sha256Hex(buf)                         -> hex
 *   keyIdFor(publicKeyB64)                 -> 16-hex key id
 *   generateKeyPair()                      -> { privateKeyPem, publicKey, keyId }
 *   publicKeyFromPrivate(pem)              -> { publicKey, keyId }
 *   signCanonical(bytes, opts)             -> envelope
 *   verifyCanonical(bytes, envelope, keys, opts) -> { ok, code, error?, key_id? }
 *   loadTrustedKeys(file?)                 -> { ok, keys, errors }
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const SIGNATURE_FORMAT = 'mcp-vault-signature/1';
const CANONICALIZATION = 'mcp-vault-jcs/1';
const ALGORITHM        = 'ed25519';
const TRUSTED_KEYS_PATH = path.resolve(__dirname, '../../assets/trusted_keys.json');

// An Ed25519 SubjectPublicKeyInfo is this fixed 12-byte header followed by the
// 32-byte key. Knowing it is what lets a public key be a short base64 string in
// a JSON file instead of a PEM block.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean': return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new Error('canonical JSON: non-finite number');
      return JSON.stringify(value);
    case 'string': return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((v) => (v === undefined ? 'null' : canonicalize(v))).join(',')}]`;
      }
      const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
    }
    default:
      throw new Error(`canonical JSON: cannot encode a ${typeof value}`);
  }
}

/** Canonical UTF-8 bytes of a value, or of JSON text (parsed first). */
function canonicalBytes(input) {
  const value = Buffer.isBuffer(input) || typeof input === 'string'
    ? JSON.parse(String(input))
    : input;
  return Buffer.from(canonicalize(value), 'utf8');
}

const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function rawPublicKey(publicKeyB64) {
  const raw = Buffer.from(String(publicKeyB64 || ''), 'base64');
  if (raw.length !== 32) throw new Error('an Ed25519 public key is 32 bytes (base64)');
  return raw;
}

function keyIdFor(publicKeyB64) {
  return sha256Hex(rawPublicKey(publicKeyB64)).slice(0, 16);
}

function publicKeyObject(publicKeyB64) {
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, rawPublicKey(publicKeyB64)]),
    format: 'der', type: 'spki',
  });
}

function exportRaw(publicKey) {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return der.subarray(der.length - 32).toString('base64');
}

/**
 * A fresh key pair. The private half is returned as PKCS#8 PEM — the same
 * thing `openssl genpkey -algorithm ed25519` writes — and is the caller's to
 * put somewhere safe. Nothing here writes it anywhere.
 */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = exportRaw(publicKey);
  return {
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicKey: pub,
    keyId: keyIdFor(pub),
  };
}

function privateKeyObject(pem) {
  const key = crypto.createPrivateKey(String(pem));
  if (key.asymmetricKeyType !== 'ed25519') throw new Error(`signing key must be Ed25519 (got ${key.asymmetricKeyType})`);
  return key;
}

function publicKeyFromPrivate(pem) {
  const pub = exportRaw(crypto.createPublicKey(privateKeyObject(pem)));
  return { publicKey: pub, keyId: keyIdFor(pub) };
}

/** The bytes the signature covers: every envelope field except the signature. */
function signedMessage(envelope) {
  const { signature, ...rest } = envelope; // eslint-disable-line no-unused-vars
  return Buffer.from(canonicalize(rest), 'utf8');
}

function signCanonical(bytes, { privateKeyPem, artifact, now = Date.now() } = {}) {
  const key = privateKeyObject(privateKeyPem);
  const { keyId } = publicKeyFromPrivate(privateKeyPem);
  const envelope = {
    format:           SIGNATURE_FORMAT,
    algorithm:        ALGORITHM,
    key_id:           keyId,
    canonicalization: CANONICALIZATION,
    artifact:         String(artifact || ''),
    sha256:           sha256Hex(bytes),
    signed_at:        new Date(now).toISOString(),
  };
  envelope.signature = crypto.sign(null, signedMessage(envelope), key).toString('base64');
  return envelope;
}

const dateOnly = (s) => String(s || '').slice(0, 10);

/**
 * Check `bytes` (already canonical) against `envelope` with a keyring.
 *
 * Every refusal has a `code`, so a caller and a test can tell "unknown key"
 * from "wrong bytes" without reading prose. The order of checks matters in one
 * place: the digest is compared before the signature is, so a tampered file
 * says "the content changed" rather than the less useful "bad signature".
 */
function verifyCanonical(bytes, envelope, keys, { artifact = null } = {}) {
  const fail = (code, error, extra = {}) => ({ ok: false, code, error, ...extra });
  if (!envelope || typeof envelope !== 'object') return fail('no-signature', 'no signature');
  if (envelope.format !== SIGNATURE_FORMAT) return fail('malformed', `unknown signature format ${JSON.stringify(envelope.format)}`);
  if (envelope.algorithm !== ALGORITHM) return fail('malformed', `unsupported algorithm ${JSON.stringify(envelope.algorithm)}`);
  if (envelope.canonicalization !== CANONICALIZATION) return fail('malformed', `unsupported canonicalization ${JSON.stringify(envelope.canonicalization)}`);
  for (const f of ['key_id', 'sha256', 'signed_at', 'signature']) {
    if (typeof envelope[f] !== 'string' || !envelope[f]) return fail('malformed', `signature has no ${f}`);
  }
  if (Number.isNaN(Date.parse(envelope.signed_at))) return fail('malformed', 'signed_at is not a date');
  if (artifact !== null && envelope.artifact !== artifact) {
    // A valid signature over a *different* artifact, renamed into place.
    return fail('artifact-mismatch', `signature is for ${JSON.stringify(envelope.artifact)}, not ${JSON.stringify(artifact)}`);
  }

  const key = (keys || []).find((k) => k && k.key_id === envelope.key_id);
  const kid = envelope.key_id;
  if (!key) return fail('unknown-key', `signed by key ${kid}, which is not a trusted key`, { key_id: kid });
  if (key.revoked) return fail('revoked-key', `signed by key ${kid}, which has been revoked`, { key_id: kid });
  const at = dateOnly(envelope.signed_at);
  if (key.valid_from && at < dateOnly(key.valid_from)) {
    return fail('key-not-valid', `key ${kid} is valid from ${key.valid_from}; the signature claims ${at}`, { key_id: kid });
  }
  if (key.valid_until && at > dateOnly(key.valid_until)) {
    return fail('key-not-valid', `key ${kid} was retired on ${key.valid_until}; the signature claims ${at}`, { key_id: kid });
  }

  if (sha256Hex(bytes) !== envelope.sha256) {
    return fail('digest-mismatch', 'the content does not match what was signed (sha256 differs)', { key_id: kid });
  }
  let good = false;
  try {
    good = crypto.verify(null, signedMessage(envelope), publicKeyObject(key.public_key), Buffer.from(envelope.signature, 'base64'));
  } catch (e) {
    return fail('malformed', `could not check the signature: ${e.message}`, { key_id: kid });
  }
  if (!good) return fail('bad-signature', `the signature does not verify under key ${kid}`, { key_id: kid });
  return { ok: true, code: 'verified', key_id: kid, signed_at: envelope.signed_at, sha256: envelope.sha256 };
}

/**
 * Validate a keyring. A key whose id does not match its public key is an
 * error, not a typo to route around: the id is what signatures name.
 */
function normalizeKeys(doc) {
  const errors = [];
  const keys = [];
  const list = doc && Array.isArray(doc.keys) ? doc.keys : null;
  if (!list) return { ok: false, keys, errors: ['trusted keys must be an object with a "keys" array'] };
  for (const [i, k] of list.entries()) {
    if (!k || k.algorithm !== ALGORITHM) { errors.push(`key #${i}: algorithm must be "${ALGORITHM}"`); continue; }
    let id;
    try { id = keyIdFor(k.public_key); }
    catch (e) { errors.push(`key #${i}: ${e.message}`); continue; }
    if (k.key_id !== id) { errors.push(`key #${i}: key_id ${k.key_id} does not match its public key (${id})`); continue; }
    keys.push({
      key_id: id, algorithm: ALGORITHM, public_key: k.public_key,
      valid_from: k.valid_from || null, valid_until: k.valid_until || null,
      revoked: k.revoked === true, comment: k.comment || null,
    });
  }
  return { ok: errors.length === 0, keys, errors };
}

function loadTrustedKeys(file = TRUSTED_KEYS_PATH) {
  let doc;
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return { ok: false, keys: [], errors: [`could not read ${file}: ${e.message}`] }; }
  return normalizeKeys(doc);
}

/** The keyring entry for a public key, ready to paste into trusted_keys.json. */
function keyringEntry(publicKey, { validFrom = new Date().toISOString().slice(0, 10), comment = null } = {}) {
  return {
    key_id: keyIdFor(publicKey), algorithm: ALGORITHM, public_key: publicKey,
    valid_from: validFrom, valid_until: null, revoked: false, comment,
  };
}

module.exports = {
  SIGNATURE_FORMAT, CANONICALIZATION, ALGORITHM, TRUSTED_KEYS_PATH,
  canonicalize, canonicalBytes, sha256Hex, keyIdFor,
  generateKeyPair, publicKeyFromPrivate,
  signCanonical, verifyCanonical, normalizeKeys, loadTrustedKeys, keyringEntry,
};
