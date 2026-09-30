'use strict';
/**
 * Ed25519 over canonical JSON. What matters here is the refusals: every way a
 * signature can fail to hold has its own code, and none of them is "ok".
 * Keys are generated per test run — there is no key in the repository.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');

const s = require('../mcp-ecosystem-intelligence/scripts/lib/signing.cjs');

const doc = { tools: [{ name: 'a', version: '1.0.0', notes: 'café' }], meta: { n: 1 } };
const bytes = s.canonicalBytes(doc);
const keyring = (pair, over = {}) => [{ ...s.keyringEntry(pair.publicKey, { validFrom: '2026-01-01' }), ...over }];

test('canonical form ignores key order, whitespace and escaping', () => {
  const a = s.canonicalBytes('{"b":1,"a":[1,2,{"d":"caf\\u00e9","c":null}]}');
  const b = s.canonicalBytes('{\r\n  "a": [1, 2, {"c": null, "d": "café"}],\r\n  "b": 1\r\n}\r\n');
  assert.equal(a.toString('utf8'), '{"a":[1,2,{"c":null,"d":"café"}],"b":1}');
  assert.deepEqual(a, b);
});

test('canonical form refuses what JSON cannot say', () => {
  assert.throws(() => s.canonicalize({ x: Infinity }), /non-finite/);
  assert.throws(() => s.canonicalize({ x: () => 1 }), /cannot encode/);
});

test('sign then verify', () => {
  const pair = s.generateKeyPair();
  const env = s.signCanonical(bytes, { privateKeyPem: pair.privateKeyPem, artifact: 'db.json', now: Date.parse('2026-09-30T00:00:00Z') });
  assert.equal(env.key_id, pair.keyId);
  assert.equal(env.sha256, s.sha256Hex(bytes));
  const r = s.verifyCanonical(bytes, env, keyring(pair), { artifact: 'db.json' });
  assert.equal(r.ok, true, r.error);
  assert.equal(r.code, 'verified');
});

test('one changed byte of content is a digest mismatch', () => {
  const pair = s.generateKeyPair();
  const env = s.signCanonical(bytes, { privateKeyPem: pair.privateKeyPem, artifact: 'db.json' });
  const tampered = Buffer.from(bytes);
  tampered[tampered.indexOf('1.0.0') + 4] = '1'.charCodeAt(0);   // 1.0.0 → 1.0.1
  const r = s.verifyCanonical(tampered, env, keyring(pair));
  assert.equal(r.ok, false);
  assert.equal(r.code, 'digest-mismatch');
});

test('a digest updated to match tampered content still fails the signature', () => {
  const pair = s.generateKeyPair();
  const env = s.signCanonical(bytes, { privateKeyPem: pair.privateKeyPem, artifact: 'db.json' });
  const tampered = s.canonicalBytes({ ...doc, meta: { n: 2 } });
  const r = s.verifyCanonical(tampered, { ...env, sha256: s.sha256Hex(tampered) }, keyring(pair));
  assert.equal(r.code, 'bad-signature');
});

test('the date and artifact name are signed, not decoration', () => {
  const pair = s.generateKeyPair();
  const env = s.signCanonical(bytes, { privateKeyPem: pair.privateKeyPem, artifact: 'db.json', now: Date.parse('2026-09-30T00:00:00Z') });
  assert.equal(s.verifyCanonical(bytes, { ...env, signed_at: '2026-09-29T00:00:00.000Z' }, keyring(pair)).code, 'bad-signature');
  assert.equal(s.verifyCanonical(bytes, { ...env, artifact: 'other.json' }, keyring(pair)).code, 'bad-signature');
  assert.equal(s.verifyCanonical(bytes, env, keyring(pair), { artifact: 'registry.json' }).code, 'artifact-mismatch');
  const sig = Buffer.from(env.signature, 'base64'); sig[0] ^= 1;
  assert.equal(s.verifyCanonical(bytes, { ...env, signature: sig.toString('base64') }, keyring(pair)).code, 'bad-signature');
});

test('a signature by a key not in the keyring is refused', () => {
  const trusted = s.generateKeyPair();
  const stranger = s.generateKeyPair();
  const env = s.signCanonical(bytes, { privateKeyPem: stranger.privateKeyPem, artifact: 'db.json' });
  const r = s.verifyCanonical(bytes, env, keyring(trusted));
  assert.equal(r.code, 'unknown-key');
  assert.equal(r.key_id, stranger.keyId);
  // An empty keyring verifies nothing.
  assert.equal(s.verifyCanonical(bytes, env, []).code, 'unknown-key');
});

test('a key id swapped to a trusted one does not make a stranger\'s signature good', () => {
  const trusted = s.generateKeyPair();
  const stranger = s.generateKeyPair();
  const env = s.signCanonical(bytes, { privateKeyPem: stranger.privateKeyPem, artifact: 'db.json' });
  assert.equal(s.verifyCanonical(bytes, { ...env, key_id: trusted.keyId }, keyring(trusted)).code, 'bad-signature');
});

test('rotation: each key verifies inside its window, a revoked key verifies nothing', () => {
  const oldKey = s.generateKeyPair();
  const newKey = s.generateKeyPair();
  const ring = [
    { ...s.keyringEntry(oldKey.publicKey, { validFrom: '2026-01-01' }), valid_until: '2026-06-30' },
    s.keyringEntry(newKey.publicKey, { validFrom: '2026-07-01' }),
  ];
  const at = (pair, iso) => s.signCanonical(bytes, { privateKeyPem: pair.privateKeyPem, artifact: 'db.json', now: Date.parse(iso) });

  assert.equal(s.verifyCanonical(bytes, at(oldKey, '2026-05-01T00:00:00Z'), ring).ok, true);
  assert.equal(s.verifyCanonical(bytes, at(newKey, '2026-08-01T00:00:00Z'), ring).ok, true);
  // The retired key after its retirement, the new key before its start.
  assert.equal(s.verifyCanonical(bytes, at(oldKey, '2026-08-01T00:00:00Z'), ring).code, 'key-not-valid');
  assert.equal(s.verifyCanonical(bytes, at(newKey, '2026-05-01T00:00:00Z'), ring).code, 'key-not-valid');

  const revoked = [{ ...ring[0], revoked: true }, ring[1]];
  assert.equal(s.verifyCanonical(bytes, at(oldKey, '2026-05-01T00:00:00Z'), revoked).code, 'revoked-key');
});

test('a malformed envelope is refused, not half-checked', () => {
  const pair = s.generateKeyPair();
  const env = s.signCanonical(bytes, { privateKeyPem: pair.privateKeyPem, artifact: 'db.json' });
  assert.equal(s.verifyCanonical(bytes, null, keyring(pair)).code, 'no-signature');
  assert.equal(s.verifyCanonical(bytes, { ...env, algorithm: 'rsa' }, keyring(pair)).code, 'malformed');
  const { signature, ...unsigned } = env; // eslint-disable-line no-unused-vars
  assert.equal(s.verifyCanonical(bytes, unsigned, keyring(pair)).code, 'malformed');
});

test('a keyring entry whose id does not match its key is an error', () => {
  const pair = s.generateKeyPair();
  const r = s.normalizeKeys({ keys: [{ ...s.keyringEntry(pair.publicKey), key_id: '0000000000000000' }] });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /does not match its public key/);
});

test('the shipped keyring is well-formed', () => {
  const r = s.loadTrustedKeys();
  assert.equal(r.ok, true, r.errors.join('; '));
});

test('a private key round-trips to its public key and id', () => {
  const pair = s.generateKeyPair();
  assert.deepEqual(s.publicKeyFromPrivate(pair.privateKeyPem), { publicKey: pair.publicKey, keyId: pair.keyId });
  assert.match(pair.keyId, /^[0-9a-f]{16}$/);
});
