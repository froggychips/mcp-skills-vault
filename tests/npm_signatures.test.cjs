'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const crypto   = require('node:crypto');

const s = require('../mcp-ecosystem-intelligence/scripts/lib/npm_signatures.cjs');

// A throwaway registry key, so the crypto path is exercised without a network.
function makeKey(keyid = 'SHA256:test', expires = null) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    entry: {
      keyid, expires,
      keytype: 'ecdsa-sha2-nistp256',
      scheme:  'ecdsa-sha2-nistp256',
      key:     publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    },
    sign: (message) => crypto.sign('sha256', Buffer.from(message), privateKey).toString('base64'),
  };
}

const NAME      = '@scope/pkg';
const VERSION   = '1.2.3';
const INTEGRITY = 'sha512-abc123==';

test('signatureMessage: the string npm actually signs', () => {
  assert.equal(s.signatureMessage(NAME, VERSION, INTEGRITY), '@scope/pkg@1.2.3:sha512-abc123==');
});

test('keysUrl: built off the configured registry', () => {
  assert.equal(s.keysUrl('https://registry.npmjs.org'), 'https://registry.npmjs.org/-/npm/v1/keys');
  assert.equal(s.keysUrl('https://mirror.example/'), 'https://mirror.example/-/npm/v1/keys');
});

test('verifyRegistrySignature: a good signature verifies', () => {
  const k = makeKey();
  const sig = k.sign(s.signatureMessage(NAME, VERSION, INTEGRITY));
  const r = s.verifyRegistrySignature({
    name: NAME, version: VERSION, integrity: INTEGRITY,
    signatures: [{ keyid: k.entry.keyid, sig }],
    keys: { keys: [k.entry] },
  });
  assert.deepEqual(r, { state: 'ok', keyid: 'SHA256:test' });
});

test('verifyRegistrySignature: a swapped integrity value cannot pass', () => {
  // This is the attack the signature defends against: a response whose
  // dist.integrity has been changed to match a tampered tarball.
  const k = makeKey();
  const sig = k.sign(s.signatureMessage(NAME, VERSION, INTEGRITY));
  const r = s.verifyRegistrySignature({
    name: NAME, version: VERSION, integrity: 'sha512-TAMPERED==',
    signatures: [{ keyid: k.entry.keyid, sig }],
    keys: { keys: [k.entry] },
  });
  assert.equal(r.state, 'fail');
  assert.match(r.reason, /does not verify/);
});

test('verifyRegistrySignature: signed by a key that is not the registry\'s', () => {
  const real     = makeKey('SHA256:real');
  const attacker = makeKey('SHA256:real');   // same keyid, different key material
  const sig = attacker.sign(s.signatureMessage(NAME, VERSION, INTEGRITY));
  const r = s.verifyRegistrySignature({
    name: NAME, version: VERSION, integrity: INTEGRITY,
    signatures: [{ keyid: 'SHA256:real', sig }],
    keys: { keys: [real.entry] },
  });
  assert.equal(r.state, 'fail');
});

test('verifyRegistrySignature: absent is unverified, not failed', () => {
  const k = makeKey();
  const base = { name: NAME, version: VERSION, integrity: INTEGRITY, keys: { keys: [k.entry] } };
  // A package published before npm signed anything.
  assert.equal(s.verifyRegistrySignature({ ...base, signatures: [] }).state, 'unverified');
  assert.equal(s.verifyRegistrySignature({ ...base, signatures: undefined }).state, 'unverified');
  // No integrity to sign over.
  assert.equal(s.verifyRegistrySignature({ ...base, integrity: null, signatures: [{ keyid: 'x', sig: 'y' }] }).state, 'unverified');
  // Keys document unavailable (the fetch failed).
  assert.equal(s.verifyRegistrySignature({ ...base, keys: null, signatures: [{ keyid: 'x', sig: 'y' }] }).state, 'unverified');
  // Signature references a keyid the registry does not publish.
  const unknown = s.verifyRegistrySignature({ ...base, signatures: [{ keyid: 'SHA256:who', sig: 'AAAA' }] });
  assert.equal(unknown.state, 'unverified');
  assert.match(unknown.reason, /no published key matches/);
});

test('verifyRegistrySignature: an expired key is unverified, not a pass', () => {
  const k = makeKey('SHA256:old', '2020-01-01T00:00:00.000Z');
  const sig = k.sign(s.signatureMessage(NAME, VERSION, INTEGRITY));
  const r = s.verifyRegistrySignature({
    name: NAME, version: VERSION, integrity: INTEGRITY,
    signatures: [{ keyid: 'SHA256:old', sig }],
    keys: { keys: [k.entry] },
  });
  assert.equal(r.state, 'unverified');
  assert.match(r.reason, /expired/);
});

test('verifyRegistrySignature: malformed key material does not throw', () => {
  const r = s.verifyRegistrySignature({
    name: NAME, version: VERSION, integrity: INTEGRITY,
    signatures: [{ keyid: 'SHA256:bad', sig: 'AAAA' }],
    keys: { keys: [{ keyid: 'SHA256:bad', key: 'not-a-der-key' }] },
  });
  assert.equal(r.state, 'unverified');
  assert.match(r.reason, /could not check/);
});

// ── provenance ─────────────────────────────────────────────────────────────

const envelope = (statement) => ({
  attestations: [{
    predicateType: 'https://slsa.dev/provenance/v1',
    bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString('base64') } },
  }],
});

test('provenanceClaim: SLSA v1 buildDefinition', () => {
  const claim = s.provenanceClaim(envelope({
    subject: [{ name: 'pkg:npm/%40scope/pkg@1.2.3' }],
    predicate: {
      buildDefinition: { externalParameters: { workflow: {
        repository: 'https://github.com/owner/repo', ref: 'refs/heads/main', path: '.github/workflows/publish.yml',
      } } },
      runDetails: { builder: { id: 'https://github.com/actions/runner' } },
    },
  }));
  assert.equal(claim.repository, 'https://github.com/owner/repo');
  assert.equal(claim.workflowPath, '.github/workflows/publish.yml');
  assert.equal(claim.builder, 'https://github.com/actions/runner');
  assert.deepEqual(claim.subjects, ['pkg:npm/%40scope/pkg@1.2.3']);
});

test('provenanceClaim: SLSA v0.2 configSource', () => {
  const claim = s.provenanceClaim(envelope({
    predicate: { invocation: { configSource: {
      uri: 'git+https://github.com/owner/repo@refs/heads/main',
      digest: { sha1: 'deadbeef' },
    } } },
  }));
  assert.equal(claim.repository, 'https://github.com/owner/repo');
  assert.equal(claim.ref, 'deadbeef');
});

test('provenanceClaim: null when there is nothing usable', () => {
  assert.equal(s.provenanceClaim(null), null);
  assert.equal(s.provenanceClaim({}), null);
  assert.equal(s.provenanceClaim({ attestations: [] }), null);
  assert.equal(s.provenanceClaim({ attestations: [{ bundle: {} }] }), null);
  // Payload that isn't base64 JSON must not throw.
  assert.equal(s.provenanceClaim({ attestations: [{ bundle: { dsseEnvelope: { payload: '!!!' } } }] }), null);
  // A statement with no repository anywhere.
  assert.equal(s.provenanceClaim(envelope({ predicate: {} })), null);
});
