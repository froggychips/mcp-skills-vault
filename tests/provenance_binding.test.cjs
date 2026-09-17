'use strict';
/**
 * What `bound` is allowed to mean.
 *
 * The claim is narrow and the narrowness is the point: **npm's own registry key
 * signed a statement saying this name@version has this digest**, that digest is
 * the artifact we verified, and a certificate claims the recorded repository
 * built it. The certificate chain is deliberately not validated, so the
 * identity half is a claim — and the digest half must therefore rest on the one
 * key an attacker cannot supply.
 *
 * Three holes these tests close, all of them a comparison that looked like a
 * proof:
 *   1. the statement was never tied to any key, so swapping the subject digest
 *      in an unauthenticated document was enough;
 *   2. with no certificate, the *self-reported* repository was accepted;
 *   3. the builder check was a substring, so `https://evil/actions/runner/x`
 *      passed as GitHub Actions.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const s = require('../mcp-ecosystem-intelligence/scripts/lib/npm_signatures.cjs');

// ── a real signing setup, generated here: an EC key, a statement, a DSSE
//    envelope whose signature we produce ourselves.
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const KEYID = 'SHA256:test-key';
const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

const DIGEST = 'a'.repeat(128);                       // sha512, hex
const INTEGRITY = `sha512-${Buffer.from(DIGEST, 'hex').toString('base64')}`;
const REPO = 'https://github.com/acme/server';

function statement({ digest = DIGEST, repo = REPO, builder = 'https://github.com/actions/runner/github-hosted' } = {}) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'pkg:npm/%40acme/server@1.0.0', digest: { sha512: digest } }],
    predicate: {
      buildDefinition: { externalParameters: { workflow: { repository: repo, path: '.github/workflows/publish.yml', ref: 'refs/tags/v1.0.0' } } },
      runDetails: { builder: { id: builder } },
    },
  };
}

/** A DSSE envelope signed with the key above, or with a garbage signature. */
function envelope(st, { sign = true } = {}) {
  const payload = Buffer.from(JSON.stringify(st));
  const payloadType = 'application/vnd.in-toto+json';
  const sig = sign
    ? crypto.sign('sha256', s.pae(payloadType, payload), privateKey).toString('base64')
    : 'AA==';
  return { payloadType, payload: payload.toString('base64'), signatures: [{ keyid: KEYID, sig }] };
}

const npmSigned = (st, opts) => ({
  attestations: [{
    predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1',
    bundle: { dsseEnvelope: envelope(st, opts), verificationMaterial: { publicKey: { hint: KEYID } } },
  }],
});

const KEYS = { keys: [{ keyid: KEYID, key: spki }] };
const check = (doc, over = {}) => s.checkProvenance({
  claim: s.provenanceClaim(doc),
  keys: KEYS,
  sourceUrl: REPO,
  name: '@acme/server',
  version: '1.0.0',
  integrity: INTEGRITY,
  ...over,
});

test('pae: the DSSE pre-authentication encoding, byte for byte', () => {
  // Getting this wrong means every signature check silently fails or silently
  // passes the wrong bytes.
  assert.equal(s.pae('t', Buffer.from('body')).toString('utf8'), 'DSSEv1 1 t 4 body');
});

test('verifyEnvelope: a valid signature verifies, a modified payload does not', () => {
  const env = envelope(statement());
  assert.equal(s.verifyEnvelope(env, spki).state, 'ok');

  const tampered = { ...env, payload: Buffer.from(JSON.stringify(statement({ digest: 'b'.repeat(128) }))).toString('base64') };
  assert.equal(s.verifyEnvelope(tampered, spki).state, 'fail');
});

test('verifyEnvelope: no key, no payload and no signature are each "unverified", not "ok"', () => {
  assert.equal(s.verifyEnvelope(envelope(statement()), null).state, 'unverified');
  assert.equal(s.verifyEnvelope({ payloadType: 'x', signatures: [] }, spki).state, 'unverified');
  assert.equal(s.verifyEnvelope({ payloadType: 'x', payload: 'e30=' }, spki).state, 'unverified');
});

test('the digest half of a binding rests on npm\'s key', () => {
  const r = check(npmSigned(statement()));
  assert.equal(r.subject_match, 'ok');
  assert.equal(r.subject_verified_by, 'npm registry key');
});

test('a swapped subject digest cannot pass, because the signature covers it', () => {
  // The attack: take a genuine bundle, replace the subject digest with the
  // integrity value npm signed for *our* artifact, keep everything else.
  const doc = npmSigned(statement());
  const forged = JSON.parse(JSON.stringify(doc));
  forged.attestations[0].bundle.dsseEnvelope.payload =
    Buffer.from(JSON.stringify(statement({ digest: 'c'.repeat(128) }))).toString('base64');
  const r = check(forged);
  assert.equal(r.state, 'mismatch');
  assert.match(r.findings.join(' '), /does not verify/);
});

test('an unsigned statement with the right digest is a claim, not a binding', () => {
  const r = check(npmSigned(statement(), { sign: false }));
  assert.notEqual(r.state, 'bound');
  assert.match(r.findings.join(' '), /does not verify/);
});

test('no key material at all means no binding', () => {
  // An offline caller, or a run that could not fetch npm's keys. The digest
  // still matches; that is not the same as being bound to it.
  const r = check(npmSigned(statement()), { keys: null });
  assert.equal(r.state, 'claimed');
  // 'unsigned': the digest matches and *nothing* authenticated the statement.
  // Distinct from 'self-signed', which is a signature that verified against
  // the bundle's own unvalidated certificate.
  assert.equal(r.subject_match, 'unsigned');
  assert.match(r.findings.join(' '), /no signature over that statement/);
});

test('a self-reported repository is never accepted as the identity', () => {
  // With no certificate, the repository in the statement is a field the
  // publisher types. Matching it is not evidence of who built anything.
  const r = check(npmSigned(statement()));
  assert.equal(r.repo_match, 'self-reported');
  assert.equal(r.state, 'claimed', 'no certificate, no binding');
  assert.match(r.findings.join(' '), /self-reported/);
});

test('a hostile builder id does not pass as GitHub Actions', () => {
  // `https://evil.example/actions/runner/x` matched a substring check.
  const r = check(npmSigned(statement({ builder: 'https://evil.example/actions/runner/x' })));
  assert.equal(r.issuer, 'unknown');
  assert.notEqual(r.state, 'bound');
  assert.match(r.findings.join(' '), /not a GitHub Actions runner/);
});

test('a different repository is a mismatch, not a claim', () => {
  const r = check(npmSigned(statement({ repo: 'https://github.com/someone-else/server' })));
  assert.equal(r.state, 'mismatch');
  assert.match(r.findings.join(' '), /someone-else/);
});

test('integrityToHex refuses what npm would never serve', () => {
  const good = `sha512-${Buffer.alloc(64, 5).toString('base64')}`;
  assert.equal(s.integrityToHex(good).hex, 'f'.repeat(0) + Buffer.alloc(64, 5).toString('hex'));
  // Trailing junk after a padded digest: `Buffer.from(…, 'base64')` ignores it
  // and produced exactly 64 bytes, so a value npm would reject could still
  // reach a digest comparison.
  assert.equal(s.integrityToHex(`${good}garbage`), null);
  // Several SRI tokens: refused rather than silently taking the first.
  assert.equal(s.integrityToHex(`${good} sha256-${Buffer.alloc(32).toString('base64')}`), null);
  assert.equal(s.integrityToHex('sha512-short'), null);
  assert.equal(s.integrityToHex(`sha256-${Buffer.alloc(64).toString('base64')}`), null, 'sha512-length body under a sha256 label');
  assert.equal(s.integrityToHex(''), null);
});

test('attestationRecords keeps every attestation, not just the first', () => {
  // npm publishes two, and the useful fields are split between them: the
  // publish attestation carries the digest under npm's key, the SLSA one
  // carries the workflow identity under a certificate.
  const doc = {
    attestations: [
      { predicateType: 'a', bundle: { dsseEnvelope: envelope(statement()) } },
      { predicateType: 'b', bundle: { dsseEnvelope: envelope(statement({ repo: REPO })) } },
    ],
  };
  const records = s.attestationRecords(doc);
  assert.equal(records.length, 2);
  assert.ok(records.every((r) => r.envelope), 'the envelope travels with the record so it can be checked');
});
