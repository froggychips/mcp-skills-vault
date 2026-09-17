'use strict';
const { test }   = require('node:test');
const assert     = require('node:assert/strict');
const crypto     = require('node:crypto');
const { Readable } = require('node:stream');
const { EventEmitter } = require('node:events');

const a = require('../mcp-ecosystem-intelligence/scripts/lib/artifact.cjs');

const BODY    = Buffer.from('a tarball, pretend');
const SHA512  = crypto.createHash('sha512').update(BODY).digest();
const SRI512  = `sha512-${SHA512.toString('base64')}`;
const SHA256H = crypto.createHash('sha256').update(BODY).digest('hex');

test('parseSri: base64 and hex spellings of the same digest', () => {
  const hex = '2cd74704c7b271ab1ed7be266120c20ae8ae7cc01e52dc6c549790402bad2b44';
  const b64 = Buffer.from(hex, 'hex').toString('base64');
  // hex is a subset of the base64 alphabet, so length decides. Parsing a
  // 64-char hex digest as base64 yields 48 bytes of nonsense — which is
  // exactly how a correct PyPI pin first read as a mismatch.
  assert.deepEqual(a.parseSri(`sha256-${hex}`), { algo: 'sha256', b64, fromHex: true });
  assert.deepEqual(a.parseSri(`sha256-${b64}`), { algo: 'sha256', b64 });
  assert.equal(a.sriEqual(`sha256-${hex}`, `sha256-${b64}`), true);
});

test('parseSri: rejects what it cannot use', () => {
  assert.equal(a.parseSri('md5-abc'), null);              // unsupported algorithm
  assert.equal(a.parseSri('sha256-not!base64'), null);
  assert.equal(a.parseSri('sha256-YWJj'), null);          // right alphabet, wrong length
  assert.equal(a.parseSri(''), null);
  assert.equal(a.parseSri(null), null);
  assert.equal(a.parseSri(42), null);
});

test('parseSri: takes the first usable hash from a multi-hash string', () => {
  const sri = `md5-abc ${SRI512}`;
  assert.equal(a.parseSri(sri).algo, 'sha512');
});

test('sriEqual: false for different digests, algorithms, or junk', () => {
  const other = `sha512-${crypto.createHash('sha512').update('different').digest('base64')}`;
  assert.equal(a.sriEqual(SRI512, SRI512), true);
  assert.equal(a.sriEqual(SRI512, other), false);
  assert.equal(a.sriEqual(SRI512, `sha256-${SHA256H}`), false);   // algo mismatch
  assert.equal(a.sriEqual(SRI512, null), false);
  assert.equal(a.sriEqual(undefined, undefined), false);
});

test('hashStream: hashes what it is given', async () => {
  const r = await a.hashStream(Readable.from([BODY.subarray(0, 5), BODY.subarray(5)]), 'sha512');
  assert.equal(r.ok, true);
  assert.equal(r.bytes, BODY.length);
  assert.equal(a.sriFrom('sha512', r.digest), SRI512);
});

test('hashStream: refuses to buffer past the ceiling', async () => {
  const big = Readable.from([Buffer.alloc(1024), Buffer.alloc(1024)]);
  const r = await a.hashStream(big, 'sha512', { maxBytes: 1500 });
  assert.equal(r.ok, false);
  assert.match(r.error, /exceeds 1500 bytes/);
});

test('hashStream: a stream error is a failure, not a hash of a partial body', async () => {
  const s = new Readable({ read() { this.push(Buffer.from('half')); this.destroy(new Error('ECONNRESET')); } });
  const r = await a.hashStream(s, 'sha512');
  assert.equal(r.ok, false);
  assert.match(r.error, /ECONNRESET/);
});

// A fake https.get: hands back a response stream, and records what was asked for.
function fakeGet(script) {
  const calls = [];
  const get = (url, _opts, cb) => {
    calls.push(url);
    const step = script[Math.min(calls.length - 1, script.length - 1)];
    const req = new EventEmitter();
    req.setTimeout = () => {};
    req.destroy = () => {};
    setImmediate(() => {
      if (step.error) { req.emit('error', new Error(step.error)); return; }
      const res = Readable.from(step.body === undefined ? [] : [Buffer.from(step.body)]);
      res.statusCode = step.status;
      res.headers = step.headers || {};
      cb(res);
    });
    return req;
  };
  return { get, calls };
}

test('hashUrl: hashes a 200 body', async () => {
  const { get } = fakeGet([{ status: 200, body: BODY }]);
  const r = await a.hashUrl('https://example.test/t.tgz', 'sha512', { get });
  assert.equal(r.ok, true);
  assert.equal(r.sri, SRI512);
  assert.equal(r.bytes, BODY.length);
});

test('hashUrl: follows https redirects, up to a limit', async () => {
  const { get, calls } = fakeGet([
    { status: 302, headers: { location: 'https://cdn.example.test/t.tgz' }, body: '' },
    { status: 200, body: BODY },
  ]);
  const r = await a.hashUrl('https://example.test/t.tgz', 'sha512', { get });
  assert.equal(r.ok, true);
  assert.equal(r.url, 'https://cdn.example.test/t.tgz');
  assert.deepEqual(calls, ['https://example.test/t.tgz', 'https://cdn.example.test/t.tgz']);

  const loop = fakeGet([{ status: 302, headers: { location: 'https://example.test/again' }, body: '' }]);
  const stuck = await a.hashUrl('https://example.test/t.tgz', 'sha512', { get: loop.get });
  assert.equal(stuck.ok, false);
  assert.match(stuck.error, /redirects/);
});

test('hashUrl: will not be downgraded to http by a redirect', async () => {
  const { get } = fakeGet([
    { status: 302, headers: { location: 'http://insecure.example.test/t.tgz' }, body: '' },
  ]);
  const r = await a.hashUrl('https://example.test/t.tgz', 'sha512', { get });
  assert.equal(r.ok, false);
  assert.match(r.error, /non-https/);
});

test('hashUrl: non-200 and transport errors are failures', async () => {
  const notFound = fakeGet([{ status: 404, body: 'nope' }]);
  assert.match((await a.hashUrl('https://example.test/x', 'sha512', { get: notFound.get })).error, /404/);

  const broken = fakeGet([{ error: 'ETIMEDOUT' }]);
  assert.match((await a.hashUrl('https://example.test/x', 'sha512', { get: broken.get })).error, /ETIMEDOUT/);

  const r = await a.hashUrl('not a url', 'sha512', { get: notFound.get });
  assert.equal(r.ok, false);
});

test('ociManifestDigest: a digest is the sha256 of the manifest bytes', () => {
  const manifest = '{"schemaVersion":2,"layers":[]}';
  const expected = `sha256:${crypto.createHash('sha256').update(manifest).digest('hex')}`;
  assert.equal(a.ociManifestDigest(manifest), expected);
  // Byte-identical input, different type: same answer.
  assert.equal(a.ociManifestDigest(Buffer.from(manifest)), expected);
});
