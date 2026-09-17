'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

// Every test here runs against an injected transport and a scratch cache dir:
// nothing in this file touches the network.
const cacheHome = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-httpcache-'));
process.env.MCP_VAULT_CACHE_DIR = cacheHome;
const h = require('../mcp-ecosystem-intelligence/scripts/lib/http.cjs');

test('shouldRetry: transient only', () => {
  assert.equal(h.shouldRetry(null), true);    // connection error / timeout
  assert.equal(h.shouldRetry(429), true);
  assert.equal(h.shouldRetry(403), true);     // GitHub's rate-limit answer
  assert.equal(h.shouldRetry(500), true);
  assert.equal(h.shouldRetry(503), true);
  assert.equal(h.shouldRetry(404), false);    // an answer, not a failure
  assert.equal(h.shouldRetry(401), false);
  assert.equal(h.shouldRetry(200), false);
});

test('backoffDelay: exponential, jittered, capped', () => {
  // rand() pinned so the assertions are about the shape, not luck.
  assert.equal(h.backoffDelay(0, 250, () => 1), 250);
  assert.equal(h.backoffDelay(1, 250, () => 1), 500);
  assert.equal(h.backoffDelay(2, 250, () => 1), 1000);
  assert.equal(h.backoffDelay(9, 250, () => 1), 8000);      // cap
  assert.equal(h.backoffDelay(0, 250, () => 0), 125);       // full jitter floor
  assert.equal(h.backoffDelay(-5, 250, () => 1), 250);      // no negative attempts
});

test('retryAfterMs: seconds, HTTP dates, junk, and a cap', () => {
  assert.equal(h.retryAfterMs('2'), 2000);
  assert.equal(h.retryAfterMs('0'), 0);
  assert.equal(h.retryAfterMs(undefined), null);
  assert.equal(h.retryAfterMs('later'), null);
  assert.equal(h.retryAfterMs('99999'), 30000);             // hostile value capped
  const now = Date.parse('2026-01-01T00:00:00Z');
  assert.equal(h.retryAfterMs('Thu, 01 Jan 2026 00:00:05 GMT', now), 5000);
  assert.equal(h.retryAfterMs('Thu, 01 Jan 2020 00:00:00 GMT', now), 0);   // past
});

test('cacheKey: varies by url and Accept, never embeds a token', () => {
  const a = h.cacheKey('GET', 'https://x/y', { Accept: 'application/json' });
  const b = h.cacheKey('GET', 'https://x/z', { Accept: 'application/json' });
  const c = h.cacheKey('GET', 'https://x/y', { Accept: 'application/vnd.github+json' });
  assert.notEqual(a, b);
  assert.notEqual(a, c);
  // Authenticated and anonymous responses differ, so the keys must differ…
  const anon = h.cacheKey('GET', 'https://x/y', {});
  const auth = h.cacheKey('GET', 'https://x/y', { Authorization: 'Bearer ghp_secret' });
  assert.notEqual(anon, auth);
  // …but two different tokens must land on the same key, and the key must not
  // carry the secret.
  const auth2 = h.cacheKey('GET', 'https://x/y', { Authorization: 'Bearer ghp_other' });
  assert.equal(auth, auth2);
  assert.doesNotMatch(auth, /ghp_/);
  assert.match(auth, /^[0-9a-f]{64}$/);
});

test('mapLimit: preserves order and respects the ceiling', async () => {
  let inFlight = 0, peak = 0;
  const out = await h.mapLimit([1, 2, 3, 4, 5, 6, 7], 3, async (n) => {
    inFlight++; peak = Math.max(peak, inFlight);
    await new Promise(r => setTimeout(r, n % 3));
    inFlight--;
    return n * 10;
  });
  assert.deepEqual(out, [10, 20, 30, 40, 50, 60, 70]);
  assert.ok(peak <= 3, `peak concurrency ${peak}`);
  assert.equal(peak > 1, true, 'should actually run in parallel');
});

test('mapLimit: empty input, and a limit larger than the list', async () => {
  assert.deepEqual(await h.mapLimit([], 8, async () => 1), []);
  assert.deepEqual(await h.mapLimit([1, 2], 99, async (n) => n), [1, 2]);
});

test('request: retries a 500 then succeeds', async () => {
  const seen = [];
  const transport = async () => {
    seen.push('call');
    return seen.length < 3
      ? { status: 500, headers: {}, text: 'boom' }
      : { status: 200, headers: {}, text: '{"ok":true}' };
  };
  const r = await h.request('https://example.test/a', { transport, retries: 3, onRetry: () => {} });
  assert.equal(r.ok, true);
  assert.deepEqual(r.data, { ok: true });
  assert.equal(r.attempts, 3);
});

test('request: does not retry a 404', async () => {
  let calls = 0;
  const transport = async () => { calls++; return { status: 404, headers: {}, text: 'nope' }; };
  const r = await h.request('https://example.test/b', { transport, retries: 3 });
  assert.equal(r.ok, false);
  assert.equal(calls, 1);
  assert.match(r.error, /404/);
});

test('request: honours Retry-After instead of the backoff', async () => {
  const waits = [];
  let calls = 0;
  const transport = async () => {
    calls++;
    return calls === 1
      ? { status: 429, headers: { 'retry-after': '0' }, text: '' }
      : { status: 200, headers: {}, text: '{}' };
  };
  const r = await h.request('https://example.test/c', {
    transport, retries: 2, onRetry: (i) => waits.push(i.waitMs),
  });
  assert.equal(r.ok, true);
  assert.deepEqual(waits, [0]);
});

test('request: caches a GET, then revalidates with the stored ETag', async () => {
  const url = 'https://example.test/cached';
  let calls = 0;
  const sentHeaders = [];
  const transport = async (_u, opts) => {
    calls++;
    sentHeaders.push(opts.headers);
    return { status: 200, headers: { etag: 'W/"v1"' }, text: '{"n":1}' };
  };

  const first = await h.request(url, { transport, cacheTtlMs: 60000 });
  assert.equal(first.fromCache, false);
  assert.deepEqual(first.data, { n: 1 });

  // Inside the TTL: served from disk, no request at all.
  const second = await h.request(url, { transport, cacheTtlMs: 60000 });
  assert.equal(second.fromCache, true);
  assert.equal(calls, 1);

  // TTL expired: revalidate. A 304 means the cached body stands.
  await new Promise(r => setTimeout(r, 5));
  const revalidate = async (_u, opts) => { sentHeaders.push(opts.headers); return { status: 304, headers: {}, text: '' }; };
  const third = await h.request(url, { transport: revalidate, cacheTtlMs: 1 });
  assert.equal(third.fromCache, true);
  assert.deepEqual(third.data, { n: 1 });
  assert.equal(sentHeaders.at(-1)['If-None-Match'], 'W/"v1"');
});

test('request: a stale cache entry beats reporting the feed as down', async () => {
  const url = 'https://example.test/stale';
  await h.request(url, { transport: async () => ({ status: 200, headers: {}, text: '{"v":"old"}' }), cacheTtlMs: 60000 });
  await new Promise(r => setTimeout(r, 5));   // let the 1ms TTL below actually lapse
  const down = async () => ({ status: null, error: 'ECONNRESET' });
  const r = await h.request(url, { transport: down, retries: 1, cacheTtlMs: 1 });
  assert.equal(r.ok, true);
  assert.equal(r.stale, true);
  assert.deepEqual(r.data, { v: 'old' });
});

test('request: non-JSON 200 is a failure, not a silent empty result', async () => {
  const transport = async () => ({ status: 200, headers: {}, text: '<html>nope</html>' });
  const r = await h.request('https://example.test/html', { transport, retries: 0 });
  assert.equal(r.ok, false);
  assert.match(r.error, /not JSON/);
});

test('request: refuses a non-https url', async () => {
  const r = await h.request('http://example.test/insecure', { retries: 0 });
  assert.equal(r.ok, false);
  assert.match(r.error, /non-https/);
});

test('request: a corrupt cache file is ignored, not fatal', async () => {
  const url = 'https://example.test/corrupt';
  const key = h.cacheKey('GET', url, {});
  fs.mkdirSync(h.cacheDir(), { recursive: true });
  fs.writeFileSync(path.join(h.cacheDir(), `${key}.json`), '{ this is not json');
  const r = await h.request(url, {
    transport: async () => ({ status: 200, headers: {}, text: '{"fresh":true}' }),
    cacheTtlMs: 60000,
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.data, { fresh: true });
});

test('postJson: never reads or writes the cache', async () => {
  let calls = 0;
  const transport = async (_u, opts) => {
    calls++;
    assert.equal(opts.body, JSON.stringify({ q: 1 }));
    return { status: 200, headers: {}, text: '{"r":[]}' };
  };
  await h.postJson('https://example.test/p', { q: 1 }, { transport, cacheTtlMs: 60000 });
  await h.postJson('https://example.test/p', { q: 1 }, { transport, cacheTtlMs: 60000 });
  assert.equal(calls, 2);
});
