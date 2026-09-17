'use strict';
/**
 * HTTPS with retries, a bounded worker pool and an on-disk cache.
 *
 * What this replaces: every caller had its own `https.get` wrapper that
 * resolved `null` on any failure, and the GHSA/Snyk loops awaited one request
 * per package in sequence. With 114 entries that is 114 round trips end to end,
 * and a single 403 from a rate limit turned one package's result into "feed
 * unreachable" with no second attempt. A weekly job that sits on a sleeping
 * laptop then runs for hours.
 *
 * Design notes:
 *   - Retries cover the failures that are actually transient: connection
 *     errors, timeouts, 429 and 5xx. A 404 is an answer, not a failure, and is
 *     never retried.
 *   - `Retry-After` is honoured when the server sends it (GitHub does on
 *     secondary rate limits), capped so a hostile value can't park the run.
 *   - The cache is keyed on method + URL + the headers that change the
 *     response, and stores the ETag so a revalidation can come back 304. It
 *     lives under XDG_CACHE_HOME (or ~/.cache) so nothing lands in the repo.
 *   - Authorization headers are part of the key by *presence*, never by value:
 *     a token must not be derivable from a cache filename.
 *
 * API:
 *   getJson(url, opts)            -> { ok, status, data, fromCache } | { ok:false, ... }
 *   postJson(url, payload, opts)  -> same shape
 *   mapLimit(items, limit, fn)    -> Promise<results[]>   (order preserved)
 *   backoffDelay(attempt, base)   -> ms                   (pure, testable)
 *   shouldRetry(status)           -> boolean              (pure, testable)
 *   cacheKey(method, url, headers)-> string               (pure, testable)
 *   retryAfterMs(header)          -> ms | null            (pure, testable)
 */

const https  = require('https');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_RETRIES    = 3;
const MAX_BACKOFF_MS     = 8000;
const MAX_RETRY_AFTER_MS = 30000;   // a server asking for more than this is ignored

// ── pure helpers ───────────────────────────────────────────────────────────

// Transient, so worth another attempt. 403 is included because that is what
// GitHub returns for a rate limit — with a Retry-After or a reset header.
function shouldRetry(status) {
  if (status === null || status === undefined) return true;   // transport failure
  if (status === 429 || status === 403) return true;
  return status >= 500 && status <= 599;
}

// Exponential with full jitter, so a fan-out of 8 doesn't retry in lockstep.
function backoffDelay(attempt, base = 250, rand = Math.random) {
  const ceiling = Math.min(MAX_BACKOFF_MS, base * Math.pow(2, Math.max(0, attempt)));
  return Math.round(ceiling * (0.5 + 0.5 * rand()));
}

// `Retry-After` is either seconds or an HTTP date.
function retryAfterMs(header, now = Date.now()) {
  if (!header) return null;
  const secs = Number(header);
  if (!Number.isNaN(secs) && secs >= 0) return Math.min(secs * 1000, MAX_RETRY_AFTER_MS);
  const when = Date.parse(header);
  if (Number.isNaN(when)) return null;
  return Math.max(0, Math.min(when - now, MAX_RETRY_AFTER_MS));
}

// Headers that change the response body, normalised. Authorization is recorded
// as a boolean: an authenticated response can differ from an anonymous one, but
// the token itself must never reach a filename or a cache file.
function cacheKey(method, url, headers = {}) {
  const relevant = {};
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (key === 'authorization') { relevant.authorized = true; continue; }
    if (key === 'accept' || key === 'content-type' || key === 'x-github-api-version') relevant[key] = v;
  }
  const material = JSON.stringify([method.toUpperCase(), url, relevant]);
  return crypto.createHash('sha256').update(material).digest('hex');
}

function cacheDir() {
  const base = process.env.MCP_VAULT_CACHE_DIR
    || path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir() || os.tmpdir(), '.cache'), 'mcp-vault');
  return path.join(base, 'http');
}

function readCache(key) {
  try {
    const raw = fs.readFileSync(path.join(cacheDir(), `${key}.json`), 'utf8');
    const rec = JSON.parse(raw);
    if (!rec || typeof rec !== 'object') return null;
    return rec;   // { stored_at, etag, status, data }
  } catch {
    return null;  // absent, unreadable, corrupt — all mean "no cache"
  }
}

function writeCache(key, record) {
  try {
    const dir = cacheDir();
    fs.mkdirSync(dir, { recursive: true });
    // Write-then-rename so a killed process can't leave a half-written file
    // that later parses as valid JSON.
    const tmp = path.join(dir, `${key}.${process.pid}.tmp`);
    fs.writeFileSync(tmp, JSON.stringify(record));
    fs.renameSync(tmp, path.join(dir, `${key}.json`));
  } catch {
    /* a cache that can't be written is not an error worth failing a scan for */
  }
}

function cacheFresh(record, ttlMs) {
  if (!record || !ttlMs) return false;
  return Date.now() - (record.stored_at || 0) < ttlMs;
}

// ── bounded concurrency ────────────────────────────────────────────────────

/**
 * Run `fn` over `items` with at most `limit` in flight. Results keep the input
 * order, and one rejection does not cancel the rest — `fn` is expected to
 * resolve with its own error shape, which is how every feed here behaves.
 */
async function mapLimit(items, limit, fn) {
  const list    = [...items];
  const results = new Array(list.length);
  const width   = Math.max(1, Math.min(limit || 1, list.length));
  let next = 0;

  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= list.length) return;
      results[i] = await fn(list[i], i);
    }
  }

  await Promise.all(Array.from({ length: width }, worker));
  return results;
}

// ── transport ──────────────────────────────────────────────────────────────

function once(url, { method = 'GET', headers = {}, body = null, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { resolve({ status: null, error: 'bad url' }); return; }
    if (u.protocol !== 'https:') { resolve({ status: null, error: 'refusing non-https request' }); return; }

    const req = https.request({
      hostname: u.hostname,
      port:     u.port || 443,
      path:     u.pathname + u.search,
      method,
      headers:  body
        ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers }
        : headers,
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: data }));
    });
    req.on('error', (e) => resolve({ status: null, error: e.message }));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ status: null, error: `timeout after ${timeoutMs}ms` }); });
    if (body) req.write(body);
    req.end();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * A JSON request with retries and (for GET) the disk cache.
 *
 * Returns { ok, status, data, fromCache, attempts, error? }. `ok` is true only
 * when a 2xx response parsed as JSON — every caller in this repo treats
 * anything else as "this feed did not answer", which is deliberately different
 * from "this feed says there is nothing".
 */
async function request(url, {
  method = 'GET', headers = {}, payload = undefined,
  timeoutMs = DEFAULT_TIMEOUT_MS, retries = DEFAULT_RETRIES,
  cacheTtlMs = 0, transport = once, onRetry = null,
} = {}) {
  const body     = payload === undefined ? null : JSON.stringify(payload);
  const cacheable = method.toUpperCase() === 'GET' && cacheTtlMs > 0;
  const key       = cacheable ? cacheKey(method, url, headers) : null;
  const cached    = cacheable ? readCache(key) : null;

  if (cacheFresh(cached, cacheTtlMs)) {
    return { ok: true, status: cached.status, data: cached.data, fromCache: true, attempts: 0 };
  }

  const sendHeaders = { ...headers };
  // Stale copy in hand: ask the server to confirm it instead of resending it.
  if (cached && cached.etag) sendHeaders['If-None-Match'] = cached.etag;

  let last = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const res = await transport(url, { method, headers: sendHeaders, body, timeoutMs });
    last = res;

    if (res.status === 304 && cached) {
      writeCache(key, { ...cached, stored_at: Date.now() });
      return { ok: true, status: cached.status, data: cached.data, fromCache: true, attempts: attempt + 1 };
    }

    if (res.status >= 200 && res.status < 300) {
      let data;
      try { data = JSON.parse(res.text); }
      catch { return { ok: false, status: res.status, error: 'response was not JSON', attempts: attempt + 1 }; }
      if (cacheable) {
        writeCache(key, { stored_at: Date.now(), etag: res.headers && res.headers.etag, status: res.status, data });
      }
      return { ok: true, status: res.status, data, fromCache: false, attempts: attempt + 1 };
    }

    if (attempt === retries || !shouldRetry(res.status)) break;

    const wait = retryAfterMs(res.headers && res.headers['retry-after']) ?? backoffDelay(attempt);
    if (onRetry) onRetry({ url, attempt: attempt + 1, status: res.status, error: res.error, waitMs: wait });
    await sleep(wait);
  }

  // A stale cache entry beats nothing at all: "we saw this an hour ago" is
  // better evidence than "the feed is down", and the caller is told which.
  if (cached) {
    return { ok: true, status: cached.status, data: cached.data, fromCache: true, stale: true, attempts: retries + 1 };
  }
  return {
    ok: false,
    status: last ? last.status : null,
    error: last ? (last.error || `HTTP ${last.status}`) : 'no response',
    attempts: retries + 1,
  };
}

const getJson  = (url, opts = {}) => request(url, { ...opts, method: 'GET' });
const postJson = (url, payload, opts = {}) => request(url, { ...opts, method: 'POST', payload });

module.exports = {
  getJson, postJson, request, mapLimit,
  shouldRetry, backoffDelay, retryAfterMs, cacheKey, cacheDir,
  DEFAULT_TIMEOUT_MS, DEFAULT_RETRIES,
};
