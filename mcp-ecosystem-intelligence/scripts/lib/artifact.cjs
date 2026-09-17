'use strict';
/**
 * Fetch an artifact and hash it here, rather than trusting what the registry
 * says about it.
 *
 * Why this exists: the gate compared the DB's stored pin against
 * `dist.integrity` from the npm registry — a value served by the same host that
 * serves the tarball. That is a check that the registry agrees with itself. It
 * catches a DB pin going stale, which is worth catching, but it cannot catch a
 * tarball that does not match its own published hash.
 *
 * `--deep` downloads the artifact, hashes the bytes as they arrive, and
 * compares three things: the bytes' hash, the registry's own metadata, and the
 * DB pin. A disagreement between the first two is a registry-level problem and
 * is always a hard failure.
 *
 * Nothing is written to disk — the body is streamed through the hasher and
 * dropped. A size ceiling stops a hostile or broken response from filling
 * memory; the default is generous for an MCP server tarball and far below
 * anything that would hurt.
 *
 * API:
 *   parseSri(sri)                  -> { algo, b64 } | null       (pure)
 *   sriFrom(algo, digestBuffer)    -> "sha512-…"                 (pure)
 *   sriEqual(a, b)                 -> boolean                    (pure)
 *   hashStream(readable, algo, o)  -> { ok, digest, bytes }       (no network)
 *   hashUrl(url, algo, opts)       -> { ok, digest, bytes, sri }
 *   ociManifestDigest(body)        -> "sha256:…"                  (pure)
 */

const https  = require('https');
const crypto = require('crypto');

const DEFAULT_MAX_BYTES  = 64 * 1024 * 1024;   // 64MB: ~20x the largest MCP tarball
const DEFAULT_TIMEOUT_MS = 30000;
const MAX_REDIRECTS      = 3;

// "sha512-Base64==" → { algo: 'sha512', b64: 'Base64==' }
// Subresource-Integrity strings may carry several hashes and options; the first
// recognised hash wins, which is what npm itself does.
const DIGEST_BYTES = { sha256: 32, sha384: 48, sha512: 64 };

function parseSri(sri) {
  if (typeof sri !== 'string') return null;
  for (const token of sri.trim().split(/\s+/)) {
    const m = token.match(/^(sha256|sha384|sha512)-(\S+)$/);
    if (!m) continue;
    const algo = m[1].toLowerCase();
    const raw  = m[2];
    // Two spellings are in play and hex is a *subset* of the base64 alphabet,
    // so the encoding has to be decided by length, not by character class:
    // a 64-char sha256 hex digest parses as base64 into 48 bytes of nonsense.
    // npm writes base64 SRI; this repo's DB writes `sha256-<hex>` for PyPI.
    const hexLen = DIGEST_BYTES[algo] * 2;
    if (raw.length === hexLen && /^[0-9a-f]+$/i.test(raw)) {
      return { algo, b64: Buffer.from(raw, 'hex').toString('base64'), fromHex: true };
    }
    if (/^[A-Za-z0-9+/=]+$/.test(raw) && Buffer.from(raw, 'base64').length === DIGEST_BYTES[algo]) {
      return { algo, b64: raw };
    }
  }
  return null;
}

function sriFrom(algo, digestBuffer) {
  return `${algo}-${Buffer.from(digestBuffer).toString('base64')}`;
}

// Compare two integrity strings by the bytes they describe, not by spelling:
// `sha256-<hex>` and `sha256-<base64>` of the same digest are the same hash.
function sriEqual(a, b) {
  const pa = parseSri(a);
  const pb = parseSri(b);
  if (!pa || !pb || pa.algo !== pb.algo) return false;
  const ba = Buffer.from(pa.b64, 'base64');
  const bb = Buffer.from(pb.b64, 'base64');
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

/**
 * Hash a stream, refusing to buffer more than `maxBytes`.
 * Separate from the network so it can be tested with any readable.
 */
function hashStream(readable, algo = 'sha512', { maxBytes = DEFAULT_MAX_BYTES } = {}) {
  return new Promise((resolve) => {
    const hasher = crypto.createHash(algo);
    let bytes = 0;
    let done  = false;
    const finish = (result) => { if (!done) { done = true; resolve(result); } };

    readable.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        readable.destroy();
        finish({ ok: false, error: `artifact exceeds ${maxBytes} bytes`, bytes });
        return;
      }
      hasher.update(chunk);
    });
    readable.on('error', (e) => finish({ ok: false, error: e.message, bytes }));
    readable.on('end',   ()  => finish({ ok: true, digest: hasher.digest(), bytes }));
    readable.on('close', ()  => finish({ ok: false, error: 'stream closed before end', bytes }));
  });
}

/**
 * Download `url` and return the hash of its bytes.
 *
 * Redirects are followed a few times and only ever to https — an artifact
 * fetch must not be downgradeable, and `Location` comes from the server.
 */
async function hashUrl(url, algo = 'sha512', {
  maxBytes = DEFAULT_MAX_BYTES, timeoutMs = DEFAULT_TIMEOUT_MS, headers = {}, get = https.get,
} = {}) {
  let target = url;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await new Promise((resolve) => {
      let u;
      try { u = new URL(target); } catch { resolve({ error: 'bad url' }); return; }
      if (u.protocol !== 'https:') { resolve({ error: 'refusing a non-https artifact url' }); return; }
      const req = get(target, { headers }, (r) => resolve({ stream: r, status: r.statusCode, headers: r.headers }));
      req.on('error', (e) => resolve({ error: e.message }));
      req.setTimeout(timeoutMs, () => { req.destroy(); resolve({ error: `timeout after ${timeoutMs}ms` }); });
    });

    if (res.error) return { ok: false, error: res.error };

    if (res.status >= 300 && res.status < 400 && res.headers.location) {
      res.stream.resume();                                  // drain the redirect body
      target = new URL(res.headers.location, target).toString();
      continue;
    }
    if (res.status !== 200) {
      res.stream.resume();
      return { ok: false, error: `HTTP ${res.status}` };
    }

    const hashed = await hashStream(res.stream, algo, { maxBytes });
    if (!hashed.ok) return hashed;
    return { ok: true, digest: hashed.digest, bytes: hashed.bytes, sri: sriFrom(algo, hashed.digest), url: target };
  }

  return { ok: false, error: `more than ${MAX_REDIRECTS} redirects` };
}

/**
 * A container image digest is the sha256 of the manifest document's bytes, so
 * the digest can be verified by hashing what the registry serves — no layers
 * need downloading.
 */
function ociManifestDigest(body) {
  return `sha256:${crypto.createHash('sha256').update(body).digest('hex')}`;
}

module.exports = {
  DIGEST_BYTES,
  parseSri, sriFrom, sriEqual, hashStream, hashUrl, ociManifestDigest,
  DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_MS,
};
