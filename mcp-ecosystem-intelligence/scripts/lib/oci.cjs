'use strict';
/**
 * OCI Distribution client: image references, anonymous bearer auth, manifests.
 *
 * Extracted from check_docker_drift.cjs because two callers need it now — the
 * drift prober compares the digest a tag currently serves, and
 * `verify_integrity --deep` verifies a pinned digest by hashing the manifest
 * bytes the registry serves (a digest *is* the sha256 of that document, so no
 * layers need downloading).
 *
 * Registry flow (OCI Distribution Spec):
 *   1. GET https://<registry>/v2/<repo>/manifests/<ref>
 *      → 401 with WWW-Authenticate: Bearer realm=… service=… scope=…
 *   2. GET <realm>?service=…&scope=… (anonymous) → { token }
 *   3. GET …/manifests/<ref> with Authorization: Bearer <token>
 *
 * Both the registry host and the bearer realm are allowlisted. A DB entry is
 * enough to point this client at a host, the realm arrives in a response
 * header, and this runs on a self-hosted runner inside someone's network —
 * neither input gets to choose where we connect.
 *
 * API:
 *   parseImageRef(ref)                      -> { registry, repo, tag, digest }
 *   apiHostFor(registry)                    -> host to send requests to
 *   realmAllowed(realm)                     -> boolean
 *   parseBearerChallenge(header)            -> { realm, service, scope } | null
 *   fetchManifestDigest(registry, repo, ref)-> { digest } | { error }
 *   fetchManifest(registry, repo, ref)      -> { body, digest, contentType } | { error }
 */

const https = require('https');

const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
].join(', ');

function parseImageRef(ref) {
  let rest = ref;
  let digest = null;
  const at = rest.indexOf('@sha256:');
  if (at !== -1) {
    digest = rest.slice(at + 1);            // "sha256:abc…"
    rest   = rest.slice(0, at);
  }
  // Optional :tag — strip but keep for callers that want it.
  let tag = null;
  const colon = rest.lastIndexOf(':');
  const slash = rest.lastIndexOf('/');
  if (colon > slash) {                      // ":" after the last "/" → it's a tag, not a port
    tag  = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
  }
  // Split registry / repo.
  const firstSlash = rest.indexOf('/');
  let registry = 'docker.io';
  let repo     = rest;
  if (firstSlash !== -1) {
    const head = rest.slice(0, firstSlash);
    if (head.includes('.') || head.includes(':') || head === 'localhost') {
      registry = head;
      repo     = rest.slice(firstSlash + 1);
    }
  }
  // Docker Hub uses "library/<name>" for single-segment names.
  if (registry === 'docker.io' && !repo.includes('/')) repo = `library/${repo}`;
  return { registry, repo, tag, digest };
}

function httpsRequest(opts) {
  return new Promise((resolve) => {
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end',  ()  => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error',   () => resolve(null));
    req.setTimeout(15000, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

// Parse `WWW-Authenticate: Bearer realm="…",service="…",scope="…"`.
function parseBearerChallenge(header) {
  if (!header || !/^Bearer\s/i.test(header)) return null;
  const out = {};
  for (const m of header.matchAll(/(\w+)="([^"]+)"/g)) out[m[1]] = m[2];
  return out;
}

async function fetchToken(challenge) {
  // The realm arrives in a response header: treat it as untrusted input and
  // refuse to follow it off the allowlisted registries.
  if (!realmAllowed(challenge.realm)) return null;
  const u = new URL(challenge.realm);
  if (challenge.service) u.searchParams.set('service', challenge.service);
  if (challenge.scope)   u.searchParams.set('scope',   challenge.scope);
  const res = await httpsRequest({
    hostname: u.hostname,
    path:     u.pathname + u.search,
    method:   'GET',
    headers:  { 'Accept': 'application/json' },
  });
  if (!res || res.status !== 200) return null;
  try {
    const j = JSON.parse(res.body);
    return j.token || j.access_token || null;
  } catch { return null; }
}

// `docker.io` is a namespace, not an API host: https://docker.io/v2/... answers
// 302 pointing at www.docker.com — the marketing site — which the prober
// reported as "probe HTTP 302" and turned into a permanent ERROR for every
// Docker Hub entry. Note this is NOT a follow-the-redirect fix: the redirect
// target isn't a registry at all. Docker Hub's OCI API lives on
// registry-1.docker.io, which answers the expected 401 + bearer challenge.
const REGISTRY_API_HOST = {
  'docker.io':       'registry-1.docker.io',
  'index.docker.io': 'registry-1.docker.io',
};

// The "Supported registries" list in this file's header, enforced rather than
// documented. A DB entry is enough to point this prober at an arbitrary host:
// `docker run internal.corp:5000/x@sha256:…` would have it open connections
// into whatever network the runner sits in (ours is a self-hosted box on a
// home LAN). Anything outside the list is an ERROR a human resolves — either
// the entry is wrong or the registry belongs on this list.
const ALLOWED_REGISTRIES = new Set([
  'docker.io',
  'index.docker.io',
  'registry-1.docker.io',
  'ghcr.io',
  'quay.io',
  'mcr.microsoft.com',
]);

// Bearer realms live on the registry's own domain (auth.docker.io for Hub,
// ghcr.io/token, quay.io/v2/auth, mcr.microsoft.com/oauth2/token).
function realmAllowed(realm) {
  let u;
  try { u = new URL(realm); } catch { return false; }
  if (u.protocol !== 'https:') return false;
  return [...ALLOWED_REGISTRIES].some((h) => u.hostname === h || u.hostname.endsWith(`.${h}`));
}

// Keep the namespace for display/DB purposes; only requests get rewritten.
function apiHostFor(registry) {
  return REGISTRY_API_HOST[registry] || registry;
}

async function fetchManifestDigest(registry, repo, tag) {
  const reqPath = `/v2/${repo}/manifests/${encodeURIComponent(tag)}`;
  const host    = apiHostFor(registry);

  // Probe — registries reply 401 here with the bearer challenge.
  const probe = await httpsRequest({
    hostname: host,
    path:     reqPath,
    method:   'HEAD',
    headers:  { 'Accept': MANIFEST_ACCEPT },
  });
  if (!probe) return { error: 'network error during probe' };

  let token = null;
  if (probe.status === 401) {
    const challenge = parseBearerChallenge(probe.headers['www-authenticate']);
    if (!challenge || !challenge.realm) return { error: 'no bearer challenge in 401' };
    token = await fetchToken(challenge);
    if (!token) return { error: 'failed to obtain anonymous bearer token' };
  } else if (probe.status === 200 && probe.headers['docker-content-digest']) {
    return { digest: probe.headers['docker-content-digest'] };
  } else if (probe.status !== 200) {
    return { error: `probe HTTP ${probe.status}` };
  }

  const res = await httpsRequest({
    hostname: host,
    path:     reqPath,
    method:   'HEAD',
    headers:  {
      'Accept':        MANIFEST_ACCEPT,
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    },
  });
  if (!res)              return { error: 'network error during authed fetch' };
  if (res.status === 404) return { error: 'tag not found in registry' };
  if (res.status !== 200) return { error: `authed HTTP ${res.status}` };
  const d = res.headers['docker-content-digest'];
  if (!d) return { error: 'registry response missing Docker-Content-Digest header' };
  return { digest: d };
}

// Errors fail in every mode, as this file's header promises: an unreachable or
// unexpected registry means the pin was never compared to anything, and
// `drifts: 0` in such a run reads as "clean" to the CI step consuming the JSON.
// Drift alone stays advisory unless --strict — upstream rebuilding a tag is
// routine, and the workflow has its own explicit "fail if drift" step.

/**
 * Like fetchManifestDigest, but returns the manifest document itself.
 *
 * `ref` may be a tag or a `sha256:…` digest. The returned `computed` digest is
 * the sha256 of the bytes we received, which is what a pinned digest asserts —
 * so a caller can verify the pin without trusting the Docker-Content-Digest
 * header the registry sends.
 */
async function fetchManifest(registry, repo, ref) {
  const host    = apiHostFor(registry);
  const reqPath = `/v2/${repo}/manifests/${encodeURIComponent(ref)}`;

  const probe = await httpsRequest({
    hostname: host, path: reqPath, method: 'GET',
    headers: { 'Accept': MANIFEST_ACCEPT },
  });
  if (!probe) return { error: 'network error during probe' };

  let res = probe;
  if (probe.status === 401) {
    const challenge = parseBearerChallenge(probe.headers['www-authenticate']);
    if (!challenge || !challenge.realm) return { error: 'no bearer challenge in 401' };
    const token = await fetchToken(challenge);
    if (!token) return { error: 'failed to obtain anonymous bearer token' };
    res = await httpsRequest({
      hostname: host, path: reqPath, method: 'GET',
      headers: { 'Accept': MANIFEST_ACCEPT, 'Authorization': `Bearer ${token}` },
    });
    if (!res) return { error: 'network error during authed fetch' };
  }

  if (res.status === 404) return { error: 'manifest not found in registry' };
  if (res.status !== 200) return { error: `manifest HTTP ${res.status}` };
  return {
    body:        res.body,
    headerDigest: res.headers['docker-content-digest'] || null,
    contentType: res.headers['content-type'] || null,
  };
}

module.exports = {
  parseImageRef,
  apiHostFor,
  realmAllowed,
  parseBearerChallenge,
  fetchManifestDigest,
  fetchManifest,
  httpsRequest,
  REGISTRY_API_HOST,
  ALLOWED_REGISTRIES,
  MANIFEST_ACCEPT,
};
