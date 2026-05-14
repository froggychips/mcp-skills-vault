#!/usr/bin/env node
/**
 * Detect drift between the Docker image digest pinned in
 * tools_database.json and what the registry currently serves under
 * `tracked_tag` (default "latest").
 *
 * A drift means the upstream maintainer cut a new build under the same
 * tag — the pinned digest is now stale. The DB should be refreshed to
 * the new digest *after* verifying the change is expected (security
 * scanner takes precedence over freshness).
 *
 * Registry flow (OCI Distribution Spec):
 *   1. GET https://<registry>/v2/<repo>/manifests/<tag>
 *      → 401 with WWW-Authenticate: Bearer realm=… service=… scope=…
 *   2. GET <realm>?service=…&scope=… (anonymous) → { token }
 *   3. GET …/manifests/<tag> with Authorization: Bearer <token>
 *      Accept: application/vnd.oci.image.manifest.v1+json,
 *              application/vnd.docker.distribution.manifest.v2+json,
 *              application/vnd.oci.image.index.v1+json,
 *              application/vnd.docker.distribution.manifest.list.v2+json
 *      → Docker-Content-Digest header
 *
 * Supported registries: ghcr.io, docker.io, quay.io, mcr.microsoft.com.
 *
 * Usage:
 *   node scripts/check_docker_drift.cjs           verify, exit 0 if clean
 *   node scripts/check_docker_drift.cjs --json    machine-readable
 *   node scripts/check_docker_drift.cjs --strict  exit 1 on any drift
 *
 * Exit codes:
 *   0  all pins match upstream (or --strict not set and only drifts found)
 *   1  --strict + at least one drift, or hard error during fetch
 *   2  bad arguments
 */

'use strict';

const fs    = require('fs');
const https = require('https');
const path  = require('path');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
const argv    = process.argv.slice(2);
const AS_JSON = argv.includes('--json');
const STRICT  = argv.includes('--strict');

const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
].join(', ');

// ── helpers ────────────────────────────────────────────────────────────────

// "docker run ... <image> [args]" → image reference token.
// Mirrors the parser in verify_integrity.cjs but lives here to keep this
// script self-contained.
function dockerImageRef(cmd) {
  if (!/^docker\s+run/.test(cmd)) return null;
  const tokens = cmd.split(/\s+/).slice(2);
  const FLAG_WITH_VAL = new Set(['-e', '--env', '-v', '--volume', '--cap-drop', '--cap-add',
                                  '--security-opt', '-p', '--publish', '--name', '--user',
                                  '--network', '--mount', '--tmpfs']);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith('-')) {
      if (FLAG_WITH_VAL.has(t)) i++;
      continue;
    }
    return t;
  }
  return null;
}

// "ghcr.io/owner/repo@sha256:abc" → { registry, repo, digest }
// "owner/repo:latest"             → { registry: docker.io, repo: library/.. , digest: null }
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

async function fetchManifestDigest(registry, repo, tag) {
  const reqPath = `/v2/${repo}/manifests/${encodeURIComponent(tag)}`;

  // Probe — registries reply 401 here with the bearer challenge.
  const probe = await httpsRequest({
    hostname: registry,
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
    hostname: registry,
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

// ── main ───────────────────────────────────────────────────────────────────

async function main() {
  const db    = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  const items = [];

  for (const tool of db.tools) {
    if (!/^docker\s+run/.test(tool.install_cmd)) continue;
    const ref = dockerImageRef(tool.install_cmd);
    if (!ref) { items.push({ name: tool.name, status: 'SKIP', reason: 'cannot parse image reference' }); continue; }

    const parsed = parseImageRef(ref);
    if (!parsed.digest) {
      items.push({ name: tool.name, status: 'SKIP', reason: 'image not pinned by digest (verify_integrity flags this)' });
      continue;
    }

    const trackedTag = tool.tracked_tag || 'latest';
    const result     = await fetchManifestDigest(parsed.registry, parsed.repo, trackedTag);

    if (result.error) {
      items.push({
        name: tool.name, status: 'ERROR',
        registry: parsed.registry, repo: parsed.repo, tag: trackedTag,
        reason: result.error,
      });
      continue;
    }

    const upstream = result.digest;
    const pinned   = parsed.digest;
    items.push({
      name: tool.name,
      status: upstream === pinned ? 'OK' : 'DRIFT',
      registry: parsed.registry, repo: parsed.repo, tag: trackedTag,
      pinned, upstream,
    });
  }

  const drifts = items.filter(i => i.status === 'DRIFT');
  const errors = items.filter(i => i.status === 'ERROR');

  if (AS_JSON) {
    process.stdout.write(JSON.stringify({ checked: items.length, drifts: drifts.length, errors: errors.length, items }, null, 2) + '\n');
  } else {
    for (const i of items) {
      if (i.status === 'OK')    console.log(`OK     ${i.name.padEnd(26)} ${i.repo}:${i.tag}`);
      if (i.status === 'SKIP')  console.log(`SKIP   ${i.name.padEnd(26)} ${i.reason}`);
      if (i.status === 'ERROR') console.log(`ERROR  ${i.name.padEnd(26)} ${i.registry}/${i.repo}:${i.tag} — ${i.reason}`);
      if (i.status === 'DRIFT') {
        console.log(`DRIFT  ${i.name.padEnd(26)} ${i.repo}:${i.tag}`);
        console.log(`         pinned   : ${i.pinned}`);
        console.log(`         upstream : ${i.upstream}`);
      }
    }
    console.log(`\n${items.length} docker entries checked — ${drifts.length} drift(s), ${errors.length} error(s)`);
    if (drifts.length) console.log('Refresh with: node scripts/verify_integrity.cjs --update (after reviewing the upstream change).');
  }

  if (STRICT && (drifts.length || errors.length)) process.exit(1);
  process.exit(0);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
