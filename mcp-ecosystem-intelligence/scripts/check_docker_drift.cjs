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
 * The registry client (bearer auth, manifest fetch, the host and realm
 * allowlists) lives in lib/oci.cjs.
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
 *   1  --strict + at least one drift, or a hard error during fetch (any mode —
 *      a registry we couldn't read is not a registry that agrees with us)
 *   2  bad arguments
 */

'use strict';

const fs    = require('fs');
const path  = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { dockerImageRef } = require('./lib/install_cmd.cjs');
// The registry client, allowlist included, now lives in lib/oci.cjs —
// verify --deep needs the same auth dance to hash a manifest.
const {
  parseImageRef, apiHostFor, realmAllowed, parseBearerChallenge,
  fetchManifestDigest, REGISTRY_API_HOST, ALLOWED_REGISTRIES,
} = require('./lib/oci.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
const argv    = process.argv.slice(2);
const AS_JSON = argv.includes('--json');
const STRICT  = argv.includes('--strict');


// ── helpers ────────────────────────────────────────────────────────────────

// "ghcr.io/owner/repo@sha256:abc" → { registry, repo, digest }
// "owner/repo:latest"             → { registry: docker.io, repo: library/.. , digest: null }
function driftExitCode({ drifts = 0, errors = 0, strict = false } = {}) {
  if (errors > 0) return 1;
  if (strict && drifts > 0) return 1;
  return 0;
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
    if (!ALLOWED_REGISTRIES.has(parsed.registry)) {
      items.push({
        name: tool.name, status: 'ERROR',
        registry: parsed.registry, repo: parsed.repo, tag: tool.tracked_tag || 'latest',
        reason: `registry "${parsed.registry}" is not in the supported allowlist`,
      });
      continue;
    }
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

  exitAfterFlush(driftExitCode({ drifts: drifts.length, errors: errors.length, strict: STRICT }));
}

if (require.main === module) {
  main().catch((e) => { console.error(e.message); process.exit(1); });
}

module.exports = {
  dockerImageRef,
  parseImageRef,
  parseBearerChallenge,
  apiHostFor,
  realmAllowed,
  driftExitCode,
  REGISTRY_API_HOST,
  ALLOWED_REGISTRIES,
};
