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
 *   node scripts/check_docker_drift.cjs --write   update the drifted pins in the DB
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
const { writeDb } = require('./lib/db_io.cjs');
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
// --write: move the pins to the digests upstream currently serves, so the
// change can be reviewed as a diff. A red CI job says "something moved"; a
// diff says what moved, from what, to what.
const WRITE   = argv.includes('--write');


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
      source_url: tool.source_url || null,
      _tool: tool,
    });
  }

  const drifts = items.filter(i => i.status === 'DRIFT');
  const errors = items.filter(i => i.status === 'ERROR');

  // --write moves each drifted pin to the digest upstream serves now. The DB
  // keeps the digest in two places for docker entries — inside install_cmd and
  // in pkg_integrity — and both have to move together or the next verify run
  // contradicts itself.
  const updated = [];
  if (WRITE && drifts.length) {
    for (const item of drifts) {
      const tool = item._tool;
      const before = tool.install_cmd;
      tool.install_cmd = before.replace(item.pinned, item.upstream);
      if (tool.install_cmd === before) continue;            // nothing replaced: leave it alone
      if (typeof tool.pkg_integrity === 'string' && tool.pkg_integrity.startsWith('sha256-')) {
        tool.pkg_integrity = `sha256-${item.upstream.replace(/^sha256:/, '')}`;
      }
      updated.push({
        name: tool.name,
        repo: item.repo,
        tag: item.tag,
        from: item.pinned,
        to: item.upstream,
        // Where a human should look to judge the change.
        review: item.source_url ? `${item.source_url.replace(/\/$/, '')}/releases` : null,
      });
    }
    if (updated.length) writeDb(DB_PATH, db);
  }

  if (AS_JSON) {
    process.stdout.write(JSON.stringify({
      schema: 'mcp-vault/docker-drift@1',
      checked: items.length, drifts: drifts.length, errors: errors.length,
      updated,
      items: items.map(({ _tool, ...rest }) => rest),
    }, null, 2) + '\n');
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
    if (updated.length) {
      console.log(`\nUpdated ${updated.length} pin(s) in ${DB_PATH}:`);
      for (const u of updated) {
        console.log(`  ${u.name}: ${u.from.slice(0, 19)}… → ${u.to.slice(0, 19)}…`);
        if (u.review) console.log(`    review: ${u.review}`);
      }
      console.log('\nReview the diff before merging: a rebuilt tag is routine, a hijack looks identical from here.');
    } else if (drifts.length) {
      console.log('Refresh with: node scripts/check_docker_drift.cjs --write (then review the diff).');
    }
  }

  // With --write the drift has been turned into a diff, so it is no longer a
  // failure — the review is the gate. Errors still fail: an unreachable
  // registry means nothing was compared.
  exitAfterFlush(driftExitCode({
    drifts: WRITE ? 0 : drifts.length,
    errors: errors.length,
    strict: STRICT,
  }));
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
