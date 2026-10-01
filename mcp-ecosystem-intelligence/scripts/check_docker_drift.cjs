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
 * Exit codes (a Decision per entry, docs/adr/0001 — mode observe; a registry
 * that could not be read fails closed, so this command asks with
 * --fail-unverified always on):
 *   0  all pins match upstream (or --strict not set and only drifts found)
 *   1  --strict + at least one drift, or a hard error during fetch (any mode —
 *      a registry we couldn't read is not a registry that agrees with us), or
 *      --write + a drift that could not be applied (malformed or unsupported
 *      upstream digest, pin missing from install_cmd) — the old pin is still
 *      there and nobody was told
 *   2  bad arguments
 */

'use strict';

const fs    = require('fs');
const path  = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { dockerImageRef, ociIntegrity } = require('./lib/install_cmd.cjs');
const { writeDb } = require('./lib/db_io.cjs');
const { readWallClock } = require('./lib/clock.cjs');
const { subject, finding } = require('./lib/finding.cjs');
const { subjectForTool } = require('./lib/findings_from.cjs');
const { commandPolicy, decideRun, unanswered } = require('./lib/run_decision.cjs');
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
/**
 * `1` is "there is a finding"; `2` is "the question was not answered".
 *
 * Every registry error used to be a `1`, including the case where *nothing*
 * could be read — so a total outage reported the same code as a real drift,
 * and a reader of the exit status could not tell "your pins moved" from "we
 * could not reach a registry".
 */
/**
 * The run as findings, decided (docs/adr/0001). Each list holds
 * `{ subject, message }`:
 *
 *   drifts     the tag moved: medium (warn — fails under --strict). Under
 *              --write a moved pin is a diff to review, not a failure, so
 *              the caller passes the drifts it could not write as `unapplied`
 *   unapplied  --write found a drift and could not move the pin: high. It
 *              used to be swallowed with the rest of the drift count, so the
 *              job exited 0, the stale pin stayed, and the workflow (which
 *              opens a PR only when something was updated) did nothing
 *   errors     a registry that could not be read: not-run, which fails
 *              closed (this command's policy has fail_unverified on) — a
 *              registry we couldn't read is not a registry that agrees with
 *              us; when every checked entry errored and nothing drifted,
 *              scope/unanswered (2): nothing was compared at all
 */
function driftDecision({ drifts = [], errors = [], unapplied = [], checked = null, strict = false, asOf = 0 } = {}) {
  const nothing = errors.length > 0 && checked !== null && drifts.length === 0 && errors.length >= checked;
  const findings = [
    ...drifts.map((x) => finding({ rule: 'drift/docker-digest', subject: x.subject, scope: 'docker-drift', severity: 'medium', message: x.message })),
    ...unapplied.map((x) => finding({ rule: 'drift/docker-unapplied', subject: x.subject, scope: 'docker-drift', severity: 'high', message: x.message })),
    ...errors.map((x) => (nothing
      ? unanswered({ subject: x.subject, scope: 'docker-drift', message: x.message })
      : finding({ rule: 'drift/registry-error', subject: x.subject, scope: 'docker-drift', severity: 'medium', state: 'not-run', message: x.message }))),
  ];
  return decideRun({
    findings, subjects: [...drifts, ...unapplied, ...errors].map((x) => x.subject),
    mode: 'observe', scope: 'docker-drift', asOf, policy: commandPolicy({ strict, failUnverified: true }),
  });
}

/**
 * The exit code for counts alone — driftDecision over placeholder subjects,
 * so the counts and the run are judged by the same rows. Nothing here ages,
 * so the instant is immaterial and defaults to the epoch.
 */
function driftExitCode({ drifts = 0, errors = 0, unapplied = 0, checked = null, strict = false } = {}) {
  const n = (k, count) => Array.from({ length: count }, (_, i) => ({ subject: subject.artifact({ entry: `${k}-${i + 1}` }), message: k }));
  return driftDecision({ drifts: n('drift', drifts), errors: n('error', errors), unapplied: n('unapplied', unapplied), checked, strict }).exit;
}

/**
 * Move one docker entry from `pinned` to `upstream`, in place. Both copies of
 * the digest move: install_cmd, and pkg_integrity in its canonical spelling.
 * Returns false (and leaves the entry untouched) when install_cmd does not
 * contain `pinned` or `upstream` is not a sha256 digest.
 */
function applyDriftUpdate(tool, pinned, upstream) {
  const integrity = ociIntegrity(upstream);
  if (!integrity || typeof tool.install_cmd !== 'string' || !tool.install_cmd.includes(pinned)) return false;
  tool.install_cmd = tool.install_cmd.replace(pinned, upstream);
  tool.pkg_integrity = integrity;
  return true;
}

/**
 * Apply --write to every drifted item. Returns { updated, unapplied }: the
 * pins that moved, and the drifts that could not be moved (with a reason).
 * An unapplied drift is not a quiet no-op — the caller reports it and fails.
 */
function writeDrifts(drifts) {
  const updated = [];
  const unapplied = [];
  for (const item of drifts) {
    const tool = item._tool;
    if (!applyDriftUpdate(tool, item.pinned, item.upstream)) {
      unapplied.push({
        name: tool.name,
        repo: item.repo,
        tag: item.tag,
        pinned: item.pinned,
        upstream: item.upstream,
        reason: ociIntegrity(item.upstream)
          ? 'pinned digest not found in install_cmd'
          : 'upstream digest is malformed or not sha256',
      });
      continue;
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
  return { updated, unapplied };
}

// ── main ───────────────────────────────────────────────────────────────────

async function main() {
  const db    = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  const items = [];

  for (const tool of db.tools) {
    if (!/^docker\s+run/.test(tool.install_cmd)) continue;
    const ref = dockerImageRef(tool.install_cmd);
    if (!ref) { items.push({ name: tool.name, status: 'SKIP', reason: 'cannot parse image reference', _tool: tool }); continue; }

    const parsed = parseImageRef(ref);
    if (!ALLOWED_REGISTRIES.has(parsed.registry)) {
      items.push({
        name: tool.name, status: 'ERROR',
        registry: parsed.registry, repo: parsed.repo, tag: tool.tracked_tag || 'latest',
        reason: `registry "${parsed.registry}" is not in the supported allowlist`,
        _tool: tool,
      });
      continue;
    }
    if (!parsed.digest) {
      items.push({ name: tool.name, status: 'SKIP', reason: 'image not pinned by digest (verify_integrity flags this)', _tool: tool });
      continue;
    }

    const trackedTag = tool.tracked_tag || 'latest';
    const result     = await fetchManifestDigest(parsed.registry, parsed.repo, trackedTag);

    if (result.error) {
      items.push({
        name: tool.name, status: 'ERROR',
        registry: parsed.registry, repo: parsed.repo, tag: trackedTag,
        reason: result.error,
        _tool: tool,
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
  // contradicts itself. pkg_integrity is rewritten unconditionally, in the
  // canonical `sha256-<hex>` form: it used to move only when it was already
  // spelled `sha256-…`, so an entry stored as `sha256:…` kept the old digest
  // while its install_cmd moved on (PR #106, terraform-mcp-server).
  let updated = [];
  let unapplied = [];
  if (WRITE && drifts.length) {
    ({ updated, unapplied } = writeDrifts(drifts));
    if (updated.length) writeDb(DB_PATH, db);
  }

  // The verdict is a Decision. With --write the drift has been turned into a
  // diff, so it is no longer a failure — the review is the gate. A drift
  // --write could NOT turn into a diff still fails, and so do errors: an
  // unreachable registry means nothing was compared.
  const subj = (name) => {
    const it = items.find((i) => i.name === name);
    return subjectForTool((it && it._tool) || { name });
  };
  const run = driftDecision({
    drifts: WRITE ? [] : drifts.map((i) => ({ subject: subj(i.name), message: `${i.repo}:${i.tag} moved: pinned ${i.pinned}, upstream ${i.upstream}` })),
    unapplied: unapplied.map((u) => ({ subject: subj(u.name), message: `${u.repo}:${u.tag}: ${u.reason} — the old pin is still in the DB` })),
    errors: errors.map((i) => ({ subject: subj(i.name), message: `${i.registry}/${i.repo}:${i.tag} — ${i.reason}` })),
    checked: items.length,
    strict: STRICT,
    // When this run looked; the decision is made at the same instant.
    asOf: readWallClock(),
  });

  if (AS_JSON) {
    process.stdout.write(JSON.stringify({
      schema: 'mcp-vault/docker-drift@1',
      checked: items.length, drifts: drifts.length, errors: errors.length,
      updated,
      unapplied,
      items: items.map(({ _tool, ...rest }) => rest),
      // Additive (mcp-vault/findings@1): each entry's Decision.
      findings: run.document,
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
    }
    if (unapplied.length) {
      console.log(`\nUNAPPLIED ${unapplied.length} drift(s) — the old pin is still in the DB:`);
      for (const u of unapplied) {
        console.log(`  ${u.name}: ${u.reason} (upstream: ${JSON.stringify(u.upstream)})`);
      }
    }
    if (!WRITE && drifts.length) {
      console.log('Refresh with: node scripts/check_docker_drift.cjs --write (then review the diff).');
    }
  }

  exitAfterFlush(run.exit);
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
  driftDecision,
  applyDriftUpdate,
  writeDrifts,
  REGISTRY_API_HOST,
  ALLOWED_REGISTRIES,
};
