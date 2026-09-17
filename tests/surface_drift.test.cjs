'use strict';
/**
 * Attributing a tool-surface change to an artifact — or admitting it cannot be.
 *
 * The comparison this feature exists for is "the surface changed and the
 * artifact did not". Getting that wrong in the *safe* direction (reporting
 * "artifact changed too") hides the finding completely, which is what happened:
 * the previous version compared `launched.install_cmd` strings and treated a
 * missing field as a difference, while the weekly job's snapshot did not carry
 * that field at all. Every drift therefore looked explained by a version bump.
 *
 * So `artifact_changed` has three values, and `null` is not falsy-equivalent to
 * `false` anywhere that matters.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const e = require('../mcp-ecosystem-intelligence/scripts/mcp_eval.cjs');
const { fingerprintTools } = require('../mcp-ecosystem-intelligence/scripts/lib/surface.cjs');

const tool = (over = {}) => ({
  name: 'x', install_cmd: 'npx -y pkg@1.0.0', version: '1.0.0', pkg_integrity: 'sha512-AAA', ...over,
});
const parsed = { command: 'npx', args: ['-y', 'pkg@1.0.0'] };

const surfaceA = fingerprintTools([{ name: 'read', description: 'Read', inputSchema: { type: 'object' } }]);
const surfaceB = fingerprintTools([{ name: 'read', description: 'Read, and also exfiltrate', inputSchema: { type: 'object' } }]);

const run = (identity, surface, checked_at = '2026-09-01') => ({ name: 'x', identity, surface, checked_at });

test('identity is fields, not a command string', () => {
  const id = e.artifactIdentity(tool(), parsed);
  assert.equal(id.artifact_id, 'npm:pkg@1.0.0');
  assert.equal(id.artifact_integrity, 'sha512-AAA');
  assert.equal(id.db_version, '1.0.0');
  assert.match(id.launch_digest, /^[a-f0-9]{32}$/);

  // Reformatting the command does not change the artifact…
  const reformatted = e.artifactIdentity(tool({ install_cmd: 'npx  -y   pkg@1.0.0' }), parsed);
  assert.equal(reformatted.artifact_id, id.artifact_id);
  assert.equal(reformatted.launch_digest, id.launch_digest, 'the digest is over the parsed contract, not the prose');
  // …but changing what is launched does.
  const other = e.artifactIdentity(tool(), { command: 'npx', args: ['-y', 'pkg@1.0.0', '--all-tools'] });
  assert.notEqual(other.launch_digest, id.launch_digest);
});

test('artifactChangedBetween: yes, no, and cannot tell', () => {
  const id = e.artifactIdentity(tool(), parsed);

  assert.equal(e.artifactChangedBetween({ identity: id }, { identity: id }), false);
  assert.equal(e.artifactChangedBetween({ identity: { ...id, db_version: '0.9.0' } }, { identity: id }), true);
  assert.equal(e.artifactChangedBetween({ identity: { ...id, artifact_integrity: 'sha512-DIFFERENT' } }, { identity: id }), true);

  // The case that broke the feature: a snapshot with no identity recorded.
  assert.equal(e.artifactChangedBetween({}, { identity: id }), null);
  assert.equal(e.artifactChangedBetween({ identity: id }, {}), null);
  assert.equal(e.artifactChangedBetween(null, null), null);
  // Fields present on one side only say nothing about themselves.
  assert.equal(e.artifactChangedBetween({ identity: { artifact_id: null, db_version: null, artifact_integrity: null, launch_digest: null } }, { identity: id }), null);
});

test('an unchanged surface is not a drift at all', () => {
  const id = e.artifactIdentity(tool(), parsed);
  assert.equal(e.surfaceDrift(run(id, surfaceA), run(id, surfaceA)), null);
});

test('the same artifact with a different surface is reported as unexplained', () => {
  const id = e.artifactIdentity(tool(), parsed);
  const d = e.surfaceDrift(run(id, surfaceA), run(id, surfaceB));
  assert.equal(d.artifact_changed, false);
  assert.equal(d.artifact_comparison, 'compared');
  assert.deepEqual(d.changed, [{ name: 'read', fields: ['description'] }]);
  assert.equal(d.previous_sha256, surfaceA.sha256);
  assert.equal(d.sha256, surfaceB.sha256);
});

test('an upgrade that changes the surface is attributed to the upgrade', () => {
  const before = e.artifactIdentity(tool({ version: '1.0.0' }), parsed);
  const after  = e.artifactIdentity(tool({ version: '2.0.0', install_cmd: 'npx -y pkg@2.0.0' }), { command: 'npx', args: ['-y', 'pkg@2.0.0'] });
  const d = e.surfaceDrift(run(before, surfaceA), run(after, surfaceB));
  assert.equal(d.artifact_changed, true);
});

test('a snapshot with no identity says so instead of blaming a version bump', () => {
  const id = e.artifactIdentity(tool(), parsed);
  // Exactly what the weekly job used to write: surface, no identity.
  const d = e.surfaceDrift({ name: 'x', surface: surfaceA, checked_at: '2026-09-01' }, run(id, surfaceB));
  assert.equal(d.artifact_changed, null);
  assert.equal(d.artifact_comparison, 'not-recorded');
  // And a caller counting "unexplained" must not pick this up, which is why
  // the comparison in mcp_eval is `=== false` rather than `!`.
  assert.notEqual(d.artifact_changed, false);
});

test('both identities travel with the finding, so a reader can see what moved', () => {
  const before = e.artifactIdentity(tool({ version: '1.0.0' }), parsed);
  const after  = e.artifactIdentity(tool({ version: '1.0.1', install_cmd: 'npx -y pkg@1.0.1' }), { command: 'npx', args: ['-y', 'pkg@1.0.1'] });
  const d = e.surfaceDrift(run(before, surfaceA), run(after, surfaceB));
  assert.equal(d.previous_identity.db_version, '1.0.0');
  assert.equal(d.identity.db_version, '1.0.1');
});

test('the shipped snapshot does not carry surfaces with identities selectively', () => {
  // A snapshot written before identities existed has none, and the
  // `not-recorded` state handles that honestly. What must never happen is a
  // *mixture*: that means the writer is dropping the field for some entries,
  // and those entries' drift would be misattributed while the rest looks fine.
  const results = require('../mcp-ecosystem-intelligence/assets/eval_results.json').results;
  const withSurface = results.filter((r) => r.surface && r.surface.sha256);
  assert.ok(withSurface.length > 0, 'the snapshot should carry measured surfaces');
  const withIdentity = withSurface.filter((r) => r.identity && r.identity.artifact_id);
  assert.ok(withIdentity.length === 0 || withIdentity.length === withSurface.length,
    `${withIdentity.length} of ${withSurface.length} measured surfaces carry an identity — `
    + 'a mixture means the writer drops the field for some entries');
});

test('the CI snapshot writer keeps both surface and identity', () => {
  // Enforced against the workflow text: the field was dropped there once, and
  // the loss is invisible until a week later when the comparison is wrong.
  const fs = require('fs');
  const path = require('path');
  const yml = fs.readFileSync(path.resolve(__dirname, '../.github/workflows/security-scan.yml'), 'utf8');
  const slim = yml.slice(yml.indexOf('const slim = (r) =>'), yml.indexOf('const byName = new Map'));
  for (const field of ['surface:', 'surface_drift:', 'identity:']) {
    assert.ok(slim.includes(field), `the snapshot writer drops ${field}`);
  }
});

test('a partly-recorded identity cannot answer "unchanged"', () => {
  // The subtler half of the same rule. Comparing only the fields present on
  // both sides and answering `false` establishes "the parts I could measure
  // are unchanged" — not "the artifact is unchanged". A missing input had
  // become a value again, one level down from where it was just fixed.
  const full    = { artifact_id: 'npm:p@1.0.0', artifact_integrity: 'sha512-A', db_version: '1.0.0', launch_digest: 'abc' };
  const partial = { artifact_id: 'npm:p@1.0.0', artifact_integrity: null, db_version: '1.0.0', launch_digest: null };

  assert.equal(e.artifactChangedBetween({ identity: full }, { identity: full }), false);
  assert.equal(e.artifactChangedBetween({ identity: partial }, { identity: full }), null,
    'the integrity value and the launch contract were never compared');
  // A proven mismatch still outranks an unknown: one differing field is enough.
  assert.equal(e.artifactChangedBetween({ identity: { ...partial, db_version: '0.9.0' } }, { identity: full }), true);
});

test('which fields are relevant depends on the ecosystem', () => {
  // An OCI image has no npm integrity value and no semver version — its digest
  // *is* its identity. Demanding the npm field set everywhere would make every
  // container comparison permanently "cannot tell", which is its own
  // dishonesty: refusing to answer a question that can be answered.
  const oci = { artifact_id: 'oci:ghcr.io/o/r@sha256:aa', artifact_integrity: null, db_version: null, launch_digest: 'd1' };
  assert.deepEqual(e.relevantIdentityFields(oci), ['artifact_id', 'launch_digest']);
  assert.equal(e.artifactChangedBetween({ identity: oci }, { identity: oci }), false);
  assert.equal(
    e.artifactChangedBetween({ identity: { ...oci, artifact_id: 'oci:ghcr.io/o/r@sha256:bb' } }, { identity: oci }),
    true,
  );
  // And an entry that changed ecosystem entirely is a change, not a puzzle.
  const npm = { artifact_id: 'npm:p@1.0.0', artifact_integrity: 'sha512-A', db_version: '1.0.0', launch_digest: 'abc' };
  assert.equal(e.artifactChangedBetween({ identity: npm }, { identity: oci }), true);
});
