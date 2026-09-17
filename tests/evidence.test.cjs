'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const ev = require('../mcp-ecosystem-intelligence/scripts/lib/evidence.cjs');

const NOW = Date.parse('2026-09-17T12:00:00Z');
const entry = (findings, extra = {}) => ({
  name: 'e', status: 'OK', integrity: 'sha512-x',
  findings: findings.map(([tag, message]) => ({ tag, message, level: 'note', rule: 'x' })),
  ...extra,
});

test('buildEvidence: records only the checks that ran', () => {
  // A check that did not run must be absent, not "fine". This is the property
  // that lets a later run fill it in without overwriting a real answer — and
  // the one that was broken while evidence was derived from report prose.
  const e = ev.buildEvidence({ signature: { state: 'verified', keyid: 'SHA256:k' } }, { now: NOW, artifactId: 'npm:p@1' });
  assert.deepEqual(Object.keys(e.dimensions), ['signature']);
  assert.equal(e.dimensions.signature.status, 'verified');
  assert.equal(e.dimensions.signature.keyid, 'SHA256:k');
  assert.equal(e.dimensions.signature.checked_at, '2026-09-17');
  assert.equal(e.artifact_id, 'npm:p@1');
  // Nothing at all is an empty record, not a clean one.
  assert.deepEqual(ev.buildEvidence(null, { now: NOW }).dimensions, {});
  assert.deepEqual(ev.buildEvidence({}, { now: NOW }).dimensions, {});
});

test('buildEvidence: a digest pin on its own is not a verified artifact', () => {
  // The docker path used to report OK without fetching the manifest, and that
  // OK was recorded as artifact+source_binding+advisories verified.
  const pinOnly = ev.buildEvidence({ artifact: { state: 'unverified', method: 'digest-pin-only' } }, { now: NOW });
  assert.equal(pinOnly.dimensions.artifact.status, 'unverified');
  assert.equal(pinOnly.dimensions.artifact.method, 'digest-pin-only');
  assert.equal(pinOnly.dimensions.source_binding, undefined);
  assert.equal(pinOnly.dimensions.advisories, undefined);
});

test('buildEvidence: method distinguishes how the artifact was checked', () => {
  const deep = ev.buildEvidence({ artifact: { state: 'verified', method: 'deep-hash' } }, { now: NOW });
  assert.equal(deep.dimensions.artifact.method, 'deep-hash');
  const meta = ev.buildEvidence({ artifact: { state: 'verified', method: 'registry-metadata' } }, { now: NOW });
  assert.equal(meta.dimensions.artifact.method, 'registry-metadata');
  const offline = ev.buildEvidence({ artifact: { state: 'unverified', method: 'offline-pin-present' } }, { now: NOW });
  assert.equal(offline.dimensions.artifact.status, 'unverified');
});

test('buildEvidence: a mismatch is recorded as a mismatch', () => {
  const e = ev.buildEvidence({ artifact: { state: 'mismatch', method: 'deep-hash' } }, { now: NOW });
  assert.equal(e.dimensions.artifact.status, 'mismatch');
});

test('buildEvidence: advisory and dependency states pass through as given', () => {
  for (const state of ['clean', 'vulnerable', 'advisories-present', 'unverified']) {
    assert.equal(ev.buildEvidence({ advisories: { state } }, { now: NOW }).dimensions.advisories.status, state);
  }
  const deps = ev.buildEvidence({ dependencies: { state: 'hooks', count: 608 } }, { now: NOW });
  assert.equal(deps.dimensions.dependencies.status, 'hooks');
  assert.equal(deps.dimensions.dependencies.count, 608);
});

test('mergeEvidence: newest per dimension wins, untouched dimensions survive', () => {
  const existing = {
    artifact_id: 'npm:p@1',
    dimensions: {
      artifact:   { status: 'verified', checked_at: '2026-09-01', method: 'deep-hash' },
      advisories: { status: 'clean',    checked_at: '2026-09-01' },
      smoke:      { status: 'pass',     checked_at: '2026-08-20', tools: 5 },
    },
  };
  const fresh = { artifact_id: 'npm:p@1', dimensions: { advisories: { status: 'vulnerable', checked_at: '2026-09-17' } } };
  const merged = ev.mergeEvidence(existing, fresh);
  assert.equal(merged.dimensions.advisories.status, 'vulnerable');
  assert.equal(merged.dimensions.artifact.checked_at, '2026-09-01');  // untouched, still dated
  assert.equal(merged.dimensions.smoke.tools, 5);
});

test('mergeEvidence: evidence does not survive a version change', () => {
  // What we learned about 1.2.3 says nothing about 1.2.4.
  const old = { artifact_id: 'npm:p@1.2.3', dimensions: { artifact: { status: 'verified', checked_at: '2026-09-01' } } };
  const fresh = { artifact_id: 'npm:p@1.2.4', dimensions: { signature: { status: 'verified', checked_at: '2026-09-17' } } };
  const merged = ev.mergeEvidence(old, fresh);
  assert.equal(merged.artifact_id, 'npm:p@1.2.4');
  assert.equal(merged.dimensions.artifact, undefined);
  assert.equal(merged.dimensions.signature.status, 'verified');
});

test('staleDimensions: advisories perish faster than hashes', () => {
  const evidence = {
    artifact_id: 'npm:p@1',
    dimensions: {
      artifact:   { status: 'verified', checked_at: '2026-08-01' },   // 47 days
      advisories: { status: 'clean',    checked_at: '2026-09-01' },   // 16 days
    },
  };
  const stale = ev.staleDimensions(evidence, ev.DEFAULT_MAX_AGE_DAYS, NOW);
  assert.deepEqual(stale.map(s => s.dimension), ['advisories']);   // 16 > 7, 47 < 90
  assert.equal(stale[0].age_days, 16);

  // A flat number applies the same bar everywhere.
  assert.deepEqual(ev.staleDimensions(evidence, 10, NOW).map(s => s.dimension), ['artifact', 'advisories']);
  assert.deepEqual(ev.staleDimensions(evidence, 365, NOW), []);
});

test('deriveTrust: the word is computed, not typed', () => {
  const fresh = (status) => ({ artifact_id: 'npm:p@1', dimensions: { artifact: { status, checked_at: '2026-09-17' }, advisories: { status: 'clean', checked_at: '2026-09-17' } } });
  assert.equal(ev.deriveTrust(fresh('verified'), { now: NOW }), 'verified');
  assert.equal(ev.deriveTrust(fresh('unverified'), { now: NOW }), 'candidate');
  assert.equal(ev.deriveTrust(fresh('mismatch'), { now: NOW }), 'unverified');
  // Nothing recorded at all is not vetted yet.
  assert.equal(ev.deriveTrust({ dimensions: {} }, { now: NOW }), 'candidate');
  // An unrecognised status is treated as "nothing established", so adding a
  // status later cannot accidentally read as a pass.
  assert.equal(ev.deriveTrust({ dimensions: { artifact: { status: 'something-new', checked_at: '2026-09-17' } } }, { now: NOW }), 'candidate');
  // A vulnerable dependency chain is "found wanting", not "not yet looked at".
  assert.equal(ev.deriveTrust({ dimensions: { artifact: { status: 'verified', checked_at: '2026-09-17' }, advisories: { status: 'vulnerable', checked_at: '2026-09-17' } } }, { now: NOW }), 'unverified');
});

test('deriveTrust: verified-eight-months-ago is not verified', () => {
  const old = { artifact_id: 'npm:p@1', dimensions: { artifact: { status: 'verified', checked_at: '2026-01-01' } } };
  assert.equal(ev.deriveTrust(old, { now: NOW }), 'candidate');
});

test('smokeEvidence: a separate stream, with its own date', () => {
  assert.deepEqual(
    ev.smokeEvidence({ status: 'pass', tool_count: 29, checked_at: '2026-09-10T00:00:00.000Z' }),
    { status: 'pass', checked_at: '2026-09-10', tools: 29, error: undefined },
  );
  assert.equal(ev.smokeEvidence({ status: 'fail', error_code: 'CRASH' }).status, 'fail');
  assert.equal(ev.smokeEvidence({ status: 'skip' }).status, 'skipped');
  assert.equal(ev.smokeEvidence(null), null);
});

test('requiredFor: what "verified" needs depends on what is checkable', () => {
  // npm and PyPI have advisory feeds keyed by package@version; an image digest
  // does not, so demanding an advisory result there would make every docker
  // entry a permanent candidate.
  assert.deepEqual(ev.requiredFor('npm'), ['artifact', 'advisories']);
  assert.deepEqual(ev.requiredFor('pypi'), ['artifact', 'advisories']);
  assert.deepEqual(ev.requiredFor('oci'), ['artifact']);
  assert.deepEqual(ev.requiredFor('git'), []);
  assert.deepEqual(ev.requiredFor(undefined), ['artifact']);
});

test('deriveTrust: an npm entry needs an advisory answer, an image does not', () => {
  const artifactOnly = { artifact_id: 'x', dimensions: { artifact: { status: 'verified', checked_at: '2026-09-17' } } };
  assert.equal(ev.deriveTrust(artifactOnly, { now: NOW, require: ev.requiredFor('oci') }), 'verified');
  assert.equal(ev.deriveTrust(artifactOnly, { now: NOW, require: ev.requiredFor('npm') }), 'candidate');
});

test('deriveTrust: nothing checkable never becomes verified', () => {
  // A git source install has no artifact to hash; having no requirements must
  // not mean having nothing to fail.
  const empty = { artifact_id: 'git:git+https://x/y', dimensions: {} };
  assert.equal(ev.deriveTrust(empty, { now: NOW, require: ev.requiredFor('git') }), 'candidate');
});

test('staleness is measured from the last confirmation, not the last look', () => {
  // An offline run records `unverified (offline-pin-present)`. That is a look,
  // not a confirmation — letting it refresh the date made stale evidence look
  // current by running a check that verifies nothing.
  const confirmed = ev.buildEvidence({ artifact: { state: 'verified', method: 'deep-hash' } }, { now: Date.parse('2026-01-01T00:00:00Z') });
  assert.equal(confirmed.dimensions.artifact.verified_at, '2026-01-01');

  const looked = ev.buildEvidence({ artifact: { state: 'unverified', method: 'offline-pin-present' } }, { now: NOW });
  assert.equal(looked.dimensions.artifact.verified_at, undefined);

  const merged = ev.mergeEvidence(
    { ...confirmed, artifact_id: 'npm:p@1' },
    { ...looked, artifact_id: 'npm:p@1' },
  );
  assert.equal(merged.dimensions.artifact.status, 'unverified');
  assert.equal(merged.dimensions.artifact.verified_at, '2026-01-01', 'the confirmation date must survive');
  // And it is that date that makes it stale.
  const stale = ev.staleDimensions(merged, ev.DEFAULT_MAX_AGE_DAYS, NOW);
  assert.deepEqual(stale.map(s => s.dimension), ['artifact']);
});

test('a confirmed vulnerability is not softened by another feed being down', () => {
  // Reporting 'unverified' first meant a known-vulnerable version lost its
  // blocking status the moment any other feed stumbled.
  const e = ev.buildEvidence({ advisories: { state: 'vulnerable', complete: false } }, { now: NOW });
  assert.equal(e.dimensions.advisories.status, 'vulnerable');
  assert.equal(ev.deriveTrust({ artifact_id: 'x', dimensions: { artifact: { status: 'verified', checked_at: '2026-09-17', verified_at: '2026-09-17' }, ...e.dimensions } }, { now: NOW }), 'unverified');
});


test('mergeEvidence: unidentified history does not attach itself to a new artifact', () => {
  // Stored evidence with no id used to merge into whatever came next and take
  // its identity, handing the new version an advisory result nothing checked.
  const anonymous = { artifact_id: null, dimensions: { advisories: { status: 'clean', checked_at: '2026-09-17', verified_at: '2026-09-17' } } };
  const named = { artifact_id: 'npm:other@2.0.0', dimensions: { artifact: { status: 'verified', checked_at: '2026-09-17', verified_at: '2026-09-17' } } };
  const merged = ev.mergeEvidence(anonymous, named);
  assert.equal(merged.artifact_id, 'npm:other@2.0.0');
  assert.equal(merged.dimensions.advisories, undefined, 'the unidentified advisory result must not transfer');
  assert.equal(ev.deriveTrust(merged, { now: NOW, require: ev.requiredFor('npm') }), 'candidate');
});

test('mergeEvidence: a record written before verified_at existed keeps its date', () => {
  // Legacy shape: positive status, only checked_at.
  const legacy = { artifact_id: 'npm:p@1', dimensions: { artifact: { status: 'verified', checked_at: '2024-01-01' } } };
  const looked = { artifact_id: 'npm:p@1', dimensions: { artifact: { status: 'unverified', checked_at: '2026-09-17', method: 'offline-pin-present' } } };
  const merged = ev.mergeEvidence(legacy, looked);
  assert.equal(merged.dimensions.artifact.verified_at, '2024-01-01');
  const stale = ev.staleDimensions(merged, ev.DEFAULT_MAX_AGE_DAYS, NOW);
  assert.deepEqual(stale.map(s => s.dimension), ['artifact'], 'a 2024 confirmation is not current in 2026');
});

test('mergeEvidence: inheriting requires a positive identity match', () => {
  // Earlier this treated a missing id as "probably the same entry", which let
  // unidentified evidence attach itself to whatever was merged next. Nothing
  // inherits without both sides naming the same artifact.
  const stored = { artifact_id: 'npm:p@1', dimensions: { artifact: { status: 'verified', checked_at: '2026-09-17', verified_at: '2026-09-17' } } };

  const same = ev.mergeEvidence(stored, { artifact_id: 'npm:p@1', dimensions: { smoke: { status: 'pass', checked_at: '2026-09-17' } } });
  assert.equal(same.dimensions.artifact.status, 'verified');
  assert.equal(same.dimensions.smoke.status, 'pass');

  const different = ev.mergeEvidence(stored, { artifact_id: 'npm:p@2', dimensions: { smoke: { status: 'pass', checked_at: '2026-09-17' } } });
  assert.equal(different.dimensions.artifact, undefined);

  const unnamed = ev.mergeEvidence(stored, { artifact_id: null, dimensions: { smoke: { status: 'pass', checked_at: '2026-09-17' } } });
  assert.equal(unnamed.dimensions.artifact, undefined, 'an unnamed run cannot claim the stored evidence');

  // Two unidentified records belong to the same entry the caller is holding.
  const bothUnnamed = ev.mergeEvidence(
    { artifact_id: null, dimensions: { smoke: { status: 'pass', checked_at: '2026-09-01' } } },
    { artifact_id: null, dimensions: { artifact: { status: 'unverified', checked_at: '2026-09-17' } } },
  );
  assert.equal(bothUnnamed.dimensions.smoke.status, 'pass');
});
