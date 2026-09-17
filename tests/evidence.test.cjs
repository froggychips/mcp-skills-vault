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

test('buildEvidence: records only what the run actually examined', () => {
  // A --no-audit run says nothing about advisories; writing "clean" would
  // overwrite a real answer from a run that did query the feeds.
  const e = ev.buildEvidence(entry([['SIG', 'registry signature verified (SHA256:k)']]), { now: NOW, mode: 'no-audit', artifactId: 'npm:p@1' });
  assert.equal(e.dimensions.advisories, undefined);
  assert.equal(e.dimensions.signature.status, 'verified');
  assert.equal(e.dimensions.signature.keyid, 'SHA256:k');
  assert.equal(e.dimensions.signature.checked_at, '2026-09-17');
  assert.equal(e.artifact_id, 'npm:p@1');
});

test('buildEvidence: deep hash and registry metadata are different methods', () => {
  const deep = ev.buildEvidence(entry([['DEEP', 'hashed 100 bytes locally: sha512-x']]), { now: NOW, mode: 'full' });
  assert.deepEqual(deep.dimensions.artifact, { status: 'verified', checked_at: '2026-09-17', method: 'deep-hash' });
  const shallow = ev.buildEvidence(entry([]), { now: NOW, mode: 'full' });
  assert.equal(shallow.dimensions.artifact.method, 'registry-metadata');
});

test('buildEvidence: a mismatch is recorded as a mismatch', () => {
  const e = ev.buildEvidence(entry([['FAIL', 'integrity mismatch stored: a npm: b']], { status: 'FAIL' }), { now: NOW, mode: 'full' });
  assert.equal(e.dimensions.artifact.status, 'mismatch');
});

test('buildEvidence: advisory state distinguishes clean, present and unverified', () => {
  const clean = ev.buildEvidence(entry([]), { now: NOW, mode: 'full' });
  assert.equal(clean.dimensions.advisories.status, 'clean');

  const hard = ev.buildEvidence(entry([['CVE', '[CRITICAL] (GHSA) rce']]), { now: NOW, mode: 'full' });
  assert.equal(hard.dimensions.advisories.status, 'vulnerable');

  const mild = ev.buildEvidence(entry([['CVE', '[MODERATE] (OSV) something']]), { now: NOW, mode: 'full' });
  assert.equal(mild.dimensions.advisories.status, 'advisories-present');

  const degraded = ev.buildEvidence(entry([['UNVERIFIED', 'advisory feeds unreachable: GHSA']]), { now: NOW, mode: 'full' });
  assert.equal(degraded.dimensions.advisories.status, 'unverified');
});

test('buildEvidence: dependency findings carry the tree size', () => {
  const e = ev.buildEvidence(entry([
    ['DEPS', '608 transitive packages, max depth 2'],
    ['DEPHOOK', 'install scripts in dependencies (2): a@1, b@2'],
  ]), { now: NOW, mode: 'full' });
  assert.equal(e.dimensions.dependencies.status, 'hooks');
  assert.equal(e.dimensions.dependencies.count, 608);
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
