'use strict';
/**
 * lib/clock.cjs, and the rule it exists for: nothing that decides may pick
 * the time on its own.
 */
const { test } = require('node:test');
const assert   = require('node:assert/strict');

const S = '../mcp-ecosystem-intelligence/scripts';
const clock = require(`${S}/lib/clock.cjs`);

test('parseAsOf: a bare date is midnight UTC; an instant needs a zone', () => {
  assert.equal(clock.parseAsOf('2026-09-24'), Date.parse('2026-09-24T00:00:00Z'));
  assert.equal(clock.parseAsOf('2026-09-24T10:30:00Z'), Date.parse('2026-09-24T10:30:00Z'));
  assert.equal(clock.parseAsOf('2026-09-24T10:30:00.123+03:00'), Date.parse('2026-09-24T07:30:00.123Z'));
  // Without a zone the same text is a different moment on every machine.
  assert.throws(() => clock.parseAsOf('2026-09-24T10:30:00'), RangeError);
  // A date that does not exist is a typo, not a request for the day after.
  assert.throws(() => clock.parseAsOf('2026-02-30'), /not a calendar date/);
  for (const bad of ['', 'yesterday', '24.09.2026', '2026-9-24', null, undefined]) {
    assert.throws(() => clock.parseAsOf(bad), RangeError, String(bad));
  }
});

test('asOfFromArgv: --as-of wins, both spellings; absent means the wall clock', () => {
  assert.deepEqual(clock.asOfFromArgv(['--as-of', '2026-09-24']),
    { asOf: Date.parse('2026-09-24T00:00:00Z'), source: 'as-of', iso: '2026-09-24T00:00:00.000Z' });
  assert.equal(clock.asOfFromArgv(['--json', '--as-of=2026-09-24T12:00:00Z']).iso, '2026-09-24T12:00:00.000Z');
  const now = clock.asOfFromArgv(['--json']);
  assert.equal(now.source, 'wall-clock');
  assert.ok(Number.isFinite(now.asOf));
  // A usage error is returned, not thrown, so each command keeps its exit 2.
  assert.match(clock.asOfFromArgv(['--as-of']).error, /needs a date/);
  assert.match(clock.asOfFromArgv(['--as-of', '--json']).error, /needs a date/);
  assert.match(clock.asOfFromArgv(['--as-of', 'soon']).error, /expected YYYY-MM-DD/);
  assert.deepEqual(clock.stripAsOf(['a', '--as-of', 'x', '--as-of=y', 'b']), ['a', 'b']);
});

test('requireAsOf: a missing instant is a pointed error, not a quiet Date.now()', () => {
  assert.equal(clock.requireAsOf(5, 'f'), 5);
  assert.equal(clock.requireAsOf(new Date(7), 'f'), 7);
  assert.throws(() => clock.requireAsOf(undefined, 'trustScore'), (e) => e instanceof TypeError
    && /trustScore: asOf is required/.test(e.message) && /CLI entry point/.test(e.message));
  assert.throws(() => clock.requireAsOf('2026-09-24', 'f'), TypeError);
  assert.throws(() => clock.requireAsOf(NaN, 'f'), TypeError);
});

test('every library function that judges time refuses to guess it', async () => {
  const ev  = require(`${S}/lib/evidence.cjs`);
  const sc  = require(`${S}/lib/scores.cjs`);
  const ti  = require(`${S}/lib/tiers.cjs`);
  const sig = require(`${S}/lib/npm_signatures.cjs`);
  const rep = require(`${S}/lib/report.cjs`);
  const lf  = require(`${S}/lib/lockfile.cjs`);
  const fi  = require(`${S}/lib/finding.cjs`);
  const pr  = require(`${S}/lib/policy_rules.cjs`);
  const orch = require(`${S}/orchestrate.cjs`);
  const drift = require(`${S}/check_license_drift.cjs`);
  const evidence = { artifact_id: 'npm:p@1', dimensions: { artifact: { status: 'verified', checked_at: '2026-09-17' } } };
  const tool = { name: 'p', install_cmd: 'npx -y p@1', version: '1', trust_evidence: evidence };
  const cases = {
    buildEvidence:    () => ev.buildEvidence({}, {}),
    smokeEvidence:    () => ev.smokeEvidence({ status: 'pass' }),
    staleDimensions:  () => ev.staleDimensions(evidence),
    deriveTrust:      () => ev.deriveTrust(evidence),
    trustScore:       () => sc.trustScore(evidence),
    classifyEntry:    () => ti.classifyEntry(tool, null),
    verifyRegistrySignature: () => sig.verifyRegistrySignature({ name: 'p', version: '1', integrity: 'sha512-x', signatures: [], keys: null }),
    toJsonReport:     () => rep.toJsonReport({ results: [] }),
    lockEntry:        () => lf.lockEntry({ tool }),
    emptyLock:        () => lf.emptyLock(),
    matchDB:          () => orch.matchDB({ tools: [tool] }, { dbs: new Set(), infra: new Set() }, null),
    decide:           () => fi.decide([], pr.effectivePolicy(null)),
    findingsDocument: () => fi.findingsDocument({}),
  };
  for (const [name, fn] of Object.entries(cases)) {
    assert.throws(fn, (e) => e instanceof TypeError && /asOf is required/.test(e.message), `${name} accepted a missing asOf`);
  }
  await assert.rejects(drift.runDriftCheck({ tools: [] }, { fetcher: async () => ({}), noFetch: true }), /asOf is required/);
});
