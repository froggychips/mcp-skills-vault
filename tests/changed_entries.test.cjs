'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');

const e = require('../mcp-ecosystem-intelligence/scripts/changed_entries.cjs');

const t = (name, install_cmd, version) => ({ name, install_cmd, version });

test('changedEntries: identical sets → nothing changed', () => {
  const a = [t('x', 'npx -y x@1.0.0', '1.0.0'), t('y', 'uvx y==2', '2')];
  assert.deepEqual(e.changedEntries(a, a), []);
});

test('changedEntries: version bump → changed', () => {
  const base = [t('x', 'npx -y x@1.0.0', '1.0.0')];
  const head = [t('x', 'npx -y x@1.1.0', '1.1.0')];
  assert.deepEqual(e.changedEntries(base, head), ['x']);
});

test('changedEntries: install_cmd rewritten at the same version → changed', () => {
  // The dangerous case: same version string, different artifact. A registry
  // swap or a hand-edited install_cmd must not slip past the smoke.
  const base = [t('x', 'npx -y x@1.0.0', '1.0.0')];
  const head = [t('x', 'docker run --rm -i evil/x@sha256:beef', '1.0.0')];
  assert.deepEqual(e.changedEntries(base, head), ['x']);
});

test('changedEntries: newly added entry → changed (never smoked before)', () => {
  const base = [t('x', 'npx -y x@1', '1')];
  const head = [t('x', 'npx -y x@1', '1'), t('new', 'npx -y new@0.1', '0.1')];
  assert.deepEqual(e.changedEntries(base, head), ['new']);
});

test('changedEntries: removed entry is not reported (nothing left to smoke)', () => {
  const base = [t('x', 'npx -y x@1', '1'), t('gone', 'npx -y gone@1', '1')];
  const head = [t('x', 'npx -y x@1', '1')];
  assert.deepEqual(e.changedEntries(base, head), []);
});

test('changedEntries: metric-only churn is ignored', () => {
  // This is the whole point of keying on [install_cmd, version]: the weekly
  // refresh rewrites stars/health_score/last_checked across ~100 entries and
  // must not queue all of them for a behavioural smoke.
  const base = [{ ...t('x', 'npx -y x@1', '1'), stars: 10, health_score: 70, last_checked: '2026-06-22' }];
  const head = [{ ...t('x', 'npx -y x@1', '1'), stars: 99, health_score: 80, last_checked: '2026-07-31' }];
  assert.deepEqual(e.changedEntries(base, head), []);
});

test('changedEntries: empty base (ref carries no DB) → everything is changed', () => {
  const head = [t('a', 'npx -y a@1', '1'), t('b', 'npx -y b@1', '1')];
  assert.deepEqual(e.changedEntries([], head), ['a', 'b']);
  assert.deepEqual(e.changedEntries(null, head), ['a', 'b']);
});

test('changedEntries: missing install_cmd/version compare as null, not as equal-by-accident', () => {
  const base = [{ name: 'x' }];
  const head = [t('x', 'npx -y x@1', '1')];
  assert.deepEqual(e.changedEntries(base, head), ['x']);
  // …and two entries that both lack the fields are genuinely unchanged.
  assert.deepEqual(e.changedEntries([{ name: 'y' }], [{ name: 'y' }]), []);
});

test('parseArgs: defaults to HEAD, accepts --base/--db/--json', () => {
  assert.equal(e.parseArgs([]).base, 'HEAD');
  assert.equal(e.parseArgs(['--base', 'abc123']).base, 'abc123');
  assert.equal(e.parseArgs(['--db', '/tmp/db.json']).db, '/tmp/db.json');
  assert.equal(e.parseArgs(['--json']).json, true);
  assert.equal(e.parseArgs(['--nope']).help, true);
});
