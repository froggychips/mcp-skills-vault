'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');

// refresh_scores.cjs is CLI-only at runtime (it calls gh auth status on
// require if not guarded). We test only the pure helpers it exports.
const r = require('../mcp-ecosystem-intelligence/scripts/refresh_scores.cjs');

// ── normalizeLicense ───────────────────────────────────────────────────────

test('normalizeLicense: maps GitHub short SPDX → canonical -or-later', () => {
  assert.equal(r.normalizeLicense('GPL-3.0',  null), 'GPL-3.0-or-later');
  assert.equal(r.normalizeLicense('GPL-2.0',  null), 'GPL-2.0-or-later');
  assert.equal(r.normalizeLicense('LGPL-2.1', null), 'LGPL-2.1-or-later');
  assert.equal(r.normalizeLicense('LGPL-3.0', null), 'LGPL-3.0-or-later');
  assert.equal(r.normalizeLicense('AGPL-3.0', null), 'AGPL-3.0-or-later');
});

test('normalizeLicense: NOASSERTION → falls back to stored DB value', () => {
  assert.equal(r.normalizeLicense('NOASSERTION', 'MIT'),   'MIT');
  assert.equal(r.normalizeLicense('NOASSERTION', 'BSL'),   'BSL');
  assert.equal(r.normalizeLicense('NOASSERTION', null),    '');
  assert.equal(r.normalizeLicense('NOASSERTION', ''),      '');
});

test('normalizeLicense: null/undefined GitHub SPDX → falls back', () => {
  assert.equal(r.normalizeLicense(null,      'MIT'), 'MIT');
  assert.equal(r.normalizeLicense(undefined, 'MIT'), 'MIT');
  assert.equal(r.normalizeLicense('',        'MIT'), 'MIT');
  // No fallback provided → empty string.
  assert.equal(r.normalizeLicense(null, undefined), '');
});

test('normalizeLicense: unmapped SPDX passes through unchanged', () => {
  assert.equal(r.normalizeLicense('MIT',          'fallback'), 'MIT');
  assert.equal(r.normalizeLicense('Apache-2.0',   'fallback'), 'Apache-2.0');
  assert.equal(r.normalizeLicense('BSD-3-Clause', 'fallback'), 'BSD-3-Clause');
  assert.equal(r.normalizeLicense('FSL-1.1',      'fallback'), 'FSL-1.1');
});

test('GITHUB_SPDX_MAP: only covers GitHub short forms (sanity)', () => {
  // All values end with -or-later; all keys lack the -only/-or-later suffix.
  for (const [k, v] of Object.entries(r.GITHUB_SPDX_MAP)) {
    assert.ok(v.endsWith('-or-later'), `${k} → ${v} should map to -or-later`);
    assert.ok(!/-or-later$|-only$/.test(k), `${k} should not already have suffix`);
  }
});

// ── githubOwnerRepo ────────────────────────────────────────────────────────

test('githubOwnerRepo: extracts owner/repo from plain github URL', () => {
  assert.equal(r.githubOwnerRepo('https://github.com/foo/bar'),  'foo/bar');
  assert.equal(r.githubOwnerRepo('http://github.com/foo/bar'),   'foo/bar');
  assert.equal(r.githubOwnerRepo('https://github.com/foo/bar/'), 'foo/bar');
});

test('githubOwnerRepo: strips /tree/<branch>/<path> tail', () => {
  assert.equal(
    r.githubOwnerRepo('https://github.com/modelcontextprotocol/servers/tree/main/src/git'),
    'modelcontextprotocol/servers',
  );
});

test('githubOwnerRepo: handles deeper paths and trailing slashes', () => {
  assert.equal(
    r.githubOwnerRepo('https://github.com/foo/bar/blob/main/README.md'),
    'foo/bar',
  );
});

test('githubOwnerRepo: returns null for non-github URLs and empty input', () => {
  assert.equal(r.githubOwnerRepo('https://gitlab.com/foo/bar'), null);
  assert.equal(r.githubOwnerRepo(''),    null);
  assert.equal(r.githubOwnerRepo(null),  null);
  assert.equal(r.githubOwnerRepo(undefined), null);
});

// ── daysSince ──────────────────────────────────────────────────────────────

test('daysSince: 0 for today (with small skew tolerance)', () => {
  const iso = new Date().toISOString();
  // Date.now() can tick between calls; allow ±1 day.
  const d = r.daysSince(iso);
  assert.ok(d >= 0 && d <= 1, `expected 0..1, got ${d}`);
});

test('daysSince: ~30 for 30 days ago', () => {
  const past = new Date(Date.now() - 30 * 86400000).toISOString();
  const d = r.daysSince(past);
  // floor rounding + ms-level skew between Date.now calls can give 29 or 30.
  assert.ok(d === 29 || d === 30, `expected 29 or 30, got ${d}`);
});

test('daysSince: negative for future dates', () => {
  const future = new Date(Date.now() + 10 * 86400000).toISOString();
  assert.ok(r.daysSince(future) < 0);
});
