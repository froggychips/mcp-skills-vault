'use strict';
const { test }   = require('node:test');
const assert     = require('node:assert/strict');
const v = require('../mcp-ecosystem-intelligence/scripts/verify_integrity.cjs');

test('normalizeGitUrl: strips .git, /issues, git+ prefixes', () => {
  assert.equal(v.normalizeGitUrl('git+https://github.com/foo/bar.git'),       'https://github.com/foo/bar');
  assert.equal(v.normalizeGitUrl('git+ssh://git@github.com/foo/bar.git'),     'https://github.com/foo/bar');
  assert.equal(v.normalizeGitUrl('git@github.com:foo/bar.git'),               'https://github.com/foo/bar');
  assert.equal(v.normalizeGitUrl('https://github.com/foo/bar/issues'),        'https://github.com/foo/bar');
  assert.equal(v.normalizeGitUrl('https://github.com/foo/bar/issues/'),       'https://github.com/foo/bar');
});

test('normalizeGitUrl: handles null / non-strings', () => {
  assert.equal(v.normalizeGitUrl(null), null);
  assert.equal(v.normalizeGitUrl(undefined), null);
  assert.equal(v.normalizeGitUrl(123), null);
});

test('npmPkgName: extracts scoped + unscoped package names', () => {
  assert.equal(v.npmPkgName('npx -y @scope/pkg@1.2.3'),          '@scope/pkg');
  assert.equal(v.npmPkgName('npx -y pkg-name@1.2.3'),            'pkg-name');
  assert.equal(v.npmPkgName('npx -y pkg-name'),                  'pkg-name');
  assert.equal(v.npmPkgName('npx -y @scope/pkg@1.2.3 extra arg'), '@scope/pkg');
});

test('npmPkgName: returns null on unparseable input', () => {
  assert.equal(v.npmPkgName('uvx pkg'),       null);
  assert.equal(v.npmPkgName('docker run x'),  null);
  assert.equal(v.npmPkgName(''),              null);
});

test('pypiPkgName: handles plain + versioned uvx, rejects --from', () => {
  assert.equal(v.pypiPkgName('uvx pkg-name'),           'pkg-name');
  assert.equal(v.pypiPkgName('uvx pkg-name==1.2.3'),    'pkg-name');
  assert.equal(v.pypiPkgName('uvx pkg-name extra arg'), 'pkg-name');
  assert.equal(v.pypiPkgName('uvx --from git+https://… pkg'), null);
});

test('dockerImageRef: walks past flags with values', () => {
  // Real-world entry from the DB.
  const cmd = 'docker run -i --rm --cap-drop ALL --security-opt no-new-privileges -e GITHUB_TOKEN ghcr.io/github/github-mcp-server@sha256:abc';
  assert.equal(v.dockerImageRef(cmd), 'ghcr.io/github/github-mcp-server@sha256:abc');
});

test('dockerImageRef: handles bare image + non-docker commands', () => {
  assert.equal(v.dockerImageRef('docker run nginx:latest'), 'nginx:latest');
  assert.equal(v.dockerImageRef('npx -y pkg'),              null);
  assert.equal(v.dockerImageRef(''),                        null);
});

test('severityIsHard: HIGH/CRITICAL only, case-insensitive', () => {
  assert.equal(v.severityIsHard('HIGH'),     true);
  assert.equal(v.severityIsHard('CRITICAL'), true);
  assert.equal(v.severityIsHard('high'),     true);
  assert.equal(v.severityIsHard('critical'), true);
  assert.equal(v.severityIsHard('MEDIUM'),   false);
  assert.equal(v.severityIsHard('LOW'),      false);
  assert.equal(v.severityIsHard(null),       false);
  assert.equal(v.severityIsHard(''),         false);
});

test('osvSeverity: pulls severity from CVSS scores when present', () => {
  assert.equal(v.osvSeverity({ severity: [{ score: 'CRITICAL/AV:N' }] }),                   'CRITICAL');
  assert.equal(v.osvSeverity({ severity: [{ score: 'CVSS:3.1/AV:N/AC:L/PR:N — high' }] }),   'HIGH');
  // Fallback to database_specific.
  assert.equal(v.osvSeverity({ severity: [], database_specific: { severity: 'medium' } }), 'MEDIUM');
  assert.equal(v.osvSeverity({}),                                                          'UNKNOWN');
});

test('unifyAdvisories: dedupes by id across sources', () => {
  const out = v.unifyAdvisories({
    npmList:  [{ id: 'GHSA-aaa', severity: 'high', title: 'foo', url: 'u' }],
    osvList:  [{ id: 'GHSA-aaa', severity: [{ score: 'HIGH' }], summary: 'foo OSV view' }],
    ghsaList: [{ id: 'GHSA-bbb', severity: 'CRITICAL', title: 'bar', url: 'u2', source: 'GHSA' }],
    snykList: [],
  });
  // GHSA-aaa is the same advisory from npm + OSV — kept once.
  assert.equal(out.length, 2);
  assert.deepEqual(out.map(a => a.id), ['GHSA-aaa', 'GHSA-bbb']);
});

test('unifyAdvisories: normalises severity to uppercase, tags source', () => {
  const out = v.unifyAdvisories({
    npmList:  [{ id: 'A', severity: 'high', title: 't', url: 'u' }],
    osvList:  [],
    ghsaList: [],
    snykList: [],
  });
  assert.equal(out[0].severity, 'HIGH');
  assert.equal(out[0].source,   'npm');
});

test('unifyAdvisories: empty inputs return empty list', () => {
  assert.deepEqual(v.unifyAdvisories({}), []);
  assert.deepEqual(
    v.unifyAdvisories({ npmList: [], osvList: [], ghsaList: [], snykList: [] }),
    [],
  );
});
