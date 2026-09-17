'use strict';
const { test }   = require('node:test');
const assert     = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
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

test('degradedFeedsFor: null result is degraded, [] is healthy', () => {
  const health = {
    npm:     { ok: true,  data: {} },
    osvNpm:  { ok: true,  data: [] },
    osvPypi: { ok: true,  data: [] },
    ghsa:    { ok: false, data: { 'npm:foo': null, 'npm:bar': [] }, failures: 1 },
    snyk:    { ok: true,  data: {}, skipped: 'SNYK_TOKEN not set', failures: 0 },
  };
  // foo: GHSA was unreachable (null) → must be reported, not read as clean.
  assert.deepEqual(v.degradedFeedsFor('npm', 'npm:foo', health), ['GHSA']);
  // bar: GHSA queried OK, no advisories ([]) → healthy.
  assert.deepEqual(v.degradedFeedsFor('npm', 'npm:bar', health), []);
});

test('degradedFeedsFor: whole-feed outage flags the package', () => {
  const health = {
    npm:     { ok: false, data: {} },
    osvNpm:  { ok: false, data: [] },
    osvPypi: { ok: true,  data: [] },
    ghsa:    { ok: true,  data: {}, failures: 0 },
    snyk:    { ok: true,  data: {}, skipped: false, failures: 0 },
  };
  assert.deepEqual(v.degradedFeedsFor('npm', 'npm:x', health), ['npm', 'OSV.dev']);
  // PyPI tools don't consult npm bulk.
  assert.deepEqual(v.degradedFeedsFor('PyPI', 'pip:y', health), []);
});

test('degradedFeedsFor: Snyk-skipped (no token) is NOT a degradation', () => {
  const health = {
    npm:     { ok: true, data: {} },
    osvNpm:  { ok: true, data: [] },
    osvPypi: { ok: true, data: [] },
    ghsa:    { ok: true, data: {}, failures: 0 },
    snyk:    { ok: true, data: {}, skipped: 'SNYK_TOKEN not set', failures: 0 },
  };
  assert.deepEqual(v.degradedFeedsFor('npm', 'npm:x', health), []);
});

test('summarizeFeedSources: reports actual outcome, not a static list', () => {
  const s = v.summarizeFeedSources({
    npm:     { ok: false, data: {} },
    osvNpm:  { ok: true,  data: [] },
    osvPypi: { ok: true,  data: [] },
    ghsa:    { ok: false, data: {}, failures: 3 },
    snyk:    { ok: true,  data: {}, skipped: false, failures: 0 },
  });
  assert.ok(s.includes('npm bulk UNAVAILABLE'), s.join(', '));
  assert.ok(s.includes('OSV.dev'), s.join(', '));
  assert.ok(s.some((x) => x.startsWith('GHSA (3 pkg unreachable')), s.join(', '));
  assert.ok(s.includes('Snyk'), s.join(', '));
});

test('CLI --offline is the network-free smoke path', () => {
  const r = spawnSync(process.execPath, [
    'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs',
    '--offline',
  ], { cwd: require('node:path').resolve(__dirname, '..'), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr || r.stdout);
  assert.match(r.stdout, /Offline mode: validating stored pins only/);
  assert.match(r.stdout, /entries checked/);
});

test('CLI --offline rejects --update', () => {
  const r = spawnSync(process.execPath, [
    'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs',
    '--offline',
    '--update',
  ], { cwd: require('node:path').resolve(__dirname, '..'), encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--offline cannot be combined with --update/);
});

// ── CVSS scoring ────────────────────────────────────────────────────────────
// OSV usually ships a vector and no severity word. Before these, a bare vector
// scored UNKNOWN, severityIsHard() said "not hard", and a 9.8 printed as a note
// instead of failing the gate.

test('cvss3BaseScore: matches the spec examples', () => {
  const cases = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', 6.5],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10],
  ];
  for (const [vector, expected] of cases) {
    assert.equal(v.cvss3BaseScore(vector), expected, vector);
  }
});

test('cvss3BaseScore: null for vectors it does not fully understand', () => {
  // v4.0 uses a lookup-table scoring model we deliberately don't implement.
  assert.equal(v.cvss3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), null);
  assert.equal(v.cvss3BaseScore('AV:N/AC:L/Au:N/C:P/I:P/A:P'), null);   // v2
  assert.equal(v.cvss3BaseScore('CVSS:3.1/AV:N/AC:L'), null);           // truncated
  assert.equal(v.cvss3BaseScore(''), null);
});

test('scoreToSeverity: CVSS qualitative rating scale', () => {
  assert.equal(v.scoreToSeverity(9.8), 'CRITICAL');
  assert.equal(v.scoreToSeverity(9.0), 'CRITICAL');
  assert.equal(v.scoreToSeverity(7.0), 'HIGH');
  assert.equal(v.scoreToSeverity(6.9), 'MEDIUM');
  assert.equal(v.scoreToSeverity(0.1), 'LOW');
  assert.equal(v.scoreToSeverity(0),   'UNKNOWN');
  assert.equal(v.scoreToSeverity(null), 'UNKNOWN');
});

test('osvSeverity: scores a bare CVSS vector instead of giving up', () => {
  const crit = { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] };
  assert.equal(v.osvSeverity(crit), 'CRITICAL');
  assert.equal(v.severityIsHard(v.osvSeverity(crit)), true);
  // Numeric score, no words.
  assert.equal(v.osvSeverity({ severity: [{ score: '7.5' }] }), 'HIGH');
  // affected[].database_specific is the last place to look.
  assert.equal(v.osvSeverity({ affected: [{ database_specific: { severity: 'critical' } }] }), 'CRITICAL');
});

test('osvSeverity: picks the worst of several shapes', () => {
  assert.equal(v.osvSeverity({
    severity: [
      { score: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N' },  // LOW
      { score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },  // CRITICAL
    ],
    database_specific: { severity: 'moderate' },
  }), 'CRITICAL');
});

test('severityRank: orders severities, moderate == medium', () => {
  assert.equal(v.severityRank('CRITICAL') > v.severityRank('HIGH'), true);
  assert.equal(v.severityRank('MODERATE'), v.severityRank('MEDIUM'));
  assert.equal(v.severityRank('UNKNOWN'), 0);
  assert.equal(v.severityRank(undefined), 0);
});

test('unifyAdvisories: a dedupe keeps the worst severity, not the first', () => {
  // Same GHSA id from OSV (severity unreadable) and GHSA (CRITICAL). Keeping
  // the first silently downgraded a hard failure to a printed line.
  const out = v.unifyAdvisories({
    osvList:  [{ id: 'GHSA-x', severity: [{ score: 'CVSS:4.0/AV:N/AC:L' }], summary: 'osv view' }],
    ghsaList: [{ id: 'GHSA-x', severity: 'CRITICAL', title: 'the real one', source: 'GHSA' }],
  });
  assert.equal(out.length, 1);
  assert.equal(out[0].severity, 'CRITICAL');
  assert.equal(v.severityIsHard(out[0].severity), true);
  assert.match(out[0].source, /OSV\+GHSA/);
});

test('unifyAdvisories: does not mutate the callerlists', () => {
  const ghsaList = [{ id: 'GHSA-y', severity: 'LOW', source: 'GHSA' }];
  v.unifyAdvisories({ npmList: [{ id: 'GHSA-y', severity: 'critical', url: 'u' }], ghsaList });
  assert.equal(ghsaList[0].severity, 'LOW');
});

test('npmPkgName: scopes may contain dots', () => {
  // `@yoda.digital/gitlab-mcp-server` returned null, so the entry fell through
  // to a SKIP and was never integrity-checked at all.
  assert.equal(v.npmPkgName('npx -y @yoda.digital/gitlab-mcp-server'), '@yoda.digital/gitlab-mcp-server');
  assert.equal(v.npmPkgName('npx -y @yoda.digital/gitlab-mcp-server@1.2.3'), '@yoda.digital/gitlab-mcp-server');
});

test('dockerDigestPinned: anchored at the end of the reference', () => {
  const d = 'a'.repeat(64);
  assert.equal(v.dockerDigestPinned(`ghcr.io/x/y@sha256:${d}`),      true);
  assert.equal(v.dockerDigestPinned(`ghcr.io/x/y@sha256:${d}oops`),  false);
  assert.equal(v.dockerDigestPinned('ghcr.io/x/y:latest'),           false);
  assert.equal(v.dockerDigestPinned(null),                           false);
});

// ── CLI: --entry and fail-closed behaviour ──────────────────────────────────

const REPO = require('node:path').resolve(__dirname, '..');
const runVerify = (args) => spawnSync(process.execPath, [
  'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs', ...args,
], { cwd: REPO, encoding: 'utf8' });

test('CLI --entry: unknown name is a usage error, not a silent pass', () => {
  const r = runVerify(['--offline', '--entry', 'no-such-entry-in-the-db']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /no DB entry named/);
});

test('CLI --entry: checks exactly one entry', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const name = db.tools[0].name;
  const r = runVerify(['--offline', '--entry', name]);
  assert.equal(r.status, 0, r.stderr || r.stdout);
  assert.match(r.stdout, /^1 entry checked/m);
});

test('CLI --fail-unverified: an entry the gate cannot check is a failure', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  // uvx --from installs from a git URL: there is no PyPI release to compare.
  const unverifiable = db.tools.find(t => /^uvx\s+--from/.test(t.install_cmd || ''));
  if (!unverifiable) return;   // DB no longer carries one — nothing to assert
  const lenient = runVerify(['--offline', '--entry', unverifiable.name]);
  assert.equal(lenient.status, 0, 'unverified is advisory by default');
  assert.match(lenient.stdout, /UNVERIFIED/);

  const closed = runVerify(['--offline', '--entry', unverifiable.name, '--fail-unverified']);
  assert.equal(closed.status, 1, 'unverified must fail under --fail-unverified');
});

test('cvss3BaseScore: rejects vectors that only look valid', () => {
  // S:X is legal in a temporal/environmental vector, not in a Base one. It used
  // to score as if Scope were Unchanged — a plausible number for a vector we
  // did not actually understand.
  assert.equal(v.cvss3BaseScore('CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:X/C:L/I:H/A:H'), null);
  // A repeated metric is malformed; silently taking the last value is guessing.
  assert.equal(v.cvss3BaseScore('CVSS:3.1/AV:N/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), null);
  assert.equal(v.cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
});

test('verdictFor: an UNVERIFIED line keeps the entry out of OK', () => {
  assert.equal(v.verdictFor(0, []), 'OK');
  assert.equal(v.verdictFor(0, [['NOTE', 'x'], ['HOOK', 'y']]), 'OK');
  assert.equal(v.verdictFor(0, [['UNVERIFIED', 'feed down']]), 'UNVERIFIED');
  assert.equal(v.verdictFor(1, [['UNVERIFIED', 'feed down']]), 'FAIL');
  assert.equal(v.verdictFor(0, undefined), 'OK');
});

test('CLI: an entry with no stored hash is UNVERIFIED, not OK', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const nohash = db.tools.find(t => !t.pkg_integrity && /^(npx|uvx)\s/.test(t.install_cmd || ''));
  if (!nohash) return;   // DB no longer has one — nothing to assert
  const lenient = runVerify(['--offline', '--entry', nohash.name]);
  assert.equal(lenient.status, 0);
  assert.match(lenient.stdout, /UNVERIFIED/);
  assert.doesNotMatch(lenient.stdout, new RegExp(`^OK\\s+${nohash.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'm'));

  const closed = runVerify(['--offline', '--entry', nohash.name, '--fail-unverified']);
  assert.equal(closed.status, 1, 'a missing hash must fail an install gate');
});

test('CLI: --json output of the sibling CLIs stays parseable', () => {
  // exitAfterFlush() is asynchronous, so a JSON branch that forgets to return
  // keeps running and appends a human-readable report after the document.
  for (const script of ['list_entries.cjs', 'orchestrate.cjs']) {
    const r = spawnSync(process.execPath, [
      `mcp-ecosystem-intelligence/scripts/${script}`, '--json',
    ], { cwd: REPO, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    assert.equal(r.status, 0, script);
    assert.doesNotThrow(() => JSON.parse(r.stdout), `${script} --json must be a single JSON document`);
  }
});

test('CLI --json: a single document on stdout, chatter on stderr', () => {
  const r = runVerify(['--offline', '--json']);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.schema, 'mcp-vault/verify-report@1');
  assert.equal(report.mode, 'offline');
  assert.equal(report.checked, report.entries.length);
  assert.equal(report.entries.length > 100, true);
  // Progress lines must not land in the document.
  assert.match(r.stderr, /Offline mode/);
  assert.doesNotMatch(r.stdout, /Offline mode/);
});

test('CLI --sarif: valid enough for code scanning to ingest', () => {
  const r = runVerify(['--offline', '--sarif']);
  assert.equal(r.status, 0, r.stderr);
  const sarif = JSON.parse(r.stdout);
  assert.equal(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'mcp-vault verify');
  for (const res of run.results) {
    assert.ok(['error', 'warning'].includes(res.level), res.level);
    assert.ok(res.locations[0].physicalLocation.region.startLine >= 1);
    assert.match(res.locations[0].physicalLocation.artifactLocation.uri, /tools_database\.json$/);
  }
});

test('CLI --json: exit code still reflects the verdict', () => {
  assert.equal(runVerify(['--offline', '--json']).status, 0);
  assert.equal(runVerify(['--offline', '--json', '--fail-unverified']).status, 1);
});

test('npmManifestUrl: scoped names keep their slash encoded', () => {
  assert.equal(v.npmManifestUrl('mcp-server-foo', '1.2.3', 'https://r'), 'https://r/mcp-server-foo/1.2.3');
  assert.equal(v.npmManifestUrl('@scope/pkg', '1.2.3', 'https://r'), 'https://r/@scope%2fpkg/1.2.3');
  assert.equal(v.npmManifestUrl('@yoda.digital/gitlab-mcp-server', null, 'https://r'), 'https://r/@yoda.digital%2fgitlab-mcp-server/latest');
  // A version with a plus or a pre-release tag must survive intact enough to
  // address the document.
  assert.equal(v.npmManifestUrl('pkg', '1.0.0-rc.1', 'https://r'), 'https://r/pkg/1.0.0-rc.1');
});

test('versionFromInstallCmd: what a launch command actually asks for', () => {
  assert.equal(v.versionFromInstallCmd('npx -y pkg@1.2.3'), '1.2.3');
  assert.equal(v.versionFromInstallCmd('npx -y @scope/pkg@1.2.3'), '1.2.3');
  assert.equal(v.versionFromInstallCmd('npx -y pkg'), null);            // resolves latest at start
  assert.equal(v.versionFromInstallCmd('npx -y pkg@latest'), 'latest');
  assert.equal(v.versionFromInstallCmd('uvx pkg==2.0.0'), '2.0.0');
  assert.equal(v.versionFromInstallCmd('uvx pkg'), null);
  const d = 'a'.repeat(64);
  assert.equal(v.versionFromInstallCmd(`docker run -i img@sha256:${d}`), `sha256:${d}`);
  assert.equal(v.versionFromInstallCmd('docker run -i img:latest'), null);
  assert.equal(v.versionFromInstallCmd(null), null);
  assert.equal(v.versionFromInstallCmd('node ./server.js'), null);
});

test('CLI --installed: verifies configured servers, not the DB', () => {
  const fs = require('node:fs'), os = require('node:os'), pathMod = require('node:path');
  const proj = fs.mkdtempSync(pathMod.join(os.tmpdir(), 'mcp-installed-cli-'));
  // A project config with one unpinned server. Offline so no network is needed:
  // the point is that the subject list comes from the config.
  fs.writeFileSync(pathMod.join(proj, '.mcp.json'), JSON.stringify({
    mcpServers: { 'some-server': { command: 'npx', args: ['-y', 'some-server'] } },
  }));
  const r = spawnSync(process.execPath, [
    'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs',
    '--installed', '--offline', '--cwd', proj, '--json',
  ], { cwd: REPO, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.subject, 'installed');
  const found = report.entries.find(e => e.name === 'some-server');
  assert.ok(found, 'the configured server must be in the report');
  assert.equal(found.status, 'UNVERIFIED');
  fs.rmSync(proj, { recursive: true, force: true });
});

test('CLI --installed: refuses --update, which would write the DB from a config', () => {
  const r = runVerify(['--installed', '--update']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /cannot be combined with --update/);
});
