'use strict';
/**
 * The upgrade plan.
 *
 * The properties that make a recommendation trustworthy, each of which is a way
 * this could be quietly wrong:
 *   - the target clears *every* advisory, not the first one
 *   - the target is the shortest hop, not the newest release
 *   - an advisory with no published fix is said out loud rather than dropped,
 *     because otherwise "upgrade to X" reads as an all-clear
 *   - a pre-release is not offered as a target unless asked for
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const u = require('../mcp-ecosystem-intelligence/scripts/suggest_upgrade.cjs');

const vuln = (id, fixed, severity = 'HIGH', pkg = 'pkg') => ({
  id,
  database_specific: { severity },
  summary: `${id} summary`,
  affected: [{
    package: { name: pkg, ecosystem: 'npm' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, ...(fixed ? [{ fixed }] : [])] }],
  }],
});

const published = ['1.0.0', '1.0.1', '1.1.0', '2.0.0', '2.0.1', '2.1.0'];

test('the target clears every advisory, not just the first', () => {
  const plan = u.planUpgrade({
    ecosystem: 'npm', pkg: 'pkg', current: '1.0.0',
    vulns: [vuln('GHSA-a', '1.0.1'), vuln('GHSA-b', '2.0.0'), vuln('GHSA-c', '1.1.0')],
    published,
  });
  assert.equal(plan.state, 'upgrade');
  assert.equal(plan.needed, '2.0.0', 'the highest fix, or one of them still applies');
  assert.equal(plan.target, '2.0.0');
});

test('the target is the shortest hop that reaches the fix, not the latest release', () => {
  const plan = u.planUpgrade({
    ecosystem: 'npm', pkg: 'pkg', current: '1.0.0',
    vulns: [vuln('GHSA-a', '1.0.1')],
    published,
  });
  assert.equal(plan.target, '1.0.1');
  assert.equal(plan.latest, '2.1.0');
  assert.match(plan.steps_behind_latest, /not the latest/);
});

test('an advisory with no published fix is reported, and does not become an all-clear', () => {
  const plan = u.planUpgrade({
    ecosystem: 'npm', pkg: 'pkg', current: '1.0.0',
    vulns: [vuln('GHSA-fixed', '1.1.0'), vuln('GHSA-open', null)],
    published,
  });
  assert.equal(plan.state, 'upgrade');
  assert.deepEqual(plan.unresolved, ['GHSA-open'], 'the upgrade does not clear this one, and says so');
});

test('no advisory with a fix at all is "no-fix", which is its own answer', () => {
  const plan = u.planUpgrade({
    ecosystem: 'npm', pkg: 'pkg', current: '1.0.0',
    vulns: [vuln('GHSA-open', null), vuln('GHSA-open-2', null)],
    published,
  });
  assert.equal(plan.state, 'no-fix');
  assert.match(plan.reason, /none names a fixed version/);
});

test('a fix that exists but is not published yet is not an upgrade', () => {
  const plan = u.planUpgrade({
    ecosystem: 'npm', pkg: 'pkg', current: '1.0.0',
    vulns: [vuln('GHSA-a', '9.9.9')],
    published,
  });
  assert.equal(plan.state, 'no-fix');
  assert.match(plan.reason, /no published version reaches it/);
  assert.match(plan.reason, /latest is 2\.1\.0/);
});

test('pre-releases are not offered unless asked for', () => {
  const withPre = ['1.0.0', '2.0.0-rc.1', '2.0.0'];
  const strict = u.planUpgrade({
    ecosystem: 'npm', pkg: 'pkg', current: '1.0.0',
    vulns: [vuln('GHSA-a', '1.5.0')], published: withPre,
  });
  assert.equal(strict.target, '2.0.0');

  const loose = u.planUpgrade({
    ecosystem: 'npm', pkg: 'pkg', current: '1.0.0',
    vulns: [vuln('GHSA-a', '1.5.0')], published: withPre, allowPrerelease: true,
  });
  assert.equal(loose.target, '2.0.0-rc.1');
});

test('an advisory covering several packages only orders its own', () => {
  // A GHSA that lists both a server and one of its dependencies would otherwise
  // pull the dependency's fixed version into the server's plan.
  const multi = {
    id: 'GHSA-multi',
    database_specific: { severity: 'HIGH' },
    affected: [
      { package: { name: 'other-pkg', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '99.0.0' }] }] },
      { package: { name: 'pkg', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.1.0' }] }] },
    ],
  };
  const plan = u.planUpgrade({ ecosystem: 'npm', pkg: 'pkg', current: '1.0.0', vulns: [multi], published });
  assert.equal(plan.target, '1.1.0');
});

test('nothing known means nothing to do', () => {
  const plan = u.planUpgrade({ ecosystem: 'npm', pkg: 'pkg', current: '1.0.0', vulns: [], published });
  assert.equal(plan.state, 'clear');
});

test('an ecosystem with no ordering is unknown, never clear', () => {
  const plan = u.planUpgrade({ ecosystem: 'oci', pkg: 'img', current: 'sha256:aaa', vulns: [vuln('GHSA-a', '1.0.0')], published: [] });
  assert.equal(plan.state, 'unknown');
  assert.match(plan.reason, /no version ordering/);
});

test('an unorderable fixed version abstains instead of guessing', () => {
  const plan = u.planUpgrade({
    ecosystem: 'npm', pkg: 'pkg', current: '1.0.0',
    vulns: [vuln('GHSA-a', 'sometime-soon')], published,
  });
  assert.equal(plan.state, 'unknown');
  assert.match(plan.reason, /could not order/);
});

test('PyPI versions order by PEP 440, so 0.22.0 beats 0.21.10', () => {
  const plan = u.planUpgrade({
    ecosystem: 'pypi', pkg: 'mcp-atlassian', current: '0.21.1',
    vulns: [vuln('GHSA-a', '0.21.10', 'HIGH', 'mcp-atlassian'), vuln('GHSA-b', '0.22.0', 'HIGH', 'mcp-atlassian')],
    published: ['0.21.1', '0.21.9', '0.21.10', '0.22.0', '0.23.1'],
  });
  assert.equal(plan.needed, '0.22.0');
  assert.equal(plan.target, '0.22.0');
});

test('severityOf reads the database field, then the CVSS score, then abstains', () => {
  assert.equal(u.severityOf({ database_specific: { severity: 'critical' } }), 'CRITICAL');
  assert.equal(u.severityOf({ severity: [{ type: 'CVSS_V3', score: '9.8' }] }), 'CRITICAL');
  assert.equal(u.severityOf({ severity: [{ type: 'CVSS_V3', score: '7.1' }] }), 'HIGH');
  assert.equal(u.severityOf({ severity: [{ type: 'CVSS_V3', score: '4.0' }] }), 'MODERATE');
  assert.equal(u.severityOf({ severity: [{ type: 'CVSS_V3', score: '2.0' }] }), 'LOW');
  // A vector string is not a score, and inventing one from it here would
  // duplicate the CVSS computation that lives in the gate.
  assert.equal(u.severityOf({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N' }] }), 'UNKNOWN');
  assert.equal(u.severityOf({}), 'UNKNOWN');
});

test('fixedVersions keeps an unfixed advisory in the list', () => {
  const list = u.fixedVersions([vuln('GHSA-a', '1.0.0'), vuln('GHSA-b', null)], 'pkg');
  assert.deepEqual(list.map((a) => [a.id, a.fixed]), [['GHSA-a', ['1.0.0']], ['GHSA-b', []]]);
});
