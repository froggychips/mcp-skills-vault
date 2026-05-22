'use strict';
const { test }   = require('node:test');
const assert     = require('node:assert/strict');

const drift = require('../mcp-ecosystem-intelligence/scripts/check_license_drift.cjs');
const calc  = require('../mcp-ecosystem-intelligence/scripts/calculate_health.cjs');

// ── normalizeLicense ──────────────────────────────────────────────────────

test('normalizeLicense: trims whitespace, returns trimmed SPDX', () => {
  assert.equal(drift.normalizeLicense('  MIT  '), 'MIT');
  assert.equal(drift.normalizeLicense('Apache-2.0'), 'Apache-2.0');
});

test('normalizeLicense: collapses unknown sentinels to null', () => {
  assert.equal(drift.normalizeLicense(null),          null);
  assert.equal(drift.normalizeLicense(undefined),     null);
  assert.equal(drift.normalizeLicense(''),            null);
  assert.equal(drift.normalizeLicense('   '),         null);
  assert.equal(drift.normalizeLicense('Unknown'),     null);
  assert.equal(drift.normalizeLicense('UNKNOWN'),     null);
  assert.equal(drift.normalizeLicense('NOASSERTION'), null);
});

test('normalizeLicense: upgrades GitHub short SPDX to -or-later canonical', () => {
  assert.equal(drift.normalizeLicense('GPL-3.0'),  'GPL-3.0-or-later');
  assert.equal(drift.normalizeLicense('LGPL-2.1'), 'LGPL-2.1-or-later');
  assert.equal(drift.normalizeLicense('AGPL-3.0'), 'AGPL-3.0-or-later');
});

// ── classifyLicense (re-exported from calculate_health) ───────────────────

test('calculate_health.classifyLicense: OSI permissive + copyleft', () => {
  for (const l of ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC', 'MPL-2.0', 'GPL-3.0-or-later', 'AGPL-3.0-or-later']) {
    assert.equal(calc.classifyLicense(l), 'osi', `${l} should be osi`);
  }
});

test('calculate_health.classifyLicense: restrictive source-available', () => {
  for (const l of ['BSL-1.1', 'SSPL-1.0', 'Elastic-2.0', 'FSL-1.1-ALv2', 'FSL-1.1-MIT', 'Commons-Clause']) {
    assert.equal(calc.classifyLicense(l), 'restrictive', `${l} should be restrictive`);
  }
});

test('calculate_health.classifyLicense: unknown sentinels', () => {
  assert.equal(calc.classifyLicense(null),          'unknown');
  assert.equal(calc.classifyLicense(undefined),     'unknown');
  assert.equal(calc.classifyLicense(''),            'unknown');
  assert.equal(calc.classifyLicense('Unknown'),     'unknown');
  assert.equal(calc.classifyLicense('NOASSERTION'), 'unknown');
});

// ── diffLicense — the table the design doc spells out ─────────────────────

test('diffLicense: MIT → MIT (match)', () => {
  assert.equal(drift.diffLicense('MIT', 'MIT'), 'match');
});

test('diffLicense: MIT → Apache-2.0 (drift-osi-to-osi)', () => {
  assert.equal(drift.diffLicense('MIT', 'Apache-2.0'), 'drift-osi-to-osi');
});

test('diffLicense: MIT → BSL-1.1 (drift-osi-to-restrictive)', () => {
  assert.equal(drift.diffLicense('MIT', 'BSL-1.1'), 'drift-osi-to-restrictive');
});

test('diffLicense: MIT → SSPL-1.0 / Elastic-2.0 / FSL — all osi-to-restrictive', () => {
  for (const r of ['SSPL-1.0', 'Elastic-2.0', 'FSL-1.1-ALv2', 'Commons-Clause']) {
    assert.equal(drift.diffLicense('MIT', r), 'drift-osi-to-restrictive', `MIT → ${r}`);
  }
});

test('diffLicense: SSPL-1.0 → MIT (drift-restrictive-to-osi)', () => {
  assert.equal(drift.diffLicense('SSPL-1.0', 'MIT'), 'drift-restrictive-to-osi');
});

test('diffLicense: MIT → null (drift-to-unknown)', () => {
  assert.equal(drift.diffLicense('MIT', null), 'drift-to-unknown');
  assert.equal(drift.diffLicense('MIT', 'NOASSERTION'), 'drift-to-unknown');
  assert.equal(drift.diffLicense('MIT', 'Unknown'), 'drift-to-unknown');
});

test('diffLicense: null → MIT (drift-from-unknown)', () => {
  assert.equal(drift.diffLicense(null, 'MIT'), 'drift-from-unknown');
  assert.equal(drift.diffLicense('NOASSERTION', 'MIT'), 'drift-from-unknown');
});

test('diffLicense: null → null is a match (no information changed)', () => {
  assert.equal(drift.diffLicense(null, null), 'match');
  assert.equal(drift.diffLicense('Unknown', 'NOASSERTION'), 'match');
});

test('diffLicense: BSL-1.1 → SSPL-1.0 (restrictive-to-restrictive treated as hard)', () => {
  // Swap between two source-available licenses isn't a no-op — the new
  // terms can be materially different (BSL→SSPL = MongoDB pattern).
  assert.equal(drift.diffLicense('BSL-1.1', 'SSPL-1.0'), 'drift-osi-to-restrictive');
});

// ── isHardFail ────────────────────────────────────────────────────────────

test('isHardFail: only osi-to-restrictive trips --strict', () => {
  assert.equal(drift.isHardFail('drift-osi-to-restrictive'), true);
  assert.equal(drift.isHardFail('drift-osi-to-osi'),         false);
  assert.equal(drift.isHardFail('drift-restrictive-to-osi'), false);
  assert.equal(drift.isHardFail('drift-to-unknown'),         false);
  assert.equal(drift.isHardFail('drift-from-unknown'),       false);
  assert.equal(drift.isHardFail('match'),                    false);
});

// ── parsers ───────────────────────────────────────────────────────────────

test('npmPkgName: scoped + unscoped', () => {
  assert.equal(drift.npmPkgName('npx -y @scope/pkg@1.0.0'),  '@scope/pkg');
  assert.equal(drift.npmPkgName('npx -y plain-pkg@1.0.0'),   'plain-pkg');
  assert.equal(drift.npmPkgName('npx -y plain-pkg'),         'plain-pkg');
  assert.equal(drift.npmPkgName('uvx pkg'),                  null);
});

test('pypiPkgName: rejects --from git installs', () => {
  assert.equal(drift.pypiPkgName('uvx pkg-name==1.2.3'), 'pkg-name');
  assert.equal(drift.pypiPkgName('uvx --from git+https://example/foo bar'), null);
});

test('githubOwnerRepo: strips trailing path', () => {
  assert.equal(drift.githubOwnerRepo('https://github.com/foo/bar'),                'foo/bar');
  assert.equal(drift.githubOwnerRepo('https://github.com/foo/bar/tree/main/x'),   'foo/bar');
  assert.equal(drift.githubOwnerRepo('https://gitlab.com/foo/bar'),               null);
  assert.equal(drift.githubOwnerRepo(null),                                       null);
});

// ── PyPI license extraction ───────────────────────────────────────────────

test('pypiLicenseFromMeta: prefers info.license when set', () => {
  const meta = { info: { license: 'MIT', classifiers: ['License :: OSI Approved :: Apache Software License'] } };
  assert.equal(drift.pypiLicenseFromMeta(meta), 'MIT');
});

test('pypiLicenseFromMeta: falls back to classifiers when info.license blank', () => {
  const meta = { info: { license: '', classifiers: ['License :: OSI Approved :: MIT License'] } };
  assert.equal(drift.pypiLicenseFromMeta(meta), 'MIT');
});

test('pypiLicenseFromMeta: returns null when nothing usable', () => {
  assert.equal(drift.pypiLicenseFromMeta({ info: { license: '', classifiers: [] } }), null);
  assert.equal(drift.pypiLicenseFromMeta({ info: { license: 'UNKNOWN', classifiers: [] } }), null);
  assert.equal(drift.pypiLicenseFromMeta({}), null);
});

test('pypiClassifierToSpdx: known mappings + passthrough tail', () => {
  assert.equal(drift.pypiClassifierToSpdx('License :: OSI Approved :: MIT License'),                'MIT');
  assert.equal(drift.pypiClassifierToSpdx('License :: OSI Approved :: Apache Software License'),   'Apache-2.0');
  assert.equal(drift.pypiClassifierToSpdx('License :: OSI Approved :: BSD License'),               'BSD-3-Clause');
  // Other/Proprietary → null (we treat as unknown so it can't masquerade as a real license)
  assert.equal(drift.pypiClassifierToSpdx('License :: Other/Proprietary License'),                 null);
  // Unknown tail — passed through. (Free-form strings still allow equality comparison.)
  assert.equal(drift.pypiClassifierToSpdx('License :: OSI Approved :: Some Future License'),       'Some Future License');
  assert.equal(drift.pypiClassifierToSpdx('not a license string'),                                  null);
});

// ── runDriftCheck — end-to-end with a stubbed fetcher ─────────────────────

test('runDriftCheck: integration over a small DB with stubbed fetcher', async () => {
  const db = {
    tools: [
      { name: 'unchanged',            install_cmd: 'npx -y a@1', license: 'MIT' },
      { name: 'relicensed-to-bsl',    install_cmd: 'npx -y b@1', license: 'MIT' },
      { name: 'mit-to-apache',        install_cmd: 'npx -y c@1', license: 'MIT' },
      { name: 'license-disappeared',  install_cmd: 'npx -y d@1', license: 'MIT' },
      { name: 'sspl-going-osi',       install_cmd: 'npx -y e@1', license: 'SSPL-1.0' },
      { name: 'docker-skipped',       install_cmd: 'docker run img@sha256:abc', license: 'MIT' },
      { name: 'fetcher-broke',        install_cmd: 'npx -y f@1', license: 'MIT' },
    ],
  };
  // Map by entry name to keep the stub readable.
  const fixture = {
    'unchanged':            { source: 'npm',    license: 'MIT' },
    'relicensed-to-bsl':    { source: 'npm',    license: 'BSL-1.1' },
    'mit-to-apache':        { source: 'npm',    license: 'Apache-2.0' },
    'license-disappeared':  { source: 'npm',    license: null },
    'sspl-going-osi':       { source: 'npm',    license: 'MIT' },
    'docker-skipped':       { source: 'docker-license-from-source', skip: true },
    'fetcher-broke':        { source: 'npm',    error: 'registry timeout' },
  };
  const fetcher = async (tool) => fixture[tool.name];

  const report = await drift.runDriftCheck(db, { fetcher, noFetch: false });

  assert.equal(report.checked, 6,            'docker entry is still counted as an item (skipped, not error)');
  assert.equal(report.errors.length, 1,      'fetcher-broke surfaced as an error, not as a drift');
  assert.equal(report.errors[0].name, 'fetcher-broke');
  assert.equal(report.errors[0].error, 'registry timeout');

  const driftByName = Object.fromEntries(report.drifts.map((d) => [d.name, d]));
  assert.ok(!driftByName['unchanged'],            'MIT → MIT does not appear in drifts');
  assert.ok(!driftByName['docker-skipped'],       'docker skip does not appear in drifts');
  assert.equal(driftByName['relicensed-to-bsl'].classification,   'drift-osi-to-restrictive');
  assert.equal(driftByName['mit-to-apache'].classification,        'drift-osi-to-osi');
  assert.equal(driftByName['license-disappeared'].classification,  'drift-to-unknown');
  assert.equal(driftByName['sspl-going-osi'].classification,       'drift-restrictive-to-osi');

  // Only the BSL drift should trip --strict.
  const hardFails = report.drifts.filter((d) => drift.isHardFail(d.classification));
  assert.equal(hardFails.length, 1);
  assert.equal(hardFails[0].name, 'relicensed-to-bsl');
});

test('runDriftCheck: --no-fetch produces match-only items, no network calls', async () => {
  const db = {
    tools: [
      { name: 'a', install_cmd: 'npx -y a@1', license: 'MIT' },
      { name: 'b', install_cmd: 'npx -y b@1', license: 'BSL-1.1' },
    ],
  };
  // Fetcher that would explode if called — proves --no-fetch never invokes it.
  const fetcher = async () => { throw new Error('fetcher should not be called in --no-fetch'); };

  const report = await drift.runDriftCheck(db, { fetcher, noFetch: true });
  assert.equal(report.checked, 2);
  assert.equal(report.drifts.length, 0);
  assert.equal(report.errors.length, 0);
  // Per-item self-classification is exposed so a CI smoke can still flag
  // a DB row whose stored license is restrictive (just informational).
  const byName = Object.fromEntries(report.items.map((i) => [i.name, i]));
  assert.equal(byName['a'].stored_class, 'osi');
  assert.equal(byName['b'].stored_class, 'restrictive');
});

test('runDriftCheck: a thrown fetcher exception becomes an error, not a crash', async () => {
  const db = { tools: [{ name: 'kaboom', install_cmd: 'npx -y k@1', license: 'MIT' }] };
  const fetcher = async () => { throw new Error('boom'); };
  const report = await drift.runDriftCheck(db, { fetcher, noFetch: false });
  assert.equal(report.errors.length, 1);
  assert.equal(report.errors[0].error, 'boom');
  assert.equal(report.drifts.length, 0);
});
