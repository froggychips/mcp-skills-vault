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

test('githubOwnerRepo is anchored: github.com inside someone else\'s URL is not a match', () => {
  // A `url.includes('github.com')` pre-check used to guard this function, and
  // it accepted exactly the URLs the anchored matcher rejects — so the guard
  // decided nothing and read as if it did. The anchored pattern in
  // lib/repo_url.cjs is the only thing deciding now.
  assert.equal(drift.githubOwnerRepo('https://evil.example/github.com/acme/server'), null);
  assert.equal(drift.githubOwnerRepo('https://github.com.evil.example/acme/server'), null);
  assert.equal(drift.githubOwnerRepo('https://github.com/acme/server'), 'acme/server');
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
  // Other/Proprietary is not an SPDX id, but it is a definite statement: not
  // open source. 'Proprietary' classifies as restrictive, so an MIT → proprietary
  // move becomes drift-osi-to-restrictive and fails --strict. As null it used to
  // be drift-to-unknown, which --strict lets through.
  assert.equal(drift.pypiClassifierToSpdx('License :: Other/Proprietary License'),                 'Proprietary');
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

test('MIT → Other/Proprietary is a hard --strict failure', () => {
  const spdx = drift.pypiClassifierToSpdx('License :: Other/Proprietary License');
  const kind = drift.diffLicense('MIT', spdx);
  assert.equal(kind, 'drift-osi-to-restrictive');
  assert.equal(drift.isHardFail(kind), true);
});

test('licenseExitCode: --strict fails on fetch errors, not just on drift', () => {
  const clean   = { drifts: [], errors: [] };
  const errored = { drifts: [], errors: [{ name: 'x', error: 'npm view failed' }] };
  const drifted = { drifts: [{ classification: 'drift-osi-to-restrictive' }], errors: [] };
  const soft    = { drifts: [{ classification: 'drift-to-unknown' }], errors: [] };

  assert.equal(drift.licenseExitCode(clean,   true),  0);
  assert.equal(drift.licenseExitCode(drifted, true),  1);
  // The hole: every feed unreachable used to exit 0, so the weekly gate went
  // green having checked nothing.
  assert.equal(drift.licenseExitCode(errored, true),  1);
  assert.equal(drift.licenseExitCode(soft,    true),  0);
  // Without --strict nothing fails — the report is the output.
  assert.equal(drift.licenseExitCode(errored, false), 0);
  assert.equal(drift.licenseExitCode(drifted, false), 0);
});

// ── a name that is gone ─────────────────────────────────────────────────────

// Dates in these fixtures are relative: `availability` is seven-day evidence,
// so a literal date would start failing this file a week after it was written.
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);

test('an entry recorded as availability:gone is reported, not fetched, and does not fail --strict', async () => {
  // @diskd-ai/email-mcp went 404 on npm. check_availability recorded it as
  // `gone` on 2026-09-17; the weekly licence gate then failed every run after
  // that, because a 404 arrived as a fetch error and --strict fails on those.
  // The rule is sound — a run that read no licences is not a run that found no
  // drift — but this is not a failed measurement. There is nothing to measure,
  // and the DB knew it.
  const asked = [];
  const db = {
    tools: [
      {
        name: 'vanished',
        install_cmd: 'npx -y vanished@0.3.8',
        license: 'LGPL-3.0',
        trust_evidence: {
          dimensions: { availability: { status: 'gone', checked_at: daysAgo(2) } },
        },
      },
      { name: 'still-there', install_cmd: 'npx -y ok@1', license: 'MIT' },
    ],
  };
  const fetcher = async (tool) => {
    asked.push(tool.name);
    return { source: 'npm', license: 'MIT' };
  };

  const report = await drift.runDriftCheck(db, { fetcher, noFetch: false });

  assert.deepEqual(asked, ['still-there'], 'the gone entry must not be fetched at all');
  assert.equal(report.errors.length, 0,    'a recorded gone is not a fetch error');
  assert.equal(report.drifts.length, 0,    'and not a drift either — no licence was read');
  assert.equal(drift.licenseExitCode(report, true), 0, '--strict stays green');

  // Visible, not silent: an entry nobody watches any more should be countable.
  const goneItem = report.items.find((i) => i.name === 'vanished');
  assert.ok(goneItem, 'the entry is still an item');
  assert.equal(goneItem.skipped, true);
  assert.equal(goneItem.gone.recorded_at, daysAgo(2));
});

test('a package that disappears before it is recorded still fails --strict', async () => {
  // The other half of the rule. Skipping on the *recorded* state rather than
  // on the 404 is what keeps the first week loud.
  const db = { tools: [{ name: 'just-vanished', install_cmd: 'npx -y x@1', license: 'MIT' }] };
  const fetcher = async () => ({ source: 'npm', error: 'Command failed: npm view x@1 license --json' });

  const report = await drift.runDriftCheck(db, { fetcher, noFetch: false });

  assert.equal(report.errors.length, 1);
  assert.equal(drift.licenseExitCode(report, true), 1, 'an unrecorded disappearance is still a failure');
});

test('a stale gone is re-fetched: an unpublished name is claimable, so the record expires', async () => {
  // Codex, P2 on #109: trusting a recorded `gone` forever would mean the
  // licence gate stays green for a name somebody else has since registered and
  // published under. `availability` is seven-day evidence in this repo, and the
  // comment on that limit gives this exact reason.
  const asked = [];
  const db = {
    tools: [{
      name: 'gone-a-while-ago',
      install_cmd: 'npx -y vanished@0.3.8',
      license: 'LGPL-3.0',
      trust_evidence: {
        dimensions: { availability: { status: 'gone', checked_at: daysAgo(30) } },
      },
    }],
  };
  const fetcher = async (tool) => {
    asked.push(tool.name);
    return { source: 'npm', error: 'Command failed: npm view vanished@0.3.8 license --json' };
  };

  const report = await drift.runDriftCheck(db, { fetcher, noFetch: false });

  assert.deepEqual(asked, ['gone-a-while-ago'], 'a stale record is not a reason to skip the fetch');
  assert.equal(report.errors.length, 1, 'still 404 → the error comes back');
  assert.equal(drift.licenseExitCode(report, true), 1, 'and --strict says the availability evidence needs re-running');
});

test('a stale gone whose name was re-published reads the new licence', async () => {
  // The case the freshness limit exists for: the name was claimed by someone
  // else and now resolves. A permanent skip would never have looked.
  const db = {
    tools: [{
      name: 'reclaimed',
      install_cmd: 'npx -y reclaimed@1.0.0',
      license: 'MIT',
      trust_evidence: {
        dimensions: { availability: { status: 'gone', checked_at: daysAgo(30) } },
      },
    }],
  };
  const fetcher = async () => ({ source: 'npm', license: 'BSL-1.1' });

  const report = await drift.runDriftCheck(db, { fetcher, noFetch: false });

  assert.equal(report.drifts.length, 1);
  assert.equal(report.drifts[0].classification, 'drift-osi-to-restrictive');
  assert.equal(drift.licenseExitCode(report, true), 1, 'a re-published name relicensed to BSL must fail the gate');
});
