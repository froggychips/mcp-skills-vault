'use strict';
//
// Regression coverage for the OSI_APPROVED set in calculate_health.cjs.
//
// Bug: bare GPL/LGPL/AGPL SPDX forms (which `gh api .license.spdx_id`
// returns) were absent from OSI_APPROVED, so they incorrectly took a -10
// license penalty even though the README / SKILL.md document copyleft as
// no-penalty.
//
// These tests spawn the CLI rather than importing it, because
// calculate_health.cjs has no exports on master — and rewiring it as a
// module is out of scope for this fix.
//
const { test }         = require('node:test');
const assert           = require('node:assert/strict');
const { spawnSync }    = require('node:child_process');
const path             = require('node:path');

const SCRIPT = path.resolve(
  __dirname,
  '..',
  'mcp-ecosystem-intelligence',
  'scripts',
  'calculate_health.cjs',
);

// Run the script and return the parsed JSON output.
function runHealth(license) {
  // Use the same fixed inputs across all cases so any score delta is
  // driven by license alone:
  //   stars=100 → popularity 10·log10(101) ≈ 20.04 → capped at 20
  //   days=30   → recency 20 (< 90d)
  //   inReg=true→ +30, install=true → +15, issues=1 → +5
  //   base before license = 90, license penalty either 0 or -10.
  const args = ['100', '30', 'true', 'true', '1'];
  if (license !== undefined) args.push(license);

  const res = spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: 'utf8',
  });
  assert.equal(res.status, 0, `script exited non-zero: ${res.stderr}`);
  return JSON.parse(res.stdout);
}

// ── Bare-form copyleft SPDX (what GitHub returns) → no penalty ─────────────

for (const lic of ['GPL-2.0', 'GPL-3.0', 'LGPL-2.1', 'LGPL-3.0', 'AGPL-3.0']) {
  test(`OSI_APPROVED: bare "${lic}" gets no license penalty`, () => {
    const out = runHealth(lic);
    assert.equal(out.breakdown.license, 0, `expected no penalty for ${lic}`);
    assert.equal(out.health_score, 90);
  });
}

// ── Canonical "-only" / "-or-later" forms remain OSI (regression) ──────────

for (const lic of [
  'GPL-2.0-only', 'GPL-2.0-or-later',
  'GPL-3.0-only', 'GPL-3.0-or-later',
  'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'AGPL-3.0-only', 'AGPL-3.0-or-later',
]) {
  test(`OSI_APPROVED: canonical "${lic}" gets no license penalty`, () => {
    const out = runHealth(lic);
    assert.equal(out.breakdown.license, 0, `expected no penalty for ${lic}`);
  });
}

// ── Permissive sanity: MIT / Apache / BSD / MPL still no-penalty ───────────

for (const lic of ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC', 'MPL-2.0']) {
  test(`OSI_APPROVED: permissive "${lic}" gets no license penalty`, () => {
    const out = runHealth(lic);
    assert.equal(out.breakdown.license, 0);
  });
}

// ── Source-available / unknown still penalised (regression) ────────────────

for (const lic of ['BSL-1.1', 'SSPL-1.0', 'Elastic-2.0', 'Commons-Clause', 'Unknown', 'FSL-1.1-ALv2']) {
  test(`license penalty: non-OSI "${lic}" still gets -10`, () => {
    const out = runHealth(lic);
    assert.equal(out.breakdown.license, -10);
    assert.equal(out.health_score, 80);
  });
}

// ── License argument omitted → no penalty (back-compat) ────────────────────

test('license: omitted argument skips the penalty entirely', () => {
  const out = runHealth(undefined);
  assert.equal(out.breakdown.license, 0);
  assert.equal(out.health_score, 90);
});
