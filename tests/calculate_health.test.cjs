'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path  = require('node:path');

const h = require('../mcp-ecosystem-intelligence/scripts/calculate_health.cjs');
const SCRIPT = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts/calculate_health.cjs');

// Helpers ----------------------------------------------------------------

// Minimal call wrapper — provides safe defaults so each test focuses on the
// single dimension under test.
const score = (over = {}) => h.calculateHealth({
  stars:           0,
  lastCommitDays:  9999,
  inRegistry:      false,
  hasInstallCmd:   false,
  criticalIssues:  9999,
  license:         undefined,
  ...over,
});

const approx = (a, b, eps = 0.01) => Math.abs(a - b) < eps;

// ── popularity (0–20, capped) ──────────────────────────────────────────────

test('popularity: 0 stars → 0 (log10(1)=0)', () => {
  assert.equal(h.popularityScoreOf(0), 0);
});

test('popularity: 10 stars → 10·log10(11) ≈ 10.41', () => {
  assert.ok(approx(h.popularityScoreOf(10), 10.413926851582251));
});

test('popularity: capped at 20 for mega-repos (1e6 stars)', () => {
  assert.equal(h.popularityScoreOf(1_000_000), 20);
});

test('popularity: at the cap boundary — stars=10^19 still 20', () => {
  assert.equal(h.popularityScoreOf(1e19), 20);
});

test('popularity: stars=99 → 10·log10(100)=20 hits cap exactly', () => {
  assert.equal(h.popularityScoreOf(99), 20);
});

// ── recency bonus (0/10/20/40, graduated) ──────────────────────────────────

test('recency: < 30 days → 40 (active)', () => {
  assert.equal(h.recencyBonusOf(0),  40);
  assert.equal(h.recencyBonusOf(29), 40);
});

test('recency: boundary at 30 days → 20', () => {
  assert.equal(h.recencyBonusOf(30), 20);
});

test('recency: < 90 days → 20 (recent)', () => {
  assert.equal(h.recencyBonusOf(89), 20);
});

test('recency: boundary at 90 days → 10', () => {
  assert.equal(h.recencyBonusOf(90), 10);
});

test('recency: < 180 days → 10 (dormant)', () => {
  assert.equal(h.recencyBonusOf(179), 10);
});

test('recency: boundary at 180 days → 0 (stale)', () => {
  assert.equal(h.recencyBonusOf(180), 0);
});

test('recency: > 180 days → 0', () => {
  assert.equal(h.recencyBonusOf(181),  0);
  assert.equal(h.recencyBonusOf(9999), 0);
});

// ── registry / install / issues / license  (component flags) ──────────────

test('registry: in_registry=false adds 0; true adds 30', () => {
  assert.equal(score({ inRegistry: false }).breakdown.registry, 0);
  assert.equal(score({ inRegistry: true  }).breakdown.registry, 30);
});

test('install_cmd: false adds 0; true adds 15', () => {
  assert.equal(score({ hasInstallCmd: false }).breakdown.install_cmd, 0);
  assert.equal(score({ hasInstallCmd: true  }).breakdown.install_cmd, 15);
});

test('issues: critical_issues < 5 adds 5', () => {
  assert.equal(score({ criticalIssues: 0 }).breakdown.low_issues, 5);
  assert.equal(score({ criticalIssues: 4 }).breakdown.low_issues, 5);
});

test('issues: critical_issues >= 5 adds 0', () => {
  assert.equal(score({ criticalIssues: 5  }).breakdown.low_issues, 0);
  assert.equal(score({ criticalIssues: 99 }).breakdown.low_issues, 0);
});

// ── license penalty (-10 / 0) ──────────────────────────────────────────────

const NON_OSI = ['BSL', 'SSPL', 'Unknown', 'Commons Clause', 'FSL-1.1', 'Elastic-2.0'];
for (const lic of NON_OSI) {
  test(`license: non-OSI "${lic}" → -10 penalty`, () => {
    assert.equal(h.licensePenaltyOf(lic), -10);
  });
}

const OSI = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'MPL-2.0', 'ISC', 'GPL-3.0-or-later', 'AGPL-3.0-or-later'];
for (const lic of OSI) {
  test(`license: OSI "${lic}" → 0 penalty`, () => {
    assert.equal(h.licensePenaltyOf(lic), 0);
  });
}

test('license: undefined skips penalty (back-compat)', () => {
  assert.equal(h.licensePenaltyOf(undefined), 0);
});

test('license: empty string is non-OSI → -10', () => {
  // calcScore in refresh_scores.cjs may pass '' when DB has no license.
  // Until that's fixed, ensure the formula treats '' as non-OSI.
  assert.equal(h.licensePenaltyOf(''), -10);
});

test('license: bare "GPL-3.0" (GitHub short SPDX) is NOT in OSI set', () => {
  // OSI set only contains the canonical "-only"/"-or-later" variants;
  // callers must normalize via refresh_scores GITHUB_SPDX_MAP first.
  assert.equal(h.licensePenaltyOf('GPL-3.0'), -10);
});

// ── classify tier mapping (boundaries) ─────────────────────────────────────

test('classify: 85 → Core, 84.99 → Recommended', () => {
  assert.equal(h.classify(85),    'Core');
  assert.equal(h.classify(84.99), 'Recommended');
});

test('classify: 65 → Recommended, 64.99 → Experimental', () => {
  assert.equal(h.classify(65),    'Recommended');
  assert.equal(h.classify(64.99), 'Experimental');
});

test('classify: 40 → Experimental, 39.99 → Deprecated', () => {
  assert.equal(h.classify(40),    'Experimental');
  assert.equal(h.classify(39.99), 'Deprecated');
});

test('classify: edge values — 110 (max), 0, -10 (min)', () => {
  assert.equal(h.classify(110), 'Core');
  assert.equal(h.classify(0),   'Deprecated');
  assert.equal(h.classify(-10), 'Deprecated');
});

// ── integration: full end-to-end ───────────────────────────────────────────

test('calculateHealth: full Core example (1200 stars / 15d / registry / install / MIT)', () => {
  const r = h.calculateHealth({
    stars:          1200,
    lastCommitDays: 15,
    inRegistry:     true,
    hasInstallCmd:  true,
    criticalIssues: 2,
    license:        'MIT',
  });
  // popularity = min(20, 10·log10(1201)) = 20 (since log10(1201) ≈ 3.08)
  assert.equal(r.breakdown.popularity,  20);
  assert.equal(r.breakdown.recency,     40);
  assert.equal(r.breakdown.registry,    30);
  assert.equal(r.breakdown.install_cmd, 15);
  assert.equal(r.breakdown.low_issues,  5);
  assert.equal(r.breakdown.license,     0);
  assert.equal(r.health_score,  110);
  assert.equal(r.classification, 'Core');
});

test('calculateHealth: source-available, low-star, stale → Deprecated', () => {
  const r = h.calculateHealth({
    stars:          50,
    lastCommitDays: 200,
    inRegistry:     false,
    hasInstallCmd:  true,
    criticalIssues: 10,
    license:        'FSL-1.1-ALv2',
  });
  // popularity = 10·log10(51) ≈ 17.08, recency = 0 (≥180), no registry,
  // install +15, issues ≥5 → 0, license -10  →  17.08 + 15 - 10 = 22.08
  assert.ok(approx(r.health_score, 22.08));
  assert.equal(r.classification, 'Deprecated');
});

test('calculateHealth: omitted license skips penalty (back-compat)', () => {
  const r = h.calculateHealth({
    stars: 1200, lastCommitDays: 15, inRegistry: true,
    hasInstallCmd: true, criticalIssues: 2,
    // license: undefined
  });
  assert.equal(r.breakdown.license, 0);
});

test('calculateHealth: rounds to 2 decimal places', () => {
  const r = h.calculateHealth({
    stars: 10, lastCommitDays: 9999, inRegistry: false,
    hasInstallCmd: false, criticalIssues: 9999,
  });
  // 10·log10(11) = 10.41392685...  →  rounds to 10.41
  assert.equal(r.health_score, 10.41);
});

// ── CLI parity ─────────────────────────────────────────────────────────────

test('CLI: matches programmatic output (1200/15/true/true/2 MIT)', () => {
  const cli = spawnSync(process.execPath, [SCRIPT, '1200', '15', 'true', 'true', '2', 'MIT'], { encoding: 'utf8' });
  assert.equal(cli.status, 0, cli.stderr);
  const parsed = JSON.parse(cli.stdout);
  const direct = h.calculateHealth({
    stars: 1200, lastCommitDays: 15, inRegistry: true,
    hasInstallCmd: true, criticalIssues: 2, license: 'MIT',
  });
  assert.deepEqual(parsed, direct);
});

test('CLI: missing args → exit 1 with usage', () => {
  const cli = spawnSync(process.execPath, [SCRIPT, '1', '2'], { encoding: 'utf8' });
  assert.equal(cli.status, 1);
  assert.match(cli.stderr, /Usage:/);
});

test('CLI: --help → exit 0', () => {
  const cli = spawnSync(process.execPath, [SCRIPT, '--help'], { encoding: 'utf8' });
  assert.equal(cli.status, 0);
  assert.match(cli.stdout, /Usage:/);
});
