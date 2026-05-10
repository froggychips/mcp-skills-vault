/**
 * Calculate the Health Score for an MCP tool based on the specified formula.
 *
 * Formula:
 *   Health Score = min(20, 10 × log10(stars + 1))  [0–20,  popularity component, capped]
 *                + recency bonus                   [0–40,  how recently maintained]
 *                + 30 (if present in official registry)
 *                + 15 (if install command exists)
 *                + 5  (if critical issues < 5)
 *                − 10 (if license is non-OSI / source-available / Unknown)
 *
 * Popularity is capped at 20 so that mega-repos (50k+ stars) cannot dominate the
 * score and crowd everything into the Core tier; max total = 110, min = -10.
 *
 * Recency bonus (graduated to reward freshness, not just a binary cutoff):
 *   40  – last commit < 30 days   (actively maintained)
 *   20  – last commit < 90 days   (recently maintained)
 *   10  – last commit < 180 days  (dormant but alive)
 *   0   – last commit >= 180 days (stale)
 *
 * License penalty applies for source-available / proprietary / unknown licenses
 * (e.g. FSL-1.1, BSL, SSPL, Elastic-2.0, Commons Clause). OSI-approved licenses
 * — both permissive (MIT/Apache/BSD/ISC/MPL) and copyleft (GPL/LGPL/AGPL) — get
 * no penalty. The license argument is OPTIONAL for backward compatibility:
 * callers that omit it skip the license adjustment entirely.
 *
 * Classification thresholds (out of 110):
 *   85+    → Core
 *   65–84  → Recommended
 *   40–64  → Experimental
 *   <40    → Deprecated
 *
 * Usage:
 *   node calculate_health.cjs <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues> [license]
 *
 * Examples:
 *   node calculate_health.cjs 1200 15 true true 2 MIT
 *   node calculate_health.cjs 50 200 false true 10 FSL-1.1-ALv2
 *   node calculate_health.cjs 1200 15 true true 2            # license check skipped (back-compat)
 */

const args = process.argv.slice(2);

// Print help when requested
if (args[0] === '--help' || args[0] === '-h') {
  console.log(
    'Usage: node calculate_health.cjs <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues> [license]\n' +
    '\n' +
    'Arguments:\n' +
    '  stars            GitHub star count (integer >= 0)\n' +
    '  last_commit_days Days since last commit (integer >= 0)\n' +
    '  in_registry      true/1 if listed in official MCP registry\n' +
    '  has_install_cmd  true/1 if a clear install command is documented\n' +
    '  critical_issues  Number of open critical issues (integer >= 0)\n' +
    '  license          (optional) SPDX identifier; non-OSI licenses incur -10\n'
  );
  process.exit(0);
}

// Require exactly 5 positional arguments
if (args.length < 5) {
  console.error(
    'Usage: node calculate_health.cjs <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues>\n' +
    'Run with --help for details.'
  );
  process.exit(1);
}

// --- Input parsing & validation ----------------------------------------

const stars = parseInt(args[0], 10);
const lastCommitDays = parseInt(args[1], 10);
const inRegistry = args[2] === 'true' || args[2] === '1';
const hasInstallCmd = args[3] === 'true' || args[3] === '1';
const criticalIssues = parseInt(args[4], 10);
const license = args[5];   // optional — undefined skips the license check

// SPDX identifiers for OSI-approved licenses commonly seen on npm/PyPI.
// Permissive + copyleft both count as OSI-approved (still open source).
const OSI_APPROVED = new Set([
  'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Unlicense',
  '0BSD', 'MPL-2.0', 'CC0-1.0', 'Zlib', 'Python-2.0', 'PostgreSQL',
  'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'AGPL-3.0-only', 'AGPL-3.0-or-later',
]);

// Validate that numeric fields parsed correctly and are non-negative
if (isNaN(stars) || stars < 0) {
  console.error('Error: <stars> must be a non-negative integer.');
  process.exit(1);
}
if (isNaN(lastCommitDays) || lastCommitDays < 0) {
  console.error('Error: <last_commit_days> must be a non-negative integer.');
  process.exit(1);
}
if (isNaN(criticalIssues) || criticalIssues < 0) {
  console.error('Error: <critical_issues> must be a non-negative integer.');
  process.exit(1);
}

// --- Scoring ---------------------------------------------------------------

// Popularity component: logarithmic so large star counts don't dominate the score.
// Adding 1 to stars avoids log10(0) = -Infinity for tools with zero stars.
// Capped at 20 so that mega-repos can't single-handedly push every entry into the
// Core tier (without the cap, an 85k-star monorepo scores 49+ on popularity alone).
const popularityScore = Math.min(20, 10 * Math.log10(stars + 1));

// Graduated recency bonus rewards freshly-maintained tools over stale ones
// while still giving partial credit for repos that were active within 6 months.
let recencyBonus = 0;
if (lastCommitDays < 30) {
  recencyBonus = 40; // Actively maintained
} else if (lastCommitDays < 90) {
  recencyBonus = 20; // Recently maintained
} else if (lastCommitDays < 180) {
  recencyBonus = 10; // Dormant but not dead
}
// >= 180 days: recencyBonus stays 0 (stale)

// Registry membership confirms the tool is vetted by the MCP project itself
const registryBonus = inRegistry ? 30 : 0;

// An install command is required for the tool to be usable in practice
const installBonus = hasInstallCmd ? 15 : 0;

// Penalize tools with too many unresolved critical issues
const issueBonus = criticalIssues < 5 ? 5 : 0;

// License penalty: -10 for source-available / proprietary / unknown licenses.
// Skipped entirely when the license argument is omitted (back-compat).
let licensePenalty = 0;
if (license !== undefined) {
  licensePenalty = OSI_APPROVED.has(license) ? 0 : -10;
}

const score = popularityScore + recencyBonus + registryBonus + installBonus + issueBonus + licensePenalty;

// --- Classification --------------------------------------------------------

/**
 * Map a raw health score to a human-readable tier label.
 * @param {number} s - The calculated health score
 * @returns {'Core'|'Recommended'|'Experimental'|'Deprecated'}
 */
function classify(s) {
  if (s >= 85) return 'Core';
  if (s >= 65) return 'Recommended';
  if (s >= 40) return 'Experimental';
  return 'Deprecated';
}

// --- Output ----------------------------------------------------------------

// Round to 2 decimal places for stable, readable output
const healthScore = Math.round(score * 100) / 100;

console.log(JSON.stringify({
  health_score: healthScore,
  classification: classify(healthScore),
  // Score breakdown helps callers understand which factors drive the result
  breakdown: {
    popularity: Math.round(popularityScore * 100) / 100,
    recency: recencyBonus,
    registry: registryBonus,
    install_cmd: installBonus,
    low_issues: issueBonus,
    license: licensePenalty,
  },
}, null, 2));
