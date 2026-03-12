/**
 * Calculate the Health Score for an MCP tool based on the specified formula.
 *
 * Formula:
 *   Health Score = 10 × log10(stars + 1)          [0–∞,  popularity component]
 *                + recency bonus                   [0–40, how recently maintained]
 *                + 30 (if present in official registry)
 *                + 15 (if install command exists)
 *                + 5  (if critical issues < 5)
 *
 * Recency bonus (graduated to reward freshness, not just a binary cutoff):
 *   40  – last commit < 30 days   (actively maintained)
 *   20  – last commit < 90 days   (recently maintained)
 *   10  – last commit < 180 days  (dormant but alive)
 *   0   – last commit >= 180 days (stale)
 *
 * Classification thresholds:
 *   85–100 → Core
 *   65–84  → Recommended
 *   40–64  → Experimental
 *   <40    → Deprecated
 *
 * Usage:
 *   node calculate_health.cjs <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues>
 *
 * Examples:
 *   node calculate_health.cjs 1200 15 true true 2
 *   node calculate_health.cjs 50 200 false true 10
 */

const args = process.argv.slice(2);

// Print help when requested
if (args[0] === '--help' || args[0] === '-h') {
  console.log(
    'Usage: node calculate_health.cjs <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues>\n' +
    '\n' +
    'Arguments:\n' +
    '  stars            GitHub star count (integer >= 0)\n' +
    '  last_commit_days Days since last commit (integer >= 0)\n' +
    '  in_registry      true/1 if listed in official MCP registry\n' +
    '  has_install_cmd  true/1 if a clear install command is documented\n' +
    '  critical_issues  Number of open critical issues (integer >= 0)\n'
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
const popularityScore = 10 * Math.log10(stars + 1);

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

const score = popularityScore + recencyBonus + registryBonus + installBonus + issueBonus;

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
  },
}, null, 2));
