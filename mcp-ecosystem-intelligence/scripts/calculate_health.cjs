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

'use strict';

// SPDX identifiers for OSI-approved licenses commonly seen on npm/PyPI.
// Permissive + copyleft both count as OSI-approved (still open source).
// Exported so other scripts (check_license_drift.cjs) can reuse the same
// classifier — single source of truth for what counts as "OSI".
//
// The bare GPL/LGPL/AGPL forms (e.g. "GPL-3.0") are what `gh api .license.spdx_id`
// returns; the "-only" / "-or-later" forms are the canonical SPDX variants used
// by npm/PyPI metadata. Both must resolve to OSI so callers don't have to
// normalize before scoring.
const OSI_APPROVED = new Set([
  'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Unlicense',
  '0BSD', 'MPL-2.0', 'CC0-1.0', 'Zlib', 'Python-2.0', 'PostgreSQL',
  'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later',
  'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'EPL-1.0', 'EPL-2.0',           // Eclipse — OSI-approved, was missing
  'CDDL-1.0', 'Artistic-2.0', 'BlueOak-1.0.0',
  // Boost Software License. NOT the same thing as BUSL-1.1 (Business Source
  // License), which is source-available and must keep classifying as
  // restrictive. The two ids are one character apart and "BSL" is used
  // colloquially for the Business one, so never fold them together.
  'BSL-1.0',
]);

// npm allows two non-SPDX values in the `license` field: a pointer to a
// bundled file, and an explicit refusal to grant a license. Neither means
// "source-available" — they mean a human has to go read something, which is
// `unknown`. Classifying them as restrictive is what pinned the license-drift
// gate red for @bitwarden/mcp-server ("SEE LICENSE IN LICENSE.txt").
const NPM_NON_SPDX = /^(SEE LICENSE IN\b|UNLICENSED$)/i;

// --- Pure scoring components -------------------------------------------

/**
 * Popularity component: logarithmic so large star counts don't dominate the score.
 * Adding 1 to stars avoids log10(0) = -Infinity for tools with zero stars.
 * Capped at 20 so that mega-repos can't single-handedly push every entry into the
 * Core tier (without the cap, an 85k-star monorepo scores 49+ on popularity alone).
 */
function popularityScoreOf(stars) {
  return Math.min(20, 10 * Math.log10(stars + 1));
}

/**
 * Graduated recency bonus rewards freshly-maintained tools over stale ones
 * while still giving partial credit for repos that were active within 6 months.
 */
function recencyBonusOf(lastCommitDays) {
  if (lastCommitDays < 30)  return 40; // Actively maintained
  if (lastCommitDays < 90)  return 20; // Recently maintained
  if (lastCommitDays < 180) return 10; // Dormant but not dead
  return 0;                            // Stale
}

/**
 * Classify an SPDX-like license string as one of:
 *   'osi'         — OSI-approved (MIT/Apache/BSD/ISC/MPL/GPL/LGPL/AGPL/…)
 *   'restrictive' — source-available / proprietary (BSL/SSPL/FSL/Elastic/Commons Clause/…)
 *   'unknown'     — null, undefined, empty, "Unknown", "NOASSERTION", or unrecognised
 *
 * Single source of truth for "is this license OSI?" — imported by both
 * licensePenaltyOf below and check_license_drift.cjs.
 */
function classifyLicense(license) {
  if (license === null || license === undefined) return 'unknown';
  const s = String(license).trim();
  if (s === '' || s === 'Unknown' || s === 'NOASSERTION' || s === 'UNKNOWN') return 'unknown';
  if (NPM_NON_SPDX.test(s)) return 'unknown';
  if (OSI_APPROVED.has(s)) return 'osi';
  const expr = classifySpdxExpression(s);
  if (expr) return expr;
  // Everything else that's a real string but not on the OSI list — treat as
  // restrictive. This catches BSL-1.1, SSPL-1.0, Elastic-2.0, FSL-1.1-ALv2,
  // FSL-1.1-MIT, Commons-Clause, ELv2, and any future relicensing token.
  return 'restrictive';
}

/**
 * Classify a compound SPDX expression, e.g. "(MIT OR Apache-2.0)" or
 * "EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0".
 *
 * Returns 'osi' | 'restrictive', or null when the string isn't an expression
 * (so the caller can fall through to its own default).
 *
 * Exact-string lookup treated every expression as restrictive, which is
 * backwards for the common case: a dual license is a *wider* offer, not a
 * narrower one. `A OR B` lets the recipient pick, so one OSI option is enough.
 * `A AND B` stacks obligations, so all of them must be OSI.
 *
 * `WITH <exception>` is dropped and the base license judged instead —
 * exceptions (Classpath, LLVM, GCC) only add permissions.
 *
 * Simplification, stated because it is one: expressions mixing OR and AND are
 * not evaluated by precedence. If any OR is present and any operand is OSI we
 * answer 'osi'. Mixed expressions are vanishingly rare in package metadata,
 * and the failure direction is the mild one — an over-permissive read here
 * shows up as a missing drift alert, not as a wrongful accusation of
 * relicensing. Revisit if a real case appears.
 */
function classifySpdxExpression(s) {
  if (!/[()]|\s(?:OR|AND|WITH)\s/i.test(s)) return null;

  const hasOr = /\sOR\s/i.test(s);
  const operands = s
    .replace(/[()]/g, ' ')
    .split(/\s+(?:OR|AND)\s+/i)
    .map(part => part.trim().split(/\s+WITH\s+/i)[0].trim())
    .filter(Boolean);

  if (operands.length === 0) return null;
  // A lone operand means the only token was a WITH exception or parentheses —
  // judge it directly rather than reporting a compound verdict.
  const kinds = operands.map(o => (OSI_APPROVED.has(o) ? 'osi' : 'restrictive'));
  if (hasOr) return kinds.includes('osi') ? 'osi' : 'restrictive';
  return kinds.every(k => k === 'osi') ? 'osi' : 'restrictive';
}

/**
 * License penalty: -10 for source-available / proprietary / unknown licenses.
 * Returns 0 when license is omitted (back-compat) or is OSI-approved.
 */
function licensePenaltyOf(license) {
  if (license === undefined) return 0;
  return classifyLicense(license) === 'osi' ? 0 : -10;
}

/**
 * Map a raw health score to a human-readable tier label.
 * @returns {'Core'|'Recommended'|'Experimental'|'Deprecated'}
 */
function classify(s) {
  if (s >= 85) return 'Core';
  if (s >= 65) return 'Recommended';
  if (s >= 40) return 'Experimental';
  return 'Deprecated';
}

/**
 * Full health-score computation. Pure function — no I/O.
 * @returns {{health_score:number, classification:string, breakdown:object}}
 */
function calculateHealth({ stars, lastCommitDays, inRegistry, hasInstallCmd, criticalIssues, license }) {
  const popularityScore = popularityScoreOf(stars);
  const recencyBonus    = recencyBonusOf(lastCommitDays);
  const registryBonus   = inRegistry ? 30 : 0;
  const installBonus    = hasInstallCmd ? 15 : 0;
  const issueBonus      = criticalIssues < 5 ? 5 : 0;
  const licensePenalty  = licensePenaltyOf(license);

  const score = popularityScore + recencyBonus + registryBonus + installBonus + issueBonus + licensePenalty;
  // Round to 2 decimal places for stable, readable output
  const healthScore = Math.round(score * 100) / 100;

  return {
    health_score: healthScore,
    classification: classify(healthScore),
    breakdown: {
      popularity: Math.round(popularityScore * 100) / 100,
      recency: recencyBonus,
      registry: registryBonus,
      install_cmd: installBonus,
      low_issues: issueBonus,
      license: licensePenalty,
    },
  };
}

// --- CLI entry point -------------------------------------------------------

function main() {
  const args = process.argv.slice(2);

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

  if (args.length < 5) {
    console.error(
      'Usage: node calculate_health.cjs <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues>\n' +
      'Run with --help for details.'
    );
    process.exit(1);
  }

  const stars          = parseInt(args[0], 10);
  const lastCommitDays = parseInt(args[1], 10);
  const inRegistry     = args[2] === 'true' || args[2] === '1';
  const hasInstallCmd  = args[3] === 'true' || args[3] === '1';
  const criticalIssues = parseInt(args[4], 10);
  const license        = args[5];   // optional — undefined skips the license check

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

  const result = calculateHealth({ stars, lastCommitDays, inRegistry, hasInstallCmd, criticalIssues, license });
  console.log(JSON.stringify(result, null, 2));
}

if (require.main === module) {
  main();
}

module.exports = {
  OSI_APPROVED,
  popularityScoreOf,
  recencyBonusOf,
  classifyLicense,
  classifySpdxExpression,
  licensePenaltyOf,
  classify,
  calculateHealth,
  // legacy alias for callers written against an earlier C2 draft
  computeHealth: calculateHealth,
};
