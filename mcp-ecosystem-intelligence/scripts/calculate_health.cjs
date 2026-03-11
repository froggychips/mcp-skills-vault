/**
 * Calculate the Health Score for an MCP tool based on the specified formula.
 * Formula:
 * Health Score = 10 × log10(stars + 1) 
 *                + 40 (if last_commit < 30 days) 
 *                + 30 (if present in official registry) 
 *                + 15 (if install command exists) 
 *                + 5 (if critical issues < 5)
 */

const args = process.argv.slice(2);
if (args.length < 5) {
  console.log("Usage: node calculate_health.cjs <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues>");
  process.exit(1);
}

const stars = parseInt(args[0], 10);
const lastCommitDays = parseInt(args[1], 10);
const inRegistry = args[2] === 'true' || args[2] === '1';
const hasInstallCmd = args[3] === 'true' || args[3] === '1';
const criticalIssues = parseInt(args[4], 10);

let score = 10 * Math.log10(stars + 1);

if (lastCommitDays < 30) {
  score += 40;
}

if (inRegistry) {
  score += 30;
}

if (hasInstallCmd) {
  score += 15;
}

if (criticalIssues < 5) {
  score += 5;
}

console.log(JSON.stringify({
  health_score: Math.round(score * 100) / 100,
  classification: score >= 85 ? "Core" : score >= 65 ? "Recommended" : score >= 40 ? "Experimental" : "Deprecated"
}, null, 2));
