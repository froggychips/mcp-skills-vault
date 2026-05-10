#!/usr/bin/env node
/**
 * Refresh GitHub metrics (stars, last_commit_days, open_issues) and
 * recalculate health_score + classification for all DB entries that
 * have a github.com source_url.
 *
 * Requires: gh CLI authenticated (`gh auth status`)
 *
 * Usage:
 *   node scripts/refresh_scores.cjs              dry-run (prints diff, no write)
 *   node scripts/refresh_scores.cjs --write      write changes to tools_database.json
 *
 * Exit codes:
 *   0  success
 *   1  gh CLI not found or not authenticated
 */

'use strict';

const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

const DB_PATH  = path.resolve(__dirname, '../assets/tools_database.json');
const CALC     = path.resolve(__dirname, 'calculate_health.cjs');
const WRITE    = process.argv.includes('--write');
const TODAY    = new Date().toISOString().slice(0, 10);

// ── helpers ────────────────────────────────────────────────────────────────

// GitHub uses short GPL/LGPL/AGPL SPDX IDs (e.g. "GPL-3.0") that differ from
// canonical SPDX ("GPL-3.0-only" / "GPL-3.0-or-later"). Normalize to the
// "-or-later" variant since that is how GitHub intends them.
// "NOASSERTION" means GitHub couldn't auto-detect the license — fall back to
// the stored DB value rather than applying a wrongful penalty.
const GITHUB_SPDX_MAP = {
  'GPL-2.0':  'GPL-2.0-or-later',
  'GPL-3.0':  'GPL-3.0-or-later',
  'LGPL-2.0': 'LGPL-2.0-or-later',
  'LGPL-2.1': 'LGPL-2.1-or-later',
  'LGPL-3.0': 'LGPL-3.0-or-later',
  'AGPL-3.0': 'AGPL-3.0-or-later',
};

function normalizeLicense(githubSpdx, fallback) {
  if (!githubSpdx || githubSpdx === 'NOASSERTION') return fallback || '';
  return GITHUB_SPDX_MAP[githubSpdx] || githubSpdx;
}

function ghApi(endpoint) {
  try {
    return JSON.parse(execSync(`gh api "${endpoint}"`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  } catch {
    return null;
  }
}

function calcScore(stars, days, inRegistry, hasInstall, critIssues, license) {
  try {
    const out = execSync(
      `node "${CALC}" ${stars} ${days} ${inRegistry} ${hasInstall} ${critIssues} ${license || ''}`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    return JSON.parse(out);
  } catch {
    return null;
  }
}

// Extract owner/repo from a github.com URL, stripping /tree/... paths.
function githubOwnerRepo(url) {
  if (!url || !url.includes('github.com')) return null;
  const m = url.match(/github\.com\/([^/]+\/[^/]+?)(?:\/|$)/);
  return m ? m[1] : null;
}

function daysSince(isoDate) {
  return Math.floor((Date.now() - new Date(isoDate).getTime()) / 86400000);
}

// ── main ───────────────────────────────────────────────────────────────────

// Verify gh is available and authenticated.
try {
  execSync('gh auth status', { stdio: 'pipe' });
} catch {
  console.error('gh CLI not found or not authenticated. Run: gh auth login');
  process.exit(1);
}

const db      = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
const changed = [];
let   skipped = 0;

for (const tool of db.tools) {
  const repo = githubOwnerRepo(tool.source_url);
  if (!repo) {
    console.log(`SKIP  ${tool.name}: no github.com source_url`);
    skipped++;
    continue;
  }

  process.stdout.write(`FETCH ${repo} ... `);
  const meta = ghApi(`repos/${repo}`);
  if (!meta) {
    console.log('FAIL (gh api error)');
    skipped++;
    continue;
  }

  const stars    = meta.stargazers_count ?? tool.stars;
  const days     = daysSince(meta.pushed_at);
  const issues   = meta.open_issues_count ?? tool.open_issues;
  const critIss  = Math.floor(issues / 10);
  const license  = normalizeLicense(meta.license?.spdx_id, tool.license);

  const result = calcScore(stars, days, tool.in_registry, true, critIss, license);
  if (!result) {
    console.log('FAIL (score calc error)');
    skipped++;
    continue;
  }

  const prev = {
    stars:            tool.stars,
    last_commit_days: tool.last_commit_days,
    open_issues:      tool.open_issues,
    health_score:     tool.health_score,
    classification:   tool.classification,
  };

  tool.stars            = stars;
  tool.last_commit_days = days;
  tool.open_issues      = issues;
  tool.health_score     = result.health_score;
  tool.classification   = result.classification;
  tool.last_checked     = TODAY;

  const diff = [];
  if (prev.stars            !== stars)                   diff.push(`stars ${prev.stars}→${stars}`);
  if (prev.last_commit_days !== days)                    diff.push(`days ${prev.last_commit_days}→${days}`);
  if (prev.open_issues      !== issues)                  diff.push(`issues ${prev.open_issues}→${issues}`);
  if (prev.health_score     !== result.health_score)     diff.push(`score ${prev.health_score}→${result.health_score}`);
  if (prev.classification   !== result.classification)   diff.push(`tier ${prev.classification}→${result.classification}`);

  if (diff.length > 0) {
    console.log(diff.join(', '));
    changed.push(tool.name);
  } else {
    console.log('no change');
  }
}

console.log(`\n${changed.length} changed, ${skipped} skipped`);

if (changed.length > 0) {
  if (WRITE) {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2) + '\n');
    console.log(`Wrote ${DB_PATH}`);
  } else {
    console.log('Dry-run — pass --write to apply changes');
  }
}
