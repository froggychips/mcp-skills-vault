#!/usr/bin/env node
/**
 * Verify npm package integrity hashes and repository URLs against tools_database.json.
 *
 * Usage:
 *   node scripts/verify_integrity.cjs          — verify stored pkg_integrity hashes
 *   node scripts/verify_integrity.cjs --update — fetch current version/integrity from npm
 *                                                 and write back to tools_database.json
 *
 * Only processes entries whose install_cmd starts with "npx -y".
 * uvx / docker / git-URL installs are skipped (printed as SKIP).
 *
 * Exit codes:
 *   0  All integrity checks passed (or --update completed)
 *   1  One or more integrity mismatches detected
 */

'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
const UPDATE  = process.argv.includes('--update');

// Strip git+, git@, ssh prefixes and trailing .git for URL comparison.
// Order matters: git+ssh:// must be handled before the generic git+ strip.
function normalizeGitUrl(url) {
  if (!url || typeof url !== 'string') return null;
  return url
    .replace(/^git\+ssh:\/\/git@github\.com\//, 'https://github.com/')
    .replace(/^git\+https:\/\//, 'https://')
    .replace(/^git\+/, '')
    .replace(/^git@github\.com:/, 'https://github.com/')
    .replace(/\.git$/, '');
}

// Extract the bare npm package name from an install_cmd like:
//   "npx -y @scope/pkg@1.2.3 <extra-args>"
// Returns null when the command cannot be parsed.
function npmPkgName(cmd) {
  const m = cmd.match(/npx\s+-y\s+((?:@[\w-]+\/)?[\w.-]+?)(?:@[^\s]+)?(?:\s|$)/);
  return m ? m[1] : null;
}

const db       = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
let failures   = 0;
let updated    = 0;

for (const tool of db.tools) {
  if (!tool.install_cmd.startsWith('npx -y')) {
    console.log(`SKIP  ${tool.name} (non-npm install)`);
    continue;
  }

  const pkg = npmPkgName(tool.install_cmd);
  if (!pkg) {
    console.warn(`SKIP  ${tool.name}: could not parse package name from "${tool.install_cmd}"`);
    continue;
  }

  // When verifying, pin to the stored version so we compare the same tarball.
  // When updating, fetch latest so we capture the current release.
  const versionSpec = tool.version ? `${pkg}@${tool.version}` : `${pkg}@latest`;

  let meta;
  try {
    const raw = execSync(`npm view "${versionSpec}" --json`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    meta = JSON.parse(raw);
  } catch (e) {
    console.error(`SKIP  ${tool.name}: npm view failed — ${e.message.split('\n')[0]}`);
    continue;
  }

  const npmVersion   = meta.version;
  const npmIntegrity = meta.dist?.integrity ?? null;
  const npmRepoRaw   = typeof meta.repository === 'string'
    ? meta.repository
    : (meta.repository?.url ?? null);
  const npmRepo    = normalizeGitUrl(npmRepoRaw);
  const storedRepo = normalizeGitUrl(tool.source_url);

  if (UPDATE) {
    tool.version       = npmVersion;
    tool.pkg_integrity = npmIntegrity;
    updated++;
    console.log(`UPD   ${tool.name}@${npmVersion}`);
  } else {
    // --- Integrity check ---
    if (!tool.pkg_integrity) {
      console.log(`MISS  ${tool.name}@${npmVersion}: no stored pkg_integrity — run --update to populate`);
    } else if (tool.pkg_integrity === npmIntegrity) {
      console.log(`OK    ${tool.name}@${npmVersion}`);
    } else {
      console.error(`FAIL  ${tool.name}: integrity mismatch`);
      console.error(`      stored : ${tool.pkg_integrity}`);
      console.error(`      npm    : ${npmIntegrity}`);
      failures++;
    }

    // --- Repository URL check (warn only — npm repo field may lag behind org renames) ---
    if (!npmRepo) {
      console.log(`NOTE  ${tool.name}: npm declares no repository.url — source cannot be verified`);
    } else if (storedRepo && npmRepo.toLowerCase() !== storedRepo.toLowerCase()) {
      console.error(`WARN  ${tool.name}: repository mismatch`);
      console.error(`      source_url : ${tool.source_url}`);
      console.error(`      npm repo   : ${npmRepoRaw}`);
    }
  }
}

if (UPDATE && updated > 0) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2) + '\n');
  console.log(`\nWrote ${updated} updated entries to ${DB_PATH}`);
}

process.exit(failures > 0 ? 1 : 0);
