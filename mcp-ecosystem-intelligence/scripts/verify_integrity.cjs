#!/usr/bin/env node
/**
 * Security scanner for MCP tools in tools_database.json.
 *
 * Checks (npm-only, in order):
 *   1. pkg_integrity  — tarball sha512 matches stored hash (hard fail)
 *   2. repository URL — npm repository.url matches source_url (warn / --strict: fail)
 *   3. install hooks  — warns when preinstall/install/postinstall scripts are present
 *   4. advisories     — queries npm advisory bulk API for known CVEs
 *                       (high/critical = hard fail; moderate/low = warn)
 *   5. socket.dev     — optional deeper scan via @socketsecurity/cli (--socket flag)
 *
 * Usage:
 *   node scripts/verify_integrity.cjs              verify stored hashes + advisory scan
 *   node scripts/verify_integrity.cjs --update     fetch current version/integrity from npm
 *   node scripts/verify_integrity.cjs --socket     also run socket.dev CLI scan
 *   node scripts/verify_integrity.cjs --strict     treat WARNs as hard failures
 *   node scripts/verify_integrity.cjs --no-audit   skip advisory API call (offline mode)
 *
 * Exit codes:
 *   0  all checks passed
 *   1  one or more hard failures detected — do NOT install
 */

'use strict';

const { execSync }  = require('child_process');
const https         = require('https');
const fs            = require('fs');
const path          = require('path');

const DB_PATH    = path.resolve(__dirname, '../assets/tools_database.json');
const UPDATE     = process.argv.includes('--update');
const SOCKET     = process.argv.includes('--socket');
const STRICT     = process.argv.includes('--strict');
const NO_AUDIT   = process.argv.includes('--no-audit');

// npm lifecycle hooks that execute arbitrary code during `npm install` / `npx -y`
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack'];

// ── helpers ────────────────────────────────────────────────────────────────

function normalizeGitUrl(url) {
  if (!url || typeof url !== 'string') return null;
  return url
    .replace(/^git\+ssh:\/\/git@github\.com\//, 'https://github.com/')
    .replace(/^git\+https:\/\//, 'https://')
    .replace(/^git\+/, '')
    .replace(/^git@github\.com:/, 'https://github.com/')
    .replace(/\.git$/, '');
}

function npmPkgName(cmd) {
  const m = cmd.match(/npx\s+-y\s+((?:@[\w-]+\/)?[\w.-]+?)(?:@[^\s]+)?(?:\s|$)/);
  return m ? m[1] : null;
}

// Bulk advisory query: POST {"pkg": ["version"]} → {"pkg": [{severity,title,...}]}
function fetchAdvisories(pkgMap) {
  return new Promise((resolve) => {
    const body = JSON.stringify(pkgMap);
    const req = https.request(
      {
        hostname: 'registry.npmjs.org',
        path: '/-/npm/v1/security/advisories/bulk',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch { resolve({}); }
        });
      }
    );
    req.on('error', () => resolve({}));
    req.setTimeout(10000, () => { req.destroy(); resolve({}); });
    req.write(body);
    req.end();
  });
}

function label(tag) {
  const colors = { OK: '\x1b[32m', FAIL: '\x1b[31m', WARN: '\x1b[33m',
                   HOOK: '\x1b[33m', CVE: '\x1b[31m', SOCK: '\x1b[35m',
                   SKIP: '\x1b[90m', NOTE: '\x1b[90m', UPD: '\x1b[36m', MISS: '\x1b[33m' };
  const reset = '\x1b[0m';
  return `${colors[tag] || ''}${tag.padEnd(4)}${reset}`;
}

// ── main ────────────────────────────────────────────────────────────────────

async function main() {
  const db      = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  let failures  = 0;
  let updated   = 0;

  // ── pass 1: fetch npm metadata for all npm tools ──────────────────────────
  const npmTools = [];   // { tool, pkg, meta }
  const pkgMap   = {};   // { pkg: [version] } for advisory bulk query

  for (const tool of db.tools) {
    if (!tool.install_cmd.startsWith('npx -y')) {
      console.log(`${label('SKIP')}  ${tool.name} (non-npm install)`);
      continue;
    }

    const pkg = npmPkgName(tool.install_cmd);
    if (!pkg) {
      console.warn(`${label('SKIP')}  ${tool.name}: cannot parse package name from "${tool.install_cmd}"`);
      continue;
    }

    const versionSpec = tool.version ? `${pkg}@${tool.version}` : `${pkg}@latest`;
    let meta;
    try {
      const raw = execSync(`npm view "${versionSpec}" --json`, {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      meta = JSON.parse(raw);
    } catch (e) {
      console.error(`${label('SKIP')}  ${tool.name}: npm view failed — ${e.message.split('\n')[0]}`);
      continue;
    }

    npmTools.push({ tool, pkg, meta });
    pkgMap[pkg] = [meta.version];
  }

  // ── advisory bulk fetch (skip in update mode or --no-audit) ───────────────
  let advisories = {};
  if (!UPDATE && !NO_AUDIT && npmTools.length > 0) {
    process.stdout.write(`\nQuerying npm advisory database for ${npmTools.length} packages... `);
    advisories = await fetchAdvisories(pkgMap);
    console.log('done.\n');
  }

  // ── pass 2: verify / update each tool ────────────────────────────────────
  for (const { tool, pkg, meta } of npmTools) {
    const npmVersion   = meta.version;
    const npmIntegrity = meta.dist?.integrity ?? null;
    const npmRepoRaw   = typeof meta.repository === 'string'
      ? meta.repository
      : (meta.repository?.url ?? null);
    const npmRepo    = normalizeGitUrl(npmRepoRaw);
    const storedRepo = normalizeGitUrl(tool.source_url);

    // ── update mode ────────────────────────────────────────────────────────
    if (UPDATE) {
      tool.version       = npmVersion;
      tool.pkg_integrity = npmIntegrity;
      updated++;
      console.log(`${label('UPD')}   ${tool.name}@${npmVersion}`);
      continue;
    }

    // ── check 1: integrity ─────────────────────────────────────────────────
    if (!tool.pkg_integrity) {
      console.log(`${label('MISS')}  ${tool.name}@${npmVersion}: no stored pkg_integrity — run --update to populate`);
    } else if (tool.pkg_integrity === npmIntegrity) {
      console.log(`${label('OK')}    ${tool.name}@${npmVersion}: integrity ✓`);
    } else {
      console.error(`${label('FAIL')}  ${tool.name}: integrity mismatch`);
      console.error(`        stored : ${tool.pkg_integrity}`);
      console.error(`        npm    : ${npmIntegrity}`);
      failures++;
    }

    // ── check 2: repository URL ────────────────────────────────────────────
    if (!npmRepo) {
      console.log(`${label('NOTE')}  ${tool.name}: npm declares no repository.url — source unverifiable`);
    } else if (storedRepo && npmRepo.toLowerCase() !== storedRepo.toLowerCase()) {
      // Monorepo subdirectory references (…/tree/main/src/…) always differ from the
      // root repo URL that npm publishes — suppress those to reduce noise.
      const isMonorepoSubdir = storedRepo.includes('/tree/');
      if (!isMonorepoSubdir) {
        console.error(`${label('WARN')}  ${tool.name}: repository mismatch`);
        console.error(`        source_url : ${tool.source_url}`);
        console.error(`        npm repo   : ${npmRepoRaw}`);
        if (STRICT) failures++;
      }
    }

    // ── check 3: install-time hooks ────────────────────────────────────────
    const scripts     = meta.scripts || {};
    const foundHooks  = INSTALL_HOOKS.filter((h) => scripts[h]);
    if (foundHooks.length > 0) {
      const cmds = foundHooks.map((h) => `${h}: ${scripts[h].slice(0, 60)}`).join('\n        ');
      console.error(`${label('HOOK')}  ${tool.name}: install-time scripts present — review before running`);
      console.error(`        ${cmds}`);
      if (STRICT) failures++;
    }

    // ── check 4: npm advisory database ────────────────────────────────────
    const pkgAdvisories = advisories[pkg] || [];
    if (pkgAdvisories.length > 0) {
      for (const adv of pkgAdvisories) {
        const sev = (adv.severity || 'unknown').toUpperCase();
        console.error(`${label('CVE')}   ${tool.name}: [${sev}] ${adv.title || adv.url || adv.id}`);
      }
      const isHard = pkgAdvisories.some((a) => ['critical', 'high'].includes(a.severity));
      if (isHard) {
        failures++;
      }
    }

    // ── check 5: socket.dev (optional) ────────────────────────────────────
    if (SOCKET) {
      try {
        const out = execSync(
          `npx --yes @socketsecurity/cli info "${pkg}@${npmVersion}" 2>&1`,
          { encoding: 'utf8', timeout: 45000 }
        );
        // Non-zero exit already throws; if we're here the scan passed
        console.log(`${label('SOCK')}  ${tool.name}: socket.dev scan passed`);
      } catch (e) {
        const output = (e.stdout || e.message || '').slice(0, 300);
        console.error(`${label('SOCK')}  ${tool.name}: socket.dev flagged issues`);
        console.error(`        ${output.replace(/\n/g, '\n        ')}`);
        failures++;
      }
    }
  }

  // ── write back if updating ────────────────────────────────────────────────
  if (UPDATE && updated > 0) {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2) + '\n');
    console.log(`\nWrote ${updated} updated entries to ${DB_PATH}`);
  }

  // ── summary ───────────────────────────────────────────────────────────────
  if (!UPDATE) {
    const checked = npmTools.length;
    console.log(`\n${checked} packages checked — ${failures} failure(s)`);
    if (failures > 0) {
      console.error('DO NOT install until failures are resolved.');
    }
  }

  process.exit(failures > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
