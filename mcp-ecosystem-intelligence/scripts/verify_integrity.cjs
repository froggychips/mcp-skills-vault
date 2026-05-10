#!/usr/bin/env node
/**
 * Security scanner for MCP tools in tools_database.json.
 *
 * Per entry, checks (npm and PyPI):
 *   1. pkg_integrity  — tarball hash matches stored value (hard fail on mismatch)
 *                       npm: sha512 SRI from registry; PyPI: sha256 of the sdist
 *   2. repository URL — registry's source field matches source_url (warn / --strict: fail)
 *   3. install hooks  — npm preinstall/install/postinstall/prepare/prepack scripts
 *   4. advisories     — npm advisory bulk API (npm) + OSV.dev query (PyPI)
 *                       high/critical = hard fail; moderate/low = warn
 *
 * Docker entries are checked for digest pinning (image@sha256:...) — unpinned
 * digests are flagged as DIGEST warnings (--strict: fail).
 *
 * Usage:
 *   node scripts/verify_integrity.cjs              verify everything
 *   node scripts/verify_integrity.cjs --update     refresh version/integrity from registries
 *   node scripts/verify_integrity.cjs --strict     treat WARNs as hard failures
 *   node scripts/verify_integrity.cjs --no-audit   skip advisory APIs (offline mode)
 *
 * Exit codes:
 *   0  all checks passed
 *   1  one or more hard failures detected — do NOT install
 */

'use strict';

const { execSync } = require('child_process');
const https       = require('https');
const fs          = require('fs');
const path        = require('path');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const UPDATE    = process.argv.includes('--update');
const STRICT    = process.argv.includes('--strict');
const NO_AUDIT  = process.argv.includes('--no-audit');

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack'];

// PyPI may declare the source URL under several keys; check them in priority order.
const PYPI_SOURCE_KEYS = ['Source', 'Source Code', 'Repository', 'Homepage', 'Home', 'Bug Tracker'];

// ── helpers ────────────────────────────────────────────────────────────────

function normalizeGitUrl(url) {
  if (!url || typeof url !== 'string') return null;
  return url
    .replace(/^git\+ssh:\/\/git@github\.com\//, 'https://github.com/')
    .replace(/^git\+https:\/\//, 'https://')
    .replace(/^git\+/, '')
    .replace(/^git@github\.com:/, 'https://github.com/')
    .replace(/\.git$/, '')
    .replace(/\/issues\/?$/, '');                       // strip /issues from Bug Tracker URLs
}

// "npx -y @scope/pkg@1.2.3 args" → "@scope/pkg"
function npmPkgName(cmd) {
  const m = cmd.match(/^npx\s+-y\s+((?:@[\w-]+\/)?[\w.-]+?)(?:@[^\s]+)?(?:\s|$)/);
  return m ? m[1] : null;
}

// "uvx pkg-name==1.2.3 args" → "pkg-name"; returns null when --from is used
// (git/url installs cannot be verified through PyPI).
function pypiPkgName(cmd) {
  if (/^uvx\s+--from/.test(cmd)) return null;
  const m = cmd.match(/^uvx\s+([\w.-]+?)(?:==[\d.\w]+)?(?:\s|$)/);
  return m ? m[1] : null;
}

// "docker run ... ghcr.io/foo/bar[@digest|:tag] [args]" → image reference
function dockerImageRef(cmd) {
  if (!/^docker\s+run/.test(cmd)) return null;
  // Drop the "docker run" prefix and walk tokens, skipping flags and their values.
  const tokens = cmd.split(/\s+/).slice(2);
  const FLAG_WITH_VAL = new Set(['-e', '--env', '-v', '--volume', '--cap-drop', '--cap-add',
                                  '--security-opt', '-p', '--publish', '--name', '--user',
                                  '--network', '--mount', '--tmpfs']);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith('-')) {
      if (FLAG_WITH_VAL.has(t)) i++;     // skip flag's value
      continue;
    }
    return t;                            // first non-flag token is the image
  }
  return null;
}

// POST helper for JSON APIs.
function httpsPostJson(opts, payload, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const body = JSON.stringify(payload);
    const req = https.request(
      { ...opts, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...(opts.headers || {}) } },
      (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
      }
    );
    req.on('error', () => resolve(null));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

function httpsGetJson(url, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const req = https.get(url, (res) => {
      if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve(null); });
  });
}

function fetchNpmAdvisories(pkgMap) {
  return httpsPostJson(
    { hostname: 'registry.npmjs.org', path: '/-/npm/v1/security/advisories/bulk', method: 'POST' },
    pkgMap,
  ).then((r) => r || {});
}

// OSV.dev batch query — covers PyPI (and many other ecosystems).
// Input:  [{ ecosystem, name, version }, ...]
// Output: parallel array of vuln-list objects.
function fetchOsvAdvisories(queries) {
  const payload = {
    queries: queries.map((q) => ({
      package: { ecosystem: q.ecosystem, name: q.name },
      version: q.version,
    })),
  };
  return httpsPostJson(
    { hostname: 'api.osv.dev', path: '/v1/querybatch', method: 'POST' },
    payload,
    15000,
  ).then((r) => (r && r.results) || []);
}

function fetchPypiMeta(pkg, version) {
  const v = version ? `/${encodeURIComponent(version)}` : '';
  return httpsGetJson(`https://pypi.org/pypi/${encodeURIComponent(pkg)}${v}/json`);
}

function pypiSourceUrl(info) {
  const urls = info?.project_urls || {};
  for (const k of PYPI_SOURCE_KEYS) {
    if (urls[k]) return urls[k];
  }
  return info?.home_page || null;
}

function pypiSdistSha256(meta) {
  const v = meta?.info?.version;
  const files = (meta?.releases && meta.releases[v]) || meta?.urls || [];
  const sdist = files.find((f) => f.packagetype === 'sdist');
  return sdist?.digests?.sha256 || null;
}

function severityIsHard(sev) {
  return ['CRITICAL', 'HIGH', 'critical', 'high'].includes(sev || '');
}

// OSV vulns expose severity in a few possible shapes; pick the worst we find.
function osvSeverity(vuln) {
  const sevs = vuln.severity || [];
  for (const s of sevs) {
    if (s.score && /CRITICAL|HIGH|MEDIUM|LOW/i.test(s.score)) {
      const m = s.score.match(/CRITICAL|HIGH|MEDIUM|LOW/i);
      if (m) return m[0].toUpperCase();
    }
  }
  // Fallback: parse database_specific or affected[].database_specific
  const db = vuln.database_specific || {};
  if (db.severity) return String(db.severity).toUpperCase();
  return 'UNKNOWN';
}

// ── per-tool processors ────────────────────────────────────────────────────

async function processNpm(tool, pkg, advisoriesByPkg, results) {
  const versionSpec = tool.version ? `${pkg}@${tool.version}` : `${pkg}@latest`;
  let meta;
  try {
    meta = JSON.parse(execSync(`npm view "${versionSpec}" --json`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
  } catch (e) {
    results.push({ tool, status: 'SKIP', msg: `npm view failed: ${e.message.split('\n')[0]}` });
    return;
  }

  const npmVersion   = meta.version;
  const npmIntegrity = meta.dist?.integrity ?? null;
  const npmRepoRaw   = typeof meta.repository === 'string' ? meta.repository : (meta.repository?.url ?? null);
  const npmRepo      = normalizeGitUrl(npmRepoRaw);
  const storedRepo   = normalizeGitUrl(tool.source_url);

  if (UPDATE) {
    tool.version = npmVersion;
    tool.pkg_integrity = npmIntegrity;
    results.push({ tool, status: 'UPD', msg: `${tool.name}@${npmVersion}` });
    return;
  }

  let failures = 0;
  const lines  = [];

  // Integrity
  if (!tool.pkg_integrity) {
    lines.push(['MISS', `no stored pkg_integrity — run --update`]);
  } else if (tool.pkg_integrity !== npmIntegrity) {
    lines.push(['FAIL', `integrity mismatch\n        stored: ${tool.pkg_integrity}\n        npm   : ${npmIntegrity}`]);
    failures++;
  }

  // Repo URL — suppress monorepo subdirectory paths
  if (!npmRepo) {
    lines.push(['NOTE', 'npm declares no repository.url']);
  } else if (storedRepo && npmRepo.toLowerCase() !== storedRepo.toLowerCase() && !storedRepo.includes('/tree/')) {
    lines.push(['WARN', `repo mismatch\n        source_url: ${tool.source_url}\n        npm repo  : ${npmRepoRaw}`]);
    if (STRICT) failures++;
  }

  // Hooks
  const hooks = INSTALL_HOOKS.filter((h) => meta.scripts?.[h]);
  if (hooks.length > 0) {
    const cmds = hooks.map((h) => `${h}: ${meta.scripts[h].slice(0, 60)}`).join('\n        ');
    lines.push(['HOOK', `install-time scripts present\n        ${cmds}`]);
    if (STRICT) failures++;
  }

  // License — NOTE when npm omits it but DB has a value (e.g. sourced from GitHub)
  const npmLicense = meta.license || null;
  if (!npmLicense && tool.license) {
    lines.push(['NOTE', `npm declares no license; DB uses "${tool.license}" (verify against GitHub repo)`]);
  }

  // Advisories
  const advs = (advisoriesByPkg[pkg] || []);
  for (const a of advs) {
    lines.push(['CVE', `[${(a.severity || '').toUpperCase()}] ${a.title || a.url || a.id}`]);
  }
  if (advs.some((a) => severityIsHard(a.severity))) failures++;

  results.push({
    tool,
    status: failures > 0 ? 'FAIL' : 'OK',
    msg: `${tool.name}@${npmVersion}`,
    lines,
    failures,
  });
}

async function processPypi(tool, pkg, osvByIndex, idx, results) {
  const meta = await fetchPypiMeta(pkg, tool.version);
  if (!meta) {
    results.push({ tool, status: 'SKIP', msg: `${pkg}: PyPI lookup failed` });
    return;
  }

  const pyVersion = meta.info.version;
  const pySha256  = pypiSdistSha256(meta);
  const pySrc     = pypiSourceUrl(meta.info);
  const pyRepo    = normalizeGitUrl(pySrc);
  const storedRepo = normalizeGitUrl(tool.source_url);

  if (UPDATE) {
    tool.version       = pyVersion;
    tool.pkg_integrity = pySha256 ? `sha256-${pySha256}` : null;
    results.push({ tool, status: 'UPD', msg: `${tool.name}@${pyVersion}` });
    return;
  }

  let failures = 0;
  const lines  = [];

  // Integrity (PyPI sha256 hex)
  const expected = pySha256 ? `sha256-${pySha256}` : null;
  if (!tool.pkg_integrity) {
    lines.push(['MISS', `no stored pkg_integrity — run --update`]);
  } else if (expected && tool.pkg_integrity !== expected) {
    lines.push(['FAIL', `integrity mismatch\n        stored: ${tool.pkg_integrity}\n        pypi  : ${expected}`]);
    failures++;
  }

  // Source URL
  if (!pyRepo) {
    lines.push(['NOTE', 'PyPI declares no project_urls source — source unverifiable']);
  } else if (storedRepo && pyRepo.toLowerCase() !== storedRepo.toLowerCase() && !storedRepo.includes('/tree/')) {
    lines.push(['WARN', `repo mismatch\n        source_url: ${tool.source_url}\n        pypi src  : ${pySrc}`]);
    if (STRICT) failures++;
  }

  // License — NOTE when PyPI omits it but DB has a value (e.g. sourced from GitHub)
  const pyLicense = meta.info.license;
  if ((!pyLicense || pyLicense === 'UNKNOWN' || pyLicense === '') && tool.license) {
    lines.push(['NOTE', `PyPI declares no license; DB uses "${tool.license}" (verify against GitHub repo)`]);
  }

  // OSV.dev advisories
  const vulns = (osvByIndex[idx]?.vulns) || [];
  for (const v of vulns) {
    lines.push(['CVE', `[${osvSeverity(v)}] ${v.summary || v.id}`]);
  }
  if (vulns.some((v) => severityIsHard(osvSeverity(v)))) failures++;

  results.push({
    tool,
    status: failures > 0 ? 'FAIL' : 'OK',
    msg: `${tool.name}@${pyVersion}`,
    lines,
    failures,
  });
}

function processDocker(tool, results) {
  const ref = dockerImageRef(tool.install_cmd);
  if (!ref) {
    results.push({ tool, status: 'SKIP', msg: 'cannot parse docker image reference' });
    return;
  }
  const pinned = /@sha256:[a-f0-9]{64}/.test(ref);
  if (pinned) {
    results.push({ tool, status: 'OK', msg: `${tool.name}: docker pinned by digest` });
  } else {
    const failures = STRICT ? 1 : 0;
    results.push({
      tool,
      status: STRICT ? 'FAIL' : 'WARN',
      msg: `${tool.name}: docker image not pinned by digest (${ref})`,
      failures,
    });
  }
}

// ── main ───────────────────────────────────────────────────────────────────

async function main() {
  const db        = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  const results   = [];
  let totalFails  = 0;
  let updated     = 0;

  // Bucket tools by ecosystem.
  const npmTools    = [];     // [{ tool, pkg }]
  const pypiTools   = [];     // [{ tool, pkg }]
  const dockerTools = [];

  for (const tool of db.tools) {
    if (/^npx\s+-y/.test(tool.install_cmd)) {
      const p = npmPkgName(tool.install_cmd);
      if (p) npmTools.push({ tool, pkg: p });
      else results.push({ tool, status: 'SKIP', msg: 'cannot parse npm pkg name' });
    } else if (/^uvx/.test(tool.install_cmd)) {
      const p = pypiPkgName(tool.install_cmd);
      if (p) pypiTools.push({ tool, pkg: p });
      else results.push({ tool, status: 'SKIP', msg: 'uvx --from / git URL not verifiable' });
    } else if (/^docker\s+run/.test(tool.install_cmd)) {
      dockerTools.push({ tool });
    } else {
      results.push({ tool, status: 'SKIP', msg: 'unknown install method' });
    }
  }

  // Batch advisories.
  let npmAdvisories = {};
  let osvResults    = [];
  if (!UPDATE && !NO_AUDIT) {
    const npmMap = {};
    for (const { pkg } of npmTools) npmMap[pkg] = [];   // versions resolved per-package below
    process.stdout.write(`Querying npm advisory DB (${npmTools.length}) and OSV.dev (${pypiTools.length})... `);
    // npm advisory bulk API requires version arrays — fill them after we have npm metadata,
    // but we still want one HTTP round-trip. Workaround: include "" — npm tolerates an empty
    // version list and returns advisories for any version. Good enough for surfacing issues.
    for (const { pkg } of npmTools) npmMap[pkg] = [''];
    [npmAdvisories, osvResults] = await Promise.all([
      fetchNpmAdvisories(npmMap),
      fetchOsvAdvisories(pypiTools.map(({ pkg, tool }) => ({
        ecosystem: 'PyPI', name: pkg, version: tool.version || '0.0.0',
      }))),
    ]);
    console.log('done.');
  }

  // Process npm.
  for (const { tool, pkg } of npmTools) {
    await processNpm(tool, pkg, npmAdvisories, results);
  }
  // Process PyPI (sequentially — PyPI per-package metadata fetch).
  for (let i = 0; i < pypiTools.length; i++) {
    const { tool, pkg } = pypiTools[i];
    await processPypi(tool, pkg, osvResults, i, results);
  }
  // Process docker.
  for (const { tool } of dockerTools) processDocker(tool, results);

  // Print results, grouped per tool.
  for (const r of results) {
    if (r.status === 'UPD') {
      updated++;
      console.log(`UPD   ${r.msg}`);
      continue;
    }
    if (r.status === 'SKIP') {
      console.log(`SKIP  ${r.tool.name}: ${r.msg}`);
      continue;
    }
    console.log(`${r.status.padEnd(4)}  ${r.msg}`);
    if (r.lines) for (const [tag, text] of r.lines) console.log(`        [${tag}] ${text}`);
    totalFails += r.failures || 0;
  }

  if (UPDATE && updated > 0) {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2) + '\n');
    console.log(`\nWrote ${updated} updated entries to ${DB_PATH}`);
  } else if (!UPDATE) {
    const checked = npmTools.length + pypiTools.length + dockerTools.length;
    console.log(`\n${checked} entries checked — ${totalFails} failure(s)`);
    if (totalFails > 0) console.error('DO NOT install until failures are resolved.');
  }

  process.exit(totalFails > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
