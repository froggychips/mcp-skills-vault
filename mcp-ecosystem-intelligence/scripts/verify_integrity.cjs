#!/usr/bin/env node
/**
 * Security scanner for MCP tools in tools_database.json.
 *
 * Per entry, checks (npm and PyPI):
 *   1. pkg_integrity  — tarball hash matches stored value (hard fail on mismatch)
 *                       npm: sha512 SRI from registry; PyPI: sha256 of the sdist
 *   2. repository URL — registry's source field matches source_url (warn / --strict: fail)
 *   3. install hooks  — npm preinstall/install/postinstall/prepare/prepack scripts
 *   4. advisories     — four feeds, merged and deduplicated:
 *                         • npm advisory bulk API (npm)
 *                         • OSV.dev /v1/querybatch (npm + PyPI)
 *                         • GitHub Advisory Database REST (npm + PyPI; uses
 *                           GITHUB_TOKEN if present, else 60 req/hr anon)
 *                         • Snyk OSS (npm + PyPI; only when SNYK_TOKEN is set)
 *                       high/critical = hard fail; moderate/low = warn
 *
 * Docker entries are checked for digest pinning (image@sha256:...) — unpinned
 * digests are flagged as DIGEST warnings (--strict: fail).
 *
 * Usage:
 *   node scripts/verify_integrity.cjs              verify everything
 *   node scripts/verify_integrity.cjs --update     refresh version/integrity from registries
 *   node scripts/verify_integrity.cjs --strict     treat WARNs as hard failures
 *   node scripts/verify_integrity.cjs --no-audit   skip advisory APIs; still checks live registries
 *   node scripts/verify_integrity.cjs --offline    true offline mode; validate DB pins only
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
const { writeDb } = require('./lib/db_io.cjs');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const UPDATE    = process.argv.includes('--update');
const STRICT    = process.argv.includes('--strict');
const NO_AUDIT  = process.argv.includes('--no-audit');
const OFFLINE   = process.argv.includes('--offline');

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
        if (res.statusCode < 200 || res.statusCode >= 300) { res.resume(); resolve(null); return; }
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

function httpsGetJson(url, timeoutMs = 10000, headers = {}) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const req = https.get(
      { hostname: u.hostname, path: u.pathname + u.search, headers },
      (res) => {
        if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
      },
    );
    req.on('error', () => resolve(null));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve(null); });
  });
}

function fetchNpmAdvisories(pkgMap) {
  return httpsPostJson(
    { hostname: 'registry.npmjs.org', path: '/-/npm/v1/security/advisories/bulk', method: 'POST' },
    pkgMap,
  ).then((r) => ({ ok: r !== null, data: r || {} }));
}

// OSV.dev batch query — covers npm, PyPI, and ~30 other ecosystems.
// Aggregates from GHSA, PyPA, RustSec, Go, OSS-Fuzz, etc. — but with a lag,
// which is why we *also* call GHSA REST directly.
// Input:  [{ ecosystem, name, version }, ...]
// Output: parallel array of vuln-list objects.
function fetchOsvAdvisories(queries) {
  if (!queries.length) return Promise.resolve({ ok: true, data: [] });
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
  ).then((r) => ({ ok: r !== null, data: (r && r.results) || [] }));
}

// GitHub Advisory Database (public REST). One request per (ecosystem, pkg).
// Anonymous rate limit is 60/hr — the DB now exceeds that (112+ entries), so a
// tokenless run WILL hit 403 partway through; CI passes GITHUB_TOKEN via env to
// raise the limit to 5000/hr. A 403/timeout/5xx for a package surfaces as an
// UNVERIFIED result for that package (data[key] === null), NOT a silent "no
// advisories" — see degradedFeedsFor() and the fail-closed-under-strict path.
// Filters by `pkg@version` server-side so we only get advisories that affect the
// *pinned* version — without this, the endpoint returns every advisory in the
// package's history regardless of whether the pinned version is patched (was the
// root cause of the false-positive batch in the first GHSA rollout).
//
// OSV.dev already pulls GHSA, but with a lag (hours-to-days). Hitting GHSA
// directly closes the window for freshly-disclosed advisories.
//
// Returns: { ok, failures, data: { "npm:pkg": [advisory,...] | null, ... } }
//   data[key] === null → feed unreachable for that pkg (degraded, not "clean")
//   data[key] === []   → queried OK, no advisory affects the pinned version
async function fetchGhsaAdvisories(queries) {
  if (!queries.length) return { ok: true, data: {}, failures: 0 };
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    'User-Agent':           'mcp-skills-vault/verify_integrity.cjs',
    'Accept':               'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
  };
  const out = {};
  let failures = 0;
  for (const q of queries) {
    // GHSA ecosystem codes: "npm", "pip" (PyPI), "rubygems", "maven", "go", …
    const ecoCode = q.ecosystem === 'PyPI' ? 'pip' : q.ecosystem;
    const key = `${ecoCode}:${q.name}`;
    // affects=pkg@version → server-side filter to only advisories that the
    // pinned version is actually inside the vulnerable range of. If version
    // is unknown, fall back to the pkg-wide query (caller's problem to triage).
    const affects = q.version ? `${q.name}@${q.version}` : q.name;
    const url = `https://api.github.com/advisories?ecosystem=${encodeURIComponent(ecoCode)}&affects=${encodeURIComponent(affects)}&per_page=20`;
    const advs = await httpsGetJson(url, 10000, headers);
    if (advs === null)        { out[key] = null; failures++; continue; }  // unreachable: network / 403 rate-limit / 5xx
    if (!Array.isArray(advs)) { out[key] = [];               continue; }  // 200 but unexpected shape → no advisories
    out[key] = advs.map((a) => ({
      id:       a.ghsa_id,
      url:      a.html_url,
      severity: (a.severity || '').toUpperCase(),
      title:    a.summary,
      source:   'GHSA',
    }));
  }
  return { ok: failures === 0, data: out, failures };
}

// Snyk does not expose a public anonymous API. With SNYK_TOKEN, query the
// commercial endpoint. Without it, we return {} and surface a NOTE — the
// hook is here so users with a paid plan get coverage; we don't pretend to
// have it for free.
async function fetchSnykAdvisories(queries) {
  if (!queries.length) return { ok: true, data: {}, skipped: false, failures: 0 };
  const token = process.env.SNYK_TOKEN;
  if (!token) return { ok: true, data: {}, skipped: 'SNYK_TOKEN not set', failures: 0 };
  const out = {};
  let failures = 0;
  const headers = {
    'Authorization': `token ${token}`,
    'User-Agent':    'mcp-skills-vault/verify_integrity.cjs',
  };
  for (const q of queries) {
    const eco = q.ecosystem === 'PyPI' ? 'pip' : q.ecosystem;
    const key = `${eco}:${q.name}`;
    const url = `https://api.snyk.io/v1/test/${encodeURIComponent(eco)}/${encodeURIComponent(q.name)}/${encodeURIComponent(q.version || '0.0.0')}`;
    const data = await httpsGetJson(url, 10000, headers);
    if (data === null) { out[key] = null; failures++; continue; }  // unreachable
    const vulns = (data?.issues?.vulnerabilities || []);
    out[key] = vulns.map((v) => ({
      id:       v.id,
      url:      v.url,
      severity: (v.severity || '').toUpperCase(),
      title:    v.title,
      source:   'Snyk',
    }));
  }
  return { ok: failures === 0, data: out, skipped: false, failures };
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

// Merge advisories from npm + OSV + GHSA + Snyk into a unified array per
// package, deduplicated by ID (GHSA shares IDs with OSV — keep one).
// Unified shape: { id, severity, title, url, source }.
function unifyAdvisories({ npmList, osvList, ghsaList, snykList }) {
  const seen = new Set();
  const out  = [];
  const push = (a) => {
    const key = a.id || `${a.source}:${a.title || a.url}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(a);
  };
  for (const a of (npmList || [])) {
    push({
      id:       a.id || a.url,
      severity: (a.severity || '').toUpperCase(),
      title:    a.title || a.url,
      url:      a.url,
      source:   'npm',
    });
  }
  for (const v of (osvList || [])) {
    push({
      id:       v.id,
      severity: osvSeverity(v),
      title:    v.summary || v.id,
      url:      v.id ? `https://osv.dev/vulnerability/${v.id}` : null,
      source:   'OSV',
    });
  }
  for (const a of (ghsaList || [])) push(a);
  for (const a of (snykList || [])) push(a);
  return out;
}

// ── feed-health adjudication ─────────────────────────────────────────────────
// The four advisory feeds resolve to null on any failure (network, timeout,
// non-2xx, unparseable body, GHSA 403 rate-limit). A null MUST NOT be silently
// coalesced into "no advisories" — for a supply-chain gate that is fail-open: a
// transient outage would read as "clean, safe to install". These helpers
// distinguish "feed unreachable" (null) from "queried, nothing found" ([]).

// Advisory feeds that were UNREACHABLE for a given (ecosystem, mapKey).
// Snyk-without-token is an intentional skip, not a degradation.
function degradedFeedsFor(ecosystem, mapKey, health) {
  const out = [];
  if (ecosystem === 'npm') {
    if (!health.npm.ok)    out.push('npm');
    if (!health.osvNpm.ok) out.push('OSV.dev');
  } else {
    if (!health.osvPypi.ok) out.push('OSV.dev');
  }
  if (health.ghsa.data[mapKey] === null) out.push('GHSA');
  if (!health.snyk.skipped && health.snyk.data[mapKey] === null) out.push('Snyk');
  return out;
}

// Human-readable per-feed status for the run banner. Reflects what actually
// happened on the wire, not a static list of feed names.
function summarizeFeedSources(health) {
  const s = [];
  s.push(health.npm.ok ? 'npm bulk' : 'npm bulk UNAVAILABLE');
  s.push((health.osvNpm.ok && health.osvPypi.ok) ? 'OSV.dev' : 'OSV.dev UNAVAILABLE');
  if (health.ghsa.failures > 0) {
    s.push(`GHSA (${health.ghsa.failures} pkg unreachable — set GITHUB_TOKEN to lift the 60/hr anon limit)`);
  } else {
    s.push('GHSA');
  }
  if (health.snyk.skipped) s.push(`Snyk skipped (${health.snyk.skipped})`);
  else                     s.push(health.snyk.ok ? 'Snyk' : 'Snyk UNAVAILABLE');
  return s;
}

// ── per-tool processors ────────────────────────────────────────────────────

async function processNpm(tool, pkg, advisoriesForTool, degraded, results) {
  if (OFFLINE) {
    processOfflinePackage(tool, pkg, 'npm', results);
    return;
  }
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

  // Advisories (merged: npm + OSV + GHSA + Snyk)
  for (const a of advisoriesForTool) {
    lines.push(['CVE', `[${a.severity}] (${a.source}) ${a.title || a.url || a.id}`]);
  }
  if (advisoriesForTool.some((a) => severityIsHard(a.severity))) failures++;

  // Unreachable advisory feeds: we cannot assert "no known CVEs" when a feed was
  // down. Surface it loudly; hard-fail under --strict (never silently pass).
  if (degraded.length) {
    lines.push(['UNVERIFIED', `advisory feeds unreachable: ${degraded.join(', ')} — cannot assert "no known CVEs"${STRICT ? '' : ' (use --strict to fail closed)'}`]);
    if (STRICT) failures++;
  }

  results.push({
    tool,
    status: failures > 0 ? 'FAIL' : 'OK',
    msg: `${tool.name}@${npmVersion}`,
    lines,
    failures,
  });
}

async function processPypi(tool, pkg, advisoriesForTool, degraded, results) {
  if (OFFLINE) {
    processOfflinePackage(tool, pkg, 'PyPI', results);
    return;
  }
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

  // Advisories (merged: OSV + GHSA + Snyk; npm bulk doesn't cover PyPI)
  for (const a of advisoriesForTool) {
    lines.push(['CVE', `[${a.severity}] (${a.source}) ${a.title || a.url || a.id}`]);
  }
  if (advisoriesForTool.some((a) => severityIsHard(a.severity))) failures++;

  // Unreachable advisory feeds: we cannot assert "no known CVEs" when a feed was
  // down. Surface it loudly; hard-fail under --strict (never silently pass).
  if (degraded.length) {
    lines.push(['UNVERIFIED', `advisory feeds unreachable: ${degraded.join(', ')} — cannot assert "no known CVEs"${STRICT ? '' : ' (use --strict to fail closed)'}`]);
    if (STRICT) failures++;
  }

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

function processOfflinePackage(tool, pkg, ecosystem, results) {
  let failures = 0;
  const lines = [];

  if (!tool.version) {
    lines.push(['MISS', 'no pinned version in DB']);
    if (STRICT) failures++;
  }
  if (!tool.pkg_integrity) {
    lines.push(['MISS', 'no stored pkg_integrity — cannot compare without network']);
    if (STRICT) failures++;
  }
  if (!tool.source_url) {
    lines.push(['NOTE', 'no source_url in DB']);
  }

  const pin = tool.version ? `@${tool.version}` : '@?';
  results.push({
    tool,
    status: failures > 0 ? 'FAIL' : 'OK',
    msg: `${tool.name}${pin} (${ecosystem} offline pin present for ${pkg})`,
    lines,
    failures,
  });
}

// ── main ───────────────────────────────────────────────────────────────────

async function main() {
  if (OFFLINE && UPDATE) {
    console.error('--offline cannot be combined with --update (refresh requires registries).');
    process.exit(2);
  }

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

  // Batch advisories across 4 feeds: npm bulk + OSV.dev + GHSA REST + Snyk.
  // npm bulk covers npm only. OSV covers npm + PyPI. GHSA covers both directly
  // (less lag than OSV's aggregation). Snyk requires SNYK_TOKEN (optional).
  // Feed-health objects: each is { ok, data, ... }. ok=false (or a per-pkg null
  // in data) means the feed was unreachable — surfaced as UNVERIFIED, never
  // silently treated as "no advisories". See degradedFeedsFor()/summarizeFeedSources().
  let npmAdvisories = { ok: true, data: {} };
  let osvNpm        = { ok: true, data: [] };
  let osvPypi       = { ok: true, data: [] };
  let ghsa          = { ok: true, data: {}, failures: 0 };
  let snyk          = { ok: true, data: {}, skipped: false, failures: 0 };
  if (!UPDATE && !NO_AUDIT && !OFFLINE) {
    const npmMap = {};
    for (const { pkg } of npmTools) npmMap[pkg] = [''];   // npm tolerates empty version array
    const npmQueries  = npmTools.map(({ pkg, tool })  => ({ ecosystem: 'npm',  name: pkg, version: tool.version || '0.0.0' }));
    const pypiQueries = pypiTools.map(({ pkg, tool }) => ({ ecosystem: 'PyPI', name: pkg, version: tool.version || '0.0.0' }));
    const allQueries  = [...npmQueries, ...pypiQueries];
    process.stdout.write(`Querying npm bulk (${npmTools.length}), OSV.dev (${allQueries.length}), GHSA (${allQueries.length}), Snyk... `);
    [npmAdvisories, osvNpm, osvPypi, ghsa, snyk] = await Promise.all([
      fetchNpmAdvisories(npmMap),
      fetchOsvAdvisories(npmQueries),
      fetchOsvAdvisories(pypiQueries),
      fetchGhsaAdvisories(allQueries),
      fetchSnykAdvisories(allQueries),
    ]);
    console.log(`done — sources: ${summarizeFeedSources({ npm: npmAdvisories, osvNpm, osvPypi, ghsa, snyk }).join(', ')}.`);
  }
  const health = { npm: npmAdvisories, osvNpm, osvPypi, ghsa, snyk };

  // Process npm.
  if (OFFLINE) {
    console.log('Offline mode: validating stored pins only; no registry/advisory network calls.');
  } else if (NO_AUDIT && !UPDATE) {
    console.log('No-audit mode: checking live registry metadata; advisory feeds skipped.');
  }

  // Process npm.
  for (let i = 0; i < npmTools.length; i++) {
    const { tool, pkg } = npmTools[i];
    // null (feed down) coalesces to [] for the merge, but degradedFeedsFor() reads
    // the raw null below so the outage is reported rather than read as "clean".
    const advs = unifyAdvisories({
      npmList:  npmAdvisories.data[pkg] || [],
      osvList:  osvNpm.data[i]?.vulns || [],
      ghsaList: ghsa.data[`npm:${pkg}`] || [],
      snykList: snyk.data[`npm:${pkg}`] || [],
    });
    const degraded = (UPDATE || NO_AUDIT) ? [] : degradedFeedsFor('npm', `npm:${pkg}`, health);
    await processNpm(tool, pkg, advs, degraded, results);
  }
  // Process PyPI (sequentially — PyPI per-package metadata fetch).
  for (let i = 0; i < pypiTools.length; i++) {
    const { tool, pkg } = pypiTools[i];
    const advs = unifyAdvisories({
      npmList:  [],
      osvList:  osvPypi.data[i]?.vulns || [],
      ghsaList: ghsa.data[`pip:${pkg}`] || [],
      snykList: snyk.data[`pip:${pkg}`] || [],
    });
    const degraded = (UPDATE || NO_AUDIT) ? [] : degradedFeedsFor('PyPI', `pip:${pkg}`, health);
    await processPypi(tool, pkg, advs, degraded, results);
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
    writeDb(DB_PATH, db);
    console.log(`\nWrote ${updated} updated entries to ${DB_PATH}`);
  } else if (!UPDATE) {
    const checked = Array.isArray(db.tools) ? db.tools.length : (npmTools.length + pypiTools.length + dockerTools.length);
    console.log(`\n${checked} entries checked — ${totalFails} failure(s)`);
    if (totalFails > 0) console.error('DO NOT install until failures are resolved.');
  }

  process.exit(totalFails > 0 ? 1 : 0);
}

if (require.main === module) {
  main().catch((e) => { console.error(e.message); process.exit(1); });
}

module.exports = {
  normalizeGitUrl,
  npmPkgName,
  pypiPkgName,
  dockerImageRef,
  severityIsHard,
  osvSeverity,
  unifyAdvisories,
  degradedFeedsFor,
  summarizeFeedSources,
};
