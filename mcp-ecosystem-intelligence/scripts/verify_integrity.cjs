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
 *   node scripts/verify_integrity.cjs --entry NAME  check a single DB entry by name
 *   node scripts/verify_integrity.cjs --fail-unverified  UNVERIFIED → hard failure
 *   node scripts/verify_integrity.cjs --deep       download artifacts and hash them locally
 *   node scripts/verify_integrity.cjs --require-signatures  unsigned npm release = failure
 *   node scripts/verify_integrity.cjs --require-provenance  no provenance attestation = failure
 *   node scripts/verify_integrity.cjs --json       structured report on stdout
 *   node scripts/verify_integrity.cjs --sarif      SARIF 2.1.0 (GitHub code scanning)
 *
 * Exit codes:
 *   0  all checks passed
 *   1  one or more hard failures detected — do NOT install
 *   2  bad arguments (unknown --entry, --offline with --update)
 *
 * A registry that cannot be reached is UNVERIFIED, never OK: the gate can only
 * assert an artifact matches its pin when it has actually seen the artifact.
 * Callers that must not proceed on a maybe (`orchestrate --install`) pass
 * --fail-unverified, which turns every UNVERIFIED into a hard failure.
 */

'use strict';

const { getJson, postJson, mapLimit } = require('./lib/http.cjs');
const { hashUrl, sriEqual, parseSri, ociManifestDigest } = require('./lib/artifact.cjs');
const { parseImageRef, fetchManifest, ALLOWED_REGISTRIES } = require('./lib/oci.cjs');
const {
  verifyRegistrySignature, provenanceClaim, keysUrl,
} = require('./lib/npm_signatures.cjs');
const https       = require('https');
const fs          = require('fs');
const path        = require('path');
const { writeDb } = require('./lib/db_io.cjs');
const { exitAfterFlush } = require('./lib/exit.cjs');
// install_cmd parsing lives in one place — see lib/install_cmd.cjs for why.
const {
  npmPkgName, pypiPkgName, dockerImageRef, dockerDigestPinned,
} = require('./lib/install_cmd.cjs');
const { toJsonReport, toSarif, dbLineIndex } = require('./lib/report.cjs');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const UPDATE    = process.argv.includes('--update');
const STRICT    = process.argv.includes('--strict');
const NO_AUDIT  = process.argv.includes('--no-audit');
const OFFLINE   = process.argv.includes('--offline');
// --entry NAME: check one DB entry instead of all 100+. `orchestrate --install`
// uses it so a single install doesn't drag the whole registry over the wire.
const ENTRY     = (() => {
  const i = process.argv.indexOf('--entry');
  return i !== -1 ? process.argv[i + 1] : null;
})();
// Two separate kinds of severity, kept separate on purpose:
//   --strict           WARNs (repo mismatch, install hooks, missing pins) are failures
//   --fail-unverified  "we could not check this at all" is a failure
// --strict implies --fail-unverified; an install gate wants the latter without
// necessarily refusing every entry that ships a postinstall hook.
const FAIL_UNVERIFIED = STRICT || process.argv.includes('--fail-unverified');
// Machine-readable output. --sarif is SARIF 2.1.0 for GitHub code scanning,
// which puts each finding on the tools_database.json line that caused it.
const AS_JSON  = process.argv.includes('--json');
const AS_SARIF = process.argv.includes('--sarif');
// --deep: download the artifact and hash it here, instead of comparing the DB
// pin against metadata served by the same registry that serves the tarball.
const DEEP = process.argv.includes('--deep');
// Artifact downloads are heavier than metadata requests, so they get their own
// (smaller) pool.
const DEEP_CONCURRENCY = Math.max(1, Number(process.env.MCP_VAULT_DEEP_CONCURRENCY || 4));
const DEEP_MAX_BYTES   = Math.max(1, Number(process.env.MCP_VAULT_DEEP_MAX_BYTES || 64 * 1024 * 1024));
// A package the registry never signed, or that ships no provenance, is common
// enough that flagging it by default would bury the real findings. These turn
// "absent" into a failure for anyone who wants that bar.
const REQUIRE_SIGNATURES = process.argv.includes('--require-signatures');
const REQUIRE_PROVENANCE = process.argv.includes('--require-provenance');

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack'];

// PyPI may declare the source URL under several keys; check them in priority order.
const PYPI_SOURCE_KEYS = ['Source', 'Source Code', 'Repository', 'Homepage', 'Home', 'Bug Tracker'];

// ── helpers ────────────────────────────────────────────────────────────────

// Progress chatter. In --json/--sarif mode stdout belongs to the document, so
// this goes to stderr instead of interleaving with it.
function progress(line) {
  if (AS_JSON || AS_SARIF) process.stderr.write(line);
  else                     process.stdout.write(line);
}


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

// Registry and feed transport. Both wrappers keep the old contract — a null
// means "this did not answer" — but underneath they retry transient failures
// (timeouts, 429, 403 rate limits, 5xx) and, for GETs, revalidate a disk cache
// with the stored ETag. Before this, one 403 partway through the GHSA loop
// turned a package's result into "feed unreachable" with no second attempt.
const CACHE_TTL_MS = Number(process.env.MCP_VAULT_CACHE_TTL_MS || 15 * 60 * 1000);
// How many registry/feed requests are in flight at once. The feeds are the slow
// part of a run: 114 entries once meant 114 sequential round trips per feed.
const CONCURRENCY = Math.max(1, Number(process.env.MCP_VAULT_CONCURRENCY || 8));
// npm's public registry, overridable for a mirror or a private registry.
const NPM_REGISTRY = (process.env.MCP_VAULT_NPM_REGISTRY || 'https://registry.npmjs.org').replace(/\/+$/, '');

function httpsPostJson(url, payload, timeoutMs = 10000) {
  return postJson(url, payload, { timeoutMs }).then((r) => (r.ok ? r.data : null));
}

function httpsGetJson(url, timeoutMs = 10000, headers = {}, cacheTtlMs = CACHE_TTL_MS) {
  return getJson(url, { headers, timeoutMs, cacheTtlMs }).then((r) => (r.ok ? r.data : null));
}

function fetchNpmAdvisories(pkgMap) {
  return httpsPostJson(
    `${NPM_REGISTRY}/-/npm/v1/security/advisories/bulk`,
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
    'https://api.osv.dev/v1/querybatch',
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

  // One request per (ecosystem, package), up to CONCURRENCY at a time. The
  // client retries a 403 with backoff, which is what an anonymous run hits
  // after 60 packages.
  const fetched = await mapLimit(queries, CONCURRENCY, async (q) => {
    // GHSA ecosystem codes: "npm", "pip" (PyPI), "rubygems", "maven", "go", …
    const ecoCode = q.ecosystem === 'PyPI' ? 'pip' : q.ecosystem;
    // affects=pkg@version → server-side filter to only advisories the pinned
    // version is actually inside the vulnerable range of. Without it the
    // endpoint returns every advisory in the package's history regardless of
    // whether the pinned version is patched (the false-positive batch in the
    // first GHSA rollout).
    const affects = q.version ? `${q.name}@${q.version}` : q.name;
    const url = `https://api.github.com/advisories?ecosystem=${encodeURIComponent(ecoCode)}&affects=${encodeURIComponent(affects)}&per_page=20`;
    return { key: `${ecoCode}:${q.name}`, advs: await httpsGetJson(url, 10000, headers) };
  });

  for (const { key, advs } of fetched) {
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
  const headers = {
    'Authorization': `token ${token}`,
    'User-Agent':    'mcp-skills-vault/verify_integrity.cjs',
  };
  const out = {};
  let failures = 0;

  const fetched = await mapLimit(queries, CONCURRENCY, async (q) => {
    const eco = q.ecosystem === 'PyPI' ? 'pip' : q.ecosystem;
    const url = `https://api.snyk.io/v1/test/${encodeURIComponent(eco)}/${encodeURIComponent(q.name)}/${encodeURIComponent(q.version || '0.0.0')}`;
    return { key: `${eco}:${q.name}`, data: await httpsGetJson(url, 10000, headers) };
  });

  for (const { key, data } of fetched) {
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

/**
 * The version manifest for one npm package, straight from the registry.
 *
 * This replaces `npm view <pkg>@<version> --json`, which cost a child process
 * per entry — 102 sequential `npm view` calls, the slowest part of a full run —
 * and pulled DB-controlled strings onto a command line. The per-version
 * document is small (unlike the full packument) and carries everything the gate
 * reads: dist.integrity, dist.tarball, repository, scripts, license.
 */
/**
 * Hash the artifact the registry would actually serve and compare it with both
 * the registry's own metadata and the DB pin.
 *
 * Three outcomes worth telling apart:
 *   - bytes disagree with the registry's metadata → the registry is serving
 *     something that does not match what it says. Always a hard failure.
 *   - bytes disagree with the DB pin → the pin is stale or the release was
 *     replaced. Hard failure.
 *   - could not download → UNVERIFIED, never a pass.
 */
async function deepCheckArtifact({ url, algo, registryIntegrity, storedIntegrity }) {
  if (!url) return { state: 'unverified', message: 'no artifact url in registry metadata' };
  const hashed = await hashUrl(url, algo, { maxBytes: DEEP_MAX_BYTES });
  if (!hashed.ok) return { state: 'unverified', message: `could not hash the artifact: ${hashed.error}` };

  if (registryIntegrity && !sriEqual(hashed.sri, registryIntegrity)) {
    return {
      state: 'fail',
      message: `the bytes the registry served do not match the registry's own metadata\n        bytes   : ${hashed.sri}\n        metadata: ${registryIntegrity}`,
    };
  }
  if (storedIntegrity && !sriEqual(hashed.sri, storedIntegrity)) {
    return {
      state: 'fail',
      message: `downloaded artifact does not match the stored pin\n        bytes : ${hashed.sri}\n        stored: ${storedIntegrity}`,
    };
  }
  return { state: 'ok', message: `hashed ${hashed.bytes} bytes locally: ${hashed.sri.slice(0, 24)}…`, sri: hashed.sri, bytes: hashed.bytes };
}

// npm's signing keys. One request per run, cached for a day — they rotate on
// the order of years, and a run that cannot fetch them reports signatures as
// unverified rather than as failures.
let registryKeysPromise = null;
function fetchRegistryKeys() {
  if (!registryKeysPromise) {
    registryKeysPromise = getJson(keysUrl(NPM_REGISTRY), { cacheTtlMs: 24 * 60 * 60 * 1000 })
      .then((r) => (r.ok ? r.data : null));
  }
  return registryKeysPromise;
}

// A scoped name keeps its slash encoded: /@scope%2fpkg/1.2.3
function npmManifestUrl(pkg, version, registry = NPM_REGISTRY) {
  const name = pkg.startsWith('@')
    ? `@${encodeURIComponent(pkg.slice(1)).replace(/%2F/i, '%2f')}`
    : encodeURIComponent(pkg);
  return `${registry}/${name}/${encodeURIComponent(version || 'latest')}`;
}

// Returns the http client's result object, not just the body: a 404 means the
// package or version is gone from the registry, which is a different thing
// from "the registry did not answer" and deserves saying out loud.
function fetchNpmManifest(pkg, version) {
  return getJson(npmManifestUrl(pkg, version), { cacheTtlMs: CACHE_TTL_MS });
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

function pypiSdistFile(meta) {
  const v = meta?.info?.version;
  const files = (meta?.releases && meta.releases[v]) || meta?.urls || [];
  return files.find((f) => f.packagetype === 'sdist') || null;
}

function pypiSdistSha256(meta) {
  return pypiSdistFile(meta)?.digests?.sha256 || null;
}

// Severity ordering. MODERATE is npm's word for MEDIUM; UNKNOWN sorts lowest so
// a feed that couldn't tell us never outranks one that could.
const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MODERATE: 2, MEDIUM: 2, LOW: 1 };

function severityRank(sev) {
  return SEVERITY_RANK[String(sev || '').toUpperCase()] || 0;
}

function severityIsHard(sev) {
  return severityRank(sev) >= SEVERITY_RANK.HIGH;
}

// CVSS v3.x base-score weights (CVSS:3.1 specification, §7.1).
const CVSS3_W = {
  AV:   { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC:   { L: 0.77, H: 0.44 },
  UI:   { N: 0.85, R: 0.62 },
  CIA:  { H: 0.56, L: 0.22, N: 0 },   // v3 impact metrics are High/Low/None
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
};

// The spec's Roundup(): smallest 1-decimal number >= x, computed over integers
// because the float form rounds 8.6-ish values the wrong way.
function roundUp1(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

// Compute the base score from a CVSS v3.x vector string. Returns null for
// anything we don't fully understand (including v4.0, whose scoring is a lookup
// table, and v2 vectors) — callers treat null as "severity unknown", not "fine".
function cvss3BaseScore(vector) {
  const m = {};
  for (const part of String(vector).split('/')) {
    const [k, v, ...rest] = part.split(':');
    if (!k || !v || rest.length) return null;   // malformed component
    if (k in m) return null;                    // a repeated metric is not a valid vector
    m[k] = v;
  }
  if (!/^3\.[01]$/.test(m.CVSS || '')) return null;
  // Base Scope is U or C and nothing else (spec §6). `S:X` — legal only in a
  // temporal/environmental vector — otherwise scored as if it were Unchanged
  // and produced a plausible-looking number for a vector we didn't understand.
  if (m.S !== 'U' && m.S !== 'C') return null;
  const changed = m.S === 'C';
  const av = CVSS3_W.AV[m.AV];
  const ac = CVSS3_W.AC[m.AC];
  const ui = CVSS3_W.UI[m.UI];
  const pr = (changed ? CVSS3_W.PR_C : CVSS3_W.PR_U)[m.PR];
  const c  = CVSS3_W.CIA[m.C];
  const i  = CVSS3_W.CIA[m.I];
  const a  = CVSS3_W.CIA[m.A];
  if ([av, ac, ui, pr, c, i, a].some((w) => w === undefined)) return null;
  const iss    = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return roundUp1(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
}

// CVSS qualitative severity rating scale (CVSS:3.1, §5).
function scoreToSeverity(score) {
  if (typeof score !== 'number' || Number.isNaN(score)) return 'UNKNOWN';
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score >  0.0) return 'LOW';
  return 'UNKNOWN';                       // 0.0 is CVSS "None" — nothing to rate
}

// OSV vulns expose severity in a few possible shapes; pick the worst we find.
// Most OSV records carry only a CVSS vector — no severity word anywhere — so
// without scoring the vector a 9.8 came back UNKNOWN and severityIsHard() said
// "not hard": a critical advisory that printed but didn't fail the gate.
function osvSeverity(vuln) {
  let worst = 'UNKNOWN';
  const consider = (sev) => { if (severityRank(sev) > severityRank(worst)) worst = sev; };

  for (const s of (vuln.severity || [])) {
    const score = s && s.score;
    if (!score) continue;
    if (/^CVSS:/i.test(String(score))) {
      const computed = scoreToSeverity(cvss3BaseScore(score));
      if (computed !== 'UNKNOWN') { consider(computed); continue; }
    }
    const word = String(score).match(/CRITICAL|HIGH|MEDIUM|MODERATE|LOW/i);
    if (word) { consider(word[0].toUpperCase()); continue; }
    const numeric = Number(score);
    if (String(score).trim() !== '' && !Number.isNaN(numeric)) consider(scoreToSeverity(numeric));
  }

  const db = vuln.database_specific || {};
  if (db.severity) consider(String(db.severity).toUpperCase());
  for (const aff of (vuln.affected || [])) {
    const s = aff && aff.database_specific && aff.database_specific.severity;
    if (s) consider(String(s).toUpperCase());
  }
  return worst;
}

// Merge advisories from npm + OSV + GHSA + Snyk into a unified array per
// package, deduplicated by ID (GHSA shares IDs with OSV — keep one).
// Unified shape: { id, severity, title, url, source }.
function unifyAdvisories({ npmList, osvList, ghsaList, snykList }) {
  const byKey = new Map();
  const push = (a) => {
    const key  = a.id || `${a.source}:${a.title || a.url}`;
    const prev = byKey.get(key);
    if (!prev) { byKey.set(key, { ...a }); return; }
    // Same advisory seen through two feeds: keep the worst severity either one
    // reported. Keeping the first meant an OSV record whose severity we couldn't
    // read masked the CRITICAL that GHSA had for the very same GHSA id — the
    // merge silently downgraded a hard failure to a printed note.
    if (severityRank(a.severity) > severityRank(prev.severity)) {
      prev.severity = a.severity;
      prev.source   = `${prev.source}+${a.source}`;
    }
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
  return [...byKey.values()];
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

// A run that printed an [UNVERIFIED] line did not verify that entry, so the
// headline verdict must not read OK. Without this, a wheel-only PyPI release or
// a degraded advisory feed showed `OK` on the entry line and the summary
// counted zero unverified entries, because the counter only looks at statuses.
function verdictFor(failures, lines) {
  if (failures > 0) return 'FAIL';
  if ((lines || []).some(([tag]) => tag === 'UNVERIFIED')) return 'UNVERIFIED';
  return 'OK';
}

// ── per-tool processors ────────────────────────────────────────────────────

async function processNpm(tool, pkg, fetched, advisoriesForTool, degraded, results) {
  if (OFFLINE) {
    processOfflinePackage(tool, pkg, 'npm', results);
    return;
  }
  // `fetched` is the http result; `meta` is its body.
  const meta = fetched && fetched.ok ? fetched.data : null;
  if (!meta || !meta.version) {
    // A 404 is not a transport problem: the package or the pinned version is
    // no longer in the registry. Unpublished, renamed, or taken down — and the
    // name may now be claimable by someone else, so say which case this is.
    const gone = fetched && fetched.status === 404;
    const why = gone
      ? `no longer in the npm registry (404) — unpublished, renamed, or taken down`
      : `npm registry lookup failed: ${(fetched && fetched.error) || 'no response'}`;
    results.push({
      tool,
      status: 'UNVERIFIED',
      msg: `${tool.name}: ${pkg}@${tool.version || 'latest'} ${why}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`,
      failures: FAIL_UNVERIFIED ? 1 : 0,
    });
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
    // No stored hash means nothing was compared. That is UNVERIFIED, not a
    // cosmetic MISS: an install used to sail through on an entry with a
    // version and no hash at all.
    lines.push(['UNVERIFIED', `no stored pkg_integrity — run --update${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
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

  // Registry signature. npm signs `<name>@<version>:<integrity>` with a
  // published ECDSA key, so this is a real cryptographic check: it proves the
  // registry vouched for this exact integrity value, and a response with a
  // swapped `dist.integrity` cannot pass it.
  const keys = await fetchRegistryKeys();
  const sig  = verifyRegistrySignature({
    name:       meta.name || pkg,
    version:    npmVersion,
    integrity:  npmIntegrity,
    signatures: meta.dist?.signatures,
    keys,
  });
  if (sig.state === 'fail') {
    lines.push(['FAIL', `registry signature does not verify — ${sig.reason}`]);
    failures++;
  } else if (sig.state === 'ok') {
    lines.push(['SIG', `registry signature verified (${sig.keyid})`]);
  } else if (REQUIRE_SIGNATURES) {
    lines.push(['FAIL', `no verifiable registry signature — ${sig.reason}`]);
    failures++;
  } else {
    lines.push(['NOTE', `registry signature not verified — ${sig.reason}`]);
  }

  // Provenance. Reported as a *claim*: verifying a sigstore bundle properly
  // means a Fulcio chain and a Rekor inclusion proof, which this tool does not
  // do, and saying "verified" without doing it would be worse than not saying
  // it. What is checked is whether the claim points at the repository the DB
  // says this package comes from.
  const attestationsUrl = meta.dist?.attestations?.url;
  if (attestationsUrl) {
    const att = await httpsGetJson(attestationsUrl, 10000, {}, CACHE_TTL_MS);
    const claim = att ? provenanceClaim(att) : null;
    if (!claim) {
      lines.push(['NOTE', 'provenance attestation present but unreadable']);
    } else {
      const claimedRepo = normalizeGitUrl(claim.repository);
      if (storedRepo && claimedRepo && claimedRepo.toLowerCase() !== storedRepo.toLowerCase()) {
        lines.push(['WARN', `provenance names a different repository\n        source_url: ${tool.source_url}\n        provenance: ${claim.repository}`]);
        if (STRICT) failures++;
      } else {
        lines.push(['PROV', `provenance claims ${claim.repository}${claim.workflowPath ? ` (${claim.workflowPath})` : ''} — claim read, not cryptographically verified`]);
      }
    }
  } else if (REQUIRE_PROVENANCE) {
    lines.push(['FAIL', 'no provenance attestation published for this version']);
    failures++;
  }

  // --deep: hash what the registry would actually serve.
  if (DEEP) {
    const deep = await deepCheckArtifact({
      url:               meta.dist?.tarball,
      algo:              parseSri(npmIntegrity || tool.pkg_integrity)?.algo || 'sha512',
      registryIntegrity: npmIntegrity,
      storedIntegrity:   tool.pkg_integrity,
    });
    if (deep.state === 'fail') { lines.push(['FAIL', deep.message]); failures++; }
    else if (deep.state === 'unverified') {
      lines.push(['UNVERIFIED', `${deep.message}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
      if (FAIL_UNVERIFIED) failures++;
    } else {
      lines.push(['DEEP', deep.message]);
    }
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
    lines.push(['UNVERIFIED', `advisory feeds unreachable: ${degraded.join(', ')} — cannot assert "no known CVEs"${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  }

  results.push({
    tool,
    status: verdictFor(failures, lines),
    msg: `${tool.name}@${npmVersion}`,
    lines,
    failures,
  });
}

async function processPypi(tool, pkg, meta, advisoriesForTool, degraded, results) {
  if (OFFLINE) {
    processOfflinePackage(tool, pkg, 'PyPI', results);
    return;
  }
  if (!meta) {
    results.push({
      tool,
      status: 'UNVERIFIED',
      msg: `${tool.name}: ${pkg} PyPI lookup failed${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`,
      failures: FAIL_UNVERIFIED ? 1 : 0,
    });
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
  // Two independent conditions, not a chain: an entry with no stored hash AND a
  // wheel-only release used to report only the first and still come back OK.
  if (!tool.pkg_integrity) {
    lines.push(['UNVERIFIED', `no stored pkg_integrity — run --update${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  }
  if (!expected) {
    // Wheel-only release: there is no sdist to hash, so a stored pin cannot be
    // compared against anything. Saying OK here would bless an unchecked file.
    lines.push(['UNVERIFIED', `PyPI ${pyVersion} publishes no sdist — integrity cannot be compared${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  } else if (tool.pkg_integrity && tool.pkg_integrity !== expected) {
    lines.push(['FAIL', `integrity mismatch\n        stored: ${tool.pkg_integrity}\n        pypi  : ${expected}`]);
    failures++;
  }

  if (DEEP) {
    const sdist = pypiSdistFile(meta);
    const deep = await deepCheckArtifact({
      url:               sdist?.url,
      algo:              'sha256',
      registryIntegrity: sdist?.digests?.sha256 ? `sha256-${sdist.digests.sha256}` : null,
      storedIntegrity:   tool.pkg_integrity,
    });
    if (deep.state === 'fail') { lines.push(['FAIL', deep.message]); failures++; }
    else if (deep.state === 'unverified') {
      lines.push(['UNVERIFIED', `${deep.message}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
      if (FAIL_UNVERIFIED) failures++;
    } else {
      lines.push(['DEEP', deep.message]);
    }
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
    lines.push(['UNVERIFIED', `advisory feeds unreachable: ${degraded.join(', ')} — cannot assert "no known CVEs"${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  }

  results.push({
    tool,
    status: verdictFor(failures, lines),
    msg: `${tool.name}@${pyVersion}`,
    lines,
    failures,
  });
}

async function processDocker(tool, results) {
  const ref = dockerImageRef(tool.install_cmd);
  if (!ref) {
    results.push({
      tool,
      status: 'UNVERIFIED',
      msg: `${tool.name}: cannot parse docker image reference${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`,
      failures: FAIL_UNVERIFIED ? 1 : 0,
    });
    return;
  }
  const pinned = dockerDigestPinned(ref);
  if (pinned) {
    const lines = [];
    let failures = 0;
    // --deep: a digest *is* the sha256 of the manifest document, so the pin can
    // be verified by hashing what the registry serves. No layers to download.
    if (DEEP && !OFFLINE) {
      const { registry, repo, digest } = parseImageRef(ref);
      if (!ALLOWED_REGISTRIES.has(registry)) {
        lines.push(['UNVERIFIED', `registry "${registry}" is not in the supported allowlist${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
        if (FAIL_UNVERIFIED) failures++;
      } else {
        const m = await fetchManifest(registry, repo, digest);
        if (m.error) {
          lines.push(['UNVERIFIED', `could not fetch the manifest: ${m.error}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
          if (FAIL_UNVERIFIED) failures++;
        } else {
          const computed = ociManifestDigest(m.body);
          if (computed !== digest) {
            lines.push(['FAIL', `manifest digest mismatch\n        pinned  : ${digest}\n        computed: ${computed}`]);
            failures++;
          } else {
            lines.push(['DEEP', `manifest hashed locally: ${computed.slice(0, 26)}…`]);
          }
        }
      }
    }
    results.push({
      tool,
      status: verdictFor(failures, lines),
      msg: `${tool.name}: docker pinned by digest`,
      lines,
      failures,
    });
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

  // Offline, the pins *are* the evidence. A missing one means this entry was
  // never verified — the same verdict the online path now gives.
  if (!tool.version) {
    lines.push(['UNVERIFIED', `no pinned version in DB${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  }
  if (!tool.pkg_integrity) {
    lines.push(['UNVERIFIED', `no stored pkg_integrity — cannot compare without network${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  }
  if (!tool.source_url) {
    lines.push(['NOTE', 'no source_url in DB']);
  }

  const pin = tool.version ? `@${tool.version}` : '@?';
  results.push({
    tool,
    status: verdictFor(failures, lines),
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

  const allTools = Array.isArray(db.tools) ? db.tools : [];
  const scope    = ENTRY ? allTools.filter((t) => t.name === ENTRY) : allTools;
  if (ENTRY && scope.length === 0) {
    console.error(`--entry: no DB entry named "${ENTRY}"`);
    process.exit(2);
  }

  // Bucket tools by ecosystem.
  const npmTools    = [];     // [{ tool, pkg }]
  const pypiTools   = [];     // [{ tool, pkg }]
  const dockerTools = [];

  // An entry we can't route to a registry is UNVERIFIED, not SKIP: nothing about
  // its pin was ever checked, so --strict must refuse to call the run clean.
  const unroutable = (tool, why) => results.push({
    tool,
    status: 'UNVERIFIED',
    msg: `${tool.name}: ${why}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`,
    failures: FAIL_UNVERIFIED ? 1 : 0,
  });

  for (const tool of scope) {
    if (/^npx\s+-y/.test(tool.install_cmd)) {
      const p = npmPkgName(tool.install_cmd);
      if (p) npmTools.push({ tool, pkg: p });
      else unroutable(tool, 'cannot parse npm pkg name');
    } else if (/^uvx/.test(tool.install_cmd)) {
      const p = pypiPkgName(tool.install_cmd);
      if (p) pypiTools.push({ tool, pkg: p });
      else unroutable(tool, 'uvx --from / git URL not verifiable');
    } else if (/^docker\s+run/.test(tool.install_cmd)) {
      dockerTools.push({ tool });
    } else {
      unroutable(tool, 'unknown install method');
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
    progress(`Querying npm bulk (${npmTools.length}), OSV.dev (${allQueries.length}), GHSA (${allQueries.length}), Snyk... `);
    [npmAdvisories, osvNpm, osvPypi, ghsa, snyk] = await Promise.all([
      fetchNpmAdvisories(npmMap),
      fetchOsvAdvisories(npmQueries),
      fetchOsvAdvisories(pypiQueries),
      fetchGhsaAdvisories(allQueries),
      fetchSnykAdvisories(allQueries),
    ]);
    progress(`done — sources: ${summarizeFeedSources({ npm: npmAdvisories, osvNpm, osvPypi, ghsa, snyk }).join(', ')}.\n`);
  }
  const health = { npm: npmAdvisories, osvNpm, osvPypi, ghsa, snyk };

  // Process npm.
  if (OFFLINE) {
    progress('Offline mode: validating stored pins only; no registry/advisory network calls.\n');
  } else if (NO_AUDIT && !UPDATE) {
    progress('No-audit mode: checking live registry metadata; advisory feeds skipped.\n');
  }

  // Registry metadata for every entry, fetched concurrently. The processing
  // below stays sequential so the report keeps DB order.
  let npmMetas  = [];
  let pypiMetas = [];
  if (!OFFLINE) {
    if (npmTools.length || pypiTools.length) {
      progress(`Fetching registry metadata for ${npmTools.length} npm + ${pypiTools.length} PyPI entries (${CONCURRENCY} at a time)... `);
    }
    [npmMetas, pypiMetas] = await Promise.all([
      mapLimit(npmTools,  CONCURRENCY, ({ tool, pkg }) => fetchNpmManifest(pkg, tool.version)),
      mapLimit(pypiTools, CONCURRENCY, ({ tool, pkg }) => fetchPypiMeta(pkg, tool.version)),
    ]);
    if (npmTools.length || pypiTools.length) progress('done.\n');
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
    await processNpm(tool, pkg, npmMetas[i], advs, degraded, results);
  }
  // Process PyPI.
  for (let i = 0; i < pypiTools.length; i++) {
    const { tool, pkg } = pypiTools[i];
    const advs = unifyAdvisories({
      npmList:  [],
      osvList:  osvPypi.data[i]?.vulns || [],
      ghsaList: ghsa.data[`pip:${pkg}`] || [],
      snykList: snyk.data[`pip:${pkg}`] || [],
    });
    const degraded = (UPDATE || NO_AUDIT) ? [] : degradedFeedsFor('PyPI', `pip:${pkg}`, health);
    await processPypi(tool, pkg, pypiMetas[i], advs, degraded, results);
  }
  // Process docker.
  for (const { tool } of dockerTools) await processDocker(tool, results);

  // Machine-readable modes: one document on stdout, nothing else. Everything
  // human-facing has gone to stderr already, so `--json` stays pipeable.
  if (AS_JSON || AS_SARIF) {
    totalFails = results.reduce((n, r) => n + (r.failures || 0), 0);
    const report = toJsonReport({
      results,
      meta: {
        mode: OFFLINE ? 'offline' : (UPDATE ? 'update' : (NO_AUDIT ? 'no-audit' : 'full')),
        entry: ENTRY,
        fail_unverified: FAIL_UNVERIFIED,
        strict: STRICT,
        feeds: (UPDATE || NO_AUDIT || OFFLINE) ? null : summarizeFeedSources(health),
      },
    });
    if (AS_SARIF) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      process.stdout.write(JSON.stringify(toSarif(report, {
        dbPath: path.relative(process.cwd(), DB_PATH).split(path.sep).join('/'),
        lineOf: dbLineIndex(raw),
      }), null, 2) + '\n');
    } else {
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
    if (UPDATE && results.some((r) => r.status === 'UPD')) writeDb(DB_PATH, db);
    return exitAfterFlush(totalFails > 0 ? 1 : 0);
  }

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
    const checked    = scope.length || (npmTools.length + pypiTools.length + dockerTools.length);
    const unverified = results.filter((r) => r.status === 'UNVERIFIED').length;
    const tail       = unverified ? `, ${unverified} unverified` : '';
    console.log(`\n${checked} entr${checked === 1 ? 'y' : 'ies'} checked — ${totalFails} failure(s)${tail}`);
    if (totalFails > 0)  console.error('DO NOT install until failures are resolved.');
    if (unverified && !FAIL_UNVERIFIED) {
      console.error(`${unverified} entr${unverified === 1 ? 'y was' : 'ies were'} not verified — re-run with --fail-unverified to treat that as a failure.`);
    }
  }

  // Not process.exit(): the summary above is still buffered when stdout is a
  // pipe, and exiting drops it. See lib/exit.cjs.
  exitAfterFlush(totalFails > 0 ? 1 : 0);
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
  severityRank,
  cvss3BaseScore,
  scoreToSeverity,
  dockerDigestPinned,
  npmManifestUrl,
  verdictFor,
  osvSeverity,
  unifyAdvisories,
  degradedFeedsFor,
  summarizeFeedSources,
};
