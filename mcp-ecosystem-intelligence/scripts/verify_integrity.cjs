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
 *   node scripts/verify_integrity.cjs --installed  check the servers local hosts launch
 *                                                  (.mcp.json, ~/.claude.json, Cursor, …)
 *   node scripts/verify_integrity.cjs --fail-unverified  UNVERIFIED → hard failure
 *   node scripts/verify_integrity.cjs --deps       resolve and check dependency trees
 *   node scripts/verify_integrity.cjs --no-policy  ignore .mcp-vault.policy.json
 *   node scripts/verify_integrity.cjs --record-evidence  write dated per-dimension
 *                                                  evidence back into the DB
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
const { readInstalledServers } = require('./lib/installed.cjs');
const {
  resolveNpmTreeCached, pypiDirectDependencies, summarizeTree,
} = require('./lib/deps.cjs');
const { loadPolicy, evaluateEntry } = require('./lib/policy.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const {
  buildEvidence, mergeEvidence, staleDimensions, deriveTrust, requiredFor, DEFAULT_MAX_AGE_DAYS,
} = require('./lib/evidence.cjs');
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
const CWD = (() => {
  const i = process.argv.indexOf('--cwd');
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : process.cwd();
})();

// A policy file (.mcp-vault.policy.json, nearest at or above --cwd) states the
// bar once, so CI and a developer's shell enforce the same one instead of each
// assembling its own garland of flags. Flags still win where they are given: an
// explicit flag is someone saying what they want right now. A policy can only
// raise the bar here, never lower it.
const NO_POLICY = process.argv.includes('--no-policy');
// --record-evidence: write what this run established back into the DB, dated
// per dimension. Trust then becomes a derived value instead of a word someone
// typed once.
const RECORD_EVIDENCE = process.argv.includes('--record-evidence');
const POLICY = NO_POLICY
  ? { ok: true, policy: null, path: null, errors: [], found: false }
  : loadPolicy(CWD);

// Per-dimension age limits: the policy's number overrides every dimension,
// otherwise each dimension keeps its own default (advisories perish fastest).
function evidenceMaxAge() {
  const fromPolicy = POLICY.ok && POLICY.policy ? POLICY.policy.maxEvidenceAgeDays : null;
  if (!Number.isFinite(fromPolicy)) return DEFAULT_MAX_AGE_DAYS;
  // A policy raises the bar; it does not lower it. `maxEvidenceAgeDays: 30`
  // applied flatly would have *extended* the 7-day advisory window, so a
  // twenty-day-old "clean" became acceptable by adding a policy.
  const merged = {};
  for (const [dimension, dflt] of Object.entries(DEFAULT_MAX_AGE_DAYS)) {
    merged[dimension] = Math.min(dflt, fromPolicy);
  }
  return merged;
}

function policySays(predicate) {
  return Boolean(POLICY.ok && POLICY.policy && predicate(POLICY.policy));
}
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
const FAIL_UNVERIFIED = STRICT || process.argv.includes('--fail-unverified') || policySays((p) => p.unverified === 'fail');
// Machine-readable output. --sarif is SARIF 2.1.0 for GitHub code scanning,
// which puts each finding on the tools_database.json line that caused it.
const AS_JSON  = process.argv.includes('--json');
const AS_SARIF = process.argv.includes('--sarif');
// --deep: download the artifact and hash it here, instead of comparing the DB
// pin against metadata served by the same registry that serves the tarball.
const DEEP = process.argv.includes('--deep') || policySays((p) => p.deep);
// Artifact downloads are heavier than metadata requests, so they get their own
// (smaller) pool.
const DEEP_CONCURRENCY = Math.max(1, Number(process.env.MCP_VAULT_DEEP_CONCURRENCY || 4));
const DEEP_MAX_BYTES   = Math.max(1, Number(process.env.MCP_VAULT_DEEP_MAX_BYTES || 64 * 1024 * 1024));
// A package the registry never signed, or that ships no provenance, is common
// enough that flagging it by default would bury the real findings. These turn
// "absent" into a failure for anyone who wants that bar.
const REQUIRE_SIGNATURES = process.argv.includes('--require-signatures') || policySays((p) => p.signatures === 'require');
const REQUIRE_PROVENANCE = process.argv.includes('--require-provenance') || policySays((p) => p.provenance === 'require');
// --installed: verify what the local hosts are configured to launch, instead of
// what the DB says. The DB is still consulted — for a pin to compare against —
// but the subjects are the configured servers.
const INSTALLED = process.argv.includes('--installed');
// --deps: resolve each package's dependency tree and check it too. An
// install-time script is far more often in a transitive dependency than in the
// package itself, so a one-level check is a check at the wrong depth.
// A policy that forbids dependency hooks or advisories cannot be judged
// without the tree, so requiring either implies resolving it. Otherwise the
// rule silently checked nothing.
const DEPS = process.argv.includes('--deps')
  || policySays((p) => p.deps || p.dependencyHooks === 'fail' || p.dependencyAdvisories === 'fail');
// A hard failure on a transitive advisory is a policy choice, not a fact about
// the artifact: most trees carry something. Off unless asked for.
const FAIL_DEP_ADVISORIES = process.argv.includes('--fail-dep-advisories') || policySays((p) => p.dependencyAdvisories === 'fail');
const DEPS_CONCURRENCY = Math.max(1, Number(process.env.MCP_VAULT_DEPS_CONCURRENCY || 4));


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

// Returns the body, or null when the feed did not answer. A *stale* cache hit
// is not an answer: lib/http.cjs prefers old bytes over nothing, which is the
// right default for a fetch but the wrong one for a verdict — an old empty
// GHSA response would read as "queried, no advisories". Callers that care
// (all of them) use httpsGetJsonMeta and treat `stale` as a degraded feed.
function httpsGetJsonMeta(url, timeoutMs = 10000, headers = {}, cacheTtlMs = CACHE_TTL_MS) {
  return getJson(url, { headers, timeoutMs, cacheTtlMs })
    .then((r) => ({ data: r.ok ? r.data : null, stale: !!r.stale, status: r.status, error: r.error }));
}

function httpsGetJson(url, timeoutMs = 10000, headers = {}, cacheTtlMs = CACHE_TTL_MS) {
  // Fresh-or-nothing: a stale body is reported as no answer here.
  return httpsGetJsonMeta(url, timeoutMs, headers, cacheTtlMs)
    .then((r) => (r.stale ? null : r.data));
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

/**
 * Fill in the detail querybatch leaves out.
 *
 * `/v1/querybatch` returns `{ id, modified }` per hit — no severity, no summary.
 * Reading severity off those records makes every OSV finding UNKNOWN, which
 * `severityIsHard()` then treats as not-hard: a critical advisory printed as a
 * line and did not fail the gate. The full record is one GET per id, cached for
 * a day (an advisory's severity does not churn), fetched through the pool.
 */
async function enrichOsvVulns(resultLists) {
  const ids = new Set();
  for (const r of resultLists || []) {
    for (const v of (r?.vulns || [])) if (v && v.id) ids.add(v.id);
  }
  if (!ids.size) return { byId: new Map(), failed: new Set() };
  const list = [...ids];
  const fetched = await mapLimit(list, CONCURRENCY, (id) =>
    httpsGetJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, 10000, {}, 24 * 60 * 60 * 1000));
  const byId = new Map();
  const failed = new Set();
  // An advisory we could not fetch keeps severity UNKNOWN, and UNKNOWN is not
  // hard — so silently keeping the stub turns "we don't know how bad this is"
  // into "not bad enough to fail". Track the misses and surface them.
  list.forEach((id, i) => { if (fetched[i]) byId.set(id, fetched[i]); else failed.add(id); });
  return { byId, failed };
}

// Replace each stub with its full record where we have one, so severity is
// read from something that actually carries it. Anything still a stub is
// flagged so the caller can report it as unverified rather than as mild.
function withOsvDetail(vulns, detail) {
  const byId = detail && detail.byId;
  return (vulns || []).map((v) => {
    const full = byId && byId.get(v.id);
    if (full) return full;
    return { ...v, _severityUnresolved: true };
  });
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

// Why there is no pin to compare against, phrased for the subject at hand.
function missingPinAdvice(tool) {
  const inst = tool._installed;
  if (!inst) return 'no stored pkg_integrity — run --update';
  if (!inst.in_vault) return `not in the vault DB — no stored hash to compare this artifact against`;
  return `this version is not the one the vault pinned — no stored hash for it`;
}

// The version a configured launch command actually asks for: `pkg@1.2.3` for
// npm, `pkg==1.2.3` for PyPI, the digest for an image. null means unpinned —
// the server runs whatever the registry resolves at startup.
function versionFromInstallCmd(cmd) {
  if (!cmd) return null;
  if (/^docker\s+run/.test(cmd)) {
    const ref = dockerImageRef(cmd);
    const m = ref && ref.match(/@(sha256:[a-f0-9]{64})$/);
    return m ? m[1] : null;
  }
  const npm = npmPkgName(cmd);
  if (npm) {
    const token = cmd.split(/\s+/).find((t) => t === npm || t.startsWith(`${npm}@`));
    return token && token !== npm ? token.slice(npm.length + 1) : null;
  }
  const py = pypiPkgName(cmd);
  if (py) {
    const token = cmd.split(/\s+/).find((t) => t.startsWith(`${py}==`));
    return token ? token.slice(py.length + 2) : null;
  }
  return null;
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

// What a processor actually established, as opposed to what its prose implies.
// Evidence is built from this, never from matching text: a check that did not
// run must not be indistinguishable from a check that passed.
// Tags present in a line list, for the few places that need to look back at
// what was reported rather than re-derive it.
function tags(lines) {
  return new Set((lines || []).map(([tag]) => tag));
}

function newChecks() {
  return {
    artifact:       null,   // { state: 'verified'|'mismatch'|'unverified', method }
    signature:      null,   // { state: 'verified'|'absent'|'unverified', keyid }
    provenance:     null,   // { state: 'claimed'|'unreadable'|'absent' , repository }
    source_binding: null,   // { state: 'verified'|'mismatch'|'unverified' }
    advisories:     null,   // { state: 'clean'|'vulnerable'|'advisories-present'|'unverified' }
    dependencies:   null,   // { state: 'clean'|'hooks'|'advisories-present'|'unverified', count }
  };
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
      unresolved: v._severityUnresolved === true,
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

async function processNpm(tool, pkg, fetched, advisoriesForTool, degraded, results, tree = null, depAdvisories = null, depAdvisoriesUnknown = null) {
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
      // An early return is still a result: without this, a package that has
      // since 404'd kept its recorded `artifact: verified` from last week.
      checks: { ...newChecks(), artifact: { state: 'unverified', method: gone ? 'registry-404' : 'registry-unreachable' } },
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
  const checks = newChecks();

  // Integrity
  if (!tool.pkg_integrity) {
    // No stored hash means nothing was compared. That is UNVERIFIED, not a
    // cosmetic MISS: an install used to sail through on an entry with a
    // version and no hash at all.
    lines.push(['UNVERIFIED', `${missingPinAdvice(tool)}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    checks.artifact = { state: 'unverified', method: 'none' };
    if (FAIL_UNVERIFIED) failures++;
  } else if (tool.pkg_integrity !== npmIntegrity) {
    lines.push(['FAIL', `integrity mismatch\n        stored: ${tool.pkg_integrity}\n        npm   : ${npmIntegrity}`]);
    checks.artifact = { state: 'mismatch', method: 'registry-metadata' };
    failures++;
  } else {
    checks.artifact = { state: 'verified', method: 'registry-metadata' };
  }

  // Repo URL — suppress monorepo subdirectory paths
  if (!npmRepo) {
    lines.push(['NOTE', 'npm declares no repository.url']);
    checks.source_binding = { state: 'unverified' };
  } else if (storedRepo && npmRepo.toLowerCase() !== storedRepo.toLowerCase() && !storedRepo.includes('/tree/')) {
    lines.push(['WARN', `repo mismatch\n        source_url: ${tool.source_url}\n        npm repo  : ${npmRepoRaw}`]);
    checks.source_binding = { state: 'mismatch' };
    if (STRICT) failures++;
  } else {
    checks.source_binding = { state: 'verified' };
  }

  // An installed server with no version in its launch command resolves `latest`
  // at every start. For the DB that is a pin to add; for a live config it is the
  // thing that actually runs being unknown.
  if (tool._installed && !tool.version) {
    lines.push(['UNVERIFIED', `launch command has no version pin — this resolves "latest" at every start${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
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
    checks.signature = { state: 'mismatch', keyid: sig.keyid || null };
    failures++;
  } else if (sig.state === 'ok') {
    lines.push(['SIG', `registry signature verified (${sig.keyid})`]);
    checks.signature = { state: 'verified', keyid: sig.keyid };
  } else if (REQUIRE_SIGNATURES) {
    lines.push(['FAIL', `no verifiable registry signature — ${sig.reason}`]);
    checks.signature = { state: 'absent' };
    failures++;
  } else {
    lines.push(['NOTE', `registry signature not verified — ${sig.reason}`]);
    checks.signature = { state: 'absent' };
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
      // "There is an attestation but we could not read it" is not evidence of
      // provenance. Under --require-provenance it fails like an absent one.
      checks.provenance = { state: 'unreadable' };
      if (REQUIRE_PROVENANCE) {
        lines.push(['FAIL', 'provenance attestation present but unreadable']);
        failures++;
      } else {
        lines.push(['NOTE', 'provenance attestation present but unreadable']);
      }
    } else {
      const claimedRepo = normalizeGitUrl(claim.repository);
      if (storedRepo && claimedRepo && claimedRepo.toLowerCase() !== storedRepo.toLowerCase()) {
        lines.push(['WARN', `provenance names a different repository\n        source_url: ${tool.source_url}\n        provenance: ${claim.repository}`]);
        checks.provenance = { state: 'mismatch', repository: claim.repository };
        if (STRICT) failures++;
      } else {
        lines.push(['PROV', `provenance claims ${claim.repository}${claim.workflowPath ? ` (${claim.workflowPath})` : ''} — claim read, not cryptographically verified`]);
        checks.provenance = { state: 'claimed', repository: claim.repository };
      }
    }
  } else if (REQUIRE_PROVENANCE) {
    lines.push(['FAIL', 'no provenance attestation published for this version']);
    checks.provenance = { state: 'absent' };
    failures++;
  } else {
    checks.provenance = { state: 'absent' };
  }

  // --deep: hash what the registry would actually serve.
  if (DEEP) {
    const deep = await deepCheckArtifact({
      url:               meta.dist?.tarball,
      algo:              parseSri(npmIntegrity || tool.pkg_integrity)?.algo || 'sha512',
      registryIntegrity: npmIntegrity,
      storedIntegrity:   tool.pkg_integrity,
    });
    // These overwrite the metadata-level conclusion on purpose: hashing the
    // bytes is a stronger statement than comparing two values the registry
    // supplied. Without this, a tarball that disagreed with its own metadata
    // reported FAIL while the recorded evidence still said verified.
    if (deep.state === 'fail') {
      lines.push(['FAIL', deep.message]);
      checks.artifact = { state: 'mismatch', method: 'deep-hash' };
      failures++;
    } else if (deep.state === 'unverified') {
      lines.push(['UNVERIFIED', `${deep.message}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
      checks.artifact = { state: 'unverified', method: 'deep-hash' };
      if (FAIL_UNVERIFIED) failures++;
    } else {
      lines.push(['DEEP', deep.message]);
      checks.artifact = { state: 'verified', method: 'deep-hash' };
    }
  }

  // Dependency tree findings.
  if (DEPS && tree) {
    if (!tree.ok) {
      lines.push(['UNVERIFIED', `could not resolve the dependency tree: ${tree.error}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
      checks.dependencies = { state: 'unverified' };
      if (FAIL_UNVERIFIED) failures++;
    } else {
      const sum = summarizeTree(tree.packages);
      let treeAuditComplete = true;
      lines.push(['DEPS', `${sum.count} transitive package${sum.count === 1 ? '' : 's'}, max depth ${sum.maxDepth}`]);

      // Install scripts anywhere in the tree. This is the finding the one-level
      // check could not see: a postinstall three levels down runs just as much
      // as one in the package itself.
      const nested = sum.withInstallScripts.filter((id) => !id.startsWith(`${pkg}@`));
      if (nested.length) {
        const shown = nested.slice(0, 8).join(', ');
        lines.push(['DEPHOOK', `install scripts in dependencies (${nested.length}): ${shown}${nested.length > 8 ? ', …' : ''}`]);
      }

      // Dependencies whose advisory state we never established.
      if (depAdvisoriesUnknown && depAdvisoriesUnknown.size) {
        const blind = tree.packages
          .filter((d) => depAdvisoriesUnknown.has(`${d.name}@${d.version}`))
          .map((d) => `${d.name}@${d.version}`);
        if (blind.length) {
          lines.push(['UNVERIFIED', `advisory state unknown for ${blind.length} package${blind.length === 1 ? '' : 's'} in the tree (OSV batch failed)${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
          treeAuditComplete = false;
          if (FAIL_UNVERIFIED) failures++;
        }
      }

      // Advisories affecting anything in the tree.
      if (depAdvisories && depAdvisories.size) {
        const hits = [];
        for (const dep of tree.packages) {
          const vulns = depAdvisories.get(`${dep.name}@${dep.version}`);
          for (const vuln of (vulns || [])) {
            const sev = osvSeverity(vuln);
            hits.push({
              id: vuln.id, sev, dep: `${dep.name}@${dep.version}`,
              hard: severityIsHard(sev),
              unresolved: vuln._severityUnresolved === true,
            });
          }
        }
        const hard = hits.filter((h) => h.hard);
        // An advisory in the tree whose severity we could not read is not a
        // mild one — the same fail-open that was fixed for the top level.
        const blindSeverity = hits.filter((h) => h.unresolved).map((h) => h.id);
        if (blindSeverity.length) {
          treeAuditComplete = false;
          lines.push(['UNVERIFIED', `severity unknown for ${blindSeverity.length} advisor${blindSeverity.length === 1 ? 'y' : 'ies'} in the tree (${blindSeverity.slice(0, 3).join(', ')}) — OSV detail fetch failed${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
          if (FAIL_UNVERIFIED) failures++;
        }
        if (hits.length) {
          const worst = hard.length ? hard : hits;
          const shown = worst.slice(0, 5).map((h) => `${h.dep} ${h.id} [${h.sev}]`).join(', ');
          lines.push(['DEPCVE', `${hits.length} advisor${hits.length === 1 ? 'y' : 'ies'} in the tree (${hard.length} high/critical): ${shown}${worst.length > 5 ? ', …' : ''}`]);
          if (hard.length && FAIL_DEP_ADVISORIES) failures += 1;
        }
      }
      checks.dependencies = {
        state: !treeAuditComplete ? 'unverified'
          : (tags(lines).has('DEPCVE') ? 'advisories-present' : (tags(lines).has('DEPHOOK') ? 'hooks' : 'clean')),
        count: sum.count,
      };
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
  // An advisory whose severity we could not read is not a mild advisory.
  const unresolved = advisoriesForTool.filter((a) => a.unresolved).map((a) => a.id).filter(Boolean);
  if (unresolved.length) {
    lines.push(['UNVERIFIED', `severity unknown for ${unresolved.length} advisor${unresolved.length === 1 ? 'y' : 'ies'} (${unresolved.slice(0, 4).join(', ')}${unresolved.length > 4 ? ', …' : ''}) — OSV detail fetch failed${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  }
  // Only a run that actually queried the feeds may state an advisory result,
  // and a degraded feed or an unreadable severity is 'unverified', not 'clean'.
  if (!NO_AUDIT && !UPDATE && !OFFLINE) {
    // Order matters. A feed that confirmed a high-severity advisory has told us
    // something definite; another feed being down does not unsay it. Reporting
    // 'unverified' first meant a known-vulnerable version lost its blocking
    // status the moment any other feed stumbled.
    const complete = !degraded.length && !unresolved.length;
    if (advisoriesForTool.some((a) => severityIsHard(a.severity))) {
      checks.advisories = { state: 'vulnerable', complete };
    } else if (!complete) {
      checks.advisories = { state: 'unverified', complete: false };
    } else if (advisoriesForTool.length) {
      checks.advisories = { state: 'advisories-present', complete: true };
    } else {
      checks.advisories = { state: 'clean', complete: true };
    }
  }

  // Unreachable advisory feeds: we cannot assert "no known CVEs" when a feed was
  // down. Surface it loudly; hard-fail under --strict (never silently pass).
  if (degraded.length) {
    lines.push(['UNVERIFIED', `advisory feeds unreachable: ${degraded.join(', ')} — cannot assert "no known CVEs"${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  }

  results.push({
    tool,
    status: verdictFor(failures, lines),
    msg: tool._installed && !tool.version
      ? `${tool.name}@${npmVersion} (unpinned — that is just today's latest)`
      : `${tool.name}@${npmVersion}`,
    lines,
    failures,
    checks,
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
      checks: { ...newChecks(), artifact: { state: 'unverified', method: 'registry-unreachable' } },
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
  const checks = newChecks();

  // Integrity (PyPI sha256 hex)
  const expected = pySha256 ? `sha256-${pySha256}` : null;
  // Two independent conditions, not a chain: an entry with no stored hash AND a
  // wheel-only release used to report only the first and still come back OK.
  if (!tool.pkg_integrity) {
    lines.push(['UNVERIFIED', `${missingPinAdvice(tool)}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    checks.artifact = { state: 'unverified', method: 'none' };
    if (FAIL_UNVERIFIED) failures++;
  }
  if (!expected) {
    // Wheel-only release: there is no sdist to hash, so a stored pin cannot be
    // compared against anything. Saying OK here would bless an unchecked file.
    lines.push(['UNVERIFIED', `PyPI ${pyVersion} publishes no sdist — integrity cannot be compared${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    checks.artifact = { state: 'unverified', method: 'none' };
    if (FAIL_UNVERIFIED) failures++;
  } else if (tool.pkg_integrity && tool.pkg_integrity !== expected) {
    lines.push(['FAIL', `integrity mismatch\n        stored: ${tool.pkg_integrity}\n        pypi  : ${expected}`]);
    checks.artifact = { state: 'mismatch', method: 'registry-metadata' };
    failures++;
  } else if (tool.pkg_integrity && expected) {
    checks.artifact = { state: 'verified', method: 'registry-metadata' };
  }

  if (DEPS) {
    const direct = pypiDirectDependencies(meta);
    lines.push(['DEPS', direct.length
      ? `${direct.length} declared direct requirement${direct.length === 1 ? '' : 's'} (PyPI metadata only — no resolved tree)`
      : 'no declared requirements in PyPI metadata']);
  }

  if (DEEP) {
    const sdist = pypiSdistFile(meta);
    const deep = await deepCheckArtifact({
      url:               sdist?.url,
      algo:              'sha256',
      registryIntegrity: sdist?.digests?.sha256 ? `sha256-${sdist.digests.sha256}` : null,
      storedIntegrity:   tool.pkg_integrity,
    });
    if (deep.state === 'fail') {
      lines.push(['FAIL', deep.message]);
      checks.artifact = { state: 'mismatch', method: 'deep-hash' };
      failures++;
    } else if (deep.state === 'unverified') {
      lines.push(['UNVERIFIED', `${deep.message}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
      checks.artifact = { state: 'unverified', method: 'deep-hash' };
      if (FAIL_UNVERIFIED) failures++;
    } else {
      lines.push(['DEEP', deep.message]);
      checks.artifact = { state: 'verified', method: 'deep-hash' };
    }
  }

  // Source URL
  if (!pyRepo) {
    lines.push(['NOTE', 'PyPI declares no project_urls source — source unverifiable']);
    checks.source_binding = { state: 'unverified' };
  } else if (storedRepo && pyRepo.toLowerCase() !== storedRepo.toLowerCase() && !storedRepo.includes('/tree/')) {
    lines.push(['WARN', `repo mismatch\n        source_url: ${tool.source_url}\n        pypi src  : ${pySrc}`]);
    checks.source_binding = { state: 'mismatch' };
    if (STRICT) failures++;
  } else {
    checks.source_binding = { state: 'verified' };
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
  // An advisory whose severity we could not read is not a mild advisory.
  const unresolved = advisoriesForTool.filter((a) => a.unresolved).map((a) => a.id).filter(Boolean);
  if (unresolved.length) {
    lines.push(['UNVERIFIED', `severity unknown for ${unresolved.length} advisor${unresolved.length === 1 ? 'y' : 'ies'} (${unresolved.slice(0, 4).join(', ')}${unresolved.length > 4 ? ', …' : ''}) — OSV detail fetch failed${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) failures++;
  }
  // Only a run that actually queried the feeds may state an advisory result,
  // and a degraded feed or an unreadable severity is 'unverified', not 'clean'.
  if (!NO_AUDIT && !UPDATE && !OFFLINE) {
    // Order matters. A feed that confirmed a high-severity advisory has told us
    // something definite; another feed being down does not unsay it. Reporting
    // 'unverified' first meant a known-vulnerable version lost its blocking
    // status the moment any other feed stumbled.
    const complete = !degraded.length && !unresolved.length;
    if (advisoriesForTool.some((a) => severityIsHard(a.severity))) {
      checks.advisories = { state: 'vulnerable', complete };
    } else if (!complete) {
      checks.advisories = { state: 'unverified', complete: false };
    } else if (advisoriesForTool.length) {
      checks.advisories = { state: 'advisories-present', complete: true };
    } else {
      checks.advisories = { state: 'clean', complete: true };
    }
  }

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
    checks,
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
    const checks = newChecks();
    let failures = 0;
    // A digest in the DB is a *claim*. Without --deep nothing fetched the
    // manifest, so the artifact is unverified — it was previously recorded as
    // verified purely because the entry looked well-formed.
    checks.artifact = { state: 'unverified', method: 'digest-pin-only' };
    // --deep: a digest *is* the sha256 of the manifest document, so the pin can
    // be verified by hashing what the registry serves. No layers to download.
    if (DEEP && !OFFLINE) {
      const { registry, repo, digest } = parseImageRef(ref);
      if (!ALLOWED_REGISTRIES.has(registry)) {
        lines.push(['UNVERIFIED', `registry "${registry}" is not in the supported allowlist${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
        checks.artifact = { state: 'unverified', method: 'none' };
        if (FAIL_UNVERIFIED) failures++;
      } else {
        const m = await fetchManifest(registry, repo, digest);
        if (m.error) {
          lines.push(['UNVERIFIED', `could not fetch the manifest: ${m.error}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
          checks.artifact = { state: 'unverified', method: 'deep-hash' };
          if (FAIL_UNVERIFIED) failures++;
        } else {
          const computed = ociManifestDigest(m.body);
          if (computed !== digest) {
            lines.push(['FAIL', `manifest digest mismatch\n        pinned  : ${digest}\n        computed: ${computed}`]);
            checks.artifact = { state: 'mismatch', method: 'deep-hash' };
            failures++;
          } else {
            lines.push(['DEEP', `manifest hashed locally: ${computed.slice(0, 26)}…`]);
            checks.artifact = { state: 'verified', method: 'deep-hash' };
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
      checks,
    });
  } else {
    // A structured finding, so a policy rule (docker: "digest") and the SARIF
    // output can both see it. As a bare headline it existed only in prose, and
    // the policy rule that looks for it never fired.
    const failures = STRICT ? 1 : 0;
    results.push({
      tool,
      status: STRICT ? 'FAIL' : 'WARN',
      msg: `${tool.name}: docker image not pinned by digest (${ref})`,
      lines: [['DIGEST', `image ${ref} is referenced by tag, not by @sha256 digest`]],
      failures,
      checks: { ...newChecks(), artifact: { state: 'unverified', method: 'none' } },
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
    // Offline establishes that the DB *has* pins, not that they match anything.
    // Recording 'verified' here would be recording the absence of a check.
    checks: { ...newChecks(), artifact: { state: 'unverified', method: 'offline-pin-present' } },
  });
}

// ── main ───────────────────────────────────────────────────────────────────

async function main() {
  // A policy that doesn't parse is not a policy: refuse rather than run a bar
  // nobody set.
  if (POLICY.found && !POLICY.ok) {
    console.error(`policy error in ${POLICY.path}:`);
    for (const e of POLICY.errors) console.error(`  - ${e}`);
    process.exit(2);
  }

  if (process.argv.includes('--show-policy')) {
    process.stdout.write(JSON.stringify({
      policy_file: POLICY.path,
      found:       POLICY.found,
      effective:   POLICY.policy || null,
      switches: {
        fail_unverified: FAIL_UNVERIFIED, deep: DEEP, deps: DEPS,
        require_signatures: REQUIRE_SIGNATURES, require_provenance: REQUIRE_PROVENANCE,
        fail_dep_advisories: FAIL_DEP_ADVISORIES, strict: STRICT,
      },
    }, null, 2) + '\n');
    return exitAfterFlush(0);
  }

  if (OFFLINE && UPDATE) {
    console.error('--offline cannot be combined with --update (refresh requires registries).');
    process.exit(2);
  }

  const db        = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  const results   = [];
  let totalFails  = 0;
  let updated     = 0;

  const allTools = Array.isArray(db.tools) ? db.tools : [];
  let scope = ENTRY ? allTools.filter((t) => t.name === ENTRY) : allTools;
  if (ENTRY && scope.length === 0) {
    console.error(`--entry: no DB entry named "${ENTRY}"`);
    process.exit(2);
  }

  // --installed replaces the subject list with the configured servers, each
  // turned into a DB-entry shape so the same checks apply. A version pin only
  // gets a stored hash to compare against when the DB has that exact version;
  // otherwise the run still verifies the registry signature, which is the part
  // that doesn't depend on us having seen the release before.
  const installedNotes = [];
  if (INSTALLED) {
    if (UPDATE) {
      console.error('--installed cannot be combined with --update (the DB is not the subject).');
      process.exit(2);
    }
    const servers = readInstalledServers({
      cwd: CWD,
      onUnreadable: (loc) => installedNotes.push({ ...loc, kind: 'unreadable' }),
    });
    if (!servers.length && !installedNotes.length) {
      const note = `No configured MCP servers found (looked in ${CWD} and the usual host config paths).`;
      if (AS_JSON || AS_SARIF) {
        // A machine-readable mode always emits a document, even an empty one:
        // "no output" is not something a caller can distinguish from a crash.
        const empty = toJsonReport({ results: [], meta: { mode: 'installed', subject: 'installed', note } });
        process.stdout.write(JSON.stringify(AS_SARIF ? toSarif(empty, {}) : empty, null, 2) + '\n');
      } else {
        console.error(note);
      }
      return exitAfterFlush(0);
    }
    const byName = new Map(allTools.map((t) => [t.name, t]));
    scope = servers.map((srv) => {
      const known = byName.get(srv.name) || null;
      const pinnedVersion = versionFromInstallCmd(srv.install_cmd);
      const sameVersion = known && pinnedVersion && known.version === pinnedVersion;
      return {
        name:          srv.name,
        install_cmd:   srv.install_cmd || `(${srv.remote ? `remote: ${srv.remote}` : srv.command || 'no command'})`,
        version:       pinnedVersion,
        // Only the DB's hash for the *same* version is evidence about this artifact.
        pkg_integrity: sameVersion ? known.pkg_integrity : null,
        source_url:    known ? known.source_url : null,
        trust:         known ? known.trust : 'not-in-vault',
        license:       known ? known.license : null,
        _installed: {
          host: srv.host, scope: srv.scope, source: srv.source, in_vault: !!known, remote: srv.remote,
          // What kind of thing this is decides what "unverifiable" means.
          kind: srv.remote ? 'remote' : (srv.install_cmd ? 'registry' : 'local'),
          command: srv.command,
        },
      };
    });
    // A config that exists but does not parse is a finding: it may be the file
    // that holds the servers nobody is checking. It used to vanish into a
    // stderr note while the run exited 0 with an empty document.
    for (const problem of installedNotes) {
      scope.push({
        name: `${problem.host || 'host'} config (${problem.path})`,
        install_cmd: '(unreadable config)',
        version: null, pkg_integrity: null, source_url: null, trust: 'not-in-vault',
        _installed: { host: problem.host, scope: problem.scope, source: problem.path, in_vault: false, kind: 'unreadable', command: null },
        _configError: problem.error,
      });
    }
  }

  // Bucket tools by ecosystem.
  const npmTools    = [];     // [{ tool, pkg }]
  const pypiTools   = [];     // [{ tool, pkg }]
  const dockerTools = [];

  // An entry we can't route to a registry is UNVERIFIED, not SKIP: nothing about
  // its pin was ever checked, so --strict must refuse to call the run clean.
  const unroutable = (tool, why) => {
    // For an installed server, "we can't check this" has three quite different
    // causes, and saying "unknown install method" for a local binary is just
    // wrong. Name the actual situation.
    const inst = tool._installed;
    const reason = !inst ? why
      : inst.kind === 'remote' ? `remote server (${inst.remote}) — no artifact to verify, trust is in the endpoint`
      : inst.kind === 'unreadable' ? `host config could not be parsed (${tool._configError}) — the servers it lists were not checked`
      : inst.kind === 'local'  ? `launched from a local command (${inst.command}) — nothing published to verify against`
      : why;
    results.push({
      tool,
      status: 'UNVERIFIED',
      msg: `${tool.name}: ${reason}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`,
      failures: FAIL_UNVERIFIED ? 1 : 0,
      checks: { ...newChecks(), artifact: { state: 'unverified', method: 'unroutable' } },
    });
  };

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
  // Severity for OSV hits comes from the full records, not the batch stubs.
  const osvDetail = (!UPDATE && !NO_AUDIT && !OFFLINE)
    ? await enrichOsvVulns([...(osvNpm.data || []), ...(osvPypi.data || [])])
    : { byId: new Map(), failed: new Set() };

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

  // --deps: resolve every npm tree (concurrently, cached on disk), then ask OSV
  // about every distinct package in all of them in a handful of batch queries
  // rather than one request per dependency.
  let npmTrees = [];
  let depAdvisories = new Map();
  // Packages whose advisory state we could not establish at all.
  const depAdvisoriesUnknown = new Set();
  if (DEPS && !OFFLINE && npmTools.length) {
    progress(`Resolving dependency trees for ${npmTools.length} npm entries (${DEPS_CONCURRENCY} at a time)... `);
    npmTrees = await mapLimit(npmTools, DEPS_CONCURRENCY, ({ tool, pkg }) =>
      resolveNpmTreeCached(pkg, tool.version, {
        registry: NPM_REGISTRY === 'https://registry.npmjs.org' ? null : NPM_REGISTRY,
        // A pinned root does not pin its tree: `dep: ^1` moves under a fixed
        // `server@1.0.0`. For an install gate (--entry, or fail-closed) that
        // means the tree checked must be the tree resolved now, so the cache is
        // off. A survey run over the whole DB may use it.
        cacheTtlMs: (ENTRY || FAIL_UNVERIFIED) ? 0 : undefined,
      }));
    const distinct = new Map();
    for (const tree of npmTrees) {
      for (const dep of (tree.ok ? tree.packages : [])) {
        if (!dep.version) continue;
        distinct.set(`${dep.name}@${dep.version}`, { ecosystem: 'npm', name: dep.name, version: dep.version });
      }
    }
    const queries = [...distinct.values()];
    progress(`${queries.length} distinct packages; querying OSV... `);
    // OSV's querybatch takes a list; keep the batches modest so one failure
    // costs one batch rather than the whole set.
    const BATCH = 500;
    const batched = [];
    for (let i = 0; i < queries.length; i += BATCH) {
      const chunk = queries.slice(i, i + BATCH);
      const res = await fetchOsvAdvisories(chunk);
      if (!res.ok) {
        // The batch did not answer. Coalescing that into "no advisories" is
        // the fail-open this whole pass exists to remove, so mark every
        // package in the batch as unknown instead.
        for (const q of chunk) depAdvisoriesUnknown.add(`${q.name}@${q.version}`);
        continue;
      }
      chunk.forEach((q, j) => {
        const vulns = res.data?.[j]?.vulns || [];
        if (vulns.length) batched.push([`${q.name}@${q.version}`, vulns]);
      });
    }
    // Same as above: the stubs carry no severity, so "0 high/critical" would be
    // a guess. Fetch the records the severity actually lives in.
    const detail = await enrichOsvVulns(batched.map(([, vulns]) => ({ vulns })));
    for (const [key, vulns] of batched) depAdvisories.set(key, withOsvDetail(vulns, detail));
    progress('done.\n');
  }

  // Process npm.
  for (let i = 0; i < npmTools.length; i++) {
    const { tool, pkg } = npmTools[i];
    // null (feed down) coalesces to [] for the merge, but degradedFeedsFor() reads
    // the raw null below so the outage is reported rather than read as "clean".
    const advs = unifyAdvisories({
      npmList:  npmAdvisories.data[pkg] || [],
      osvList:  withOsvDetail(osvNpm.data[i]?.vulns, osvDetail),
      ghsaList: ghsa.data[`npm:${pkg}`] || [],
      snykList: snyk.data[`npm:${pkg}`] || [],
    });
    const degraded = (UPDATE || NO_AUDIT) ? [] : degradedFeedsFor('npm', `npm:${pkg}`, health);
    await processNpm(tool, pkg, npmMetas[i], advs, degraded, results, npmTrees[i], depAdvisories, depAdvisoriesUnknown);
  }
  // Process PyPI.
  for (let i = 0; i < pypiTools.length; i++) {
    const { tool, pkg } = pypiTools[i];
    const advs = unifyAdvisories({
      npmList:  [],
      osvList:  withOsvDetail(osvPypi.data[i]?.vulns, osvDetail),
      ghsaList: ghsa.data[`pip:${pkg}`] || [],
      snykList: snyk.data[`pip:${pkg}`] || [],
    });
    const degraded = (UPDATE || NO_AUDIT) ? [] : degradedFeedsFor('PyPI', `pip:${pkg}`, health);
    await processPypi(tool, pkg, pypiMetas[i], advs, degraded, results);
  }
  // Process docker.
  for (const { tool } of dockerTools) await processDocker(tool, results);

  // Evidence: what this run established, dated, per dimension. Written only on
  // request — a scan is read-only unless asked otherwise.
  if (RECORD_EVIDENCE) {
    if (INSTALLED) {
      console.error('--record-evidence applies to DB entries, not to --installed subjects.');
      return exitAfterFlush(2);
    }
    let recorded = 0;
    for (let i = 0; i < results.length; i++) {
      const tool = results[i].tool;
      if (!tool || !tool.name) continue;
      const typed = toTypedEntry(tool);
      // Built from what the processors established, not from the report text.
      const fresh = buildEvidence(results[i].checks, {
        artifactId: typed ? artifactId(typed.artifact) : null,
      });
      if (!Object.keys(fresh.dimensions).length) continue;
      tool.trust_evidence = mergeEvidence(tool.trust_evidence, fresh);
      // The word stays, but it is now computed from the dated evidence.
      tool.trust = deriveTrust(tool.trust_evidence, {
        maxAgeDays: evidenceMaxAge(),
        // npm/PyPI have advisory feeds; an image digest does not, so what
        // "verified" requires differs by ecosystem.
        require: requiredFor(typed ? typed.artifact.ecosystem : null),
      });
      recorded++;
    }
    if (recorded) {
      writeDb(DB_PATH, db);
      progress(`Recorded evidence for ${recorded} entr${recorded === 1 ? 'y' : 'ies'} in ${DB_PATH}\n`);
    }
  }

  // Policy rules that are not facts about the artifact — license lists, trust
  // tiers, a health-score floor — are judged here, once each entry has its
  // findings. They ride along as ordinary findings so every output mode
  // (text, JSON, SARIF) shows them without special-casing.
  // Evidence that has aged out. An advisory result especially: "clean" means
  // clean as of that date, and disclosures don't wait.
  //
  // What counts is the *effective* evidence: this run's own results merged over
  // what was stored, whether or not --record-evidence is going to save it.
  // Otherwise a run that just checked everything successfully still failed on a
  // stored timestamp, and the only way out was to write to the DB — which made
  // a read-only verification impossible to pass.
  for (const r of results) {
    const stored = r.tool && r.tool.trust_evidence;
    if (!stored) continue;
    const typed = r.tool ? toTypedEntry(r.tool) : null;
    const fresh = buildEvidence(r.checks, { artifactId: typed ? artifactId(typed.artifact) : null });
    const evidence = Object.keys(fresh.dimensions).length ? mergeEvidence(stored, fresh) : stored;
    const stale = staleDimensions(evidence, evidenceMaxAge());
    if (!stale.length) continue;
    r.lines = r.lines || [];
    const worst = stale.sort((a, b) => b.age_days - a.age_days).slice(0, 3)
      .map((sd) => `${sd.dimension} ${sd.age_days}d old (max ${sd.max_age_days})`).join(', ');
    r.lines.push(['UNVERIFIED', `stored evidence has aged out: ${worst}${FAIL_UNVERIFIED ? '' : ' (use --fail-unverified to fail closed)'}`]);
    if (FAIL_UNVERIFIED) {
      r.failures = (r.failures || 0) + 1;
      r.status = 'FAIL';
    } else if (r.status === 'OK') {
      r.status = 'UNVERIFIED';
    }
  }

  if (POLICY.ok && POLICY.policy) {
    // Judge the policy on what this run established, merged over what was
    // stored — not on a `trust` field that only moves when --record-evidence
    // is passed. Otherwise an entry that just passed every check still failed
    // `trust: ["verified"]`, and the only way to satisfy the policy was to
    // write to the DB during a verification.
    for (const r of results) {
      if (!r.tool) continue;
      const typed = toTypedEntry(r.tool);
      const fresh = buildEvidence(r.checks, { artifactId: typed ? artifactId(typed.artifact) : null });
      if (!Object.keys(fresh.dimensions).length) continue;
      const effective = mergeEvidence(r.tool.trust_evidence, fresh);
      r.effective_trust = deriveTrust(effective, {
        maxAgeDays: evidenceMaxAge(),
        require: requiredFor(typed ? typed.artifact.ecosystem : null),
      });
    }
    const draft = toJsonReport({ results });
    for (let i = 0; i < results.length; i++) {
      // The policy sees the effective trust, not the stored word.
      const subject = results[i].effective_trust
        ? { ...results[i].tool, trust: results[i].effective_trust }
        : results[i].tool;
      const verdicts = evaluateEntry(draft.entries[i], POLICY.policy, subject);
      if (!verdicts.length) continue;
      results[i].lines = results[i].lines || [];
      for (const v of verdicts) {
        results[i].lines.push([v.level === 'fail' ? 'POLICY-FAIL' : 'POLICY-WARN', `${v.rule}: ${v.message}`]);
        if (v.level === 'fail') results[i].failures = (results[i].failures || 0) + 1;
      }
      if (results[i].failures > 0) results[i].status = 'FAIL';
    }
  }

  // Machine-readable modes: one document on stdout, nothing else. Everything
  // human-facing has gone to stderr already, so `--json` stays pipeable.
  if (AS_JSON || AS_SARIF) {
    totalFails = results.reduce((n, r) => n + (r.failures || 0), 0);
    const report = toJsonReport({
      results,
      meta: {
        mode: OFFLINE ? 'offline' : (UPDATE ? 'update' : (NO_AUDIT ? 'no-audit' : 'full')),
        subject: INSTALLED ? 'installed' : 'database',
        installed_config_problems: INSTALLED ? installedNotes : undefined,
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
  versionFromInstallCmd,
  osvSeverity,
  unifyAdvisories,
  degradedFeedsFor,
  summarizeFeedSources,
};
