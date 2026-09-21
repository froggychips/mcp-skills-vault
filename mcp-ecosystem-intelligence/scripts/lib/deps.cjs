'use strict';
/**
 * Resolve the dependency tree of a pinned package, without installing it.
 *
 * Why: the gate verified the top-level artifact only. An MCP server is a
 * regular npm package with a dependency tree, and an install-time script —
 * the thing this repo tracks most carefully — is far more often in a
 * transitive dependency than in the package itself. "Supply chain" checked one
 * level deep is checked at the wrong depth.
 *
 * How: `npm install --package-lock-only --ignore-scripts` writes a lockfile and
 * nothing else. npm does the semver resolution (writing a resolver here would
 * be a worse resolver), no package code is fetched or executed, and the
 * resulting lockfile carries exactly what is needed per node: resolved
 * version, integrity, and `hasInstallScript`.
 *
 * `--ignore-scripts` matters twice over: it is what makes this safe to run on
 * a machine at all, and `--package-lock-only` means even a malicious
 * `postinstall` is never in a position to run.
 *
 * PyPI has no equivalent one-shot resolution that doesn't build wheels, so
 * `pypiDirectDependencies()` reports declared direct requirements only, and
 * says so rather than pretending to a full tree.
 *
 * API:
 *   parseLockTree(lockJson)               -> [{ name, version, integrity, hasInstallScript, depth }]
 *   resolveNpmTree(pkg, version, opts)    -> { ok, packages, lockfile?, error? }
 *   pypiDirectDependencies(pypiMeta)      -> [{ name, spec }]
 *   summarizeTree(packages)               -> { count, withInstallScripts, maxDepth }
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const { cacheRoot } = require('./cache_dir.cjs');

const DEFAULT_TIMEOUT_MS = 120000;
// Resolution is the slow part — tens of seconds per package, because npm has to
// walk the whole graph. But a pinned root does NOT pin its tree: `server@1.0.0`
// depending on `dep: ^1` resolves to whatever `dep` published most recently, so
// a cached tree goes stale the moment any dependency ships. A day is a
// compromise between the cost of resolving and the age of the answer; callers
// that must not be wrong (an install gate) pass cacheTtlMs: 0.
const DEFAULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

// Only an exact version makes the *request* reproducible. A range or a tag is
// never cached, because the thing it names changes underneath.
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * Flatten a package-lock v2/v3 `packages` map.
 *
 * Keys look like "node_modules/foo" or "node_modules/foo/node_modules/bar";
 * depth is how many `node_modules/` segments deep the node sits, which is a
 * usable stand-in for "how far from the package I asked for".
 */
function parseLockTree(lock) {
  const packages = (lock && lock.packages) || {};
  const out = [];
  for (const [key, node] of Object.entries(packages)) {
    if (!key || key === '') continue;                       // the root project itself
    const segments = key.split('node_modules/').slice(1);
    const pathName = segments[segments.length - 1]?.replace(/\/$/, '');
    if (!pathName) continue;
    // `"alias": "npm:real-package@1.2.3"` installs real-package at
    // node_modules/alias, and the lockfile records the real name in `name`.
    // Taking the path segment meant asking OSV about a package that does not
    // exist, so the real package's advisories were never seen.
    const name = typeof node.name === 'string' && node.name ? node.name : pathName;
    out.push({
      name,
      installed_as:     name === pathName ? undefined : pathName,
      version:          node.version || null,
      integrity:        node.integrity || null,
      resolved:         node.resolved || null,
      hasInstallScript: node.hasInstallScript === true,
      dev:              node.dev === true,
      optional:         node.optional === true,
      depth:            segments.length,
    });
  }
  // Stable order so a report diff means a real change.
  return out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : String(a.version).localeCompare(String(b.version))));
}

function summarizeTree(packages) {
  const list = packages || [];
  return {
    count:              list.length,
    withInstallScripts: list.filter((p) => p.hasInstallScript).map((p) => `${p.name}@${p.version}`),
    maxDepth:           list.reduce((m, p) => Math.max(m, p.depth || 0), 0),
  };
}

/**
 * Resolve `pkg@version` into a flat package list.
 *
 * Runs in a throwaway directory containing only a minimal package.json, so
 * nothing about the host project influences resolution.
 */
function resolveNpmTree(pkg, version, {
  timeoutMs = DEFAULT_TIMEOUT_MS,
  registry = null,
  tmpRoot = os.tmpdir(),
  run = execFile,
  // Keep the lockfile npm wrote, not just the flattened summary. A summary is
  // enough to *report* a tree and not enough to *reinstall* it: `npm ci` needs
  // npm's own file, and regenerating one by re-resolving gives a different
  // tree the moment any dependency publishes. That is not a lockfile.
  keepLockfile = false,
} = {}) {
  return new Promise((resolve) => {
    let dir;
    try {
      dir = fs.mkdtempSync(path.join(tmpRoot, 'mcp-vault-deps-'));
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
        name: 'mcp-vault-dep-probe', version: '0.0.0', private: true,
      }));
    } catch (e) {
      resolve({ ok: false, error: `could not create a working directory: ${e.message}` });
      return;
    }

    const spec = version ? `${pkg}@${version}` : pkg;
    const args = [
      'install', spec,
      '--package-lock-only',   // resolve and write the lockfile; install nothing
      '--ignore-scripts',      // belt and braces: no lifecycle script ever runs
      '--no-audit', '--no-fund', '--silent',
      // No `--prefix`: it is the same directory as cwd, and passing both made
      // npm treat the prefix as a separate root and write *absolute* temp-dir
      // paths as the lockfile's package keys
      // ("../../private/var/folders/…/node_modules/pkg"). parseLockTree coped,
      // because it splits on "node_modules/", so nothing noticed until the
      // lockfile had to be handed back to npm — where `npm ci` rejected it.
    ];
    if (registry) args.push('--registry', registry);

    const cleanup = () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } };

    run('npm', args, { cwd: dir, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, _stdout, stderr) => {
      if (err) {
        cleanup();
        const detail = String(stderr || err.message || '').split('\n').find((l) => l.trim()) || 'npm failed';
        resolve({ ok: false, error: detail.slice(0, 200) });
        return;
      }
      let lock;
      try { lock = JSON.parse(fs.readFileSync(path.join(dir, 'package-lock.json'), 'utf8')); }
      catch (e) { cleanup(); resolve({ ok: false, error: `no usable lockfile: ${e.message}` }); return; }
      cleanup();
      resolve({
        ok: true,
        packages: parseLockTree(lock),
        lockfileVersion: lock.lockfileVersion || null,
        ...(keepLockfile ? { lockfile: lock } : {}),
      });
    });
  });
}

/**
 * Direct requirements declared by a PyPI release.
 *
 * `requires_dist` entries look like "httpx (>=0.27)" or
 * "pytest; extra == 'dev'". Extras-gated requirements are dropped: they are not
 * installed by a plain `uvx <pkg>`.
 */
function pypiDirectDependencies(meta) {
  const list = meta?.info?.requires_dist || [];
  const out = [];
  for (const raw of list) {
    if (typeof raw !== 'string') continue;
    const [requirement, ...markers] = raw.split(';');
    if (markers.join(';').includes('extra ==')) continue;
    const m = requirement.trim().match(/^([A-Za-z0-9._-]+)\s*(.*)$/);
    if (!m) continue;
    out.push({ name: m[1], spec: (m[2] || '').replace(/[()]/g, '').trim() || null });
  }
  return out;
}

// ── cache ──────────────────────────────────────────────────────────────────

function treeCacheDir() {
  return path.join(cacheRoot(), 'deps');
}

function treeCacheKey(pkg, version) {
  return crypto.createHash('sha256').update(`npm\u0000${pkg}\u0000${version || 'latest'}`).digest('hex');
}

/**
 * resolveNpmTree with a disk cache. An unpinned request (no version) is never
 * cached: "latest" is a moving target and a stale answer for it would be a
 * quiet lie.
 */
async function resolveNpmTreeCached(pkg, version, opts = {}) {
  const { cacheTtlMs = DEFAULT_CACHE_TTL_MS, ...rest } = opts;
  const cacheable = typeof version === 'string' && EXACT_VERSION.test(version) && cacheTtlMs > 0;
  const file = cacheable ? path.join(treeCacheDir(), `${treeCacheKey(pkg, version)}.json`) : null;

  if (file) {
    try {
      const rec = JSON.parse(fs.readFileSync(file, 'utf8'));
      const age = Date.now() - (rec.stored_at || 0);
      if (rec && age < cacheTtlMs && Array.isArray(rec.packages)) {
        // ageMs is reported so a caller can say how old the answer is rather
        // than presenting it as current.
        return { ok: true, packages: rec.packages, lockfileVersion: rec.lockfileVersion || null, fromCache: true, ageMs: age };
      }
    } catch { /* absent or corrupt: resolve again */ }
  }

  const result = await resolveNpmTree(pkg, version, rest);
  if (file && result.ok) {
    try {
      fs.mkdirSync(treeCacheDir(), { recursive: true });
      // Random name, exclusive write: see the same pattern in lib/http.cjs.
      const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ stored_at: Date.now(), packages: result.packages, lockfileVersion: result.lockfileVersion }), { mode: 0o600, flag: 'wx' });
      fs.renameSync(tmp, file);
    } catch { /* a cache that can't be written is not worth failing over */ }
  }
  return result;
}

module.exports = {
  parseLockTree, resolveNpmTree, resolveNpmTreeCached, pypiDirectDependencies,
  summarizeTree, treeCacheDir, treeCacheKey,
  DEFAULT_TIMEOUT_MS, DEFAULT_CACHE_TTL_MS,
};
