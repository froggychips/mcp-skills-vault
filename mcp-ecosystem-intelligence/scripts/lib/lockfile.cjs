'use strict';
/**
 * mcp.lock.json — what we verified, written down, so that what runs is what we
 * verified.
 *
 * The gap this closes is the oldest one in the repo. The gate verifies
 * `server@1.2.3`: its tarball hash, its signature, its provenance, its
 * advisories, and (with --deps) its dependency tree. Then `.mcp.json` says
 * `npx -y server@1.2.3`, and at every start npm resolves that package's
 * *dependency ranges* fresh. `server@1.2.3` depending on `lib: ^2` runs
 * whatever `lib` published most recently — so the tree that was checked and the
 * tree that runs are related only by hope. Pinning the top level pinned the one
 * thing an attacker is least likely to touch.
 *
 * A lockfile records three layers, each at its own level of certainty:
 *
 *   artifact  the package and the integrity value the gate compared. A fact.
 *   tree      every transitive package with its resolved version and integrity,
 *             as npm resolved it at lock time. Reproducible: `npm ci` against
 *             the stored npm lockfile installs exactly this.
 *   surface   the hash of the tool list the server presented (lib/surface.cjs).
 *             Not part of the install at all — it is what the server *says* —
 *             and kept here because "same artifact, different surface" is only
 *             detectable against a recorded baseline.
 *
 * What a lockfile is not: a promise that any of it is safe. It is a record of
 * what was true when it was written, which is what makes a later difference
 * meaningful.
 *
 * API:
 *   emptyLock()                             -> lock document
 *   lockEntry({ tool, tree, surface, … })   -> server record
 *   readLock(file)                          -> { ok, lock, error? }
 *   writeLock(file, lock)                   -> void
 *   diffLock(before, after)                 -> { servers: [{ name, changes }] }
 *   vendorFiles(entry)                      -> { packageJson, packageLock } | null
 */

const fs   = require('fs');
const path = require('path');

const LOCK_SCHEMA   = 'mcp-vault/lock@1';
const LOCK_FILENAME = 'mcp.lock.json';

function emptyLock() {
  return {
    $schema:      LOCK_SCHEMA,
    generated_at: new Date().toISOString(),
    // Deliberately not "verified_at": this file records what a run observed,
    // and the words `trust` and `verified` belong to the evidence model.
    servers:      {},
  };
}

/**
 * One server's record.
 *
 * `tree` is stored sorted and flat rather than nested: a flat list with depths
 * diffs cleanly, and the nesting carries no information a consumer here needs.
 */
function lockEntry({ tool, artifact = null, tree = null, surface = null, now = new Date() } = {}) {
  const entry = {
    locked_at: now.toISOString().slice(0, 10),
    artifact: artifact || null,
    launch:   tool && tool.install_cmd ? tool.install_cmd : null,
  };

  if (tree && Array.isArray(tree.packages)) {
    entry.tree = {
      resolved_at:     tree.resolved_at || entry.locked_at,
      lockfileVersion: tree.lockfileVersion || null,
      // npm's own lockfile, verbatim. This is the part that makes the record
      // reinstallable rather than merely descriptive: `npm ci` against it
      // installs these exact versions, where a fresh resolve would pick up
      // whatever has been published since. `packages` below is a derived index
      // of the same data, kept because it diffs cleanly and this does not.
      npm_lockfile:    tree.lockfile || null,
      count:           tree.packages.length,
      install_scripts: tree.packages.filter((p) => p.hasInstallScript).map((p) => `${p.name}@${p.version}`).sort(),
      packages: tree.packages
        // `optional` and `dev` are carried because they decide whether npm is
        // *expected* to install an entry: a Darwin-only optional dependency
        // recorded flatly made "installs exactly this tree" false on Linux,
        // where npm legitimately skips it.
        .map((p) => ({
          name: p.name,
          version: p.version || null,
          integrity: p.integrity || null,
          ...(p.optional ? { optional: true } : {}),
          ...(p.dev ? { dev: true } : {}),
        }))
        .sort((a, b) => (a.name === b.name
          ? String(a.version).localeCompare(String(b.version))
          : (a.name < b.name ? -1 : 1))),
    };
  }

  if (surface && surface.sha256) {
    entry.surface = {
      // Only the digests. The text is attacker-controlled and this file gets
      // committed; see lib/surface.cjs.
      observed_at: surface.observed_at || entry.locked_at,
      sha256:      surface.sha256,
      count:       surface.count ?? null,
      tools:       surface.tools || {},
    };
  }

  return entry;
}

function lockPath(cwd = process.cwd()) {
  return path.join(cwd, LOCK_FILENAME);
}

function readLock(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); }
  catch (e) {
    // Absent is not an error: the first `lock` run has nothing to read.
    if (e.code === 'ENOENT') return { ok: true, lock: null, missing: true };
    return { ok: false, lock: null, error: `could not read ${file}: ${e.message}` };
  }
  let doc;
  try { doc = JSON.parse(raw); }
  catch (e) { return { ok: false, lock: null, error: `${file} is not valid JSON: ${e.message}` }; }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return { ok: false, lock: null, error: `${file} does not contain a lock document` };
  }
  if (doc.$schema && doc.$schema !== LOCK_SCHEMA) {
    // Refuse rather than guess: a schema we don't know may mean the fields we
    // are about to compare mean something else.
    return { ok: false, lock: null, error: `${file} has schema ${doc.$schema}, expected ${LOCK_SCHEMA}` };
  }
  return { ok: true, lock: { ...emptyLock(), ...doc, servers: doc.servers || {} } };
}

function writeLock(file, lock) {
  fs.writeFileSync(file, `${JSON.stringify(lock, null, 2)}\n`);
}

/**
 * The tree as name → (version → integrity).
 *
 * Keyed by name *and* version on purpose. A real npm tree routinely contains
 * the same package at several versions (nested node_modules), and the first
 * version of this indexed by name alone: the map kept whichever occurrence came
 * last, so a version or integrity change in any of the others was invisible and
 * `lock --check` reported "no change" over different locked bytes.
 */
function treeIndex(entry) {
  const out = new Map();
  for (const p of entry?.tree?.packages || []) {
    if (!out.has(p.name)) out.set(p.name, new Map());
    // Two records for the same name@version can only differ in integrity; the
    // first is kept and the second would be a corrupt lock, not a finding.
    const versions = out.get(p.name);
    if (!versions.has(p.version)) versions.set(p.version, p.integrity || null);
  }
  return out;
}

/** "name@1.0.0, name@2.0.0" — for a message about a package at several versions. */
function versionList(versions) {
  return [...versions.keys()].sort().join(', ');
}

/**
 * What changed between two lock documents, per server.
 *
 * Change kinds are separate because they mean different things and one of them
 * is the interesting one:
 *
 *   artifact         the pinned package or its integrity moved
 *   tree-added       a transitive dependency appeared
 *   tree-removed     one disappeared
 *   tree-version     the set of versions for a package changed (a package can
 *                    legitimately appear at several versions in one tree) …
 *   tree-integrity   … or to the same version with different bytes, which is
 *                    not something that happens innocently
 *   install-script   a package in the tree gained an install-time hook
 *   surface          the tool list changed
 *   surface-only     the tool list changed and the artifact did not
 *   surface-unobserved  a surface was locked, and this run did not measure one
 */
function diffLock(before, after) {
  const a = (before && before.servers) || {};
  const b = (after && after.servers) || {};
  const servers = [];

  for (const name of new Set([...Object.keys(a), ...Object.keys(b)]).values()) {
    const prev = a[name];
    const next = b[name];
    if (!prev) { servers.push({ name, changes: [{ kind: 'added', detail: 'not in the previous lock' }] }); continue; }
    if (!next) { servers.push({ name, changes: [{ kind: 'removed', detail: 'no longer locked' }] }); continue; }

    const changes = [];
    const pa = prev.artifact || {};
    const na = next.artifact || {};
    const artifactChanged = pa.id !== na.id || pa.integrity !== na.integrity;
    if (pa.id !== na.id) changes.push({ kind: 'artifact', detail: `${pa.id || '(none)'} → ${na.id || '(none)'}` });
    else if (pa.integrity !== na.integrity) {
      changes.push({ kind: 'artifact', detail: `same version, different integrity: ${pa.integrity || '(none)'} → ${na.integrity || '(none)'}` });
    }

    const pi = treeIndex(prev);
    const ni = treeIndex(next);
    for (const [pkg, nowVersions] of ni) {
      const wasVersions = pi.get(pkg);
      if (!wasVersions) {
        changes.push({ kind: 'tree-added', detail: `${pkg}@${versionList(nowVersions)}` });
        continue;
      }
      // Same version, different bytes, per occurrence. npm does not allow
      // republishing a version, so this is either a registry problem or a proxy
      // in the way — and it is the finding with no innocent reading.
      for (const [version, integrity] of nowVersions) {
        if (!wasVersions.has(version)) continue;
        const before = wasVersions.get(version);
        if (before && integrity && before !== integrity) {
          changes.push({ kind: 'tree-integrity', detail: `${pkg}@${version} has different integrity than when locked` });
        }
      }
      const appeared = [...nowVersions.keys()].filter((v) => !wasVersions.has(v));
      const vanished = [...wasVersions.keys()].filter((v) => !nowVersions.has(v));
      if (appeared.length || vanished.length) {
        changes.push({
          kind: 'tree-version',
          detail: `${pkg} ${versionList(wasVersions)} → ${versionList(nowVersions)}`,
        });
      }
    }
    for (const [pkg, wasVersions] of pi) {
      if (!ni.has(pkg)) changes.push({ kind: 'tree-removed', detail: `${pkg}@${versionList(wasVersions)}` });
    }

    const prevHooks = new Set(prev.tree?.install_scripts || []);
    for (const hook of next.tree?.install_scripts || []) {
      if (!prevHooks.has(hook)) changes.push({ kind: 'install-script', detail: `${hook} runs code at install time and did not before` });
    }

    // A surface that was locked and not measured this time is not "unchanged".
    // Silence here would be the familiar bug: a check that did not run reading
    // as a check that passed.
    if (prev.surface && !next.surface) {
      changes.push({
        kind:   'surface-unobserved',
        detail: `a tool surface was locked on ${prev.surface.observed_at || 'an earlier run'} but nothing measured it this time`
          + ' — run `mcp-vault eval --name ' + name + ' --sandbox` to compare it',
      });
    }
    if (prev.surface && next.surface && prev.surface.sha256 !== next.surface.sha256) {
      changes.push({
        kind:   artifactChanged ? 'surface' : 'surface-only',
        detail: artifactChanged
          ? 'the tool surface changed along with the artifact'
          : 'the tool surface changed while the artifact did not',
      });
    }

    if (changes.length) servers.push({ name, changes });
  }

  servers.sort((x, y) => (x.name < y.name ? -1 : 1));
  return { servers };
}

/**
 * The package.json / package-lock.json pair to write for `npm ci`.
 *
 * `npm ci` refuses to run when package.json and the lockfile disagree, which is
 * the property being bought here — so both sides are written from the same
 * source, and two things npm left in the lockfile have to be normalised first:
 *
 *   - the root project's `version`. npm resolved the tree in a temp directory
 *     and recorded `version: "file:/var/folders/…/mcp-vault-deps-1U19zn"`,
 *     which is not a version and made every `npm ci` fail.
 *   - the root dependency *range*. `npm install pkg@1.2.3` saves `^1.2.3`, so
 *     `npm ci` recomputed the newest match (2026.8.31) against a lockfile that
 *     correctly held the pinned 2026.1.26 and refused as out of sync. A vendor
 *     step exists to install one exact version; the range has to say so.
 *
 * Neither field is part of the dependency tree, so rewriting them changes what
 * gets installed in no way — it only stops npm arguing with itself.
 */
function vendorFiles(entry) {
  if (!entry || !entry.artifact || entry.artifact.ecosystem !== 'npm') return null;
  const lock = entry.tree && entry.tree.npm_lockfile;
  if (!lock || !lock.packages || !lock.packages['']) return null;
  const pkg     = entry.artifact.package;
  const version = entry.artifact.version;
  if (!pkg || !version) return null;

  const NAME = 'mcp-vault-vendored';
  const VERSION = '0.0.0';
  const root = lock.packages[''];
  // Every root dependency group is carried over, with only *our* package's
  // specifier rewritten to the exact version. Replacing the whole map with one
  // pin dropped the root's devDependencies from package.json while leaving
  // them in the lockfile: `npm ci` is happy to prune what package.json no
  // longer asks for, so the installed tree was a subset of the recorded one
  // while the claim said "exactly".
  const dependencies = { ...(root.dependencies || {}), [pkg]: version };
  const devDependencies = root.devDependencies ? { ...root.devDependencies } : null;
  const optionalDependencies = root.optionalDependencies ? { ...root.optionalDependencies } : null;
  const peerDependencies = root.peerDependencies ? { ...root.peerDependencies } : null;

  // A copy: callers hold the lock document and must not have it mutated under
  // them, least of all the one field that says what to install.
  const packageLock = {
    ...lock,
    name:    NAME,
    version: VERSION,
    packages: {
      ...lock.packages,
      '': {
        ...root,
        name: NAME,
        version: VERSION,
        dependencies,
        ...(devDependencies ? { devDependencies } : {}),
        ...(optionalDependencies ? { optionalDependencies } : {}),
        ...(peerDependencies ? { peerDependencies } : {}),
      },
    },
  };

  return {
    packageJson: {
      name: NAME,
      version: VERSION,
      private: true,
      dependencies,
      ...(devDependencies ? { devDependencies } : {}),
      ...(optionalDependencies ? { optionalDependencies } : {}),
      ...(peerDependencies ? { peerDependencies } : {}),
    },
    packageLock,
  };
}

module.exports = {
  LOCK_SCHEMA, LOCK_FILENAME,
  emptyLock, lockEntry, lockPath, readLock, writeLock, diffLock, vendorFiles, treeIndex, versionList,
};
