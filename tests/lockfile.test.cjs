'use strict';
/**
 * mcp.lock.json: the record, and the difference between reading it and
 * reinstalling from it.
 *
 * The distinctions these tests hold in place:
 *   - a surface that was locked and *not measured* this run is not "unchanged"
 *   - same version + different integrity is its own finding, not a version bump
 *   - a new install script in the tree is a finding
 *   - the vendored package.json/lockfile pair pins exactly, because `npm ci`
 *     recomputes a range and then refuses the lockfile it disagrees with
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const L = require('../mcp-ecosystem-intelligence/scripts/lib/lockfile.cjs');

const entry = (over = {}) => ({
  locked_at: '2026-09-01',
  artifact: { ecosystem: 'npm', id: 'npm:pkg@1.0.0', package: 'pkg', version: '1.0.0', integrity: 'sha512-AAA', pinned: true },
  launch: 'npx -y pkg@1.0.0',
  tree: {
    resolved_at: '2026-09-01',
    lockfileVersion: 3,
    count: 2,
    install_scripts: [],
    packages: [
      { name: 'dep-a', version: '1.0.0', integrity: 'sha512-A' },
      { name: 'dep-b', version: '2.0.0', integrity: 'sha512-B' },
    ],
  },
  ...over,
});

const lockOf = (servers) => ({ ...L.emptyLock(), servers });

test('no difference is reported when nothing moved', () => {
  const a = lockOf({ s: entry() });
  const b = lockOf({ s: entry() });
  assert.deepEqual(L.diffLock(a, b).servers, []);
});

test('a dependency moving version is ordinary; the same version with different bytes is not', () => {
  const before = lockOf({ s: entry() });
  const after  = lockOf({ s: entry({ tree: { ...entry().tree, packages: [
    { name: 'dep-a', version: '1.1.0', integrity: 'sha512-A2' },
    { name: 'dep-b', version: '2.0.0', integrity: 'sha512-DIFFERENT' },
  ] } }) });
  const kinds = L.diffLock(before, after).servers[0].changes.map((c) => c.kind);
  assert.ok(kinds.includes('tree-version'));
  assert.ok(kinds.includes('tree-integrity'), 'same version, different integrity is its own finding');
});

test('packages appearing and disappearing are both reported', () => {
  const before = lockOf({ s: entry() });
  const after  = lockOf({ s: entry({ tree: { ...entry().tree, packages: [
    { name: 'dep-a', version: '1.0.0', integrity: 'sha512-A' },
    { name: 'dep-c', version: '3.0.0', integrity: 'sha512-C' },
  ] } }) });
  const changes = L.diffLock(before, after).servers[0].changes;
  assert.ok(changes.some((c) => c.kind === 'tree-added' && c.detail.includes('dep-c')));
  assert.ok(changes.some((c) => c.kind === 'tree-removed' && c.detail.includes('dep-b')));
});

test('a tree that gained an install script says so', () => {
  const before = lockOf({ s: entry() });
  const after  = lockOf({ s: entry({ tree: { ...entry().tree, install_scripts: ['dep-b@2.0.0'] } }) });
  const changes = L.diffLock(before, after).servers[0].changes;
  assert.ok(changes.some((c) => c.kind === 'install-script' && /did not before/.test(c.detail)));
});

test('surface changing without the artifact changing is a different finding from both', () => {
  const withSurface = (sha, artifactId) => entry({
    artifact: { ...entry().artifact, id: artifactId, integrity: `sha512-${artifactId}` },
    surface: { observed_at: '2026-09-01', sha256: sha, count: 3, tools: {} },
  });

  const sameArtifact = L.diffLock(
    lockOf({ s: withSurface('aaa', 'npm:pkg@1.0.0') }),
    lockOf({ s: withSurface('bbb', 'npm:pkg@1.0.0') }),
  ).servers[0].changes;
  assert.ok(sameArtifact.some((c) => c.kind === 'surface-only'), 'the case with no innocent explanation');

  const upgraded = L.diffLock(
    lockOf({ s: withSurface('aaa', 'npm:pkg@1.0.0') }),
    lockOf({ s: withSurface('bbb', 'npm:pkg@2.0.0') }),
  ).servers[0].changes;
  assert.ok(upgraded.some((c) => c.kind === 'surface'));
  assert.ok(!upgraded.some((c) => c.kind === 'surface-only'));
});

test('a locked surface that nothing measured is reported, not silently passed', () => {
  // The recurring bug in this repo, in its lockfile form: a check that did not
  // run must not read as a check that passed.
  const before = lockOf({ s: entry({ surface: { observed_at: '2026-09-01', sha256: 'aaa', count: 3, tools: {} } }) });
  const after  = lockOf({ s: entry() });   // no surface this run
  const changes = L.diffLock(before, after).servers[0].changes;
  assert.ok(changes.some((c) => c.kind === 'surface-unobserved'));
});

test('servers appearing and disappearing from the lock are reported', () => {
  const one = L.diffLock(lockOf({}), lockOf({ s: entry() })).servers[0];
  assert.equal(one.changes[0].kind, 'added');
  const two = L.diffLock(lockOf({ s: entry() }), lockOf({})).servers[0];
  assert.equal(two.changes[0].kind, 'removed');
});

test('readLock: absent is not an error, but a foreign schema is', () => {
  const missing = L.readLock('/nonexistent/mcp.lock.json');
  assert.equal(missing.ok, true);
  assert.equal(missing.missing, true);

  const fs = require('fs'), os = require('os'), path = require('path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-lock-test-'));
  const file = path.join(dir, 'mcp.lock.json');

  fs.writeFileSync(file, '{ not json');
  assert.equal(L.readLock(file).ok, false);

  fs.writeFileSync(file, JSON.stringify({ $schema: 'something/else@9', servers: {} }));
  const foreign = L.readLock(file);
  assert.equal(foreign.ok, false, 'a schema we do not know may mean the fields mean something else');
  assert.match(foreign.error, /expected mcp-vault\/lock@1/);

  fs.writeFileSync(file, JSON.stringify(lockOf({ s: entry() })));
  assert.equal(L.readLock(file).ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('lockEntry keeps npm\'s lockfile verbatim and derives the readable index', () => {
  const npmLock = { lockfileVersion: 3, packages: { '': { name: 'probe' }, 'node_modules/dep-a': { version: '1.0.0', integrity: 'sha512-A' } } };
  const e = L.lockEntry({
    tool: { name: 's', install_cmd: 'npx -y pkg@1.0.0' },
    artifact: { ecosystem: 'npm', id: 'npm:pkg@1.0.0', package: 'pkg', version: '1.0.0' },
    tree: { packages: [{ name: 'dep-a', version: '1.0.0', integrity: 'sha512-A', hasInstallScript: true }], lockfile: npmLock, lockfileVersion: 3 },
  });
  assert.deepEqual(e.tree.npm_lockfile, npmLock);
  assert.deepEqual(e.tree.install_scripts, ['dep-a@1.0.0']);
  assert.equal(e.tree.count, 1);
});

test('vendorFiles pins exactly, and normalises what npm left unusable', () => {
  const e = L.lockEntry({
    tool: { name: 's', install_cmd: 'npx -y pkg@1.0.0' },
    artifact: { ecosystem: 'npm', id: 'npm:pkg@1.0.0', package: 'pkg', version: '1.0.0' },
    tree: {
      packages: [],
      lockfile: {
        name: 'mcp-vault-dep-probe',
        // What npm actually wrote, resolving in a temp directory:
        version: 'file:../../../private/var/folders/g6/T/mcp-vault-deps-1U19zn',
        lockfileVersion: 3,
        packages: { '': { name: 'mcp-vault-dep-probe', version: '0.0.0', dependencies: { pkg: '^1.0.0' } } },
      },
    },
  });
  const v = L.vendorFiles(e);
  // The range is the bug: `npm ci` recomputes `^1.0.0` to the newest match and
  // then rejects the lockfile that correctly holds 1.0.0.
  assert.deepEqual(v.packageJson.dependencies, { pkg: '1.0.0' });
  assert.deepEqual(v.packageLock.packages[''].dependencies, { pkg: '1.0.0' });
  assert.equal(v.packageJson.version, '0.0.0');
  assert.equal(v.packageLock.version, '0.0.0', 'a temp-dir path is not a version');
  assert.equal(v.packageJson.name, v.packageLock.name, 'npm ci compares these');
  // The caller's document must not be mutated: it holds the record.
  assert.equal(e.tree.npm_lockfile.packages[''].dependencies.pkg, '^1.0.0');
});

test('vendorFiles refuses rather than re-resolving', () => {
  // Without a stored lockfile the only way to install would be a fresh
  // resolve, which is exactly what a lockfile exists to prevent.
  const noLock = L.lockEntry({
    tool: { name: 's', install_cmd: 'npx -y pkg@1.0.0' },
    artifact: { ecosystem: 'npm', id: 'npm:pkg@1.0.0', package: 'pkg', version: '1.0.0' },
  });
  assert.equal(L.vendorFiles(noLock), null);
  assert.equal(L.vendorFiles({ artifact: { ecosystem: 'oci' } }), null);
  assert.equal(L.vendorFiles(null), null);
});
