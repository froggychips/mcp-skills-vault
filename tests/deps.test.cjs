'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

const cacheHome = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-depcache-'));
process.env.MCP_VAULT_CACHE_DIR = cacheHome;
const d = require('../mcp-ecosystem-intelligence/scripts/lib/deps.cjs');

const LOCK = {
  lockfileVersion: 3,
  packages: {
    '': { name: 'probe', version: '0.0.0' },                                   // the root project
    'node_modules/top':        { version: '1.0.0', integrity: 'sha512-a', hasInstallScript: true },
    'node_modules/plain':      { version: '2.0.0', integrity: 'sha512-b' },
    'node_modules/top/node_modules/nested': { version: '3.0.0', integrity: 'sha512-c', hasInstallScript: true },
    'node_modules/devonly':    { version: '4.0.0', integrity: 'sha512-d', dev: true },
    'node_modules/optional':   { version: '5.0.0', optional: true },
  },
};

test('parseLockTree: flattens nodes, keeps what matters, drops the root', () => {
  const tree = d.parseLockTree(LOCK);
  assert.deepEqual(tree.map(p => p.name), ['devonly', 'nested', 'optional', 'plain', 'top']);
  const byName = Object.fromEntries(tree.map(p => [p.name, p]));
  assert.equal(byName.top.hasInstallScript, true);
  assert.equal(byName.plain.hasInstallScript, false);
  assert.equal(byName.nested.depth, 2);       // node_modules/top/node_modules/nested
  assert.equal(byName.plain.depth, 1);
  assert.equal(byName.devonly.dev, true);
  assert.equal(byName.optional.optional, true);
  assert.equal(byName.top.integrity, 'sha512-a');
});

test('parseLockTree: tolerates junk', () => {
  assert.deepEqual(d.parseLockTree(null), []);
  assert.deepEqual(d.parseLockTree({}), []);
  assert.deepEqual(d.parseLockTree({ packages: { '': {} } }), []);
});

test('summarizeTree: count, depth, and which packages run install scripts', () => {
  const s = d.summarizeTree(d.parseLockTree(LOCK));
  assert.equal(s.count, 5);
  assert.equal(s.maxDepth, 2);
  assert.deepEqual(s.withInstallScripts, ['nested@3.0.0', 'top@1.0.0']);
  assert.deepEqual(d.summarizeTree(null), { count: 0, withInstallScripts: [], maxDepth: 0 });
});

test('pypiDirectDependencies: parses requires_dist, skips extras', () => {
  const deps = d.pypiDirectDependencies({ info: { requires_dist: [
    'httpx (>=0.27)',
    'mcp',
    "pytest ; extra == 'dev'",
    "black; extra == 'lint'",
    'uvicorn (>=0.30,<1.0)',
    null,
  ] } });
  assert.deepEqual(deps, [
    { name: 'httpx',   spec: '>=0.27' },
    { name: 'mcp',     spec: null },
    { name: 'uvicorn', spec: '>=0.30,<1.0' },
  ]);
  assert.deepEqual(d.pypiDirectDependencies({}), []);
  assert.deepEqual(d.pypiDirectDependencies(null), []);
});

test('resolveNpmTree: runs npm in resolve-only mode, never installs or executes', async () => {
  let seenCmd = null, seenArgs = null, seenCwd = null;
  const fakeRun = (cmd, args, opts, cb) => {
    seenCmd = cmd; seenArgs = args; seenCwd = opts.cwd;
    // Emulate npm writing the lockfile into the directory it runs in. There is
    // no `--prefix`: passing it alongside cwd made npm write absolute temp-dir
    // paths as the lockfile's package keys, which `npm ci` then rejected.
    fs.writeFileSync(path.join(opts.cwd, 'package-lock.json'), JSON.stringify(LOCK));
    cb(null, '', '');
  };
  const r = await d.resolveNpmTree('pkg', '1.2.3', { run: fakeRun });
  assert.equal(r.ok, true);
  assert.equal(r.packages.length, 5);
  assert.equal(seenCmd, 'npm');
  // The two flags that make this safe: resolve only, and never run a lifecycle
  // script. Losing either turns a scan into an install.
  assert.ok(seenArgs.includes('--package-lock-only'), seenArgs.join(' '));
  assert.ok(seenArgs.includes('--ignore-scripts'), seenArgs.join(' '));
  assert.ok(seenArgs.includes('pkg@1.2.3'));
  assert.ok(!seenArgs.includes('--prefix'), 'a prefix alongside cwd corrupts the lockfile\'s paths');
  // Resolution happens in a throwaway directory, not in the user's project.
  assert.notEqual(seenCwd, process.cwd());
  assert.equal(fs.existsSync(seenCwd), false, 'the working directory is cleaned up');
});

test('resolveNpmTree: npm failing is an error, not an empty tree', async () => {
  const failing = (_c, _a, _o, cb) => cb(new Error('exit 1'), '', 'npm error code E404\nnot found');
  const r = await d.resolveNpmTree('nope', '9.9.9', { run: failing });
  assert.equal(r.ok, false);
  assert.match(r.error, /E404/);
  assert.equal(r.packages, undefined);
});

test('resolveNpmTree: a missing lockfile is an error', async () => {
  const noLock = (_c, _a, _o, cb) => cb(null, '', '');
  const r = await d.resolveNpmTree('pkg', '1.0.0', { run: noLock });
  assert.equal(r.ok, false);
  assert.match(r.error, /no usable lockfile/);
});

test('resolveNpmTreeCached: second call skips npm; unpinned is never cached', async () => {
  let calls = 0;
  const run = (_c, _args, opts, cb) => {
    calls++;
    fs.writeFileSync(path.join(opts.cwd, 'package-lock.json'), JSON.stringify(LOCK));
    cb(null, '', '');
  };
  const first  = await d.resolveNpmTreeCached('cachepkg', '1.0.0', { run });
  const second = await d.resolveNpmTreeCached('cachepkg', '1.0.0', { run });
  assert.equal(first.fromCache, undefined);
  assert.equal(second.fromCache, true);
  assert.equal(calls, 1);
  assert.deepEqual(second.packages.map(p => p.name), first.packages.map(p => p.name));

  // "latest" moves, so caching an answer for it would be a quiet lie.
  await d.resolveNpmTreeCached('cachepkg', null, { run });
  await d.resolveNpmTreeCached('cachepkg', null, { run });
  assert.equal(calls, 3);
});
