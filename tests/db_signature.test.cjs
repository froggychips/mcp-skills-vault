'use strict';
/**
 * The DB signature as the CLI enforces it: checked before a command reads the
 * DB, refusing on anything but a good signature, with a loud and explicit way
 * out for development — and a release step that will not ship a DB its own
 * clients would refuse. Keys are generated on the fly.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const s  = require('../mcp-ecosystem-intelligence/scripts/lib/signing.cjs');
const ds = require('../mcp-ecosystem-intelligence/scripts/lib/db_signature.cjs');
const signDb = require('../mcp-ecosystem-intelligence/scripts/sign_db.cjs');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-sig-'));
function dbIn(dir, value = { tools: [{ name: 'x', version: '1.0.0' }] }) {
  const file = path.join(dir, 'tools_database.json');
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
  return file;
}
const ring = (pair) => [s.keyringEntry(pair.publicKey, { validFrom: '2020-01-01' })];

const NOW = Date.parse('2026-09-30T12:00:00Z');
const PKG = { required: true, context: 'package', reason: 'test: no .git' };
const DEV = { required: false, context: 'git checkout', reason: 'test: .git' };
const check = (over) => ds.checkDb({ asOf: NOW, context: PKG, ...over });

test('checkDb: an empty keyring is "not-configured" (unknown), never "verified"', () => {
  const r = check({ dbPath: dbIn(tmp()), keys: [] });
  assert.equal(r.proceed, true);
  assert.equal(r.state, 'not-configured');
  assert.equal(r.decision.effect, 'unknown');
  assert.equal(r.decision.decided_by, 'db/signature');
});

test('checkDb: in a package, a keyring and no .sig refuses', () => {
  const pair = s.generateKeyPair();
  const r = check({ dbPath: dbIn(tmp()), keys: ring(pair) });
  assert.equal(r.proceed, false);
  assert.equal(r.state, 'refused');
  assert.equal(r.decision.effect, 'deny');
  assert.match(r.message, /no-signature/);
  assert.match(r.message, /--allow-unsigned-db/);
});

test('checkDb: in a git checkout a missing .sig is allowed — a bad one is not', () => {
  const pair = s.generateKeyPair();
  const file = dbIn(tmp());
  let r = check({ dbPath: file, keys: ring(pair), context: DEV });
  assert.equal(r.proceed, true);
  assert.equal(r.state, 'not-required');
  assert.equal(r.decision.effect, 'allow');

  fs.writeFileSync(`${file}.sig`, '{"format":"nope"}');
  r = check({ dbPath: file, keys: ring(pair), context: DEV });
  assert.equal(r.proceed, false);
  assert.match(r.message, /malformed/);
});

test('checkDb: signed file verifies; reformatting it does not break that; editing it does', () => {
  const pair = s.generateKeyPair();
  const file = dbIn(tmp());
  ds.signFile(file, { privateKeyPem: pair.privateKeyPem, now: NOW });
  assert.equal(check({ dbPath: file, keys: ring(pair) }).state, 'verified');

  // CRLF and a different indent: same canonical bytes.
  fs.writeFileSync(file, JSON.stringify(JSON.parse(fs.readFileSync(file, 'utf8')), null, 4).replace(/\n/g, '\r\n'));
  assert.equal(check({ dbPath: file, keys: ring(pair) }).state, 'verified');

  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('1.0.0', '6.6.6'));
  const r = check({ dbPath: file, keys: ring(pair) });
  assert.equal(r.proceed, false);
  assert.match(r.message, /digest-mismatch/);
});

test('checkDb: the development override proceeds, and says so loudly', () => {
  const pair = s.generateKeyPair();
  const r = check({ dbPath: dbIn(tmp()), keys: ring(pair), allowUnsigned: true });
  assert.equal(r.proceed, true);
  assert.equal(r.state, 'unsigned-allowed');
  assert.equal(r.decision.effect, 'warn');
  assert.match(r.message, /DB SIGNATURE NOT VERIFIED/);
});

test('checkDb: an unreadable keyring refuses, override or not', () => {
  const r = check({ dbPath: dbIn(tmp()), keys: [], keyringOk: false, keyringErrors: ['bad'], allowUnsigned: true, context: DEV });
  assert.equal(r.proceed, false);
  assert.match(r.message, /keyring is unreadable/);
});

test('signatureContext: .git at the package root (dir or worktree file) is a checkout; anything else is a package', () => {
  const pkg = tmp();
  assert.deepEqual([ds.signatureContext({ root: pkg, env: {} }).required, ds.signatureContext({ root: pkg, env: {} }).context], [true, 'package']);
  const dev = tmp();
  fs.mkdirSync(path.join(dev, '.git'));
  assert.equal(ds.signatureContext({ root: dev, env: {} }).required, false);
  const worktree = tmp();
  fs.writeFileSync(path.join(worktree, '.git'), 'gitdir: /elsewhere\n');
  assert.equal(ds.signatureContext({ root: worktree, env: {} }).required, false);
  // A .git further up (a package installed inside somebody's repo) does not count.
  const nested = path.join(dev, 'node_modules', 'pkg');
  fs.mkdirSync(nested, { recursive: true });
  assert.equal(ds.signatureContext({ root: nested, env: {} }).required, true);
  // The env switch only tightens.
  assert.equal(ds.signatureContext({ root: dev, env: { [ds.REQUIRE_ENV]: '1' } }).required, true);
  // This test runs from a checkout.
  assert.equal(ds.signatureContext({ env: {} }).context, 'git checkout');
});

test('the env override needs an explicit yes', () => {
  assert.equal(ds.allowUnsignedFromEnv({ MCP_VAULT_ALLOW_UNSIGNED_DB: '1' }), true);
  assert.equal(ds.allowUnsignedFromEnv({ MCP_VAULT_ALLOW_UNSIGNED_DB: 'true' }), true);
  assert.equal(ds.allowUnsignedFromEnv({ MCP_VAULT_ALLOW_UNSIGNED_DB: '0' }), false);
  assert.equal(ds.allowUnsignedFromEnv({}), false);
});

// ── sign_db --release ──

function quiet(fn) {
  const w = process.stdout.write, e = process.stderr.write;
  process.stdout.write = () => true; process.stderr.write = () => true;
  try { return fn(); } finally { process.stdout.write = w; process.stderr.write = e; }
}
function keyringFile(dir, keys) {
  const file = path.join(dir, 'trusted_keys.json');
  fs.writeFileSync(file, JSON.stringify({ keys }));
  return file;
}

test('sign_db --release: an empty keyring publishes unsigned, with a warning', () => {
  const dir = tmp();
  const file = dbIn(dir);
  const code = quiet(() => signDb.main(['--release', file], { env: {}, keyringPath: keyringFile(dir, []) }));
  assert.equal(code, 0);
  assert.equal(fs.existsSync(`${file}.sig`), false);
});

test('sign_db --release: a keyring with a key and no secret stops the release', () => {
  const dir = tmp();
  const pair = s.generateKeyPair();
  const code = quiet(() => signDb.main(['--release', dbIn(dir)], { env: {}, keyringPath: keyringFile(dir, ring(pair)) }));
  assert.equal(code, 1);
});

test('sign_db --release: a secret the keyring does not list stops the release', () => {
  const dir = tmp();
  const trusted = s.generateKeyPair();
  const other = s.generateKeyPair();
  const code = quiet(() => signDb.main(['--release', dbIn(dir)], {
    env: { MCP_VAULT_SIGNING_KEY: other.privateKeyPem }, keyringPath: keyringFile(dir, ring(trusted)),
  }));
  assert.equal(code, 1);
});

test('sign_db --release: the right key signs, and the result verifies (PEM or base64 PEM)', () => {
  const dir = tmp();
  const pair = s.generateKeyPair();
  const file = dbIn(dir);
  const keyringPath = keyringFile(dir, ring(pair));
  for (const secret of [pair.privateKeyPem, Buffer.from(pair.privateKeyPem).toString('base64')]) {
    const code = quiet(() => signDb.main(['--release', file], { env: { MCP_VAULT_SIGNING_KEY: secret }, keyringPath }));
    assert.equal(code, 0);
    assert.equal(ds.verifyFile(file, { keys: ring(pair) }).ok, true);
  }
});

// ── the CLI, end to end, on a copy of the package ──

function packageCopy(keys) {
  const dir = tmp();
  fs.cpSync(path.join(ROOT, 'bin'), path.join(dir, 'bin'), { recursive: true });
  fs.cpSync(path.join(ROOT, 'mcp-ecosystem-intelligence', 'scripts'), path.join(dir, 'mcp-ecosystem-intelligence', 'scripts'), { recursive: true });
  const assets = path.join(dir, 'mcp-ecosystem-intelligence', 'assets');
  fs.mkdirSync(assets, { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json'), path.join(assets, 'tools_database.json'));
  fs.writeFileSync(path.join(assets, 'trusted_keys.json'), JSON.stringify({ keys }));
  fs.copyFileSync(path.join(ROOT, 'package.json'), path.join(dir, 'package.json'));
  return { dir, db: path.join(assets, 'tools_database.json') };
}
const run = (dir, args, env = {}) => spawnSync(process.execPath, [path.join(dir, 'bin', 'mcp-vault.cjs'), ...args], {
  encoding: 'utf8', env: { ...process.env, MCP_VAULT_ALLOW_UNSIGNED_DB: '', MCP_VAULT_REQUIRE_SIGNED_DB: '', ...env },
});

test('bin: refuses an unsigned DB, runs with the override, runs when signed, refuses when tampered', () => {
  const pair = s.generateKeyPair();
  const pkg = packageCopy(ring(pair));

  let r = run(pkg.dir, ['list', '--json']);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /refusing to use the DB/);
  assert.equal(r.stdout, '');

  r = run(pkg.dir, ['--allow-unsigned-db', 'list', '--json']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /DB SIGNATURE NOT VERIFIED/);
  assert.ok(JSON.parse(r.stdout).count > 0);

  r = run(pkg.dir, ['list', '--json'], { MCP_VAULT_ALLOW_UNSIGNED_DB: '1' });
  assert.equal(r.status, 0, r.stderr);

  ds.signFile(pkg.db, { privateKeyPem: pair.privateKeyPem, now: NOW });
  r = run(pkg.dir, ['list', '--json']);
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /SIGNATURE/);

  const db = JSON.parse(fs.readFileSync(pkg.db, 'utf8'));
  db.tools[0].install_cmd = 'npx -y evil@1.0.0';
  fs.writeFileSync(pkg.db, JSON.stringify(db, null, 2));
  r = run(pkg.dir, ['list', '--json']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /digest-mismatch/);

  // `signature` is reachable when the DB is broken, and says why.
  r = run(pkg.dir, ['signature', '--json']);
  assert.equal(r.status, 1);
  const doc = JSON.parse(r.stdout);
  assert.equal(doc.schema, 'mcp-vault/findings@1');
  assert.equal(doc.findings[0].rule, 'db/signature-invalid');
  assert.match(doc.findings[0].message, /digest-mismatch/);
  assert.equal(doc.decisions[0].effect, 'deny');
  assert.equal(doc.decisions[0].decided_by, 'db/signature');
});

test('bin: every --db is checked, not just the first (--db a --db b, --db=b)', () => {
  const pair = s.generateKeyPair();
  const pkg = packageCopy(ring(pair));
  ds.signFile(pkg.db, { privateKeyPem: pair.privateKeyPem, now: NOW });
  const signed = dbIn(tmp());
  ds.signFile(signed, { privateKeyPem: pair.privateKeyPem, now: NOW });
  const unsigned = dbIn(tmp());
  for (const args of [['--db', signed, '--db', unsigned], [`--db=${unsigned}`], ['--db', unsigned, '--db', signed]]) {
    const r = run(pkg.dir, ['audit', ...args, '--json']);
    assert.equal(r.status, 1, args.join(' '));
    assert.match(r.stderr, /refusing to use the DB/);
  }
});

test('bin: a git checkout runs without a .sig even with a key listed; the env switch makes it a package again', () => {
  const pair = s.generateKeyPair();
  const pkg = packageCopy(ring(pair));
  fs.mkdirSync(path.join(pkg.dir, '.git'));
  let r = run(pkg.dir, ['list', '--json']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stderr, '');
  r = run(pkg.dir, ['list', '--json'], { MCP_VAULT_REQUIRE_SIGNED_DB: '1' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refusing to use the DB/);
  // A present-but-wrong signature refuses in a checkout too.
  fs.writeFileSync(`${pkg.db}.sig`, '{}');
  r = run(pkg.dir, ['list', '--json']);
  assert.equal(r.status, 1);
});

test('bin: this repository (a checkout, with the release key listed) runs without a .sig', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'bin', 'mcp-vault.cjs'), 'verify', '--offline', '--json'], {
    encoding: 'utf8', env: { ...process.env, MCP_VAULT_ALLOW_UNSIGNED_DB: '', MCP_VAULT_REQUIRE_SIGNED_DB: '' }, maxBuffer: 64 * 1024 * 1024,
  });
  assert.doesNotMatch(r.stderr, /refusing to use the DB|no signature file/);
  assert.equal(JSON.parse(r.stdout).schema, 'mcp-vault/verify-report@1');
});

test('bin: a DB passed with --db is held to the same bar', () => {
  const pair = s.generateKeyPair();
  const pkg = packageCopy(ring(pair));
  ds.signFile(pkg.db, { privateKeyPem: pair.privateKeyPem, now: NOW });
  const other = dbIn(tmp());
  const r = run(pkg.dir, ['audit', '--db', other, '--json']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refusing to use the DB/);
});

test('bin: with the shipped (empty) keyring nothing changes for today\'s users', () => {
  const pkg = packageCopy([]);
  const r = run(pkg.dir, ['list', '--json']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stderr, '');
});

// ── the pre-commit hook: `rev:` is the integrity, in pre-commit's install only ──

/**
 * pre-commit's layout for a node hook: <store>/db.db, <store>/repoXXXX (a git
 * clone of the hook repo at `rev:`), and the package `npm install -g`-ed into
 * <store>/repoXXXX/node_env-<v>/lib/node_modules/<name>.
 */
function preCommitLayout({ name = '@froggychips/mcp-vault', storeDb = true, git = true, hooks = true, sameDb = true, envDir = 'node_env-system' } = {}) {
  const store = tmp();
  if (storeDb) fs.writeFileSync(path.join(store, 'db.db'), '');
  const repo = path.join(store, 'repoab12_cd');
  const rel = path.join('mcp-ecosystem-intelligence', 'assets');
  fs.mkdirSync(path.join(repo, rel), { recursive: true });
  if (git) fs.mkdirSync(path.join(repo, '.git'));
  if (hooks) fs.writeFileSync(path.join(repo, '.pre-commit-hooks.yaml'), '- id: mcp-vault\n');
  const root = path.join(repo, envDir, 'lib', 'node_modules', ...name.split('/'));
  fs.mkdirSync(path.join(root, rel), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name }));
  const dbPath = dbIn(path.join(root, rel));
  if (sameDb) fs.copyFileSync(dbPath, path.join(repo, rel, 'tools_database.json'));
  else dbIn(path.join(repo, rel), { tools: [] });
  return { store, repo, root, dbPath };
}
const HOOK_ENV = { PRE_COMMIT: '1', [ds.PRE_COMMIT_ENV]: '1' };

test('signatureContext: pre-commit\'s install of the hook, asked by the hook entry, is pinned by rev — nothing else is', () => {
  const { root } = preCommitLayout();
  const ctx = ds.signatureContext({ root, env: HOOK_ENV });
  assert.equal(ctx.required, false);
  assert.equal(ctx.context, ds.PRE_COMMIT_CONTEXT);
  assert.match(ctx.reason, /rev: pins/);

  // Each condition is necessary.
  const required = (root2, env, why) => assert.equal(ds.signatureContext({ root: root2, env }).required, true, why);
  required(root, { PRE_COMMIT: '1' }, 'mcp-vault itself (no hook entry) never relaxes');
  required(root, { [ds.PRE_COMMIT_ENV]: '1' }, 'pre-commit is not running the hook');
  required(root, { ...HOOK_ENV, [ds.REQUIRE_ENV]: '1' }, 'MCP_VAULT_REQUIRE_SIGNED_DB still tightens');
  required(preCommitLayout({ storeDb: false }).root, HOOK_ENV, 'not a pre-commit store');
  required(preCommitLayout({ git: false }).root, HOOK_ENV, 'not a clone');
  required(preCommitLayout({ hooks: false }).root, HOOK_ENV, 'not this hook\'s repository');
  required(preCommitLayout({ sameDb: false }).root, HOOK_ENV, 'the DB is not the clone\'s bytes');
  required(preCommitLayout({ envDir: 'node_modules_x' }).root, HOOK_ENV, 'not a node_env');

  // npm and npx install elsewhere: never pinned, whatever the environment says.
  const npx = path.join(tmp(), '_npx', 'abc123', 'node_modules', '@froggychips', 'mcp-vault');
  fs.mkdirSync(npx, { recursive: true });
  fs.writeFileSync(path.join(npx, 'package.json'), JSON.stringify({ name: '@froggychips/mcp-vault' }));
  required(npx, HOOK_ENV, 'an npx install');
});

test('checkDb: pinned by pre-commit rev, a missing .sig runs — a .sig that is present still has to verify', () => {
  const pair = s.generateKeyPair();
  const { root, dbPath } = preCommitLayout();
  const context = ds.signatureContext({ root, env: HOOK_ENV });
  let r = check({ dbPath, keys: ring(pair), context });
  assert.equal(r.proceed, true);
  assert.equal(r.state, 'not-required');
  assert.equal(r.decision.effect, 'allow');

  fs.writeFileSync(`${dbPath}.sig`, '{"format":"nope"}');
  r = check({ dbPath, keys: ring(pair), context });
  assert.equal(r.proceed, false);
  assert.equal(r.decision.effect, 'deny');

  const other = s.generateKeyPair();
  ds.signFile(dbPath, { privateKeyPem: other.privateKeyPem, now: NOW });
  r = check({ dbPath, keys: ring(pair), context });
  assert.equal(r.proceed, false, 'signed by a key the keyring does not list');

  ds.signFile(dbPath, { privateKeyPem: pair.privateKeyPem, now: NOW });
  r = check({ dbPath, keys: ring(pair), context });
  assert.equal(r.proceed, true);
  assert.equal(r.state, 'verified');
});

test('bin/mcp-vault-pre-commit: runs `check` only and refuses --db; outside pre-commit\'s install it claims nothing', () => {
  const hook = path.join(ROOT, 'bin', 'mcp-vault-pre-commit.cjs');
  const dir = tmp();
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: {} }));
  const env = { ...process.env, MCP_VAULT_ALLOW_UNSIGNED_DB: '', MCP_VAULT_REQUIRE_SIGNED_DB: '', PRE_COMMIT: '1', NO_COLOR: '1' };
  const runHook = (args) => spawnSync(process.execPath, [hook, ...args], { cwd: dir, encoding: 'utf8', env });
  // This repository is a checkout: the CLI's own rule, and no pre-commit claim.
  const ok = runHook(['--fail-on', 'unknown', '.mcp.json']);
  assert.equal(ok.status, 0, ok.stderr);
  assert.doesNotMatch(ok.stderr, /pinned by pre-commit rev/);
  const db = runHook(['--db', 'x.json', '.mcp.json']);
  assert.equal(db.status, 2);
  assert.match(db.stderr, /--db is not accepted/);
});
