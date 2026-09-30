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

test('checkDb: an empty keyring is "not-configured", never "verified"', () => {
  const r = ds.checkDb({ dbPath: dbIn(tmp()), keys: [] });
  assert.equal(r.proceed, true);
  assert.equal(r.state, 'not-configured');
});

test('checkDb: a keyring and no .sig refuses', () => {
  const pair = s.generateKeyPair();
  const r = ds.checkDb({ dbPath: dbIn(tmp()), keys: ring(pair) });
  assert.equal(r.proceed, false);
  assert.equal(r.state, 'refused');
  assert.equal(r.result.code, 'no-signature');
  assert.match(r.message, /--allow-unsigned-db/);
});

test('checkDb: signed file verifies; reformatting it does not break that; editing it does', () => {
  const pair = s.generateKeyPair();
  const file = dbIn(tmp());
  ds.signFile(file, { privateKeyPem: pair.privateKeyPem });
  assert.equal(ds.checkDb({ dbPath: file, keys: ring(pair) }).state, 'verified');

  // CRLF and a different indent: same canonical bytes.
  fs.writeFileSync(file, JSON.stringify(JSON.parse(fs.readFileSync(file, 'utf8')), null, 4).replace(/\n/g, '\r\n'));
  assert.equal(ds.checkDb({ dbPath: file, keys: ring(pair) }).state, 'verified');

  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('1.0.0', '6.6.6'));
  const r = ds.checkDb({ dbPath: file, keys: ring(pair) });
  assert.equal(r.proceed, false);
  assert.equal(r.result.code, 'digest-mismatch');
});

test('checkDb: the development override proceeds, and says so loudly', () => {
  const pair = s.generateKeyPair();
  const r = ds.checkDb({ dbPath: dbIn(tmp()), keys: ring(pair), allowUnsigned: true });
  assert.equal(r.proceed, true);
  assert.equal(r.state, 'unsigned-allowed');
  assert.match(r.message, /DB SIGNATURE NOT VERIFIED/);
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
  encoding: 'utf8', env: { ...process.env, MCP_VAULT_ALLOW_UNSIGNED_DB: '', ...env },
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

  ds.signFile(pkg.db, { privateKeyPem: pair.privateKeyPem });
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
  assert.equal(JSON.parse(r.stdout).files[0].code, 'digest-mismatch');
});

test('bin: a DB passed with --db is held to the same bar', () => {
  const pair = s.generateKeyPair();
  const pkg = packageCopy(ring(pair));
  ds.signFile(pkg.db, { privateKeyPem: pair.privateKeyPem });
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
