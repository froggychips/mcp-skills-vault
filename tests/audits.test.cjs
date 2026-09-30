'use strict';
/**
 * Imported audits (the cargo-vet model): signed, non-transitive, offline after
 * an explicit fetch, and never a way to raise trust. Keys are generated here.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const A  = require('../mcp-ecosystem-intelligence/scripts/lib/audits.cjs');
const s  = require('../mcp-ecosystem-intelligence/scripts/lib/signing.cjs');
const ev = require('../mcp-ecosystem-intelligence/scripts/lib/evidence.cjs');
const { trustScore } = require('../mcp-ecosystem-intelligence/scripts/lib/scores.cjs');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-audits-'));
const tool = {
  name: 'demo', install_cmd: 'npx -y @demo/server@1.2.3', version: '1.2.3',
  pkg_integrity: 'sha512-AAAA', trust: 'candidate',
};
const audit = (over = {}) => ({
  who: 'Alice <alice@example.org>', ecosystem: 'npm', package: '@demo/server', version: '1.2.3',
  integrity: 'sha512-AAAA', criteria: 'safe-to-run', date: '2026-09-30', ...over,
});
function writeConfig(dir, sources) {
  fs.writeFileSync(path.join(dir, A.IMPORTS_FILE), JSON.stringify({ sources }));
  return A.readImportsConfig(dir);
}

test('an audit record with a field the format does not have is refused', () => {
  assert.equal(A.validateAudit(audit()).ok, true);
  const r = A.validateAudit(audit({ imported_from: 'bob' }));
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /unknown field "imported_from"/);
  assert.equal(A.validateAudit(audit({ integrity: '' })).ok, false);
});

test('an audit matches only the same package, version and integrity', () => {
  const subject = A.subjectOf(tool);
  assert.deepEqual(subject, { ecosystem: 'npm', package: '@demo/server', version: '1.2.3', integrity: 'sha512-AAAA' });
  assert.equal(A.auditMatches(audit(), subject), true);
  assert.equal(A.auditMatches(audit({ version: '1.2.4' }), subject), false);
  // Same version string, different bytes: not an audit of these.
  assert.equal(A.auditMatches(audit({ integrity: 'sha512-BBBB' }), subject), false);
  // Nothing pinned, nothing to audit.
  assert.equal(A.subjectOf({ name: 'g', install_cmd: 'uvx --from git+https://x/y y' }), null);
});

test('export is deterministic apart from the signature date, and verifies', () => {
  const pair = s.generateKeyPair();
  const now = Date.parse('2026-09-30T00:00:00Z');
  const b1 = A.exportBundle([audit({ package: 'b' }), audit({ package: 'a' })], { privateKeyPem: pair.privateKeyPem, now });
  const b2 = A.exportBundle([audit({ package: 'a' }), audit({ package: 'b' })], { privateKeyPem: pair.privateKeyPem, now });
  assert.deepEqual(b1, b2);
  const v = A.verifyBundle(b1, { publicKey: pair.publicKey });
  assert.equal(v.ok, true, v.error);
  assert.equal(v.audits.length, 2);
});

test('a bundle under the wrong key, or with an edited record, is refused', () => {
  const pair = s.generateKeyPair();
  const other = s.generateKeyPair();
  const bundle = A.exportBundle([audit()], { privateKeyPem: pair.privateKeyPem });
  assert.equal(A.verifyBundle(bundle, { publicKey: other.publicKey }).code, 'unknown-key');
  const edited = JSON.parse(JSON.stringify(bundle));
  edited.payload.audits[0].criteria = 'safe-to-deploy';
  assert.equal(A.verifyBundle(edited, { publicKey: pair.publicKey }).code, 'digest-mismatch');
});

test('fetch: a source with a bad signature is rejected and nothing is written', async () => {
  const dir = tmp();
  const alice = s.generateKeyPair();
  const mallory = s.generateKeyPair();
  const config = writeConfig(dir, {
    alice: { url: 'https://alice.example/audits.json', public_key: alice.publicKey, criteria: ['safe-to-run'] },
  });
  // Served by someone else, signed with their key.
  const forged = A.exportBundle([audit()], { privateKeyPem: mallory.privateKeyPem });
  const res = await A.fetchImports(config, { fetchText: async () => JSON.stringify(forged) });
  assert.equal(res.ok, false);
  assert.equal(res.report[0].code, 'unknown-key');
  assert.deepEqual(res.lock.sources, {});
});

test('import is not transitive: a bundle carrying imports is refused, and only configured URLs are fetched', async () => {
  const dir = tmp();
  const alice = s.generateKeyPair();
  const config = writeConfig(dir, {
    alice: { url: 'https://alice.example/audits.json', public_key: alice.publicKey, criteria: ['safe-to-run'] },
  });

  // Alice signs a payload that also names her own imports.
  const payload = { audits: [audit()], imports: { bob: { url: 'https://bob.example/audits.json' } } };
  const sneaky = {
    $schema: A.EXPORT_SCHEMA, payload,
    signature: s.signCanonical(s.canonicalBytes(payload), { privateKeyPem: alice.privateKeyPem, artifact: A.EXPORT_ARTIFACT }),
  };
  const requested = [];
  const res = await A.fetchImports(config, { fetchText: async (url) => { requested.push(url); return JSON.stringify(sneaky); } });
  assert.deepEqual(requested, ['https://alice.example/audits.json']);
  assert.equal(res.ok, false);
  assert.equal(res.report[0].code, 'transitive');
});

test('import is not transitive: what Alice imported is not in what Alice exports', async () => {
  const aliceDir = tmp();
  const alice = s.generateKeyPair();
  const bob = s.generateKeyPair();
  // Alice imports Bob's audit of @demo/server …
  const bobBundle = A.exportBundle([audit({ who: 'Bob' })], { privateKeyPem: bob.privateKeyPem });
  const cfg = writeConfig(aliceDir, { bob: { url: 'https://bob.example/a.json', public_key: bob.publicKey, criteria: ['safe-to-run'] } });
  const fetched = await A.fetchImports(cfg, { fetchText: async () => JSON.stringify(bobBundle) });
  assert.equal(fetched.ok, true);
  A.writeLock(aliceDir, fetched.lock);
  assert.equal(A.loadImportedAudits(aliceDir).audits.length, 1);
  // … and has one of her own, of another package.
  A.addLocalAudit(aliceDir, audit({ who: 'Alice', package: '@other/pkg' }));

  const exported = A.exportBundle(A.readLocalAudits(aliceDir).audits, { privateKeyPem: alice.privateKeyPem });
  assert.deepEqual(exported.payload.audits.map((a) => a.who), ['Alice']);
});

test('criteria: only what the source is trusted for, with implication', () => {
  assert.deepEqual(A.acceptedCriteria('safe-to-deploy', ['safe-to-run']), ['safe-to-run']);
  assert.deepEqual(A.acceptedCriteria('safe-to-run', ['safe-to-deploy']), []);
  assert.deepEqual(A.acceptedCriteria('custom', ['custom']), ['custom']);
});

async function importedFixture({ criteria = ['safe-to-run'], audits = [audit()] } = {}) {
  const dir = tmp();
  const alice = s.generateKeyPair();
  const bundle = A.exportBundle(audits, { privateKeyPem: alice.privateKeyPem });
  const exportFile = path.join(dir, 'alice.json');
  fs.writeFileSync(exportFile, JSON.stringify(bundle));
  const config = writeConfig(dir, { alice: { path: 'alice.json', public_key: alice.publicKey, criteria } });
  const res = await A.fetchImports(config, {});
  assert.equal(res.ok, true, JSON.stringify(res.report));
  A.writeLock(dir, res.lock);
  return { dir, alice, bundle };
}

test('after fetch, imports load offline, with their source and key', async () => {
  const { dir, alice } = await importedFixture({ audits: [audit(), audit({ package: 'x', criteria: 'safe-to-deploy' }), audit({ package: 'y', criteria: 'unknown-bar' })] });
  const r = A.loadImportedAudits(dir);
  assert.deepEqual(r.errors, []);
  assert.equal(r.audits.length, 2);
  assert.ok(r.audits.every((a) => a.source === 'alice' && a.key_id === alice.keyId));
  assert.equal(r.ignored.length, 1);
  assert.match(r.ignored[0].reason, /not one this source is trusted for/);
});

test('a hand-edited lock contributes nothing', async () => {
  const { dir } = await importedFixture();
  const lockFile = path.join(dir, A.LOCK_FILE);
  const lock = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
  lock.sources.alice.bundle.payload.audits[0].version = '9.9.9';
  fs.writeFileSync(lockFile, JSON.stringify(lock));
  const r = A.loadImportedAudits(dir);
  assert.equal(r.audits.length, 0);
  assert.equal(r.errors[0].code, 'lock-tampered');

  // Recomputing the lock's hash does not help: the signature still covers the payload.
  lock.sources.alice.sha256 = s.sha256Hex(s.canonicalBytes(lock.sources.alice.bundle));
  fs.writeFileSync(lockFile, JSON.stringify(lock));
  assert.equal(A.loadImportedAudits(dir).errors[0].code, 'digest-mismatch');
});

test('changing the key or location in the config invalidates the lock until the next fetch', async () => {
  const { dir } = await importedFixture();
  const cfgFile = path.join(dir, A.IMPORTS_FILE);
  const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  cfg.sources.alice.public_key = s.generateKeyPair().publicKey;
  fs.writeFileSync(cfgFile, JSON.stringify(cfg));
  assert.equal(A.loadImportedAudits(dir).errors[0].code, 'unknown-key');

  cfg.sources.alice.path = 'moved.json';
  fs.writeFileSync(cfgFile, JSON.stringify(cfg));
  assert.equal(A.loadImportedAudits(dir).errors[0].code, 'stale-lock');
});

test('the imports config refuses what it does not understand', () => {
  const dir = tmp();
  const pub = s.generateKeyPair().publicKey;
  let c = writeConfig(dir, { a: { url: 'http://insecure.example', public_key: pub, criteria: ['safe-to-run'] } });
  assert.equal(c.ok, false);
  c = writeConfig(dir, { a: { url: 'https://x.example', public_key: pub, criteria: ['safe-to-run'], follow_imports: true } });
  assert.match(c.errors[0], /unknown key "follow_imports"/);
  c = writeConfig(dir, { a: { url: 'https://x.example', public_key: pub } });
  assert.match(c.errors[0], /criteria/);
});

test('an audit is evidence with a source, and never moves trust', async () => {
  const { dir } = await importedFixture();
  const evidence = {
    artifact_id: 'npm:@demo/server@1.2.3',
    dimensions: { artifact: { status: 'unverified', checked_at: '2026-09-30' } },
  };
  const before = { trust: ev.deriveTrust(evidence, { require: ['artifact', 'advisories'] }), score: trustScore(evidence) };

  const matched = A.auditsFor(tool, { imported: A.loadImportedAudits(dir).audits });
  assert.equal(matched.length, 1);
  const e = ev.auditEvidence(matched[0]);
  assert.equal(e.source, 'alice');
  assert.equal(e.affects_trust, false);
  assert.deepEqual(e.criteria, ['safe-to-run']);

  // Nothing about the dimensions — or what is derived from them — changed.
  assert.equal(ev.DIMENSIONS.includes('audit'), false);
  assert.deepEqual({ trust: ev.deriveTrust(evidence, { require: ['artifact', 'advisories'] }), score: trustScore(evidence) }, before);
});

test('explain shows an audit with its source, and the trust score does not move', () => {
  const db = JSON.parse(fs.readFileSync(path.join(ROOT, 'mcp-ecosystem-intelligence/assets/tools_database.json'), 'utf8'));
  const entry = db.tools.find((t) => A.subjectOf(t));
  const explain = (cwd) => {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'mcp-ecosystem-intelligence/scripts/explain.cjs'), entry.name, '--json', '--cwd', cwd], { encoding: 'utf8' });
    return JSON.parse(r.stdout);
  };
  const empty = tmp();
  const withAudit = tmp();
  A.addLocalAudit(withAudit, { who: 'Me', ...A.subjectOf(entry), criteria: 'safe-to-run', date: '2026-09-30' });

  const a = explain(empty);
  const b = explain(withAudit);
  assert.deepEqual(a.evidence.audits, []);
  assert.equal(b.evidence.audits.length, 1);
  assert.equal(b.evidence.audits[0].source, 'local');
  assert.deepEqual(b.scores.trust, a.scores.trust);
  assert.equal(b.decision, a.decision);
});

test('CLI: keygen → add → export → fetch → check → list, the last three offline', () => {
  const cli = path.join(ROOT, 'mcp-ecosystem-intelligence/scripts/audits.cjs');
  const run = (args, env = {}) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  const db = JSON.parse(fs.readFileSync(path.join(ROOT, 'mcp-ecosystem-intelligence/assets/tools_database.json'), 'utf8'));
  const entry = db.tools.find((t) => A.subjectOf(t));
  const mine = tmp();
  const theirs = tmp();
  const keyFile = path.join(mine, 'audit-key.pem');

  let r = run(['keygen', keyFile, '--json']);
  assert.equal(r.status, 0, r.stderr);
  const { public_key: publicKey } = JSON.parse(r.stdout);
  assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
  assert.equal(run(['keygen', keyFile]).status, 1, 'never overwrites a key');

  r = run(['add', entry.name, '--criteria', 'safe-to-deploy', '--who', 'Me', '--cwd', mine]);
  assert.equal(r.status, 0, r.stderr);
  r = run(['export', '--cwd', mine, '--out', path.join(mine, 'export.json')], { MCP_VAULT_AUDIT_KEY: fs.readFileSync(keyFile, 'utf8') });
  assert.equal(r.status, 0, r.stderr);

  fs.writeFileSync(path.join(theirs, A.IMPORTS_FILE), JSON.stringify({
    sources: { me: { path: path.relative(theirs, path.join(mine, 'export.json')), public_key: publicKey, criteria: ['safe-to-run'] } },
  }));
  assert.equal(run(['check', '--cwd', theirs]).status, 1, 'configured but not fetched');
  r = run(['fetch', '--cwd', theirs, '--json']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(run(['check', '--cwd', theirs]).status, 0);
  r = run(['list', entry.name, '--cwd', theirs, '--json']);
  assert.equal(r.status, 0, r.stderr);
  const listed = JSON.parse(r.stdout).entries[0].audits;
  assert.equal(listed.length, 1);
  assert.deepEqual(listed[0].accepted_criteria, ['safe-to-run']);
  assert.equal(listed[0].source, 'me');
});
