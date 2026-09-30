'use strict';
// A docker entry stores its digest twice: inside install_cmd and in
// pkg_integrity. PR #106 moved the first and not the second for an entry whose
// pkg_integrity was spelled `sha256:<hex>`, and verify --deep still passed.
const { test }      = require('node:test');
const assert        = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path          = require('node:path');

const { ociIntegrity, dockerIntegrityMismatch } = require('../mcp-ecosystem-intelligence/scripts/lib/install_cmd.cjs');
const { applyDriftUpdate } = require('../mcp-ecosystem-intelligence/scripts/check_docker_drift.cjs');

const OLD = '67b4d3d39aa2c32c5ee280b21d67fb6513dab463af6c93c2ae0cdd4af09d4603';
const NEW = '423a6b0000000000000000000000000000000000000000000000000000000000';
const cmd = (hex) => `docker run -i --rm --cap-drop ALL hashicorp/terraform-mcp-server@sha256:${hex}`;

test('ociIntegrity: both spellings in, the canonical one out', () => {
  assert.equal(ociIntegrity(`sha256:${OLD}`), `sha256-${OLD}`);
  assert.equal(ociIntegrity(`sha256-${OLD}`), `sha256-${OLD}`);
  assert.equal(ociIntegrity(` sha256:${OLD} `), `sha256-${OLD}`);
  assert.equal(ociIntegrity(`sha512-${OLD}`), null);
  assert.equal(ociIntegrity(`sha256:${OLD}ff`), null);
  assert.equal(ociIntegrity(`sha256:${OLD.toUpperCase()}`), null);
  assert.equal(ociIntegrity(null), null);
  assert.equal(ociIntegrity(''), null);
});

test('applyDriftUpdate: a `sha256:` pkg_integrity moves with install_cmd (PR #106)', () => {
  const tool = { install_cmd: cmd(OLD), pkg_integrity: `sha256:${OLD}` };
  assert.equal(applyDriftUpdate(tool, `sha256:${OLD}`, `sha256:${NEW}`), true);
  assert.equal(tool.install_cmd, cmd(NEW));
  assert.equal(tool.pkg_integrity, `sha256-${NEW}`);
  assert.equal(dockerIntegrityMismatch(tool), null);
});

test('applyDriftUpdate: canonical, missing and junk pkg_integrity all end canonical', () => {
  for (const stored of [`sha256-${OLD}`, undefined, null, '', 'garbage']) {
    const tool = { install_cmd: cmd(OLD), pkg_integrity: stored };
    assert.equal(applyDriftUpdate(tool, `sha256:${OLD}`, `sha256:${NEW}`), true, String(stored));
    assert.equal(tool.pkg_integrity, `sha256-${NEW}`, String(stored));
  }
});

test('applyDriftUpdate: leaves the entry alone when nothing matches', () => {
  const tool = { install_cmd: cmd(OLD), pkg_integrity: `sha256-${OLD}` };
  const other = 'f'.repeat(64);
  assert.equal(applyDriftUpdate(tool, `sha256:${other}`, `sha256:${NEW}`), false);
  assert.equal(applyDriftUpdate(tool, `sha256:${OLD}`, 'latest'), false);
  assert.deepEqual(tool, { install_cmd: cmd(OLD), pkg_integrity: `sha256-${OLD}` });
});

test('dockerIntegrityMismatch: the exact state PR #106 would have merged', () => {
  const why = dockerIntegrityMismatch({ install_cmd: cmd(NEW), pkg_integrity: `sha256:${OLD}` });
  assert.match(why, /does not match/);
});

test('dockerIntegrityMismatch: agreement, spelling, emptiness, non-docker', () => {
  assert.equal(dockerIntegrityMismatch({ install_cmd: cmd(OLD), pkg_integrity: `sha256-${OLD}` }), null);
  assert.match(dockerIntegrityMismatch({ install_cmd: cmd(OLD), pkg_integrity: `sha256:${OLD}` }), /canonical/);
  assert.match(dockerIntegrityMismatch({ install_cmd: cmd(OLD) }), /empty/);
  assert.match(dockerIntegrityMismatch({ install_cmd: cmd(OLD), pkg_integrity: 'nope' }), /not a sha256/);
  // Not digest-pinned / not docker: other checks own these.
  assert.equal(dockerIntegrityMismatch({ install_cmd: 'docker run -i img:latest', pkg_integrity: null }), null);
  assert.equal(dockerIntegrityMismatch({ install_cmd: 'npx -y pkg@1.0.0', pkg_integrity: 'sha512-x' }), null);
  assert.equal(dockerIntegrityMismatch(null), null);
});

test('DB: every docker entry says the same digest twice, canonically', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const bad = db.tools
    .map((t) => [t.name, dockerIntegrityMismatch(t)])
    .filter(([, why]) => why);
  assert.deepEqual(bad, []);
});

test('CLI: verify --offline passes the docker entries it now cross-checks', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const docker = db.tools.filter((t) => /^docker\s+run\b/.test(t.install_cmd || ''));
  assert.ok(docker.length > 0);
  for (const t of docker) {
    const r = spawnSync(process.execPath, [
      'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs', '--offline', '--entry', t.name,
    ], { cwd: path.resolve(__dirname, '..'), encoding: 'utf8' });
    assert.equal(r.status, 0, `${t.name}: ${r.stdout}${r.stderr}`);
    assert.doesNotMatch(r.stdout, /disagree/);
  }
});

test('CLI: verify fails when install_cmd moved and pkg_integrity did not (PR #106)', (t) => {
  const fs = require('node:fs');
  const os = require('node:os');
  const src = path.resolve(__dirname, '../mcp-ecosystem-intelligence');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-docker-integrity-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  // DB_PATH is resolved next to the script, so the check runs on a copy.
  fs.cpSync(src, path.join(tmp, 'mcp-ecosystem-intelligence'), { recursive: true });
  const dbFile = path.join(tmp, 'mcp-ecosystem-intelligence/assets/tools_database.json');
  const db = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
  const entry = db.tools.find((e) => dockerIntegrityMismatch(e) === null && /^docker\s+run\b/.test(e.install_cmd || ''));
  assert.ok(entry, 'DB carries a digest-pinned docker entry');
  const pinned = ociIntegrity(entry.pkg_integrity);
  entry.install_cmd = entry.install_cmd.replace(/sha256:[a-f0-9]{64}/, `sha256:${NEW}`);
  entry.pkg_integrity = pinned.replace('sha256-', 'sha256:');   // the #106 shape
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));

  const r = spawnSync(process.execPath, [
    'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs', '--offline', '--entry', entry.name,
  ], { cwd: tmp, encoding: 'utf8' });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /install_cmd and pkg_integrity disagree/);

  // The same refusal, as the findings model states it: a typed, observed,
  // high finding, refused by decide() — not a counter inside the processor.
  const j = spawnSync(process.execPath, [
    'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs', '--offline', '--json', '--as-of', '2026-09-30', '--entry', entry.name,
  ], { cwd: tmp, encoding: 'utf8' });
  assert.equal(j.status, 1, j.stdout + j.stderr);
  const doc = JSON.parse(j.stdout);
  const f = doc.findings.findings.find((x) => x.rule === 'integrity/docker-pin-mismatch');
  assert.ok(f, 'a finding with the integrity/docker-pin-mismatch rule');
  assert.equal(f.severity, 'high');
  assert.equal(f.state, 'observed');
  const d = doc.findings.decisions.find((x) => x.findings.includes(f.id));
  assert.equal(d.effect, 'deny');
  assert.equal(d.decided_by, 'finding/severity');
  assert.equal(d.fails, true);
});
