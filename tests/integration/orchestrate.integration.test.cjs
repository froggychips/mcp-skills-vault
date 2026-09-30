'use strict';
/**
 * Integration tests for orchestrate.cjs.
 *
 * These spin up the real CLI against the real DB in a temp directory.
 * They are deliberately NOT part of the default `unit-tests` job — install
 * mode triggers `npm view` which needs network access. CI runs them
 * separately (or skips on offline runners).
 *
 * Run locally:
 *   node --test tests/integration/*.integration.test.cjs
 *
 * Skip in offline contexts:
 *   MSV_SKIP_INTEGRATION=1 node --test ...
 */

const { test }    = require('node:test');
const assert      = require('node:assert/strict');
const fs          = require('node:fs');
const os          = require('node:os');
const path        = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO_ROOT  = path.resolve(__dirname, '..', '..');
const ORCH_CJS   = path.join(REPO_ROOT, 'mcp-ecosystem-intelligence/scripts/orchestrate.cjs');

const skip = process.env.MSV_SKIP_INTEGRATION === '1';

function mkTmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'msv-int-'));
}

function rmTmp(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

function runOrch(args, opts = {}) {
  return spawnSync('node', [ORCH_CJS, ...args], { encoding: 'utf8', ...opts });
}

test('orchestrate: empty project → 0 exit, lists universals', { skip }, () => {
  const tmp = mkTmp();
  try {
    const r = runOrch(['--cwd', tmp]);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    // Universals should appear in the recommendations.
    assert.match(r.stdout, /mcp-server-filesystem/);
    assert.match(r.stdout, /mcp-server-memory/);
    assert.match(r.stdout, /context7/);
  } finally { rmTmp(tmp); }
});

test('orchestrate --json: emits valid JSON with expected shape', { skip }, () => {
  const tmp = mkTmp();
  try {
    const r = runOrch(['--cwd', tmp, '--json']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const j = JSON.parse(r.stdout);
    assert.ok(Array.isArray(j.recommended), 'recommended array');
    assert.ok(Array.isArray(j.heavy),       'heavy array');
    assert.ok(j.stack,                       'stack object');
    assert.ok(typeof j.db_entry_count === 'number' && j.db_entry_count > 0);
    // Universal tools should be in recommended (no installed servers in fresh tmp).
    const recNames = j.recommended.map(t => t.name);
    assert.ok(recNames.includes('mcp-server-filesystem'));
  } finally { rmTmp(tmp); }
});

test('orchestrate: stack detection from package.json triggers postgres mapping', { skip }, () => {
  const tmp = mkTmp();
  try {
    fs.writeFileSync(path.join(tmp, 'package.json'),
      JSON.stringify({ name: 'x', dependencies: { pg: '^8.0.0' } }));
    const r = runOrch(['--cwd', tmp, '--json']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const j = JSON.parse(r.stdout);
    assert.ok(j.stack.dbs.includes('postgres'), `stack.dbs=${j.stack.dbs}`);
    // postgres maps to mcp-server-neon
    const recNames = j.recommended.map(t => t.name);
    assert.ok(recNames.includes('mcp-server-neon'), `Expected neon in recommended, got ${recNames}`);
  } finally { rmTmp(tmp); }
});

// mysql used to be the example of a gap; PR #22 added mcp-server-mysql and the
// mapping, and this test kept asserting the gap. Loki is left unmapped on
// purpose (see SIGNAL_TO_TOOLS), so it carries the no-mapping case now.
test('orchestrate: docker-compose mysql maps to mcp-server-mysql; loki is reported as a gap', { skip }, () => {
  const tmp = mkTmp();
  try {
    fs.writeFileSync(path.join(tmp, 'docker-compose.yml'),
      'services:\n  db:\n    image: mysql:8\n  logs:\n    image: grafana/loki:3\n');
    const r = runOrch(['--cwd', tmp, '--json']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const j = JSON.parse(r.stdout);
    assert.ok(j.stack.dbs.includes('mysql'));
    assert.ok(j.recommended.map(t => t.name).includes('mcp-server-mysql'), 'mysql should map to mcp-server-mysql');
    const unmapped = j.stack.unmapped_signals;
    assert.ok(Array.isArray(unmapped));
    assert.equal(unmapped.find(u => u.signal === 'mysql'), undefined, `mysql is mapped now, got ${JSON.stringify(unmapped)}`);
    const lokiGap = unmapped.find(u => u.signal === 'loki');
    assert.ok(lokiGap, `Expected loki in unmapped, got ${JSON.stringify(unmapped)}`);
    assert.equal(lokiGap.reason, 'no mapping');
  } finally { rmTmp(tmp); }
});

test('orchestrate --install unknown-tool: exit 2', { skip }, () => {
  const tmp = mkTmp();
  try {
    const r = runOrch(['--cwd', tmp, '--install', 'totally-not-real-mcp']);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /not found in DB/);
  } finally { rmTmp(tmp); }
});

// The install gate is fail-closed on aged-out evidence (availability and
// advisories are seven-day claims), so against the shipped DB this test passed
// for a week after each refresh and failed after that — on a correct refusal.
// It now runs a copy of the scripts against a copy of the DB whose evidence for
// the entry is dated as the test needs, and checks both sides of the gate.
function copyWithEvidenceAge(entryName, daysAgo) {
  const root = mkTmp();
  fs.cpSync(path.join(REPO_ROOT, 'mcp-ecosystem-intelligence'), path.join(root, 'mcp-ecosystem-intelligence'), { recursive: true });
  const dbPath = path.join(root, 'mcp-ecosystem-intelligence/assets/tools_database.json');
  const db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  const tool = db.tools.find((t) => t.name === entryName);
  assert.ok(tool && tool.trust_evidence, `${entryName} has no recorded evidence to age`);
  const date = new Date(Date.now() - daysAgo * 86400000).toISOString().slice(0, 10);
  for (const dim of Object.values(tool.trust_evidence.dimensions)) {
    dim.checked_at = date;
    if (dim.verified_at) dim.verified_at = date;
  }
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2) + '\n');
  return { root, orch: path.join(root, 'mcp-ecosystem-intelligence/scripts/orchestrate.cjs') };
}

test('orchestrate --install --offline: writes .mcp.json without network audit', { skip }, () => {
  // mcp-server-fetch is a stable PyPI entry with no install hooks — safe
  // to install in a temp dir. --offline skips the advisory feed network calls
  // but still runs the hash check (which uses `npm view` / `pypi` via execSync).
  const tmp = mkTmp();
  const copy = copyWithEvidenceAge('mcp-server-fetch', 0);
  try {
    const r = spawnSync('node', [copy.orch, '--cwd', tmp, '--install', 'mcp-server-fetch', '--offline'], { encoding: 'utf8' });
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const mcpPath = path.join(tmp, '.mcp.json');
    assert.ok(fs.existsSync(mcpPath), '.mcp.json should exist');
    const cfg = JSON.parse(fs.readFileSync(mcpPath, 'utf8'));
    assert.ok(cfg.mcpServers['mcp-server-fetch'], `Expected mcp-server-fetch entry, got ${Object.keys(cfg.mcpServers || {})}`);
    const entry = cfg.mcpServers['mcp-server-fetch'];
    assert.equal(entry.command, 'uvx');
    assert.ok(Array.isArray(entry.args) && entry.args[0].startsWith('mcp-server-fetch'));
  } finally { rmTmp(tmp); rmTmp(copy.root); }
});

test('orchestrate --install --offline: refuses when the entry\'s evidence has aged out', { skip }, () => {
  const tmp = mkTmp();
  const copy = copyWithEvidenceAge('mcp-server-fetch', 30);
  try {
    const r = spawnSync('node', [copy.orch, '--cwd', tmp, '--install', 'mcp-server-fetch', '--offline'], { encoding: 'utf8' });
    assert.equal(r.status, 1, `expected the gate to refuse; stderr: ${r.stderr}`);
    assert.match(r.stderr, /stored evidence has aged out/);
    assert.match(r.stderr, /ABORT: integrity gate did not clear mcp-server-fetch/);
    assert.equal(fs.existsSync(path.join(tmp, '.mcp.json')), false, 'nothing may be written after a refusal');
  } finally { rmTmp(tmp); rmTmp(copy.root); }
});
