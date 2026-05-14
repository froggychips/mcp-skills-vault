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

test('orchestrate: docker-compose mysql triggers no-mapping warning (no DB match)', { skip }, () => {
  const tmp = mkTmp();
  try {
    fs.writeFileSync(path.join(tmp, 'docker-compose.yml'),
      'services:\n  db:\n    image: mysql:8\n');
    const r = runOrch(['--cwd', tmp, '--json']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const j = JSON.parse(r.stdout);
    assert.ok(j.stack.dbs.includes('mysql'));
    const unmapped = j.stack.unmapped_signals;
    assert.ok(Array.isArray(unmapped));
    const mysqlGap = unmapped.find(u => u.signal === 'mysql');
    assert.ok(mysqlGap, `Expected mysql in unmapped, got ${JSON.stringify(unmapped)}`);
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

test('orchestrate --install --offline: writes .mcp.json without network audit', { skip }, () => {
  // mcp-server-fetch is a stable PyPI entry with no install hooks — safe
  // to install in a temp dir. --offline skips the advisory feed network calls
  // but still runs the hash check (which uses `npm view` / `pypi` via execSync).
  const tmp = mkTmp();
  try {
    const r = runOrch(['--cwd', tmp, '--install', 'mcp-server-fetch', '--offline']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
    const mcpPath = path.join(tmp, '.mcp.json');
    assert.ok(fs.existsSync(mcpPath), '.mcp.json should exist');
    const cfg = JSON.parse(fs.readFileSync(mcpPath, 'utf8'));
    assert.ok(cfg.mcpServers['mcp-server-fetch'], `Expected mcp-server-fetch entry, got ${Object.keys(cfg.mcpServers || {})}`);
    const entry = cfg.mcpServers['mcp-server-fetch'];
    assert.equal(entry.command, 'uvx');
    assert.ok(Array.isArray(entry.args) && entry.args[0].startsWith('mcp-server-fetch'));
  } finally { rmTmp(tmp); }
});
