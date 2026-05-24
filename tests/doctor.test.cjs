'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const d = require('../mcp-ecosystem-intelligence/scripts/doctor.cjs');

test('versionGte checks Node major version', () => {
  assert.equal(d.versionGte('v18.0.0', 18), true);
  assert.equal(d.versionGte('v17.9.9', 18), false);
  assert.equal(d.versionGte('not-a-version', 18), false);
});

test('runDoctor reports project config parse failures', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-doctor-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), '{ nope');
  const out = d.runDoctor({ cwd: dir });
  const project = out.checks.find(c => c.name === 'project_config');
  assert.equal(project.level, 'fail');
  assert.match(project.message, /parse failed/);
});

test('CLI doctor --json emits checks', () => {
  const r = spawnSync(process.execPath, [
    'bin/mcp-vault.cjs',
    'doctor',
    '--json',
  ], { cwd: path.resolve(__dirname, '..'), encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr || r.stdout);
  const out = JSON.parse(r.stdout);
  assert.ok(Array.isArray(out.checks));
  assert.ok(out.checks.some(c => c.name === 'node'));
});
