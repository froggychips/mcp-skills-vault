'use strict';
/**
 * The one command a new reader runs.
 *
 * The quick start used to be six commands, four of which answer questions
 * about the same three inputs. `status` composes them, and the risk of a
 * composed summary is that a number loses the qualification it had in its
 * original report: a stored claim reads as a fresh check, an unparseable host
 * config reads as a host with nothing in it, a server nobody vetted reads as a
 * server that passed. These tests pin the places that would happen.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts/status.cjs');
const s      = require('../mcp-ecosystem-intelligence/scripts/status.cjs');

/** A throwaway project directory with the given `.mcp.json`, and no global config. */
function project(servers) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-status-'));
  if (servers) fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }));
  return dir;
}

/** Run the CLI with HOME pointed at an empty dir, so only the project counts. */
function run(dir, args = []) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-home-'));
  const r = spawnSync(process.execPath, [SCRIPT, '--cwd', dir, ...args], {
    encoding: 'utf8',
    env: { ...process.env, HOME: home, NO_COLOR: '1' },
  });
  return { ...r, json: args.includes('--json') ? JSON.parse(r.stdout) : null };
}

test('a clean project is exit 0 and says so in one screen', () => {
  const r = run(project(null));
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Nothing blocked, nothing drifted/);
  // "One screen" is the feature, so it is a test: 24 lines is a small terminal.
  const lines = r.stdout.trim().split('\n').length;
  assert.ok(lines <= 24, `status printed ${lines} lines:\n${r.stdout}`);
});

test('an installed server that must not run is blocking, and exit 1', () => {
  // mcp-atlassian has an advisory against its pinned version; mcp-server-aws
  // is yanked. Both are Deprecated in the derived tier — "do not install".
  const r = run(project({
    'mcp-atlassian':  { command: 'uvx', args: ['mcp-atlassian==0.21.1'] },
    'mcp-server-aws': { command: 'uvx', args: ['awslabs.core-mcp-server==1.0.27'] },
  }));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /Blocking/);
  assert.match(r.stdout, /mcp-atlassian: advisories: vulnerable/);
  assert.match(r.stdout, /mcp-server-aws: availability: yanked/);
});

test('an unvetted server is not a finding about the server, and does not fail the default', () => {
  // The distinction the default exit code turns on: "we have not checked this"
  // is a gap in our coverage, and a default that failed on it would train
  // everyone to ignore the command. --strict is where you ask for it.
  const dir = project({ 'something-homegrown': { command: 'node', args: ['./server.js'] } });
  const plain = run(dir);
  assert.equal(plain.status, 0);
  assert.match(plain.stdout, /not in the vault DB, so nothing here has checked it/);

  assert.equal(run(dir, ['--strict']).status, 1);
});

test('eleven unvetted servers are one line, not eleven', () => {
  // Measured on a real config: the per-server form pushed the blocking
  // findings off the screen this command exists to fit.
  const servers = {};
  for (let i = 0; i < 11; i++) servers[`home-grown-${i}`] = { command: 'node', args: ['./s.js'] };
  const r = run(project(servers));
  const noticeLines = r.stdout.split('\n').filter((l) => /not in the vault DB/.test(l));
  assert.equal(noticeLines.length, 1, r.stdout);
  assert.match(noticeLines[0], /11 configured servers are not in the vault DB/);
});

test('every claim is marked as stored, never as freshly checked', () => {
  const r = run(project({ 'mcp-server-fetch': { command: 'uvx', args: ['mcp-server-fetch'] } }), ['--json']);
  assert.equal(r.json.evidence_source, 'stored');
  assert.equal(r.json.schema, 'mcp-vault/status@1');
  const human = run(project({ 'mcp-server-fetch': { command: 'uvx', args: ['mcp-server-fetch'] } }));
  assert.match(human.stdout, /nothing was re-checked just now/);
  // And it makes no network calls, so it can be the first thing anyone runs.
  assert.equal(human.status, 0);
});

test('a host config that cannot be parsed blocks rather than reading as empty', () => {
  const dir = project(null);
  fs.writeFileSync(path.join(dir, '.mcp.json'), '{ "mcpServers": { oops');
  const r = run(dir);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /host config could not be read/);
});

test('the heaviest server is named, not just the total', () => {
  // "47% of your window" is a number; which server spent it is the finding.
  const r = run(project({
    'mcp-atlassian': { command: 'uvx', args: ['mcp-atlassian==0.21.1'] },
  }), ['--json']);
  assert.ok(r.json.context.heaviest, 'the heaviest server travels with the totals');
  assert.equal(r.json.context.heaviest.name, 'mcp-atlassian');
  assert.ok(r.json.context.heaviest.percent_of_context > 0);
});

test('universal suggestions are not reported as a stack match', () => {
  // matchDB always adds the universal three, so an empty project used to read
  // "no stack signals detected → 3 suggested" — a sentence contradicting
  // itself in the space of six words.
  const r = run(project(null), ['--json']);
  assert.deepEqual(r.json.project.not_installed_for_stack, []);
  assert.ok(r.json.project.not_installed_universal.length > 0);
});

test('a measured tool count outranks the DB estimate in the heavy check', () => {
  // The composition surfaced a contradiction: one screen said "396 tools,
  // measured" and "tool count unknown" about the same server.
  const audit = require('../mcp-ecosystem-intelligence/scripts/audit_setup.cjs');
  const db = { tools: [{ name: 'x', install_cmd: 'npx -y x@1.0.0', est_tools_count: null, category: 'utility' }] };
  const project_ = { x: { command: 'npx', args: ['-y', 'x@1.0.0'] } };
  const settings = { enabled: null, allowedTools: [] };

  const blind = audit.audit({ project: project_, global: {}, settings, db });
  assert.match(blind.find((f) => f.category === 'heavy-unbounded').message, /tool count unknown/);

  const seeing = audit.audit({
    project: project_, global: {}, settings, db,
    evals: new Map([['x', { name: 'x', status: 'pass', tool_count: 396 }]]),
  });
  assert.match(seeing.find((f) => f.category === 'heavy-unbounded').message, /396 tools \(measured\)/);

  // And a server measured at three tools is not an unbounded surface at all.
  const small = audit.audit({
    project: project_, global: {}, settings, db,
    evals: new Map([['x', { name: 'x', status: 'pass', tool_count: 3 }]]),
  });
  assert.equal(small.filter((f) => f.category === 'heavy-unbounded').length, 0);
});

test('bad arguments are exit 2, not a clean report', () => {
  assert.equal(run(project(null), ['--nonsense']).status, 2);
  assert.equal(s.parseArgs(['--cwd']).error, '--cwd needs a directory');
});
