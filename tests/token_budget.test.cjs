'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');
const { spawnSync } = require('node:child_process');

const b = require('../mcp-ecosystem-intelligence/scripts/token_budget.cjs');
const REPO = path.resolve(__dirname, '..');

test('estimateServer: a measured payload beats a counted estimate', () => {
  const r = b.estimateServer({ name: 's', evalEntry: { tool_count: 10, tools_payload_bytes: 4000 } });
  assert.equal(r.source, 'measured');
  assert.equal(r.tokens, 1000);               // 4000 bytes ÷ 4
  // A measurement has no range: it is the thing itself, not an estimate of it.
  assert.equal(r.low, r.tokens);
  assert.equal(r.high, r.tokens);
});

test('estimateServer: falls back to eval count, then to the DB, then gives up', () => {
  const fromEval = b.estimateServer({ name: 's', evalEntry: { tool_count: 4 } });
  assert.equal(fromEval.source, 'eval');
  assert.equal(fromEval.tokens, 4 * 350);
  assert.equal(fromEval.low, 4 * b.TOKENS_PER_TOOL_LOW);
  assert.equal(fromEval.high, 4 * b.TOKENS_PER_TOOL_HIGH);

  const fromDb = b.estimateServer({ name: 's', dbEntry: { est_tools_count: 20 } });
  assert.equal(fromDb.source, 'db');
  assert.equal(fromDb.tokens, 20 * 350);

  const nothing = b.estimateServer({ name: 's' });
  assert.equal(nothing.source, 'unknown');
  assert.equal(nothing.tokens, null);
  // An unknown server must not be quietly counted as zero.
  assert.equal(nothing.tools, null);
});

test('estimateServer: a zero-byte payload is not a measurement', () => {
  const r = b.estimateServer({ name: 's', evalEntry: { tool_count: 7, tools_payload_bytes: 0 } });
  assert.equal(r.source, 'eval');
});

test('matchDbEntry: by name, then by package', () => {
  const db = [
    { name: '@scope/server', install_cmd: 'npx -y @scope/server@1.0.0', est_tools_count: 5 },
    { name: 'git-server',    install_cmd: 'uvx mcp-server-git==1.0',    est_tools_count: 3 },
  ];
  assert.equal(b.matchDbEntry({ name: '@scope/server' }, db).est_tools_count, 5);
  // A config can name a server anything; the package is what identifies it.
  assert.equal(b.matchDbEntry({ name: 'my-git', install_cmd: 'uvx mcp-server-git==1.0' }, db).name, 'git-server');
  assert.equal(b.matchDbEntry({ name: 'unknown', install_cmd: 'npx -y other' }, db), null);
  assert.equal(b.matchDbEntry({ name: 'local', install_cmd: null }, db), null);
});

test('parseArgs: validates the numbers it is given', () => {
  assert.equal(b.parseArgs(['--context', '100000']).context, 100000);
  assert.equal(b.parseArgs(['--budget', '30']).budget, 30);
  assert.match(b.parseArgs(['--context', 'lots']).error, /--context/);
  assert.match(b.parseArgs(['--budget', '900']).error, /percentage/);
  assert.match(b.parseArgs(['--wat']).error, /unknown flag/);
});

// One project config plus one measured result file: enough to exercise the
// whole command without spawning anything.
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-budget-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: {
    big:    { command: 'npx', args: ['-y', 'big@1.0.0'] },
    small:  { command: 'npx', args: ['-y', 'small@1.0.0'] },
    remote: { url: 'https://mcp.example/sse' },
  } }));
  fs.writeFileSync(path.join(dir, 'eval.json'), JSON.stringify({ results: [
    { name: 'big',   tool_count: 396, tools_payload_bytes: 351324 },
    { name: 'small', tool_count: 4,   tools_payload_bytes: 4000 },
  ] }));
  return dir;
}

test('CLI: totals, percentage, and the source of every number', () => {
  const dir = fixture();
  const r = spawnSync(process.execPath, [
    'mcp-ecosystem-intelligence/scripts/token_budget.cjs',
    '--cwd', dir, '--results', path.join(dir, 'eval.json'), '--json',
  ], { cwd: REPO, encoding: 'utf8', env: { ...process.env, HOME: dir } });
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.schema, 'mcp-vault/token-budget@1');
  assert.equal(report.totals.tools, 400);
  assert.equal(report.totals.tokens, Math.round(351324 / 4) + 1000);
  assert.equal(report.totals.unknown_servers, 1);          // the remote one
  assert.equal(report.totals.percent_of_context > 40, true);
  // Biggest first: the point of the report is which server to look at.
  assert.equal(report.servers[0].name, 'big');
  assert.deepEqual(report.servers.map(s => s.source), ['measured', 'measured', 'unknown']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI: --budget turns the total into a gate', () => {
  const dir = fixture();
  const run = (pct) => spawnSync(process.execPath, [
    'mcp-ecosystem-intelligence/scripts/token_budget.cjs',
    '--cwd', dir, '--results', path.join(dir, 'eval.json'), '--budget', String(pct),
  ], { cwd: REPO, encoding: 'utf8', env: { ...process.env, HOME: dir } });
  const over = run(10);
  assert.equal(over.status, 1);
  assert.match(over.stderr, /over the 10% budget/);
  assert.equal(run(90).status, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI: no servers configured is a plain answer, not an error', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-budget-empty-'));
  const r = spawnSync(process.execPath, [
    'mcp-ecosystem-intelligence/scripts/token_budget.cjs', '--cwd', dir,
  ], { cwd: REPO, encoding: 'utf8', env: { ...process.env, HOME: dir } });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /No MCP servers configured/);
  fs.rmSync(dir, { recursive: true, force: true });
});
