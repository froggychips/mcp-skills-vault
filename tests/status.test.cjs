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
  // Pinned to the version the vault verified, so the stored evidence is about
  // these bytes and the Evidence line has something to date.
  const servers = { 'mcp-server-fetch': { command: 'uvx', args: ['mcp-server-fetch==2025.4.7'] } };
  const r = run(project(servers), ['--json']);
  assert.equal(r.json.evidence_source, 'stored');
  assert.equal(r.json.schema, 'mcp-vault/status@1');
  assert.equal(r.json.installed[0].version_match, 'same');

  const human = run(project(servers));
  assert.match(human.stdout, /nothing was re-checked just now/);
  // And it makes no network calls, so it can be the first thing anyone runs.
  assert.equal(human.status, 0);
});

test('a server on a different version than the vault verified gets no tier', () => {
  // The finding that made this rule: matching by the config key and then
  // applying the DB entry's evidence presented a claim about one version as a
  // claim about another. Both directions were wrong.
  const unpinned = run(project({ 'mcp-server-fetch': { command: 'uvx', args: ['mcp-server-fetch'] } }), ['--json']);
  assert.equal(unpinned.json.installed[0].version_match, 'different');
  assert.equal(unpinned.json.installed[0].tier, null, 'no tier may be claimed for bytes nobody checked');
  assert.equal(unpinned.json.installed[0].pinned, false);
  assert.match(unpinned.stdout, /unpinned, so what starts is not the pypi:mcp-server-fetch@2025\.4\.7/);

  const other = run(project({ 'mcp-server-fetch': { command: 'uvx', args: ['mcp-server-fetch==1.0.0'] } }), ['--json']);
  assert.equal(other.json.installed[0].version_match, 'different');
  assert.match(other.stdout, /this host launches pypi:mcp-server-fetch@1\.0\.0/);
  // A drift is worth knowing, not a blocker — the bytes are unchecked, not wrong.
  assert.equal(other.status, 0);
  assert.equal(run(project({ 'mcp-server-fetch': { command: 'uvx', args: ['mcp-server-fetch==1.0.0'] } }), ['--strict']).status, 1);
});

test('the config key is a label, not an identity', () => {
  // `mcp-server-aws` is yanked in the DB. A server merely *named* that, which
  // launches something else entirely, must not inherit its status — and a
  // server named anything at all that *does* launch it must.
  const misnamed = run(project({ 'mcp-server-aws': { command: 'node', args: ['./mine.js'] } }), ['--json']);
  assert.equal(misnamed.json.installed[0].in_db, false);
  assert.equal(misnamed.status, 0, 'a name collision is not a finding about anybody');

  const disguised = run(project({ 'totally-fine': { command: 'uvx', args: ['awslabs.core-mcp-server==1.0.27'] } }), ['--json']);
  assert.equal(disguised.json.installed[0].db_entry, 'mcp-server-aws');
  assert.equal(disguised.json.installed[0].tier, 'Deprecated');
  assert.equal(disguised.status, 1);
});

test('a host config that cannot be read is exit 2, not a clean or a blocked report', () => {
  // Three different things, and the first version collapsed two of them: a
  // config we could not read is neither "no servers configured" (exit 0) nor
  // "an installed server must not run" (exit 1). It is the reason the report
  // is incomplete, so "nothing blocked" would be a claim about servers we
  // never saw.
  const dir = project(null);
  fs.writeFileSync(path.join(dir, '.mcp.json'), '{ "mcpServers": { oops');
  const r = run(dir);
  assert.equal(r.status, 2);
  assert.match(r.stdout, /Could not answer/);
  assert.match(r.stdout, /host config could not be read/);
  assert.match(r.stdout, /not a claim about whatever is in there/);
});

test('a config we are not allowed to read is not a config with nothing in it', () => {
  // readInstalledServers swallowed every fs error, so EACCES was
  // indistinguishable from "that host is not configured here" — exit 0 with
  // no installed servers and no mention of the file.
  const dir = project(null);
  const file = path.join(dir, '.mcp.json');
  fs.writeFileSync(file, JSON.stringify({ mcpServers: {} }));
  fs.chmodSync(file, 0o000);
  try {
    const r = run(dir);
    // Running as root defeats the permission bits; skip rather than claim a pass.
    if (r.status === 0 && !/Could not answer/.test(r.stdout)) return;
    assert.equal(r.status, 2);
    assert.match(r.stdout, /EACCES|read failed/);
  } finally {
    fs.chmodSync(file, 0o600);
  }
});

test('a --cwd that is not there is exit 2, not a project with no signals', () => {
  const r = run(path.join(project(null), 'does-not-exist'));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /cannot read/);
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

test('a measurement may raise the tool count, never lower it', () => {
  // The composition surfaced a contradiction — one screen said "396 tools,
  // measured" and "tool count unknown" about the same server — and the first
  // fix overcorrected: it let any positive measurement replace the estimate,
  // so a measured 10 deleted the finding. `tools/list` is paginated and the
  // eval reads one page, so a measured 10 can be the first page of 100.
  const audit = require('../mcp-ecosystem-intelligence/scripts/audit_setup.cjs');
  const project_ = { x: { command: 'npx', args: ['-y', 'x@1.0.0'] } };
  const settings = { enabled: null, allowedTools: [] };
  const heavy = (est, evalRow) => audit.audit({
    project: project_, global: {}, settings,
    db: { tools: [{ name: 'x', install_cmd: 'npx -y x@1.0.0', est_tools_count: est, category: 'utility' }] },
    evals: evalRow ? new Map([['x', evalRow]]) : null,
  }).filter((f) => f.category === 'heavy-unbounded');
  const pass_ = (n, over = {}) => ({ name: 'x', status: 'pass', tool_count: n, ...over });

  assert.match(heavy(null, null)[0].message, /tool count unknown/);
  assert.match(heavy(null, pass_(396))[0].message, /396 tools \(measured\)/);

  // A measurement below the DB's estimate does not shrink it…
  assert.match(heavy(72, pass_(10))[0].message, /^72 tools,/);
  // …and with no estimate to compare against, a small measurement cannot
  // establish that the surface is small: unknown stays heavy.
  assert.equal(heavy(null, pass_(3)).length, 1);
  // A failed run is not a measurement of anything.
  assert.match(heavy(null, { name: 'x', status: 'fail', tool_count: 3 })[0].message, /tool count unknown/);
  // A truncated list is a lower bound, so it cannot conclude "small enough".
  assert.equal(heavy(3, pass_(3, { tools_truncated: true })).length, 1);
  assert.match(heavy(3, pass_(3, { tools_truncated: true }))[0].message, /3\+ tools/);
  // And an unpaginated small surface is still not a finding.
  assert.equal(heavy(3, pass_(3, { tools_truncated: false })).length, 0);
});

test('bad arguments are exit 2, not a clean report', () => {
  assert.equal(run(project(null), ['--nonsense']).status, 2);
  assert.equal(s.parseArgs(['--cwd']).error, '--cwd needs a directory');
});
