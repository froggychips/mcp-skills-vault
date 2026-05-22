'use strict';
const { test }         = require('node:test');
const assert           = require('node:assert/strict');
const { spawnSync }    = require('node:child_process');
const fs               = require('node:fs');
const os               = require('node:os');
const path             = require('node:path');

const a = require('../mcp-ecosystem-intelligence/scripts/audit_setup.cjs');

const SCRIPT = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts/audit_setup.cjs');

// ── fixture builders ───────────────────────────────────────────────────────

function makeProject({ mcp, settings } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-setup-'));
  if (mcp)      fs.writeFileSync(path.join(dir, '.mcp.json'),               JSON.stringify(mcp, null, 2));
  if (settings) {
    fs.mkdirSync(path.join(dir, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), JSON.stringify(settings, null, 2));
  }
  return dir;
}

function makeGlobalCfg(mcpServers) {
  const dir  = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-global-'));
  const file = path.join(dir, '.claude.json');
  // Include extra keys to prove we never echo them, even though we don't
  // formally diff that — this just keeps fixture realistic.
  fs.writeFileSync(file, JSON.stringify({ mcpServers, oauth: { secret: 'should-be-ignored' } }, null, 2));
  return file;
}

// Tiny synthetic DB covering every category we need to exercise.
const TEST_DB = {
  tools: [
    {
      name: 'mcp-server-filesystem',
      category: 'filesystem',
      install_cmd: 'npx -y @modelcontextprotocol/server-filesystem@2026.1.14',
      trust: 'verified',
      est_tools_count: 11,
      toolsets: null,
    },
    {
      name: 'github-mcp-server',
      category: 'vcs',
      install_cmd: 'docker run -i --rm ghcr.io/github/github-mcp-server@sha256:2ac27ef03461ef2b877031b838a7d1fd7f12b12d4ace7796d8cad91446d55959',
      trust: 'verified',
      est_tools_count: 65,
      toolsets: '--toolsets repos,issues,pull_requests',
    },
    {
      name: 'gitlab-mcp',
      category: 'vcs',
      install_cmd: 'npx -y @zereight/mcp-gitlab@1.6.0',
      trust: 'verified',
      est_tools_count: 153,
      toolsets: null,
    },
    {
      name: 'mcp-redis',
      category: 'database',
      install_cmd: 'uvx --from git+https://github.com/redis/mcp-redis mcp-redis',
      trust: 'candidate',
      est_tools_count: 10,
      toolsets: null,
      notes: 'Installed via uvx --from git+… — pkg_integrity not verifiable.',
    },
    {
      name: 'mcp-clickhouse',
      category: 'database',
      install_cmd: 'uvx mcp-clickhouse==0.3.0',
      trust: 'verified',
      est_tools_count: 4,
      toolsets: null,
    },
  ],
};

// ── pure-function tests ────────────────────────────────────────────────────

test('parseInstalledVersion: npm pkg@ver', () => {
  assert.equal(
    a.parseInstalledVersion({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2026.1.14', '/data'] }),
    '2026.1.14',
  );
});

test('parseInstalledVersion: pypi pkg==ver', () => {
  assert.equal(
    a.parseInstalledVersion({ command: 'uvx', args: ['mcp-clickhouse==0.3.0'] }),
    '0.3.0',
  );
});

test('parseInstalledVersion: docker @sha256:digest', () => {
  const v = a.parseInstalledVersion({
    command: 'docker',
    args: ['run', '-i', '--rm', 'ghcr.io/github/github-mcp-server@sha256:abcdef0123456789'],
  });
  assert.equal(v, 'sha256:abcdef0123456789');
});

test('parseInstalledVersion: no version → null', () => {
  assert.equal(a.parseInstalledVersion({ command: 'uvx', args: ['--from', 'git+https://x', 'mcp-redis'] }), null);
});

test('parseDbVersion: handles all three install styles', () => {
  assert.equal(a.parseDbVersion('npx -y pkg@1.2.3'),                                                      '1.2.3');
  assert.equal(a.parseDbVersion('uvx pkg==4.5.6 arg'),                                                    '4.5.6');
  assert.equal(a.parseDbVersion('docker run -i --rm ghcr.io/x/y@sha256:abc123def456'), 'sha256:abc123def456');
  assert.equal(a.parseDbVersion('uvx --from git+https://x mcp-redis'),                                    null);
});

test('matchDbEntry: exact name wins', () => {
  const t = a.matchDbEntry(TEST_DB, 'gitlab-mcp', { command: 'npx', args: ['-y', 'whatever'] });
  assert.equal(t.name, 'gitlab-mcp');
});

test('matchDbEntry: nickname resolves via package token', () => {
  // User named server "filesystem" but args reference the official package
  const t = a.matchDbEntry(TEST_DB, 'filesystem', {
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-filesystem@2026.1.14', '/data'],
  });
  assert.equal(t?.name, 'mcp-server-filesystem');
});

test('matchDbEntry: returns null for unknown server', () => {
  const t = a.matchDbEntry(TEST_DB, 'custom-internal', { command: 'node', args: ['./server.js'] });
  assert.equal(t, null);
});

test('hasAllowedToolsScope: matches both whole-server and per-tool forms', () => {
  assert.equal(a.hasAllowedToolsScope('github', ['mcp__github']),                  true);
  assert.equal(a.hasAllowedToolsScope('github', ['mcp__github__create_issue']),    true);
  assert.equal(a.hasAllowedToolsScope('github', ['mcp__gitlab__create_mr']),       false);
  assert.equal(a.hasAllowedToolsScope('github', []),                                false);
});

test('hasArgScope: detects --toolsets / --caps / --disabledTools', () => {
  assert.equal(a.hasArgScope({ args: ['--toolsets', 'repos,issues'] }), true);
  assert.equal(a.hasArgScope({ args: ['--caps=core'] }),                true);
  assert.equal(a.hasArgScope({ args: ['--disabledTools', 'x,y'] }),     true);
  assert.equal(a.hasArgScope({ args: ['-y', 'pkg'] }),                  false);
});

// ── audit() — finding categories ───────────────────────────────────────────

test('audit: drift finding when installed version ≠ DB version', () => {
  const findings = a.audit({
    project: {
      filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2025.0.1'] },
    },
    global:   {},
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  const drift = findings.find(f => f.category === 'drift');
  assert.ok(drift, `expected drift finding, got ${JSON.stringify(findings)}`);
  assert.equal(drift.installed,  '2025.0.1');
  assert.equal(drift.db_version, '2026.1.14');
});

test('audit: untrusted finding when DB trust=candidate', () => {
  const findings = a.audit({
    project: { 'mcp-redis': { command: 'uvx', args: ['--from', 'git+https://x', 'mcp-redis'] } },
    global:   {},
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  assert.ok(findings.some(f => f.category === 'untrusted' && f.server === 'mcp-redis'),
    `expected untrusted finding, got ${JSON.stringify(findings)}`);
});

test('audit: heavy-unbounded when est_tools_count > 15 and no scoping', () => {
  const findings = a.audit({
    project: { gitlab: { command: 'npx', args: ['-y', '@zereight/mcp-gitlab@1.6.0'] } },
    global:   {},
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  const heavy = findings.find(f => f.category === 'heavy-unbounded');
  assert.ok(heavy, `expected heavy-unbounded finding, got ${JSON.stringify(findings)}`);
  assert.equal(heavy.est_tools_count, 153);
});

test('audit: heavy-unbounded silenced by --toolsets arg', () => {
  const findings = a.audit({
    project: {
      github: { command: 'docker', args: ['run', '--toolsets', 'repos,issues', 'ghcr.io/github/github-mcp-server@sha256:2ac27ef03461ef2b877031b838a7d1fd7f12b12d4ace7796d8cad91446d55959'] },
    },
    global:   {},
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  assert.equal(findings.filter(f => f.category === 'heavy-unbounded').length, 0,
    `expected no heavy-unbounded, got ${JSON.stringify(findings)}`);
});

test('audit: heavy-unbounded silenced by allowedTools entry', () => {
  const findings = a.audit({
    project: { gitlab: { command: 'npx', args: ['-y', '@zereight/mcp-gitlab@1.6.0'] } },
    global:   {},
    settings: { enabled: null, allowedTools: ['mcp__gitlab__create_merge_request'] },
    db:       TEST_DB,
  });
  assert.equal(findings.filter(f => f.category === 'heavy-unbounded').length, 0);
});

test('audit: unknown when server not in DB', () => {
  const findings = a.audit({
    project: { 'custom-internal': { command: 'node', args: ['./bespoke.js'] } },
    global:   {},
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, 'unknown');
  assert.equal(findings[0].server,   'custom-internal');
});

test('audit: scope finding when project-scoped category installed globally', () => {
  const findings = a.audit({
    project: {},
    global:  { gitlab: { command: 'npx', args: ['-y', '@zereight/mcp-gitlab@1.6.0', '--toolsets', 'repos'] } },
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  const scope = findings.find(f => f.category === 'scope');
  assert.ok(scope, `expected scope finding, got ${JSON.stringify(findings)}`);
  assert.equal(scope.db_category, 'vcs');
});

test('audit: clean case — versions match, no candidates, no heavy-unbounded', () => {
  const findings = a.audit({
    project: {
      clickhouse: { command: 'uvx', args: ['mcp-clickhouse==0.3.0'] },
    },
    global:   {},
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  assert.deepEqual(findings, []);
});

test('audit: project-scope takes precedence over global (no double-report)', () => {
  const findings = a.audit({
    project: { gitlab: { command: 'npx', args: ['-y', '@zereight/mcp-gitlab@1.6.0', '--toolsets', 'repos'] } },
    global:  { gitlab: { command: 'npx', args: ['-y', '@zereight/mcp-gitlab@1.6.0'] } },
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  // gitlab should only appear once (from project source); no scope finding
  // because the project copy wins and project scope is fine for vcs.
  const gitlabFindings = findings.filter(f => f.server === 'gitlab');
  assert.equal(gitlabFindings.filter(f => f.category === 'scope').length, 0);
});

test('audit: version-unknown when DB pinned but installed has no @ver token', () => {
  const findings = a.audit({
    project: {
      // user wrote their own wrapper; we can't parse a version from `node`+script
      filesystem: { command: 'node', args: ['/custom/wrapper.js'] },
    },
    global:   {},
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  // Won't match by package token, so this becomes 'unknown', not version-unknown.
  // version-unknown requires a match; build that case explicitly:
  const findings2 = a.audit({
    project: {
      // server name == DB name → exact match, but args carry no parseable version
      'mcp-server-filesystem': { command: 'node', args: ['./wrapper.js'] },
    },
    global:   {},
    settings: { enabled: null, allowedTools: [] },
    db:       TEST_DB,
  });
  assert.ok(findings2.some(f => f.category === 'version-unknown'),
    `expected version-unknown, got ${JSON.stringify(findings2)}`);
  // And the earlier wrapper-by-name case:
  assert.ok(findings.some(f => f.category === 'unknown'));
});

// ── CLI integration tests ─────────────────────────────────────────────────

function runCli(extraArgs, dbPath) {
  return spawnSync('node', [SCRIPT, '--db', dbPath, ...extraArgs], { encoding: 'utf8' });
}

function writeTestDb() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-db-'));
  const file = path.join(dir, 'tools_database.json');
  fs.writeFileSync(file, JSON.stringify(TEST_DB, null, 2));
  return file;
}

test('CLI --help exits 0', () => {
  const res = spawnSync('node', [SCRIPT, '--help'], { encoding: 'utf8' });
  assert.equal(res.status, 0);
  assert.match(res.stdout, /audit_setup\.cjs/);
});

test('CLI --json emits {cwd, db_path, global_path, counts, findings}', () => {
  const dbPath  = writeTestDb();
  const proj    = makeProject({ mcp: { mcpServers: { 'mcp-redis': { command: 'uvx', args: ['--from', 'git+https://x', 'mcp-redis'] } } } });
  const globalCfg = makeGlobalCfg({});
  const res = runCli(['--json', '--cwd', proj, '--global-config', globalCfg], dbPath);
  assert.equal(res.status, 0, `stderr: ${res.stderr}`);
  const out = JSON.parse(res.stdout);
  assert.equal(out.counts.project, 1);
  assert.equal(out.counts.global,  0);
  assert.ok(Array.isArray(out.findings));
  assert.ok(out.findings.some(f => f.category === 'untrusted'));
  assert.ok(typeof out.cwd === 'string');
  assert.ok(typeof out.db_path === 'string');
});

test('CLI --strict exit code 1 on untrusted finding', () => {
  const dbPath = writeTestDb();
  const proj = makeProject({ mcp: { mcpServers: { 'mcp-redis': { command: 'uvx', args: ['--from', 'git+https://x', 'mcp-redis'] } } } });
  const globalCfg = makeGlobalCfg({});
  const res = runCli(['--strict', '--cwd', proj, '--global-config', globalCfg], dbPath);
  assert.equal(res.status, 1, `expected strict exit 1, got ${res.status}; stdout: ${res.stdout}`);
});

test('CLI --strict exit code 0 on info-only findings (unknown)', () => {
  const dbPath = writeTestDb();
  const proj = makeProject({ mcp: { mcpServers: { 'custom-internal': { command: 'node', args: ['./x.js'] } } } });
  const globalCfg = makeGlobalCfg({});
  const res = runCli(['--strict', '--cwd', proj, '--global-config', globalCfg], dbPath);
  assert.equal(res.status, 0, `expected 0 for unknown-only, got ${res.status}; stdout: ${res.stdout}`);
});

test('CLI --strict exit code 0 on clean setup', () => {
  const dbPath = writeTestDb();
  const proj = makeProject({ mcp: { mcpServers: { clickhouse: { command: 'uvx', args: ['mcp-clickhouse==0.3.0'] } } } });
  const globalCfg = makeGlobalCfg({});
  const res = runCli(['--strict', '--cwd', proj, '--global-config', globalCfg], dbPath);
  assert.equal(res.status, 0, `stderr: ${res.stderr}`);
});

test('CLI: missing .mcp.json + missing global config does not throw', () => {
  const dbPath = writeTestDb();
  const proj = makeProject({});  // no files at all
  const res = runCli(['--cwd', proj, '--global-config', '/nonexistent/path.json'], dbPath);
  assert.equal(res.status, 0, `stderr: ${res.stderr}`);
  assert.match(res.stdout, /0 project \+ 0 global/);
});

test('CLI: enabledMcpjsonServers excluding heavy server silences heavy-unbounded', () => {
  const dbPath = writeTestDb();
  const proj = makeProject({
    mcp:      { mcpServers: { gitlab: { command: 'npx', args: ['-y', '@zereight/mcp-gitlab@1.6.0'] } } },
    settings: { enabledMcpjsonServers: [] },   // gitlab is not enabled → effectively scoped out
  });
  const globalCfg = makeGlobalCfg({});
  const res = runCli(['--json', '--cwd', proj, '--global-config', globalCfg], dbPath);
  const out = JSON.parse(res.stdout);
  assert.equal(out.findings.filter(f => f.category === 'heavy-unbounded').length, 0);
});

test('CLI: bad argument exits 2', () => {
  const dbPath = writeTestDb();
  const res = runCli(['--nonsense'], dbPath);
  assert.equal(res.status, 2);
});
