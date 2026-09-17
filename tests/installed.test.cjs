'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

const inst = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');

test('hostConfigPaths: covers the hosts people actually use', () => {
  const locs = inst.hostConfigPaths({ cwd: '/proj', home: '/home/u', platform: 'linux' });
  const byHost = {};
  for (const l of locs) (byHost[l.host] ||= []).push(l.path);
  assert.deepEqual(byHost['claude-code'], ['/proj/.mcp.json', '/home/u/.claude.json']);
  assert.ok(byHost['cursor'].includes('/proj/.cursor/mcp.json'));
  assert.ok(byHost['vscode'].includes('/proj/.vscode/mcp.json'));
  assert.ok(byHost['claude-desktop'][0].includes('Claude'));
  // Project scope and user scope are distinguished: a global entry applies to
  // every project, which makes it the more interesting one to get wrong.
  const scopes = new Set(locs.map(l => l.scope));
  assert.deepEqual([...scopes].sort(), ['project', 'user']);
});

test('hostConfigPaths: platform-specific locations', () => {
  const mac = inst.hostConfigPaths({ cwd: '/p', home: '/Users/u', platform: 'darwin' });
  assert.ok(mac.some(l => l.path === '/Users/u/Library/Application Support/Claude/claude_desktop_config.json'));
  const win = inst.hostConfigPaths({ cwd: 'C:\\p', home: 'C:\\Users\\u', platform: 'win32' });
  assert.ok(win.some(l => l.host === 'claude-desktop' && l.path.includes('Claude')));
});

test('parseConfig: reads mcpServers and VS Code\'s servers key', () => {
  const a = inst.parseConfig({ mcpServers: { foo: { command: 'npx', args: ['-y', 'foo@1'] } } }, { host: 'h', scope: 'project', path: '/x' });
  assert.equal(a.length, 1);
  assert.deepEqual(a[0].args, ['-y', 'foo@1']);
  assert.equal(a[0].host, 'h');
  assert.equal(a[0].scope, 'project');

  const b = inst.parseConfig({ servers: { bar: { command: 'uvx', args: ['bar==2'] } } }, {});
  assert.deepEqual(b.map(x => x.name), ['bar']);
});

test('parseConfig: records env var names, never values', () => {
  const out = inst.parseConfig({ mcpServers: { s: { command: 'npx', args: [], env: { TOKEN: 'super-secret', OTHER: 'x' } } } }, {});
  assert.deepEqual(out[0].env_keys, ['TOKEN', 'OTHER']);
  assert.equal(JSON.stringify(out[0]).includes('super-secret'), false);
});

test('parseConfig: remote servers are kept but marked', () => {
  const out = inst.parseConfig({ mcpServers: { r: { url: 'https://mcp.example/sse', type: 'sse' } } }, {});
  assert.equal(out[0].remote, 'https://mcp.example/sse');
  assert.equal(out[0].command, null);
});

test('parseConfig: shapes with no server table yield nothing', () => {
  assert.deepEqual(inst.parseConfig(null, {}), []);
  assert.deepEqual(inst.parseConfig({}, {}), []);
  assert.deepEqual(inst.parseConfig({ mcpServers: 'nope' }, {}), []);
  assert.deepEqual(inst.parseConfig({ mcpServers: { bad: 'not-an-object' } }, {}), []);
});

test('toInstallCmd: rebuilds a command the gate can parse', () => {
  assert.equal(inst.toInstallCmd({ command: 'npx', args: ['-y', 'pkg@1.2.3'] }), 'npx -y pkg@1.2.3');
  assert.equal(inst.toInstallCmd({ command: 'uvx', args: ['pkg==1.0'] }), 'uvx pkg==1.0');
  assert.equal(inst.toInstallCmd({ command: 'docker', args: ['run', '-i', 'img@sha256:abc'] }), 'docker run -i img@sha256:abc');
  // `npx pkg` without -y means the same thing here; normalise so the shared
  // parser recognises it.
  assert.equal(inst.toInstallCmd({ command: 'npx', args: ['pkg@1'] }), 'npx -y pkg@1');
  // Windows / absolute paths to the same launchers.
  assert.equal(inst.toInstallCmd({ command: '/usr/local/bin/npx', args: ['-y', 'pkg'] }), 'npx -y pkg');
  assert.equal(inst.toInstallCmd({ command: 'npx.cmd', args: ['-y', 'pkg'] }), 'npx -y pkg');
});

test('toInstallCmd: null for anything with no published artifact', () => {
  assert.equal(inst.toInstallCmd({ command: 'node', args: ['./server.js'] }), null);
  assert.equal(inst.toInstallCmd({ command: '/opt/bin/my-mcp', args: [] }), null);
  assert.equal(inst.toInstallCmd({ remote: 'https://mcp.example/sse' }), null);
  assert.equal(inst.toInstallCmd({}), null);
  assert.equal(inst.toInstallCmd(null), null);
});

test('readInstalledServers: reads several configs, flags unreadable ones', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-installed-'));
  const good = path.join(dir, 'good.json');
  const bad  = path.join(dir, 'bad.json');
  fs.writeFileSync(good, JSON.stringify({ mcpServers: {
    pinned:   { command: 'npx', args: ['-y', 'pkg@1.2.3'] },
    unpinned: { command: 'npx', args: ['-y', 'pkg'] },
    local:    { command: 'node', args: ['./s.js'] },
  } }));
  fs.writeFileSync(bad, '{ not json');

  const problems = [];
  const servers = inst.readInstalledServers({
    paths: [
      { host: 'test', scope: 'project', path: good },
      { host: 'test', scope: 'user',    path: bad },
      { host: 'test', scope: 'user',    path: path.join(dir, 'absent.json') },
    ],
    onUnreadable: (p) => problems.push(p),
  });

  assert.deepEqual(servers.map(s => s.name), ['pinned', 'unpinned', 'local']);
  assert.equal(servers[0].install_cmd, 'npx -y pkg@1.2.3');
  assert.equal(servers[2].install_cmd, null);
  // A config that exists but cannot be parsed is a finding, not an absence;
  // a config that simply isn't there is not reported at all.
  assert.equal(problems.length, 1);
  assert.equal(problems[0].path, bad);
  fs.rmSync(dir, { recursive: true, force: true });
});
