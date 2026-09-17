'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

const h = require('../mcp-ecosystem-intelligence/scripts/lib/hosts.cjs');

const ENTRY = { command: 'npx', args: ['-y', 'pkg@1.2.3'] };

test('listHosts: the hosts people actually run MCP servers in', () => {
  const ids = h.listHosts().map(x => x.id);
  assert.deepEqual(ids, ['claude-code', 'claude-desktop', 'cursor', 'vscode', 'codex']);
  const byId = Object.fromEntries(h.listHosts().map(x => [x.id, x]));
  assert.deepEqual(byId['claude-code'].scopes, ['project', 'user']);
  assert.deepEqual(byId['vscode'].scopes, ['project']);      // VS Code is per-workspace
  assert.equal(byId['codex'].format, 'toml');
});

test('resolveTarget: paths and the per-host map key', () => {
  const at = (id, scope) => h.resolveTarget(id, scope, { cwd: '/proj', home: '/home/u', platform: 'linux' });
  assert.equal(at('claude-code', 'project').path, '/proj/.mcp.json');
  assert.equal(at('claude-code', 'user').path, '/home/u/.claude.json');
  assert.equal(at('cursor', 'project').path, '/proj/.cursor/mcp.json');
  assert.equal(at('vscode', 'project').path, '/proj/.vscode/mcp.json');
  // VS Code calls the map `servers`, everyone else `mcpServers`. Writing the
  // wrong key produces a config the host silently ignores.
  assert.equal(at('vscode', 'project').key, 'servers');
  assert.equal(at('cursor', 'project').key, 'mcpServers');
  // Unknown host or an unsupported scope for that host.
  assert.equal(at('emacs', 'project'), null);
  assert.equal(at('vscode', 'user'), null);
});

test('resolveTarget: Claude Desktop is platform-specific', () => {
  const mac = h.resolveTarget('claude-desktop', 'user', { cwd: '/p', home: '/Users/u', platform: 'darwin' });
  assert.equal(mac.path, '/Users/u/Library/Application Support/Claude/claude_desktop_config.json');
  const linux = h.resolveTarget('claude-desktop', 'user', { cwd: '/p', home: '/home/u', platform: 'linux' });
  assert.equal(linux.path, '/home/u/.config/Claude/claude_desktop_config.json');
});

test('writeServerEntry: creates a config, then updates it with a backup', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-hosts-'));
  const target = h.resolveTarget('cursor', 'project', { cwd: dir, home: dir, platform: 'linux' });

  const created = h.writeServerEntry(target, 'first', ENTRY);
  assert.equal(created.action, 'created');
  assert.equal(created.backup, null);
  assert.deepEqual(JSON.parse(fs.readFileSync(target.path, 'utf8')), { mcpServers: { first: ENTRY } });

  const updated = h.writeServerEntry(target, 'second', ENTRY);
  assert.equal(updated.action, 'updated');
  assert.ok(fs.existsSync(updated.backup), 'an existing config is backed up before being touched');
  // The server that was already there is still there.
  const doc = JSON.parse(fs.readFileSync(target.path, 'utf8'));
  assert.deepEqual(Object.keys(doc.mcpServers).sort(), ['first', 'second']);

  const replaced = h.writeServerEntry(target, 'first', { command: 'npx', args: ['-y', 'pkg@2.0.0'] });
  assert.equal(replaced.replaced, true);
  assert.equal(JSON.parse(fs.readFileSync(target.path, 'utf8')).mcpServers.first.args[1], 'pkg@2.0.0');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('writeServerEntry: preserves unrelated keys in the host config', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-hosts-keep-'));
  const target = h.resolveTarget('claude-code', 'user', { cwd: dir, home: dir, platform: 'linux' });
  fs.writeFileSync(target.path, JSON.stringify({ theme: 'dark', projects: { a: 1 }, mcpServers: { old: ENTRY } }));
  h.writeServerEntry(target, 'new', ENTRY);
  const doc = JSON.parse(fs.readFileSync(target.path, 'utf8'));
  assert.equal(doc.theme, 'dark');
  assert.deepEqual(doc.projects, { a: 1 });
  assert.deepEqual(Object.keys(doc.mcpServers).sort(), ['new', 'old']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('writeServerEntry: refuses to clobber a config it cannot parse', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-hosts-bad-'));
  const target = h.resolveTarget('cursor', 'project', { cwd: dir, home: dir, platform: 'linux' });
  fs.mkdirSync(path.dirname(target.path), { recursive: true });
  fs.writeFileSync(target.path, '{ half-written');
  assert.throws(() => h.writeServerEntry(target, 'x', ENTRY), /could not be parsed.*refusing/s);
  // The file is left exactly as it was.
  assert.equal(fs.readFileSync(target.path, 'utf8'), '{ half-written');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('writeServerEntry: a TOML host gets a snippet, not an edit', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-hosts-toml-'));
  const target = h.resolveTarget('codex', 'user', { cwd: dir, home: dir, platform: 'linux' });
  const r = h.writeServerEntry(target, 'my-server', ENTRY);
  assert.equal(r.action, 'manual');
  assert.equal(fs.existsSync(target.path), false, 'nothing is written for a TOML host');
  assert.match(r.snippet, /\[mcp_servers\.my-server\]/);
  assert.match(r.snippet, /command = "npx"/);
  assert.match(r.snippet, /args = \["-y", "pkg@1\.2\.3"\]/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('tomlSnippet: quotes names that are not bare keys, escapes values', () => {
  assert.match(h.tomlSnippet('@scope/pkg', ENTRY), /\[mcp_servers\."@scope\/pkg"\]/);
  assert.match(h.tomlSnippet('plain', { command: 'C:\\bin\\npx.cmd', args: ['a"b'] }), /command = "C:\\\\bin\\\\npx\.cmd"/);
  assert.match(h.tomlSnippet('plain', { command: 'x', args: ['a"b'] }), /args = \["a\\"b"\]/);
  assert.doesNotMatch(h.tomlSnippet('plain', { command: 'x', args: [] }), /args/);
});
