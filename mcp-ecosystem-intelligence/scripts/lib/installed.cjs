'use strict';
/**
 * Read the MCP servers a host is actually configured to launch.
 *
 * The gate and the audit both worked off the DB: the DB's pins were checked,
 * and `audit` compared *names* in the local config against DB names. Nobody
 * checked the thing that actually runs. That is where the risk lives — a config
 * written before pinning existed, an entry hand-edited to `@latest`, a server
 * installed from somewhere else entirely.
 *
 * `readInstalledServers()` turns each configured server back into the
 * `install_cmd` shape the rest of the tooling understands, so the same
 * integrity gate can run over it.
 *
 * Config shapes handled (all are `{ mcpServers: { name: { command, args } } }`):
 *   - ./.mcp.json            project scope, Claude Code
 *   - ~/.claude.json         user scope, Claude Code
 *   - Claude Desktop, Cursor, VS Code, Codex — see HOST_CONFIGS
 *
 * API:
 *   hostConfigPaths({ cwd, home, platform })  -> [{ host, scope, path }]
 *   parseConfig(json, origin)                 -> [{ name, command, args, … }]
 *   toInstallCmd(server)                      -> "npx -y pkg@1.2.3" | null
 *   readInstalledServers({ cwd, home, … })    -> [{ … , install_cmd }]
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

/**
 * Codex keeps TOML. Rather than take on a TOML parser, this reads the one shape
 * that matters here — `[mcp_servers.<name>]` blocks with `command` and `args` —
 * and ignores everything else. Narrow on purpose: a half-understood parse of
 * someone's whole config would invite acting on a misreading.
 */
function parseCodexToml(text) {
  const out = {};
  let current = null;
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const section = trimmed.match(/^\[mcp_servers\.(.+)\]$/);
    if (section) {
      const name = section[1].trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
      current = name;
      out[current] = { command: null, args: [] };
      continue;
    }
    if (/^\[/.test(trimmed)) { current = null; continue; }   // some other table
    if (!current) continue;
    const kv = trimmed.match(/^(\w+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const [, key, rawValue] = kv;
    if (key === 'command') {
      out[current].command = rawValue.trim().replace(/^["'](.*)["']$/, '$1');
    } else if (key === 'args') {
      const inner = rawValue.trim().replace(/^\[/, '').replace(/\]$/, '');
      out[current].args = inner
        ? inner.split(',').map((v) => v.trim().replace(/^["'](.*)["']$/, '$1')).filter(Boolean)
        : [];
    }
  }
  return { mcpServers: out };
}

/**
 * Where each host keeps its MCP server list. `scope` distinguishes a config
 * that travels with the project from one that applies to every project — a
 * global entry is the more interesting one to get wrong.
 */
function hostConfigPaths({ cwd = process.cwd(), home = os.homedir(), platform = process.platform } = {}) {
  const mac = platform === 'darwin';
  const win = platform === 'win32';
  const appSupport = mac
    ? path.join(home, 'Library', 'Application Support')
    : (win ? (process.env.APPDATA || path.join(home, 'AppData', 'Roaming')) : path.join(home, '.config'));

  return [
    { host: 'claude-code',    scope: 'project', path: path.join(cwd, '.mcp.json') },
    { host: 'claude-code',    scope: 'user',    path: path.join(home, '.claude.json') },
    { host: 'claude-desktop', scope: 'user',    path: path.join(appSupport, 'Claude', 'claude_desktop_config.json') },
    { host: 'cursor',         scope: 'project', path: path.join(cwd, '.cursor', 'mcp.json') },
    { host: 'cursor',         scope: 'user',    path: path.join(home, '.cursor', 'mcp.json') },
    { host: 'vscode',         scope: 'project', path: path.join(cwd, '.vscode', 'mcp.json') },
    { host: 'codex',          scope: 'user',    path: path.join(home, '.codex', 'config.toml') },
  ];
}

/**
 * Pull the server list out of one config document.
 *
 * VS Code nests its list under `servers` rather than `mcpServers`, and an
 * `.mcp.json` in the wild sometimes has neither — a config we cannot read is
 * reported as such by the caller, never silently treated as "no servers".
 */
function parseConfig(doc, origin = {}) {
  const table = (doc && (doc.mcpServers || doc.servers)) || null;
  if (!table || typeof table !== 'object') return [];
  const out = [];
  for (const [name, spec] of Object.entries(table)) {
    if (!spec || typeof spec !== 'object') continue;
    // A remote server (url/type: sse|http) has no local artifact to verify.
    const remote = typeof spec.url === 'string' ? spec.url : null;
    out.push({
      name,
      host:    origin.host || null,
      scope:   origin.scope || null,
      source:  origin.path || null,
      command: typeof spec.command === 'string' ? spec.command : null,
      args:    Array.isArray(spec.args) ? spec.args.map(String) : [],
      remote,
      // Env var *names* only: values are secrets and never leave this object.
      env_keys: spec.env && typeof spec.env === 'object' ? Object.keys(spec.env) : [],
    });
  }
  return out;
}

/**
 * Rebuild the `install_cmd` string for a configured server.
 *
 * Returns null for anything with no package to look up: a remote URL, a local
 * script (`node ./server.js`), a binary on PATH.
 */
function toInstallCmd(server) {
  if (!server || server.remote || !server.command) return null;
  const cmd = path.basename(server.command).replace(/\.(cmd|exe|bat)$/i, '');
  if (cmd !== 'npx' && cmd !== 'uvx' && cmd !== 'docker') return null;
  const args = (server.args || []).join(' ');
  // `npx pkg` without -y is equivalent for our purposes, but the shared parser
  // expects the flag, so normalise it in.
  if (cmd === 'npx' && !/(^|\s)-y(\s|$)/.test(args) && !/(^|\s)--yes(\s|$)/.test(args)) {
    return `npx -y ${args}`.trim();
  }
  return `${cmd} ${args}`.trim();
}

/**
 * Every configured server across every host config found.
 *
 * `onUnreadable` is called for a config that exists but cannot be parsed —
 * that is a finding, not an absence.
 */
function readInstalledServers({ cwd = process.cwd(), home = os.homedir(), platform = process.platform, paths = null, onUnreadable = null } = {}) {
  const locations = paths || hostConfigPaths({ cwd, home, platform });
  const servers = [];

  for (const loc of locations) {
    let raw;
    try { raw = fs.readFileSync(loc.path, 'utf8'); }
    catch (e) {
      // ENOENT is the normal case: that host is not configured here. Anything
      // else — EACCES, EISDIR, a dangling symlink — is a file we were meant to
      // read and could not, and swallowing it made "no servers configured"
      // indistinguishable from "we were not allowed to look".
      if (e.code !== 'ENOENT' && onUnreadable) onUnreadable({ ...loc, error: `${e.code || 'read failed'}: ${e.message}` });
      continue;
    }
    let doc;
    try {
      doc = loc.path.endsWith('.toml') ? parseCodexToml(raw) : JSON.parse(raw);
    } catch (e) {
      if (onUnreadable) onUnreadable({ ...loc, error: e.message });
      continue;
    }
    for (const server of parseConfig(doc, loc)) {
      servers.push({ ...server, install_cmd: toInstallCmd(server) });
    }
  }
  return servers;
}

module.exports = { hostConfigPaths, parseConfig, toInstallCmd, readInstalledServers, parseCodexToml };
