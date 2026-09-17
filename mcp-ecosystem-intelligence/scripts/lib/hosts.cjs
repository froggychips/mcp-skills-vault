'use strict';
/**
 * Where each MCP host keeps its server list, and how to write into it.
 *
 * `install` only ever wrote `./.mcp.json` and `~/.claude.json`. The same vault
 * entry is just as useful in Cursor, VS Code, Claude Desktop or Codex — the
 * only difference is a file path and, in two cases, a different shape. Keeping
 * those differences here is what makes the vault a general tool rather than a
 * Claude Code accessory.
 *
 * Two shapes exist in practice:
 *   - JSON with a `mcpServers` map (Claude Code, Claude Desktop, Cursor)
 *   - JSON with a `servers` map (VS Code)
 * and one outlier: Codex keeps TOML. Rewriting someone's TOML config without a
 * TOML parser would be a good way to destroy comments and formatting, so for
 * Codex this prints the snippet to paste instead of editing the file. A tool
 * that mangles a config it half-understands is worse than one that hands you
 * three correct lines.
 *
 * API:
 *   listHosts()                          -> [{ id, label, scopes, format }]
 *   resolveTarget(id, scope, paths)      -> { id, scope, path, format, key } | null
 *   writeServerEntry(target, name, entry, opts) -> { action, path, backup?, snippet? }
 *   tomlSnippet(name, entry)             -> string
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const HOSTS = [
  {
    id: 'claude-code',
    label: 'Claude Code',
    format: 'json',
    key: 'mcpServers',
    scopes: {
      project: ({ cwd })  => path.join(cwd, '.mcp.json'),
      user:    ({ home }) => path.join(home, '.claude.json'),
    },
  },
  {
    id: 'claude-desktop',
    label: 'Claude Desktop',
    format: 'json',
    key: 'mcpServers',
    scopes: {
      user: ({ home, platform }) => platform === 'darwin'
        ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
        : platform === 'win32'
          ? path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
          : path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    },
  },
  {
    id: 'cursor',
    label: 'Cursor',
    format: 'json',
    key: 'mcpServers',
    scopes: {
      project: ({ cwd })  => path.join(cwd, '.cursor', 'mcp.json'),
      user:    ({ home }) => path.join(home, '.cursor', 'mcp.json'),
    },
  },
  {
    id: 'vscode',
    label: 'VS Code',
    format: 'json',
    key: 'servers',                    // VS Code names the map differently
    scopes: {
      project: ({ cwd }) => path.join(cwd, '.vscode', 'mcp.json'),
    },
  },
  {
    id: 'codex',
    label: 'Codex CLI',
    format: 'toml',
    key: 'mcp_servers',
    scopes: {
      user: ({ home }) => path.join(home, '.codex', 'config.toml'),
    },
  },
];

function listHosts() {
  return HOSTS.map((h) => ({ id: h.id, label: h.label, format: h.format, scopes: Object.keys(h.scopes) }));
}

function resolveTarget(id, scope, { cwd = process.cwd(), home = os.homedir(), platform = process.platform } = {}) {
  const host = HOSTS.find((h) => h.id === id);
  if (!host) return null;
  const resolver = host.scopes[scope];
  if (!resolver) return null;
  return {
    id: host.id,
    label: host.label,
    scope,
    format: host.format,
    key: host.key,
    path: resolver({ cwd, home, platform }),
  };
}

/** A `[mcp_servers.<name>]` block, for pasting into a Codex config. */
function tomlSnippet(name, entry) {
  const quote = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  const lines = [`[mcp_servers.${/^[A-Za-z0-9_-]+$/.test(name) ? name : quote(name)}]`];
  lines.push(`command = ${quote(entry.command)}`);
  if (entry.args && entry.args.length) {
    lines.push(`args = [${entry.args.map(quote).join(', ')}]`);
  }
  return lines.join('\n') + '\n';
}

/**
 * Add or replace one server in a host's config.
 *
 * JSON targets are edited in place, with a timestamped backup of any existing
 * file — this is someone's editor configuration, and "we overwrote it and it
 * had your other servers in it" is not a recoverable mistake. TOML targets
 * return a snippet and change nothing.
 *
 * Returns { action: 'created' | 'updated' | 'manual', path, backup?, snippet?, replaced? }
 */
function writeServerEntry(target, name, entry, { mkdirp = true } = {}) {
  if (!target) throw new Error('no target');

  if (target.format === 'toml') {
    return { action: 'manual', path: target.path, snippet: tomlSnippet(name, entry) };
  }

  const dir = path.dirname(target.path);
  if (mkdirp) fs.mkdirSync(dir, { recursive: true });

  let doc = {};
  let existed = false;
  try {
    const raw = fs.readFileSync(target.path, 'utf8');
    existed = true;
    doc = JSON.parse(raw);
    if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
      throw new Error('config root is not an object');
    }
  } catch (e) {
    if (existed) {
      // A config that exists but does not parse must not be silently replaced:
      // it is more likely a file worth keeping than a file worth clobbering.
      throw new Error(`${target.path} exists but could not be parsed (${e.message}); refusing to overwrite it`);
    }
    doc = {};
  }

  let backup = null;
  if (existed) {
    backup = `${target.path}.bak.${Date.now()}`;
    fs.copyFileSync(target.path, backup);
  }

  doc[target.key] = doc[target.key] && typeof doc[target.key] === 'object' ? doc[target.key] : {};
  const replaced = Object.prototype.hasOwnProperty.call(doc[target.key], name);
  doc[target.key][name] = entry;

  fs.writeFileSync(target.path, `${JSON.stringify(doc, null, 2)}\n`);
  return { action: existed ? 'updated' : 'created', path: target.path, backup, replaced };
}

module.exports = { HOSTS, listHosts, resolveTarget, writeServerEntry, tomlSnippet };
