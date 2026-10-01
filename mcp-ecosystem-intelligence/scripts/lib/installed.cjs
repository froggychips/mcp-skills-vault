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
 *   unpinnedLaunch(server, { dbTools, only }) -> { message, advice, … } | null
 *   launchSourceOverride(server)              -> reason the package is not the public registry's | null
 *   explicitConfigPaths(list, { cwd })        -> [{ host, scope, path, explicit }]
 *   serverLine(text, name)                    -> 1-based line naming the server | null
 *   readInstalledServers({ cwd, home, … })    -> [{ … , install_cmd }]
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { parseLaunch, canonicalInstallCmd, launcherOf, isExactVersion } = require('./install_cmd.cjs');

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
 * Config files named on the command line (`verify --config <path>`), as
 * location records. CI checks the configs committed to a repository; the
 * runner's home directory is not the project, and reading it made the verdict
 * depend on whichever machine picked the job up.
 *
 * The host is inferred from the file name only to label the report — the
 * parser reads both `mcpServers` and `servers` either way. `explicit` marks a
 * path somebody asked for, so a missing one is reported instead of skipped: a
 * typo in a workflow file must not turn into "no servers configured".
 */
function explicitConfigPaths(list, { cwd = process.cwd() } = {}) {
  return (list || []).map((p) => {
    const abs  = path.resolve(cwd, p);
    const norm = abs.split(path.sep).join('/');
    const host = /\/\.vscode\/mcp\.json$/.test(norm) ? 'vscode'
      : /\/\.cursor\/mcp\.json$/.test(norm) ? 'cursor'
      : /\/claude_desktop_config\.json$/.test(norm) ? 'claude-desktop'
      : /\.toml$/.test(norm) ? 'codex'
      : /\/\.mcp\.json$/.test(norm) || /\/\.claude\.json$/.test(norm) ? 'claude-code'
      : 'custom';
    return { host, scope: 'project', path: abs, explicit: true };
  });
}

/**
 * Pull the server list out of one config document.
 *
 * VS Code nests its list under `servers` rather than `mcpServers`, and an
 * `.mcp.json` in the wild sometimes has neither — a config we cannot read is
 * reported as such by the caller, never silently treated as "no servers".
 */
/**
 * @param onInvalid  called with a reason when the document parses as JSON/TOML
 *                   but is not a config this can read. Without it, a file
 *                   saying `{"mcpServers": "broken"}` was indistinguishable
 *                   from a file with no servers in it — syntactically valid
 *                   and semantically unread, reported as "nothing configured".
 */
function parseConfig(doc, origin = {}, onInvalid = null) {
  const bad = (reason) => { if (onInvalid) onInvalid({ ...origin, error: reason }); return []; };
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return bad('not an object');
  const raw = doc.mcpServers !== undefined ? doc.mcpServers : doc.servers;
  // Absent is the normal case for a settings file that simply has no servers.
  if (raw === undefined) return [];
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return bad(`"mcpServers" is ${Array.isArray(raw) ? 'an array' : typeof raw}, not an object`);
  }
  const table = raw;
  const out = [];
  const skipped = [];
  for (const [name, spec] of Object.entries(table)) {
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) { skipped.push(name); continue; }
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
  // Entries that are present and unreadable are not entries that are absent.
  if (skipped.length && onInvalid) {
    onInvalid({
      ...origin,
      error: skipped.length === 1
        ? `server entry "${skipped[0]}" is not an object`
        : `${skipped.length} server entries are not objects: ${skipped.slice(0, 5).join(', ')}`,
      partial: true,
    });
  }
  return out;
}

/**
 * Rebuild the `install_cmd` string for a configured server, in the canonical
 * shape the gate reads (lib/install_cmd.cjs canonicalInstallCmd).
 *
 * Every npm-registry runner is a registry launch, not a local command: `npx`
 * in any option order, `npm exec`, `pnpx` / `pnpm dlx`, `bunx`, `yarn dlx`;
 * for PyPI `uvx`, `uv tool run`, `pipx run`. They become `npx -y …` / `uvx …`
 * so the same checks apply; `launch` (on readInstalledServers' records) keeps
 * what was actually written.
 *
 * A registry launcher whose package cannot be read (an unknown option, a
 * `--registry`, a git source) still comes back under the runner the gate
 * routes on, so the gate says *why* it cannot check it instead of calling it
 * a local command.
 *
 * Returns null for anything with no package to look up: a remote URL, a local
 * script (`node ./server.js`), a binary on PATH.
 */
// Environment variables that move the package source the way the source
// options do (npm reads any `npm_config_*`; uv and pip their own). Names only:
// a config's values never leave parseConfig.
const NPM_SOURCE_ENV = /^(npm_config_(registry|userconfig|globalconfig|cache|prefix|@[^:]+:registry)|yarn_npm_registry_server|bun_config_registry)$/i;
const PYPI_SOURCE_ENV = /^(uv_(index|index_url|default_index|extra_index_url|find_links|config_file|project)|pip_(index_url|extra_index_url|find_links)|pipx_default_index)$/i;

/**
 * Why this server's package does not come from the public registry, or null:
 * a source option on the command line (`--registry`, `--userconfig`, a uv
 * index or project, `pipx --path`, …) or an environment variable in the
 * config that does the same (`npm_config_registry`, `UV_INDEX_URL`, …).
 */
function launchSourceOverride(server) {
  if (!server || server.remote || !server.command) return null;
  const launch = server.launch || parseLaunch({ command: server.command, args: server.args || [] });
  if (!launch) return null;
  const reasons = [];
  if (launch.override) reasons.push(launch.override);
  const re = launch.family === 'npm' ? NPM_SOURCE_ENV : PYPI_SOURCE_ENV;
  for (const k of server.env_keys || []) if (re.test(k)) reasons.push(`sets ${k} in its environment, which moves the package source`);
  return reasons.length ? reasons.join('; ') : null;
}

function toInstallCmd(server) {
  if (!server || server.remote || !server.command) return null;
  const args = (server.args || []).map(String);
  const launch = parseLaunch({ command: server.command, args });
  if (launch) {
    // An environment override is carried into the command as the source
    // option it stands for, so every consumer of install_cmd refuses to read
    // it as a public-registry launch (fail closed), not only verify.
    const envKey = (server.env_keys || []).find((k) => (launch.family === 'npm' ? NPM_SOURCE_ENV : PYPI_SOURCE_ENV).test(k));
    if (envKey) {
      const flag = launch.family === 'npm' ? `--registry=env:${envKey}` : `--index-url=env:${envKey}`;
      return `${launch.family === 'npm' ? 'npx -y' : 'uvx'} ${flag} ${launcherOf(server.command, args).rest.join(' ')}`.trim();
    }
    const canonical = canonicalInstallCmd(launch);
    if (canonical) return canonical;
    const rest = launcherOf(server.command, args).rest;
    const head = launch.family === 'npm' ? (rest.some((a) => /^(-y|--yes(=.*)?)$/.test(a)) ? 'npx' : 'npx -y') : 'uvx';
    return `${head} ${rest.join(' ')}`.trim();
  }
  const cmd = path.basename(server.command).replace(/\.(cmd|exe|bat)$/i, '');
  if (cmd !== 'docker') return null;
  return `${cmd} ${args.join(' ')}`.trim();
}

/**
 * Does this configured server launch a registry package without an exact
 * version? That is a fact about the *config*: whatever the registry resolves
 * at each start runs — not the vault's DB missing something, and not the
 * gate failing to check. Returns null when the launch is pinned, is not a
 * registry launch, or could not be read (the gate reports that itself).
 *
 * `dbTools` is the vault DB: when it has an entry for the same package with an
 * exact version, the advice is the config's own line with that version in it.
 *
 * -> { package, ecosystem, requested, message, advice, pinned_args } | null
 */
function unpinnedLaunch(server, { dbTools = [], only = null } = {}) {
  const launch = server && (server.launch || (server.command ? parseLaunch({ command: server.command, args: server.args || [] }) : null));
  if (!launch || launch.error || !launch.package) return null;
  if (launch.ecosystem !== 'npm' && launch.ecosystem !== 'pypi') return null;
  const npm = launch.ecosystem === 'npm';
  // `only`: one of several `-p` packages (each one is installed and runs).
  const pick = only && npm ? (launch.packages || []).find((x) => x.name === only) : null;
  if (only && !pick) return null;
  const l = pick
    ? { ...launch, package: pick.name, version: pick.version, spec: pick.spec, exact: Boolean(pick.version && isExactVersion('npx', pick.version)) }
    : launch;
  if (l.exact) return null;
  const requested = l.version || null;
  const what = !requested
    ? `${l.package} without a version: whatever is latest at each start runs`
    : requested === 'latest'
      ? `${l.package}@latest, a tag rather than a version: whatever is latest at each start runs`
      : `${l.package}${npm ? '@' : ' '}${requested}, a range rather than a version: whatever matches it at each start runs`;
  const message = `this config launches ${what}`;

  // The vault's entry for the same package (not the same config key: a key is
  // a nickname), and its verified version if that is an exact one.
  const same = (a, b) => (npm ? a === b : a.toLowerCase().replace(/[-_.]+/g, '-') === b.toLowerCase().replace(/[-_.]+/g, '-'));
  const entry = (dbTools || []).find((t) => {
    if (!t || typeof t.install_cmd !== 'string') return false;
    const d = parseLaunch(t.install_cmd);
    return d && !d.error && d.ecosystem === l.ecosystem && same(d.package, l.package);
  }) || null;
  const version = entry && isExactVersion(npm ? 'npx' : 'uvx', entry.version || '') ? entry.version : null;

  let pinnedArgs = null;
  if (version && Array.isArray(server.args)) {
    const pinned = npm ? `${l.package}@${version}` : `${l.package}==${version}`;
    const args = server.args.map(String);
    const i = args.findIndex((a) => a === l.spec || a.endsWith(`=${l.spec}`));
    if (i !== -1) {
      pinnedArgs = [...args];
      pinnedArgs[i] = args[i] === l.spec ? pinned : `${args[i].slice(0, args[i].length - l.spec.length)}${pinned}`;
    }
  }
  const advice = pinnedArgs
    ? `pin it to the version the vault verified (${entry.name}): "args": ${JSON.stringify(pinnedArgs)}`
    : version
      ? `pin it to the version the vault verified (${entry.name}): ${npm ? `${l.package}@${version}` : `${l.package}==${version}`}`
      : `pin to an exact version (${npm ? `${l.package}@<x.y.z>` : `${l.package}==<version>`})`;
  return { package: l.package, ecosystem: l.ecosystem, requested, message, advice, pinned_args: pinnedArgs, db_entry: entry ? entry.name : null, db_version: version };
}

/**
 * The 1-based line that names a server in its config text — where a finding
 * about it belongs (a host-config subject is `path:line`), because that is the
 * line a pull request changed. The first key spelled like the name, in JSON
 * (`"name":`) or Codex TOML (`[mcp_servers.name]`); null when not found.
 */
function serverLine(text, name) {
  if (typeof text !== 'string' || !name) return null;
  const quoted = JSON.stringify(name);
  const idx = text.split('\n').findIndex((l) => l.includes(`${quoted}:`) || l.includes(`${quoted} :`)
    || l.includes(`[mcp_servers.${name}]`) || l.includes(`[mcp_servers.${quoted}]`));
  return idx === -1 ? null : idx + 1;
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
      // A path named explicitly is expected to exist, so its absence is a
      // finding too.
      if (e.code === 'ENOENT' && loc.explicit) {
        if (onUnreadable) onUnreadable({ ...loc, error: 'file not found' });
      } else if (e.code !== 'ENOENT' && onUnreadable) {
        onUnreadable({ ...loc, error: `${e.code || 'read failed'}: ${e.message}` });
      }
      continue;
    }
    let doc;
    try {
      doc = loc.path.endsWith('.toml') ? parseCodexToml(raw) : JSON.parse(raw);
    } catch (e) {
      if (onUnreadable) onUnreadable({ ...loc, error: e.message });
      continue;
    }
    for (const server of parseConfig(doc, loc, onUnreadable)) {
      servers.push({
        ...server,
        line: serverLine(raw, server.name),
        install_cmd: toInstallCmd(server),
        // What the config asked for, as written: runner, package, requested
        // version (or none) and whether that is an exact pin.
        launch: server.remote ? null : parseLaunch({ command: server.command, args: server.args }),
        source_override: launchSourceOverride(server),
      });
    }
  }
  return servers;
}

module.exports = { hostConfigPaths, explicitConfigPaths, serverLine, parseConfig, toInstallCmd, unpinnedLaunch, launchSourceOverride, readInstalledServers, parseCodexToml };
