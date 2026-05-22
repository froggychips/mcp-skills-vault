#!/usr/bin/env node
/**
 * Audit installed MCP setup against the vetted DB.
 *
 * Reads the user's project-scoped .mcp.json and the `mcpServers` key of
 * ~/.claude.json (and ONLY that key — auth tokens live elsewhere in the
 * file, so we never read or echo the rest), matches each installed server
 * against the DB, and reports drift, untrusted candidates in active use,
 * unbounded heavy servers, unknown servers, and global-scope misplacement.
 *
 * Closes the "Audit my MCP setup" use case from README/SKILL.md with a
 * deterministic script instead of asking Claude to step through it.
 *
 * Usage:
 *   node scripts/audit_setup.cjs              human-readable, default
 *   node scripts/audit_setup.cjs --json       machine-readable findings
 *   node scripts/audit_setup.cjs --strict     exit 1 on drift/untrusted/heavy
 *   node scripts/audit_setup.cjs --cwd <path> override project root
 *   node scripts/audit_setup.cjs --db <path>  override DB path
 *   node scripts/audit_setup.cjs --global-config <path>  override ~/.claude.json (test hook)
 *   node scripts/audit_setup.cjs --help
 *
 * Exit codes:
 *   0  clean or info-only findings
 *   1  --strict triggered (drift / untrusted / heavy-unbounded present)
 *   2  bad invocation
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const DEFAULT_DB = path.resolve(__dirname, '../assets/tools_database.json');

// Server `category` values whose deploys are typically project-specific —
// secrets like a TeamCity URL or a GitHub token belong with the project,
// not in a global config that follows you into every other repo.
const PROJECT_SCOPED_CATEGORIES = new Set(['vcs', 'ci-cd', 'pm', 'infra']);

// Heavy threshold — same one orchestrate.cjs uses for its UI tier; mirrored
// here rather than imported to keep this script standalone.
const HEAVY_THRESHOLD = 15;

// ── CLI ────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = { json: false, strict: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json')          out.json    = true;
    else if (a === '--strict')   out.strict  = true;
    else if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--cwd')           out.cwd          = argv[++i];
    else if (a === '--db')            out.db           = argv[++i];
    else if (a === '--global-config') out.globalConfig = argv[++i];
    else return { error: `unknown argument: ${a}` };
  }
  return out;
}

const HELP = `audit_setup.cjs — diff installed MCP servers against the vetted DB

Usage:
  node scripts/audit_setup.cjs [--cwd <path>] [--db <path>] [--global-config <path>]
                               [--json] [--strict]

Reads:
  <cwd>/.mcp.json                          project-scoped servers
  <cwd>/.claude/settings.json              enabledMcpjsonServers + permissions.allow
  ~/.claude.json                           ONLY the mcpServers key
  assets/tools_database.json               vetted DB

Finding categories:
  drift              installed version differs from DB-pinned version
  untrusted          DB trust=candidate but actively installed
  heavy-unbounded    est_tools_count > 15 (or unknown) with no scoping
  unknown            installed but not in DB (legitimate custom servers ok)
  scope              global install of a project-scoped category

Flags:
  --json             emit findings array as JSON
  --strict           exit 1 on any drift/untrusted/heavy-unbounded
  --cwd <path>       project root override (default: process.cwd())
  --db <path>        DB path override
  --global-config    ~/.claude.json path override (testability)
  --help             print this and exit
`;

// ── safe JSON reads (missing files = empty object, never throw) ────────────

function readJsonSafe(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return null; }
}

// We deliberately ONLY pull mcpServers from ~/.claude.json. Other keys in
// that file contain bearer tokens that have been known to leak into agent
// transcripts; restricting our read keeps that surface dead.
function readGlobalMcpServers(file) {
  const data = readJsonSafe(file);
  if (!data || typeof data !== 'object') return {};
  return data.mcpServers && typeof data.mcpServers === 'object' ? data.mcpServers : {};
}

function readProjectMcpServers(cwd) {
  const data = readJsonSafe(path.join(cwd, '.mcp.json'));
  if (!data || typeof data !== 'object') return {};
  return data.mcpServers && typeof data.mcpServers === 'object' ? data.mcpServers : {};
}

function readSettings(cwd) {
  // .claude/settings.json holds the project's enabledMcpjsonServers list
  // (whitelist of mcp.json keys Claude actually loads) and permissions.allow
  // (allowedTools-style filter that scopes which tools each server exposes).
  // Either is enough to consider a heavy server "bounded".
  const data = readJsonSafe(path.join(cwd, '.claude', 'settings.json'));
  if (!data || typeof data !== 'object') return { enabled: null, allowedTools: [] };
  const enabled = Array.isArray(data.enabledMcpjsonServers) ? data.enabledMcpjsonServers : null;
  const allow   = data.permissions && Array.isArray(data.permissions.allow)
    ? data.permissions.allow
    : (Array.isArray(data.allowedTools) ? data.allowedTools : []);
  return { enabled, allowedTools: allow };
}

// ── version parsing ────────────────────────────────────────────────────────

// Walk args[] for the first token shaped like a package@version,
// image@sha256:…, or pkg==version. Returns the version string, or null
// when we genuinely cannot tell (different from null in the DB — caller
// distinguishes via the `parsed` flag).
function parseInstalledVersion(entry) {
  const tokens = [entry?.command, ...(Array.isArray(entry?.args) ? entry.args : [])].filter(Boolean);
  for (const t of tokens) {
    if (typeof t !== 'string') continue;
    // docker image: ghcr.io/foo/bar@sha256:abc
    let m = t.match(/@sha256:([a-f0-9]{12,})/);
    if (m) return `sha256:${m[1]}`;
    // npm: @scope/pkg@1.2.3 OR pkg@1.2.3
    m = t.match(/^((?:@[\w.-]+\/)?[\w.-]+)@([^\s@]+)$/);
    if (m && !m[2].startsWith('sha')) return m[2];
    // PyPI: pkg==1.2.3
    m = t.match(/^[\w.-]+==([^\s=]+)$/);
    if (m) return m[1];
  }
  return null;
}

// Same parser, but applied to the DB's install_cmd string (split on spaces).
function parseDbVersion(installCmd) {
  if (!installCmd || typeof installCmd !== 'string') return null;
  for (const t of installCmd.split(/\s+/)) {
    let m = t.match(/@sha256:([a-f0-9]{12,})/);
    if (m) return `sha256:${m[1]}`;
    m = t.match(/^((?:@[\w.-]+\/)?[\w.-]+)@([^\s@]+)$/);
    if (m && !m[2].startsWith('sha')) return m[2];
    m = t.match(/^[\w.-]+==([^\s=]+)$/);
    if (m) return m[1];
  }
  return null;
}

// ── matching ───────────────────────────────────────────────────────────────

// The user's server name (key in mcp.json) is often nicknamed — "github"
// instead of "github-mcp-server", "atlassian" instead of "mcp-atlassian".
// So we match on three signals: exact name, exact install_cmd token, or
// fuzzy substring on the package identifier shared by both sides.
function matchDbEntry(db, serverName, entry) {
  const byName = db.tools.find(t => t.name === serverName);
  if (byName) return byName;

  const installedTokens = [entry?.command, ...(Array.isArray(entry?.args) ? entry.args : [])]
    .filter(t => typeof t === 'string')
    .map(t => t.toLowerCase());

  for (const tool of db.tools) {
    const dbCmd = (tool.install_cmd || '').toLowerCase();
    // Extract the package identifier from the DB install_cmd (between the
    // installer and the @version), e.g. "@modelcontextprotocol/server-filesystem"
    // from "npx -y @modelcontextprotocol/server-filesystem@2026.1.14 …"
    const m = dbCmd.match(/(?:^|\s)(?:npx\s+-y\s+|uvx\s+(?:--from\s+\S+\s+)?)((?:@[\w.-]+\/)?[\w.-]+)(?:[@=]|\s|$)/)
          || dbCmd.match(/(ghcr\.io\/[\w./-]+|docker\.io\/[\w./-]+)@sha256:/);
    const pkg = m ? m[1] : null;
    if (!pkg) continue;
    if (installedTokens.some(tok => tok === pkg || tok.includes(`${pkg}@`) || tok.includes(`${pkg}==`))) {
      return tool;
    }
  }
  return null;
}

// ── tool-allow scoping check ───────────────────────────────────────────────

// allowedTools entries look like "mcp__<server>__<tool>" or "mcp__<server>"
// (whole-server allow). Either form binds the server. Per-tool entries also
// count as "bounded" because the user has thought about which tools to expose.
function hasAllowedToolsScope(serverName, allowedTools) {
  const needle = `mcp__${serverName}__`;
  return allowedTools.some(a => typeof a === 'string' &&
    (a === `mcp__${serverName}` || a.startsWith(needle)));
}

// args[] entries that imply the server itself has been scoped to a subset
// of its tools. Mirrors the DB's `toolsets` hint vocabulary.
function hasArgScope(entry) {
  const args = Array.isArray(entry?.args) ? entry.args : [];
  return args.some(a => typeof a === 'string' &&
    (a === '--toolsets' || a === '--caps' || a.startsWith('--toolsets=') || a.startsWith('--caps=')
     || a === '--disabledTools' || a.startsWith('--disabledTools=')));
}

// ── findings ───────────────────────────────────────────────────────────────

function audit({ project, global, settings, db }) {
  const findings = [];
  const seen     = new Set();

  // Walk project servers first so a server present in both surfaces as project
  // (more specific). Global-only servers get the scope-misplacement check.
  const sources = [
    { servers: project, scope: 'project' },
    { servers: global,  scope: 'global'  },
  ];

  for (const { servers, scope } of sources) {
    for (const [name, entry] of Object.entries(servers)) {
      if (seen.has(name)) continue;
      seen.add(name);

      const tool         = matchDbEntry(db, name, entry);
      const installedVer = parseInstalledVersion(entry);

      if (!tool) {
        findings.push({
          category: 'unknown',
          server:   name,
          scope,
          message:  `not in DB (custom or unvetted server; informational)`,
        });
        continue;
      }

      // drift: DB pins a version, user is on a different one
      const dbVersion = parseDbVersion(tool.install_cmd);
      if (dbVersion && installedVer && dbVersion !== installedVer) {
        findings.push({
          category:    'drift',
          server:      name,
          db_name:     tool.name,
          scope,
          installed:   installedVer,
          db_version:  dbVersion,
          message:     `installed ${installedVer} ≠ DB ${dbVersion}`,
        });
      } else if (dbVersion && !installedVer) {
        findings.push({
          category:    'version-unknown',
          server:      name,
          db_name:     tool.name,
          scope,
          db_version:  dbVersion,
          message:     `cannot determine installed version (no @ver or ==ver in args)`,
        });
      }

      // untrusted: DB carries this as a candidate, but it's in active use
      if (tool.trust === 'candidate') {
        findings.push({
          category: 'untrusted',
          server:   name,
          db_name:  tool.name,
          scope,
          message:  `DB trust=candidate; review notes and consider triage before relying on it`,
          notes:    tool.notes || null,
        });
      }

      // heavy-unbounded: large surface, no scoping anywhere
      const tools = (typeof tool.est_tools_count === 'number') ? tool.est_tools_count : null;
      const isHeavy = tools === null || tools > HEAVY_THRESHOLD;
      if (isHeavy) {
        const enabledOk = settings.enabled === null || settings.enabled.includes(name);
        const argScoped = hasArgScope(entry);
        const allowScoped = hasAllowedToolsScope(name, settings.allowedTools);
        const bounded = argScoped || allowScoped || !enabledOk;
        if (!bounded) {
          findings.push({
            category:        'heavy-unbounded',
            server:          name,
            db_name:         tool.name,
            scope,
            est_tools_count: tools,
            toolsets_hint:   tool.toolsets || null,
            message:         tools === null
              ? `tool count unknown and no scoping (--toolsets/--caps/allowedTools/enabledMcpjsonServers)`
              : `${tools} tools, no scoping (--toolsets/--caps/allowedTools/enabledMcpjsonServers)`,
          });
        }
      }

      // scope: project-flavoured category installed globally
      if (scope === 'global' && tool.category && PROJECT_SCOPED_CATEGORIES.has(tool.category)) {
        findings.push({
          category:    'scope',
          server:      name,
          db_name:     tool.name,
          db_category: tool.category,
          scope,
          message:     `${tool.category} servers usually belong in project .mcp.json, not global ~/.claude.json`,
        });
      }
    }
  }

  return findings;
}

// ── reporting ──────────────────────────────────────────────────────────────

const T  = process.stdout.isTTY;
const B  = T ? '\x1b[1m'  : '';
const DM = T ? '\x1b[2m'  : '';
const YL = T ? '\x1b[33m' : '';
const RD = T ? '\x1b[31m' : '';
const GN = T ? '\x1b[32m' : '';
const RS = T ? '\x1b[0m'  : '';

const CATEGORY_ORDER = [
  'drift', 'untrusted', 'heavy-unbounded', 'scope', 'unknown', 'version-unknown',
];
const CATEGORY_COLOR = {
  'drift':           RD,
  'untrusted':       YL,
  'heavy-unbounded': YL,
  'scope':           YL,
  'unknown':         DM,
  'version-unknown': DM,
};
const STRICT_CATEGORIES = new Set(['drift', 'untrusted', 'heavy-unbounded']);

function printReport(findings, counts) {
  const total = findings.length;
  process.stdout.write(`\nAudit: ${counts.project} project + ${counts.global} global servers scanned\n`);
  if (total === 0) {
    process.stdout.write(`${GN}No findings — installed setup matches the DB.${RS}\n\n`);
    return;
  }

  // Group by category for terse output, in fixed order
  const byCat = {};
  for (const f of findings) (byCat[f.category] ||= []).push(f);

  for (const cat of CATEGORY_ORDER) {
    const list = byCat[cat];
    if (!list || !list.length) continue;
    const color = CATEGORY_COLOR[cat] || '';
    process.stdout.write(`\n${B}${color}── ${cat} (${list.length})${RS}\n`);
    for (const f of list) {
      process.stdout.write(`  ${B}${f.server}${RS} ${DM}(${f.scope})${RS}  ${f.message}\n`);
      if (cat === 'heavy-unbounded' && f.toolsets_hint) {
        process.stdout.write(`    ${DM}→ ${f.toolsets_hint}${RS}\n`);
      }
      if (cat === 'untrusted' && f.notes) {
        process.stdout.write(`    ${DM}${truncate(f.notes, 110)}${RS}\n`);
      }
    }
  }

  const counts2 = CATEGORY_ORDER
    .map(c => byCat[c] ? `${c}=${byCat[c].length}` : null)
    .filter(Boolean)
    .join(' ');
  process.stdout.write(`\n${DM}Summary: ${counts2}${RS}\n\n`);
}

function truncate(s, n) {
  s = String(s).replace(/\s+/g, ' ');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

// ── main ───────────────────────────────────────────────────────────────────

function main(argv) {
  const args = parseArgs(argv);
  if (args.error) {
    process.stderr.write(args.error + '\n');
    process.stderr.write('Try --help.\n');
    return 2;
  }
  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }

  const cwd          = args.cwd || process.cwd();
  const dbPath       = args.db  || DEFAULT_DB;
  const globalCfg    = args.globalConfig || path.join(process.env.HOME || '', '.claude.json');

  const db = readJsonSafe(dbPath);
  if (!db || !Array.isArray(db.tools)) {
    process.stderr.write(`DB not found or malformed: ${dbPath}\n`);
    return 2;
  }

  const project  = readProjectMcpServers(cwd);
  const global_  = readGlobalMcpServers(globalCfg);
  const settings = readSettings(cwd);

  const counts = { project: Object.keys(project).length, global: Object.keys(global_).length };
  const findings = audit({ project, global: global_, settings, db });

  if (args.json) {
    process.stdout.write(JSON.stringify({
      cwd,
      db_path:     dbPath,
      global_path: globalCfg,
      counts,
      findings,
    }, null, 2) + '\n');
  } else {
    printReport(findings, counts);
  }

  if (args.strict && findings.some(f => STRICT_CATEGORIES.has(f.category))) return 1;
  return 0;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = {
  parseArgs,
  parseInstalledVersion,
  parseDbVersion,
  matchDbEntry,
  hasAllowedToolsScope,
  hasArgScope,
  audit,
  main,
  PROJECT_SCOPED_CATEGORIES,
  HEAVY_THRESHOLD,
};
