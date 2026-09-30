#!/usr/bin/env node
/**
 * Audit installed MCP setup against the vetted DB.
 *
 * Reads the user's project-scoped .mcp.json and the `mcpServers` key of
 * ~/.claude.json (and ONLY that key — auth tokens live elsewhere in the
 * file, so we never read or echo the rest), matches each installed server
 * against the DB, and reports drift, untrusted candidates in active use,
 * unbounded heavy servers, unknown servers, and global-scope misplacement.
 * The secret scan also walks the per-project `mcpServers` maps under
 * `projects` — still server maps only, and it never prints a value.
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
const { exitAfterFlush } = require('./lib/exit.cjs');
const { asOfFromArgv } = require('./lib/clock.cjs');
const { scanHostConfigs } = require('./lib/secrets.cjs');
const flows = require('./lib/flows.cjs');
const lookalike = require('./lib/lookalike.cjs');
const { loadEffectivePolicy, flagsFromArgv } = require('./lib/policy_rules.cjs');
const { decide, exitCode, findingsDocument, toJson } = require('./lib/finding.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { toInstallCmd } = require('./lib/installed.cjs');

const DEFAULT_DB = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH  = path.resolve(__dirname, '../assets/eval_results.json');
const CAPS_PATH  = path.resolve(__dirname, '../assets/capabilities.json');

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
    else if (a === '--as-of')         i++;
    else if (a.startsWith('--as-of=')) { /* read below */ }
    else if (a === '--allow-lookalike') (out.allowLookalike ||= []).push(...String(argv[++i] || '').split(',').filter(Boolean));
    else return { error: `unknown argument: ${a}` };
  }
  // Nothing the audit decides ages today, but the instant is still an input
  // and is printed: findings that do depend on it plug in here (docs/adr/0001).
  const clock = asOfFromArgv(argv);
  if (clock.error) return { error: clock.error };
  out.asOf = clock.asOf;
  out.asOfIso = clock.iso;
  return out;
}

const HELP = `audit_setup.cjs — diff installed MCP servers against the vetted DB

Usage:
  node scripts/audit_setup.cjs [--cwd <path>] [--db <path>] [--global-config <path>]
                               [--json] [--strict] [--as-of <date>]
                               [--allow-lookalike <name>]

Reads:
  <cwd>/.mcp.json                          project-scoped servers
  <cwd>/.claude/settings.json              enabledMcpjsonServers + permissions.allow
  ~/.claude.json                           ONLY the mcpServers maps (top level
                                           and per project, for the secret scan)
  assets/tools_database.json               vetted DB

Finding categories:
  lookalike          not in DB, but its package or name is shaped like a DB
                     entry's (typo, homoglyph, scope swap, affix) — likely an
                     impersonation; also a DB name launching another package
  drift              installed version differs from DB-pinned version
  untrusted          DB trust=candidate but actively installed
  heavy-unbounded    est_tools_count > 15 (or unknown) with no scoping
  unknown            installed but not in DB (legitimate custom servers ok)
  scope              global install of a project-scoped category
  secret             credential written in plain text into env/args/headers/url
                     (the value is never printed; see mcp-vault secrets)
  toxic-flow         the servers together (or one alone) read untrusted content,
                     reach private data and can send outward — or let untrusted
                     content reach a destructive tool
  tool-shadowing     two servers expose the same (or nearly the same) tool name,
                     or a description names another server's tool

  toxic-flow and tool-shadowing are decided by the policy rows flows/* and
  shadowing/* ("toxicFlows" / "toolShadowing" in .mcp-vault.policy.json:
  fail | warn | allow, default warn): fail exits 1 without --strict, warn
  fails under --strict, allow and low-confidence findings never fail.

Flags:
  --json             emit findings array as JSON
  --strict           exit 1 on any lookalike/drift/untrusted/heavy-unbounded/secret
  --allow-lookalike  a server (key or package) you know is yours; still
                     reported, no longer fails --strict. Repeatable, or a,b
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

/**
 * The same read, but able to say *why* it came back with nothing.
 *
 * `readJsonSafe` collapses "the file is not there" and "the file is there and
 * malformed" into one `null`, so `audit --strict` exited 0 on a config it could
 * not parse — reporting a clean setup for servers it had never seen. A missing
 * file is the normal case; anything else is a question left unanswered.
 */
function readJsonExplained(file) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); }
  catch (e) {
    if (e.code === 'ENOENT') return { missing: true, value: null };
    return { error: `${e.code || 'read failed'}: ${e.message}`, value: null };
  }
  try { return { value: JSON.parse(raw) }; }
  catch (e) { return { error: `parse failed: ${e.message}`, value: null }; }
}

// We deliberately ONLY pull mcpServers from ~/.claude.json. Other keys in
// that file contain bearer tokens that have been known to leak into agent
// transcripts; restricting our read keeps that surface dead.
function serversFrom(file, unreadable) {
  const r = readJsonExplained(file);
  if (r.error) { if (unreadable) unreadable.push({ path: file, error: r.error }); return {}; }
  if (r.missing) return {};
  const data = r.value;
  // A document that is literally `null` parses and is not a config. Returning
  // {} for it made "no servers here" indistinguishable from "this file says
  // nothing we understand".
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    if (unreadable) unreadable.push({ path: file, error: `document is ${data === null ? 'null' : (Array.isArray(data) ? 'an array' : typeof data)}, not an object` });
    return {};
  }
  if (data.mcpServers === undefined) return {};
  if (!data.mcpServers || typeof data.mcpServers !== 'object' || Array.isArray(data.mcpServers)) {
    if (unreadable) unreadable.push({ path: file, error: '"mcpServers" is not an object' });
    return {};
  }
  // Individual entries too: `audit()` skips a non-object entry with `continue`,
  // so a server configured as a string simply vanished from the report.
  const bad = Object.entries(data.mcpServers)
    .filter(([, v]) => !v || typeof v !== 'object' || Array.isArray(v))
    .map(([k]) => k);
  if (bad.length && unreadable) {
    unreadable.push({
      path: file,
      error: bad.length === 1
        ? `server entry "${bad[0]}" is not an object`
        : `${bad.length} server entries are not objects: ${bad.slice(0, 5).join(', ')}`,
    });
  }
  return data.mcpServers;
}

function readGlobalMcpServers(file, unreadable = null) {
  return serversFrom(file, unreadable);
}

function readProjectMcpServers(cwd, unreadable = null) {
  return serversFrom(path.join(cwd, '.mcp.json'), unreadable);
}

function readSettings(cwd, unreadable = null) {
  // .claude/settings.json holds the project's enabledMcpjsonServers list
  // (whitelist of mcp.json keys Claude actually loads) and permissions.allow
  // (allowedTools-style filter that scopes which tools each server exposes).
  // Either is enough to consider a heavy server "bounded".
  const file = path.join(cwd, '.claude', 'settings.json');
  const r = readJsonExplained(file);
  // A malformed settings file used to fall back to "no scoping configured",
  // which is the answer that *creates* heavy-unbounded findings — reporting
  // on a whitelist we had failed to read.
  if (r.error && unreadable) unreadable.push({ path: file, error: r.error });
  const data = r.value;
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

/**
 * @param evals  optional Map<db name, eval row>. When present, a *measured*
 *               tool count outranks the DB's estimate for the heavy check.
 *               Without it the behaviour is unchanged — but composing this
 *               with the eval snapshot (`status.cjs`) showed the cost of not
 *               doing so: the same screen said "396 tools, measured" and
 *               "tool count unknown" about one server, and a server measured
 *               at three tools was reported as an unbounded surface.
 */
function audit({ project, global, settings, db, evals = null }) {
  const findings = [];
  const seen     = new Set();
  const index    = lookalike.buildIndex(db.tools);

  // A server that is not in the DB used to be one finding, `unknown
  // (informational)`, whether it was the user's own tool or a package one
  // letter away from a vetted one. Those are not the same thing.
  const lookalikeFinding = (name, entry, scope, dbName) => {
    const hit = lookalike.checkServer({ name, install_cmd: toInstallCmd(entry) }, index, { dbName });
    if (!hit) return null;
    const top = hit.matches[0];
    // Whether it counts is decided in lookalikeDecisions(), not here.
    return {
      category:   'lookalike',
      server:     name,
      scope,
      candidate:  hit.candidate,
      kind:       hit.kind,
      db_name:    top.db_name,
      technique:  top.technique,
      confidence: top.confidence,
      matches:    hit.matches,
      message:    lookalike.describe(hit),
    };
  };

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
        const look = lookalikeFinding(name, entry, scope, null);
        if (look) { findings.push(look); continue; }
        findings.push({
          category: 'unknown',
          server:   name,
          scope,
          message:  `not in DB (custom or unvetted server; informational)`,
        });
        continue;
      }

      // Matched — but is it launching the entry's package? Two ways it may
      // not be: the key is the vault's name and the command runs something
      // else, or the match came from matchDbEntry's substring rule, which
      // reads `@evil/mongodb-mcp-server@1.0` as containing `mongodb-mcp-server@`.
      // Either way the server is not that entry, so its other findings (drift,
      // trust) would describe the wrong thing and are not reported.
      {
        const look = lookalikeFinding(name, entry, scope, tool.name === name ? tool.name : null);
        if (look) { findings.push(look); continue; }
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
      //
      // A measurement may only *raise* the count, never lower it. `tools/list`
      // is paginated and the eval reads one page, so a measured 10 can be the
      // first page of 100 — using it to conclude "small enough" would delete a
      // finding on the strength of a partial answer. The measurement therefore
      // cannot rescue an entry whose estimate is missing either: unknown stays
      // heavy, exactly as before.
      const measured = evals && evals.get ? evals.get(tool.name) : null;
      const observed = measured && measured.status === 'pass'
        && Number.isFinite(measured.tool_count) && measured.tool_count > 0
        ? measured.tool_count
        : null;
      // Tri-state, and the middle one matters: `true` means the real count is
      // higher than `observed`, `false` means the list was complete, and
      // `null` means the row predates the field. A null cannot raise the
      // verdict — but it cannot lower it either, and it does not need to:
      // the measurement is only ever used to *raise* the count, so a row with
      // unknown completeness falls back to exactly what the DB estimate alone
      // decided before any of this existed.
      // Two values, deliberately: `truncated` is the *predicate* that may
      // raise a verdict, and `truncationKnown` is the fact that gets reported.
      // Reusing the boolean for both turned "we do not know whether that list
      // was complete" into an assertion that it was.
      const truncated = measured && measured.tools_truncated === true;
      const truncationKnown = measured && measured.tools_truncated !== undefined
        ? measured.tools_truncated
        : null;
      const estimated = (typeof tool.est_tools_count === 'number') ? tool.est_tools_count : null;
      const tools = (observed !== null && estimated !== null) ? Math.max(observed, estimated)
        : (estimated !== null ? estimated : observed);
      // `truncated` means the real count is *more* than `observed`, so it can
      // never support the conclusion "small enough".
      const isHeavy = estimated === null || truncated || tools > HEAVY_THRESHOLD;
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
            tool_count_source: (observed !== null && tools === observed) ? 'measured'
              : (estimated !== null ? 'db' : 'unknown'),
            tool_count_truncated: observed !== null ? truncationKnown : null,
            toolsets_hint:   tool.toolsets || null,
            message:         tools === null
              ? `tool count unknown and no scoping (--toolsets/--caps/allowedTools/enabledMcpjsonServers)`
              : `${tools}${truncated && tools === observed ? '+' : ''} tools`
                + `${observed !== null && tools === observed ? ' (measured)' : ''}`
                + `, no scoping (--toolsets/--caps/allowedTools/enabledMcpjsonServers)`,
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

// ── cross-server: what the set does together ───────────────────────────────

/**
 * Toxic flows and tool shadowing over the Claude Code session this audit
 * reads — project and global servers together, since that is what one session
 * loads, minus project servers `enabledMcpjsonServers` leaves out.
 *
 * A server is matched to the vault by what it launches, never by its config
 * key: a key is the user's label, and `github-mcp-server` running
 * `node innocent.js` must not inherit the GitHub entry's labels. Tool names
 * come from the stored eval surface of the matched entry; a server with
 * neither is a `no-data` finding (lib/flows.cjs).
 *
 * `policy` is the frozen effective policy and `asOf` the instant; decide()
 * judges the findings, and `findings` here is the audit@1 view of that
 * Decision (category, the effect it gave, advice).
 */
function flowFindings({ project, global, settings, db, evals = null, capabilities = null, policy, asOf }) {
  const members = [];
  const seen = new Set();
  for (const [servers, scope] of [[project, 'project'], [global, 'global']]) {
    for (const [name, entry] of Object.entries(servers || {})) {
      if (seen.has(name) || !entry || typeof entry !== 'object') continue;
      seen.add(name);
      if (scope === 'project' && settings && Array.isArray(settings.enabled) && !settings.enabled.includes(name)) continue;
      const tool = flows.dbEntryForLaunch(db.tools, toInstallCmd(entry));
      let typed = null;
      try { typed = tool ? toTypedEntry(tool) : null; } catch { typed = null; }
      members.push(flows.memberFrom({
        name,
        dbEntry: tool,
        evalEntry: tool && evals && evals.get ? evals.get(tool.name) || null : null,
        capabilities,
        artifactIds: [typed ? artifactId(typed.artifact) : null],
        launch: [entry.command, ...(Array.isArray(entry.args) ? entry.args : [])].filter((t) => typeof t === 'string').join(' '),
      }));
    }
  }
  const analysis = flows.analyseSet(members);
  const judged = flows.judgeSets([{ host: 'claude-code', scope: 'session', analysis }], policy, asOf);
  const findings = judged.lines.filter((l) => l.rule !== 'flows/no-data').map((l) => ({
    category: l.rule.startsWith('flows/') ? 'toxic-flow' : 'tool-shadowing',
    rule:     l.rule,
    effect:   l.effect,
    server:   l.servers.join(', '),
    servers:  l.servers,
    scope:    'session',
    message:  l.message,
    advice:   l.advice,
    finding_ids: l.findings,
  }));
  return { analysis, judged, findings };
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
  'lookalike', 'secret', 'drift', 'untrusted', 'heavy-unbounded', 'toxic-flow', 'tool-shadowing', 'scope', 'unknown',
  'lookalike-allowed', 'version-unknown',
];
const CATEGORY_COLOR = {
  'lookalike':       RD,
  'lookalike-allowed': DM,
  'secret':          RD,
  'drift':           RD,
  'untrusted':       YL,
  'heavy-unbounded': YL,
  'toxic-flow':      YL,
  'tool-shadowing':  YL,
  'scope':           YL,
  'unknown':         DM,
  'version-unknown': DM,
};
const STRICT_CATEGORIES = new Set(['lookalike', 'drift', 'untrusted', 'heavy-unbounded', 'secret']);
// Categories whose exit is decide()'s (lookalikeDecisions). `status` still
// reads STRICT_CATEGORIES as the legacy decider it is.
const MODEL_CATEGORIES = new Set(['lookalike', 'lookalike-allowed']);

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
      if (cat === 'secret') {
        process.stdout.write(`    ${DM}${f.file}${f.line ? `:${f.line}` : ''}${f.tracked ? ' (tracked by git: rotate it)' : ''}${RS}\n`);
      }
      if ((cat === 'toxic-flow' || cat === 'tool-shadowing') && f.advice && (f.effect === 'deny' || f.effect === 'warn')) {
        process.stdout.write(`    ${DM}→ ${f.advice}${RS}\n`);
      }
      if (cat === 'lookalike') {
        process.stdout.write(`    ${DM}→ if you meant the vetted server: mcp-vault install ${f.db_name}${RS}\n`);
      }
      if (cat === 'untrusted' && f.notes) {
        process.stdout.write(`    ${DM}${truncate(f.notes, 110)}${RS}\n`);
      }
    }
    if (cat === 'secret') {
      process.stdout.write(`  ${DM}→ mcp-vault secrets --fix-suggest: the substitution syntax each host documents${RS}\n`);
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

// ── secrets ────────────────────────────────────────────────────────────────

/**
 * Plain-text credentials in the same two files this audit reads. Only their
 * server maps are walked (`mcpServers`, and the per-project `mcpServers` under
 * `projects` in ~/.claude.json, where `claude mcp add` puts local-scope
 * servers) — never the rest of ~/.claude.json. The value is never part of a
 * finding. Unreadable files are already reported by the reads above.
 */
function secretFindings(cwd, globalCfg, { git = true } = {}) {
  const { findings } = scanHostConfigs({
    git,
    paths: [
      { host: 'claude-code', scope: 'project', path: path.join(cwd, '.mcp.json') },
      { host: 'claude-code', scope: 'user',    path: globalCfg },
    ],
  });
  return findings.map((f) => ({
    category:   'secret',
    server:     f.server,
    scope:      f.scope === 'project' ? 'project' : 'global',
    rule:       f.rule,
    type:       f.type,
    confidence: f.confidence,
    file:       f.file,
    path:       f.path,
    line:       f.line,
    length:     f.length,
    masked:     f.masked,
    tracked:    f.tracked,
    severity:   f.severity,
    recommendation: f.recommendation,
    message:    `${f.type} in plain text at ${f.path} (${f.length} chars, ${f.masked})`
      + (f.tracked ? ' — the file is tracked by git' : ''),
  }));
}

/**
 * The lookalike findings of an audit, decided (docs/adr/0001): each one a
 * `lookalike/*` finding on the name, `--allow-lookalike` an input to the
 * row, `--strict` the policy's `fail_on`. The rest of the categories are
 * still judged by STRICT_CATEGORIES below until they move (migration step 3).
 * Returns the findings@1 document and, per legacy finding, its decision.
 */
function lookalikeDecisions(findings, { policy, asOf, allow = [] }) {
  const model = [];
  const facts = {};
  const byEntry = new Map();
  for (const x of findings) {
    if (x.category !== 'lookalike') continue;
    const hit = { candidate: x.candidate, kind: x.kind, server: x.server, lookalike: true, matches: x.matches };
    const f = lookalike.toFinding(hit, { scope: x.scope });
    if (!model.some((m) => m.id === f.id)) model.push(f);
    const fx = lookalike.factsFor(hit, { intent: 'configured', allow });
    const prev = facts[f.subject.id];
    if (prev) fx.lookalike.names = [...new Set([...prev.lookalike.names, ...fx.lookalike.names])].sort();
    facts[f.subject.id] = fx;
    byEntry.set(x, f);
  }
  const decisions = decide(model, policy, asOf, { subjects: model.map((f) => f.subject), facts });
  const bySubject = new Map(decisions.map((d) => [d.subject.id, d]));
  const outcomeOf = (x) => {
    const f = byEntry.get(x);
    const d = f && bySubject.get(f.subject.id);
    return d ? { decision: d, outcome: d.rules.find((o) => o.findings.includes(f.id)) || null } : null;
  };
  const document = toJson(findingsDocument({ asOf, findings: model, decisions, scope: 'setup', policy, facts }));
  return { document, decisions, outcomeOf };
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

  const unreadable = [];
  const project  = readProjectMcpServers(cwd, unreadable);
  const global_  = readGlobalMcpServers(globalCfg, unreadable);
  const settings = readSettings(cwd, unreadable);

  const counts = { project: Object.keys(project).length, global: Object.keys(global_).length };
  const findings = audit({ project, global: global_, settings, db });
  findings.push(...secretFindings(cwd, globalCfg));

  // The cross-server pass reads the stored eval surfaces and capability
  // scans; decide() judges it under the one effective policy (the file, then
  // --strict as fail_on). A policy with errors is said out loud and counts
  // under --strict; it does not change the default exit, because this command
  // did not read the policy before (docs/COMPATIBILITY.md).
  // The one policy loader; --strict is its `fail_on`, not a branch here.
  const loaded = loadEffectivePolicy(cwd, { flags: flagsFromArgv(argv) });
  const policy = loaded.policy;
  const policyErrors = loaded.errors.map((e) => ({ path: loaded.path || '.mcp-vault.policy.json', error: e }));
  const evalRows = (readJsonSafe(EVAL_PATH) || {}).results;
  const evals = new Map((Array.isArray(evalRows) ? evalRows : []).map((r) => [r.name, r]));
  const setup = flowFindings({
    project, global: global_, settings, db, evals,
    capabilities: readJsonSafe(CAPS_PATH), policy: loaded.policy, asOf: args.asOf,
  });
  findings.push(...setup.findings);

  const looks = lookalikeDecisions(findings, { policy, asOf: args.asOf, allow: args.allowLookalike || [] });
  // Rendering: a lookalike the user vouched for is listed apart, with the
  // row's own wording.
  for (const x of findings) {
    const o = looks.outcomeOf(x);
    if (o && o.outcome && o.outcome.effect === 'allow') { x.category = 'lookalike-allowed'; x.message = o.outcome.detail; }
  }

  if (args.json) {
    process.stdout.write(JSON.stringify({
      schema:      'mcp-vault/audit@1',
      // Additive: the instant this audit was judged at (lib/clock.cjs).
      as_of:       args.asOfIso,
      cwd,
      unreadable,
      db_path:     dbPath,
      global_path: globalCfg,
      counts,
      findings,
      setup:       setup.analysis,
      // Additive (mcp-vault/findings@1): the cross-server findings and the
      // Decisions the toxic-flow / tool-shadowing rows above are a view of.
      setup_findings: toJson(findingsDocument({
        asOf: args.asOf, findings: setup.judged.findings, decisions: setup.judged.decisions,
        scope: 'setup', policy: loaded.policy, facts: setup.judged.facts,
      })),
      policy_errors: policyErrors,
      // Additive (mcp-vault/findings@1): the categories already on the
      // findings model — lookalike names — with the policy and facts they
      // were decided on. `findings` above is the audit@1 view.
      model: looks.document,
    }, null, 2) + '\n');
  } else {
    printReport(findings, counts);
  }

  // Order matters, and it is stated in docs/COMPATIBILITY.md: a finding
  // outranks an incomplete scope. A definite version drift in a config we
  // *could* read is more actionable than a second config that would not
  // parse, and returning 2 for it hid the drift behind our own inability to
  // read something else. Both are reported either way.
  for (const u of unreadable) process.stderr.write(`audit: ${u.path}: ${u.error}\n`);
  for (const u of policyErrors) process.stderr.write(`audit: ${u.path}: ${u.error} (defaults in force)\n`);
  // The cross-server part fails when its Decision does: `toxicFlows: fail`
  // without --strict, `warn` with it (fail_on) — decide() said which.
  if (setup.judged.decisions.some((d) => d.fails)) return 1;
  if (exitCode(looks.decisions) === 1) return 1;
  if (args.strict && (policyErrors.length || findings.some(f => STRICT_CATEGORIES.has(f.category) && !MODEL_CATEGORIES.has(f.category)))) return 1;
  // A config we could not read is still not a clean config: "no findings"
  // would be a claim about servers we never saw.
  if (unreadable.length) return 2;
  return 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = {
  parseArgs,
  // Exported for `status.cjs`, which composes this check with four others in
  // one process rather than spawning five.
  readProjectMcpServers,
  readGlobalMcpServers,
  readSettings,
  STRICT_CATEGORIES,
  parseInstalledVersion,
  parseDbVersion,
  matchDbEntry,
  hasAllowedToolsScope,
  hasArgScope,
  audit,
  secretFindings,
  flowFindings,
  lookalikeDecisions,
  main,
  PROJECT_SCOPED_CATEGORIES,
  HEAVY_THRESHOLD,
};
