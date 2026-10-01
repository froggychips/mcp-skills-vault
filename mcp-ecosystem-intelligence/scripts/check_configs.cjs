#!/usr/bin/env node
/**
 * mcp-vault check — the MCP configs committed to this repository, checked in
 * one pass, with one answer.
 *
 * This is the command a CI job and a pre-commit hook run. It reads the
 * project-scoped configs (.mcp.json, .vscode/mcp.json, .cursor/mcp.json —
 * every host's project scope in lib/hosts.cjs), or exactly the files it is
 * given, and nothing from the home directory: that is `status` / `audit`,
 * whose answer depends on whose machine runs them.
 *
 * It decides nothing of its own. Each check that already exists produces its
 * findings, and the run is one decide() call over all of them
 * (lib/run_decision.cjs, docs/adr/0001):
 *
 *   verify --config   pins, the hash and stored advisories of a known package,
 *                     config/unpinned-launch, config/launch-source-override,
 *                     lookalike names (verify_integrity.cjs, run as is)
 *   secrets           plain-text credentials in the config (lib/secrets.cjs);
 *                     the value is never printed, in any format
 *   flows, shadowing  what the servers of one config do together (lib/flows.cjs)
 *   tool-scan         stored tool-description scans of the vault entries the
 *                     config launches, when eval stored one (lib/tool_scan.cjs)
 *
 * Each source's subjects keep the mode their own command decides them in
 * (verify's facts as it wrote them; secrets and flows `setup`, as `status`;
 * the stored scans `observe`), so a line's decision here is the decision
 * that command gives the same line — tests/check_configs.test.cjs compares
 * them.
 *
 * Offline by default: the vault DB shipped with this version is the only
 * input besides the configs. `--online` lets verify ask the registries and
 * advisory feeds, as `verify` without `--offline` does.
 *
 * Usage:
 *   mcp-vault check [paths...] [--json | --sarif] [--strict] [--fail-on deny|unknown|warn]
 *                   [--policy <file>] [--as-of <date>] [--online] [--no-color]
 *
 * Exit codes (lib/finding.cjs exitCode):
 *   0  nothing fails at the threshold (or there is no MCP config here)
 *   1  something fails: a deny, or a warn / unknown that --strict / --fail-on reaches
 *   2  bad arguments, a policy or a named config that could not be read
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { exitAfterFlush } = require('./lib/exit.cjs');
const F = require('./lib/finding.cjs');
const { loadEffectivePolicy, flagsFromArgv, rowFor, RANK } = require('./lib/policy_rules.cjs');
const { decideRun, outcomeClass, unanswered } = require('./lib/run_decision.cjs');
const { asOfFromArgv } = require('./lib/clock.cjs');
const { readInstalledServers, explicitConfigPaths, unpinnedLaunch, serverLine, parseCodexToml } = require('./lib/installed.cjs');
const { HOSTS } = require('./lib/hosts.cjs');
const secrets = require('./lib/secrets.cjs');
const flows = require('./lib/flows.cjs');
const ts = require('./lib/tool_scan.cjs');
const { evalResultsAsOf, dbAsOf } = require('./lib/evidence.cjs');
const { evalIndex } = require('./lib/tiers.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { feedbackLine } = require('./lib/feedback.cjs');

const VERIFY    = path.join(__dirname, 'verify_integrity.cjs');
const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');
const CAPS_PATH = path.resolve(__dirname, '../assets/capabilities.json');

const HELP = `mcp-vault check — the MCP configs in this repository, checked in one pass

  mcp-vault check [paths...] [--json | --sarif] [--strict] [--fail-on <effect>]
                  [--policy <file>] [--as-of <date>] [--online] [--no-color]

  paths          config files (or directories to look in). Default: the
                 project-scoped configs here — .mcp.json, .vscode/mcp.json,
                 .cursor/mcp.json. Nothing in your home directory is read.
  --json         mcp-vault/findings@1: every finding, the decisions, and the
                 policy and facts they were decided on
  --sarif        SARIF 2.1.0, each result on the config line it is about
  --strict       warnings fail too (fail_on warn)
  --fail-on      deny (default) | unknown | warn — which decisions fail the run
  --policy       a .mcp-vault.policy.json to apply (default: the nearest one)
  --as-of        decide as of YYYY-MM-DD or an ISO-8601 instant (offline only)
  --online       also ask the registries and advisory feeds (network)
  --allow-lookalike <name>  a configured name you know is yours: reported, not failed
  --no-color     plain text

What it checks: pins and hashes of known packages, stored advisories, launches
with no exact version, overridden package sources, lookalike names, plain-text
secrets (the value is never printed), what the servers of one config can do
together, and stored tool-description scans. Exit: 0 clean, 1 something fails,
2 a config, the policy or the arguments could not be read.
`;

// ── arguments ──────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const o = {
    paths: [], json: false, sarif: false, strict: false, online: false, color: true,
    failOn: null, policy: null, allowLookalike: [], help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = String(argv[i]);
    const value = (flag) => {
      const v = argv[++i];
      if (v === undefined || String(v).startsWith('--')) throw new Error(`${flag} needs a value`);
      return String(v);
    };
    try {
      // `--` ends the options: every later argument is a path, even one
      // that starts with a dash (the Action passes the configs this way).
      if (a === '--') { o.paths.push(...argv.slice(i + 1).map(String)); break; }
      if (a === '--json') o.json = true;
      else if (a === '--sarif') o.sarif = true;
      else if (a === '--strict') o.strict = true;
      else if (a === '--online') o.online = true;
      else if (a === '--offline') o.online = false;
      else if (a === '--no-color') o.color = false;
      else if (a === '--help' || a === '-h') o.help = true;
      else if (a === '--fail-on') o.failOn = value(a);
      else if (a.startsWith('--fail-on=')) o.failOn = a.slice('--fail-on='.length);
      else if (a === '--policy') o.policy = value(a);
      else if (a.startsWith('--policy=')) o.policy = a.slice('--policy='.length);
      else if (a === '--allow-lookalike') o.allowLookalike.push(value(a));
      else if (a.startsWith('--allow-lookalike=')) o.allowLookalike.push(a.slice('--allow-lookalike='.length));
      else if (a === '--as-of') value(a);            // read by asOfFromArgv
      else if (a.startsWith('--as-of=')) continue;
      else if (a.startsWith('-')) return { error: `unknown option: ${a}` };
      else o.paths.push(a);
    } catch (e) {
      return { error: e.message };
    }
  }
  if (o.json && o.sarif) return { error: '--json and --sarif are exclusive' };
  if (o.failOn !== null && !RANK.fail_on.includes(o.failOn)) {
    return { error: `--fail-on must be ${RANK.fail_on.join(', ').replace(/, (\w+)$/, ' or $1')} (got ${JSON.stringify(o.failOn)})` };
  }
  return o;
}

// ── which configs ──────────────────────────────────────────────────────────

const isFile = (p) => { try { return fs.statSync(p).isFile(); } catch { return false; } };
const isDir  = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };

/** The project-scoped config of every host that has one, in `dir`. */
function projectConfigs(dir) {
  const out = [];
  for (const h of HOSTS) {
    if (!h.scopes.project) continue;
    const p = h.scopes.project({ cwd: dir });
    if (!out.includes(p)) out.push(p);
  }
  return out;
}

/** A path as subjects spell it: relative to where the run started. */
function rel(file, cwd) {
  const r = path.relative(cwd, file);
  return (r && !r.startsWith('..') && !path.isAbsolute(r) ? r : file).split(path.sep).join('/');
}

/**
 * The files to read. Named ones are expected to exist (a typo in a workflow is
 * not "no servers configured"); a directory, and the default, contribute the
 * project configs that are there.
 */
function resolveConfigs(paths, cwd) {
  const out = [];
  const add = (p) => { if (!out.includes(p)) out.push(p); };
  if (!paths.length) {
    for (const p of projectConfigs(cwd)) if (isFile(p)) add(p);
    return out;
  }
  for (const p of paths) {
    const abs = path.resolve(cwd, p);
    if (isDir(abs)) { for (const c of projectConfigs(abs)) if (isFile(c)) add(c); } else add(abs);
  }
  return out;
}

// The servers of one config, as one session (a `setup` subject). Its id must
// not be the file's own host-config id (`.mcp.json`): decide() keys subjects
// by id, and a set's flow is not a statement about the file.
const SESSION = '#session';
const sessionOf = (file) => `${file}${SESSION}`;
const fileOfSession = (id) => (String(id).endsWith(SESSION) ? String(id).slice(0, -SESSION.length) : String(id));

// A parse error can quote the text around the fault, and in a config with a
// secret in it that text can be the secret. Only the position survives.
function safeReadError(error) {
  const msg = String(error || 'unreadable');
  const at = msg.match(/position \d+(?: \(line \d+ column \d+\))?/);
  if (at) return `not valid JSON at ${at[0]}`;
  if (/JSON|Unexpected (token|end)/.test(msg)) return 'not valid JSON';
  return secrets.redact(msg);
}

// ── the sources ────────────────────────────────────────────────────────────

/**
 * `verify --config` over the readable configs, as it is: its findings@1
 * document. Every string that came from a config — a launch command, a
 * message quoting it — goes through lib/secrets.cjs redact(), because a
 * token passed in `args` would otherwise be printed back.
 */
function runVerify(configs, { cwd, opts, iso }) {
  const args = [VERIFY, '--json'];
  if (!opts.online) args.push('--offline', '--as-of', iso);
  if (opts.failOn) args.push('--fail-on', opts.failOn);
  if (opts.strict) args.push('--strict');
  if (opts.policy) args.push('--policy', opts.policy);
  for (const n of opts.allowLookalike) args.push('--allow-lookalike', n);
  args.push('--config', ...configs);
  const r = spawnSync(process.execPath, args, { cwd, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, env: process.env });
  let report = null;
  try { report = JSON.parse(r.stdout); } catch { report = null; }
  const doc = report && report.findings;
  if (!doc || !Array.isArray(doc.decisions)) {
    return { error: secrets.redact(String(r.stderr || r.error || `verify exited ${r.status}`).trim()) };
  }
  // The gate's own self-check (its counters against its decision) is the one
  // line of its stderr worth passing on.
  const internal = String(r.stderr || '').split('\n').filter((l) => /internal:/.test(l)).map(secrets.redact);
  return { doc, internal };
}

const redactDeep = (v) => {
  if (typeof v === 'string') return secrets.redact(v);
  if (Array.isArray(v)) return v.map(redactDeep);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, redactDeep(x)]));
  return v;
};

/** verify's findings, subjects and facts, with nothing of a secret left in them. */
function fromVerify(doc, drop = () => false) {
  const findings = (doc.findings || []).filter((f) => !drop(f.subject)).map((f) => F.finding({
    rule: f.rule, subject: redactDeep(f.subject), scope: f.scope, severity: f.severity,
    confidence: f.confidence, state: f.state, refs: f.refs, message: secrets.redact(f.message),
  }));
  const subjects = (doc.decisions || []).filter((d) => !drop(d.subject)).map((d) => redactDeep(d.subject));
  const facts = {};
  for (const s of subjects) facts[s.id] = { ...redactDeep((doc.facts || {})[s.id] || {}), mode: ((doc.facts || {})[s.id] || {}).mode || 'gate' };
  return { findings, subjects, facts };
}

/**
 * The entries of a partly broken config that are not objects, with the line
 * that names each — what lib/installed.cjs parseConfig skipped and reported
 * as `partial`. Names only; nothing of a value is kept.
 */
function brokenEntries(file) {
  let raw;
  let doc;
  try {
    raw = fs.readFileSync(file, 'utf8');
    doc = file.endsWith('.toml') ? parseCodexToml(raw) : JSON.parse(raw);
  } catch { return []; }
  const table = doc && (doc.mcpServers !== undefined ? doc.mcpServers : doc.servers);
  if (!table || typeof table !== 'object' || Array.isArray(table)) return [];
  return Object.entries(table)
    .filter(([, spec]) => !spec || typeof spec !== 'object' || Array.isArray(spec))
    .map(([name]) => ({ name, line: serverLine(raw, name) }));
}

function readJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } }

function artifactOf(installCmd) {
  try { const t = toTypedEntry({ install_cmd: installCmd }); return t ? artifactId(t.artifact) : null; } catch { return null; }
}

// ── the run ────────────────────────────────────────────────────────────────

function model({ cwd, opts, asOf, iso, replay, policy }) {
  const configs = resolveConfigs(opts.paths, cwd);
  if (!configs.length) return { configs, empty: true };

  const unreadable = [];
  const servers = readInstalledServers({
    paths: explicitConfigPaths(configs, { cwd }),
    onUnreadable: (loc) => unreadable.push(loc),
  });
  // Only a file that could not be read at all is left out. One whose broken
  // entries sit beside valid ones (`partial`) is still checked: its valid
  // servers by every source, its broken entries as questions on their lines.
  const bad = new Set(unreadable.filter((u) => !u.partial).map((u) => u.path));
  const partial = new Set(unreadable.filter((u) => u.partial).map((u) => u.path));
  const readable = configs.filter((p) => !bad.has(p));

  const findings = [];
  const subjects = [];
  const facts = {};
  const advice = {};                      // finding id -> how to fix, from the source that knows
  // A subject two sources speak about (a secret on the line that launches an
  // unpinned server) is decided once, over all its findings, in a mode whose
  // rows include every row of each source's own: `gate` (lib/policy_rules.cjs
  // ORDER.gate has every setup and observe row). Otherwise the later source's
  // mode would drop the earlier one's rows, and a finding would go undecided.
  const addFacts = (id, f) => {
    const prev = facts[id] || {};
    const mode = prev.mode && f.mode && prev.mode !== f.mode ? 'gate' : (f.mode || prev.mode);
    facts[id] = { ...prev, ...f, ...(mode ? { mode } : {}) };
  };

  // A config that is named and missing, or will not parse, is a question this
  // run could not answer: scope/unanswered, exit 2 unless something fails.
  const seenBad = new Set();
  for (const u of unreadable) {
    const key = `${u.path}\u0000${u.error}`;
    if (seenBad.has(key)) continue;
    seenBad.add(key);
    const broken = u.partial ? brokenEntries(u.path) : [];
    if (u.partial && broken.length) {
      for (const b of broken) {
        const f = unanswered({
          subject: F.subject.hostConfig({ path: rel(u.path, cwd), line: b.line, host: u.host, scope: 'project', server: b.name }),
          message: `${rel(u.path, cwd)}${b.line ? `:${b.line}` : ''}: server entry "${b.name}" is not an object — it was not checked`,
          scope: 'config',
        });
        findings.push(f);
        addFacts(f.subject.id, { mode: 'gate' });
        advice[f.id] = 'make the entry an object ({ "command": …, "args": [ … ] } or { "url": … }); it is checked once it is';
      }
      continue;
    }
    const f = unanswered({
      subject: F.subject.hostConfig({ path: rel(u.path, cwd), host: u.host, scope: 'project' }),
      message: `${rel(u.path, cwd)}: ${safeReadError(u.error)} — ${u.partial ? 'some entries were not checked' : 'nothing in it was checked'}`,
      scope: 'config',
    });
    findings.push(f);
    addFacts(f.subject.id, { mode: 'gate' });
    advice[f.id] = u.error === 'file not found' ? 'check the path' : 'fix the file so it parses; its servers are checked once it does';
  }

  let internal = [];
  if (readable.length) {
    // 1. verify --config: pins, hashes, advisories, unpinned, source overrides, lookalikes.
    const v = runVerify(readable.map((p) => rel(p, cwd)), { cwd, opts, iso });
    if (v.error) return { error: `verify --config did not answer: ${v.error}` };
    internal = v.internal;
    const vp = v.doc.policy ? F.canonicalJson(v.doc.policy) : null;
    if (vp !== F.canonicalJson(JSON.parse(JSON.stringify(policy)))) {
      return { error: 'internal: verify decided under another policy than this run — refusing to merge its findings; please report this' };
    }
    // verify reports a partly broken file as a whole ("could not be parsed");
    // check has already said which entries, on their lines, and checked the rest.
    const partialRefs = new Set([...partial].map((p) => rel(p, cwd)));
    const fv = fromVerify(v.doc, (s) => s.type === 'host-config' && !s.line && partialRefs.has(s.path));
    findings.push(...fv.findings);
    subjects.push(...fv.subjects);
    for (const [id, f] of Object.entries(fv.facts)) addFacts(id, f);

    // 2. secrets: the same files, the same scanner as `mcp-vault secrets`.
    const scan = secrets.scanHostConfigs({ paths: explicitConfigPaths(readable, { cwd }) });
    const sf = secrets.toFindings(scan, { cwd });
    const detail = new Map(sf.details.map((d) => [d.finding, d]));
    for (const f of sf.findings) {
      findings.push(f);
      addFacts(f.subject.id, { mode: 'setup' });
      const d = detail.get(f.id);
      const plus = d && d.fix_suggestion && d.fix_suggestion.lines && d.fix_suggestion.lines.find((l) => l.startsWith('+'));
      const rotate = d && d.tracked ? '; it is in git history, so rotate it' : '';
      const how = secrets.recommendation(f.subject.host, f.subject.scope);
      advice[f.id] = plus ? `replace it with ${plus.slice(2)} and set the value in the environment${rotate}`
        : `${how.charAt(0).toLowerCase()}${how.slice(1).replace(/\.$/, '')}${rotate}`;
    }

    // 3. flows and shadowing: the servers of one config are one session.
    const rawDb = readJson(DB_PATH) || { tools: [] };
    const db = replay ? dbAsOf(rawDb, asOf) : rawDb;
    const evalRows = evalResultsAsOf(((readJson(EVAL_PATH) || {}).results) || [], asOf) || [];
    const evals = evalIndex(evalRows);
    const capabilities = readJson(CAPS_PATH) || { packages: {} };
    const entryOf = new Map();
    for (const srv of servers) entryOf.set(srv, srv.install_cmd ? flows.dbEntryForLaunch(db.tools, srv.install_cmd) : null);
    for (const file of readable) {
      const members = servers.filter((s) => s.source === file).map((srv) => {
        const dbEntry = entryOf.get(srv);
        return flows.memberFrom({
          name: srv.name, dbEntry, evalEntry: dbEntry ? evals.get(dbEntry.name) || null : null, capabilities,
          artifactIds: [artifactOf(srv.install_cmd), dbEntry ? artifactOf(dbEntry.install_cmd) : null],
          launch: srv.install_cmd,
        });
      });
      if (!members.length) continue;
      const r = flows.findingsFor(flows.analyseSet(members), { host: sessionOf(rel(file, cwd)), scope: 'config' });
      for (const f of r.findings) {
        findings.push(f);
        addFacts(f.subject.id, { mode: 'setup' });
        if (r.meta[f.id] && r.meta[f.id].advice) advice[f.id] = r.meta[f.id].advice;
      }
    }

    // 4. tool-scan: what eval stored about the vault entries this config
    //    launches — only where it stored a scan.
    const scanned = new Set();
    for (const srv of servers) {
      const entry = entryOf.get(srv);
      if (!entry || scanned.has(entry.name)) continue;
      const row = evalRows.find((x) => x && x.name === entry.name && x.tool_scan);
      if (!row) continue;
      scanned.add(entry.name);
      const m = ts.evalRowFindings(row, { asOf, scope: 'config' });
      if (!m) continue;
      subjects.push(m.subject);
      addFacts(m.subject.id, { tool_scan: m.facts, mode: 'observe' });
      for (const f of m.findings) {
        findings.push(f);
        addFacts(f.subject.id, { mode: 'observe' });
        advice[f.id] = `read what ${entry.name}'s tool descriptions say: mcp-vault tool-scan --name ${entry.name}`;
      }
    }
  }

  const run = decideRun({ findings, subjects, policy, asOf, mode: 'gate', facts, scope: 'config' });
  return { configs, readable, servers, unreadable, findings, advice, internal, ...run };
}

// ── text ───────────────────────────────────────────────────────────────────

/** Where a subject is, as a config file and line, for grouping the report. */
function locate(s, doc, servers, cwd) {
  const at = (srv) => ({ path: rel(srv.source, cwd), line: srv.line || null, server: srv.name });
  if (s.type === 'host-config') return { path: s.path, line: s.line, server: s.server };
  if (s.type === 'setup') return { path: fileOfSession(s.host), line: null, server: null };
  if (s.type === 'tool' && s.tool !== '*') return { path: fileOfSession(s.location || ''), line: null, server: s.server };
  if (s.type === 'name') {
    const names = new Set((((doc.facts || {})[s.id] || {}).lookalike || {}).names || [s.name]);
    const srv = servers.find((x) => names.has(x.name) || (x.launch && names.has(x.launch.package)));
    return srv ? at(srv) : { path: '', line: null, server: s.name };
  }
  if (s.type === 'tool') {
    const srv = servers.find((x) => x.name === s.server);
    return srv ? at(srv) : { path: '', line: null, server: s.server };
  }
  return { path: '', line: null, server: s.id };
}

/** One line: what to change. From the source that knows, else per rule. */
function fixFor(o, f, { m, srv, policyPath, dbTools }) {
  if (f && m.advice[f.id]) return m.advice[f.id];
  const rule = f ? f.rule : o.rule;
  const msg = f ? f.message : String(o.detail || '');
  if (rule.startsWith('lookalike/')) {
    const d = (m.document.facts[f.subject.id] || {}).lookalike || {};
    const match = (d.matches || [])[0];
    return `${match ? `if you meant the vetted server: mcp-vault install ${match.db_name}; ` : ''}if this one is yours: --allow-lookalike ${(d.names || [])[0] || ''}`.trim();
  }
  if (rule.startsWith('policy/') || rule.startsWith('org/')) return `${policyPath ? `the policy in ${policyPath}` : 'the policy'} refuses it: pick another server, or change the policy`;
  if (srv && srv.source_override) return 'launch it from the public registry, or verify that source yourself';
  if (srv && srv.remote) return 'nothing to pin: a remote server ships no artifact, trust is in the endpoint';
  if (srv && !srv.install_cmd) return 'nothing to pin: a local command has no published release to verify against';
  if (srv && srv.install_cmd) {
    const u = unpinnedLaunch(srv, { dbTools });
    if (u) return secrets.redact(u.advice);
  }
  if (/not in the vault/.test(msg)) return 'not in the vault, so there is no hash to compare: use a vetted server (mcp-vault list), or accept it as unverified';
  if (/source install|git URL|VCS/.test(msg)) return 'launch a published release from the registry, or verify that source yourself';
  return `run \`mcp-vault verify --offline --config ${srv ? rel(srv.source, process.cwd()) : '<file>'}\` for the full gate report`;
}

function render(m, { opts, policyPath, cwd, color }) {
  const C = (code) => (color ? `\x1b[${code}m` : '');
  const B = C(1), DM = C(2), RD = C(31), YL = C(33), GN = C(32), RS = C(0);
  const out = [];
  const doc = m.document;
  const byId = new Map(doc.findings.map((f) => [f.id, f]));
  const dbTools = (readJson(DB_PATH) || {}).tools || [];
  // One line per finding, under the worst gate outcome that rests on it (a
  // secret is both `secrets/*`'s deny and `finding/severity`'s warning), and
  // one per outcome that rests on none (a policy's licence deny). Which
  // outcomes are shown is lib/run_decision.cjs outcomeClass's reading.
  const shown = new Map();
  for (const d of doc.decisions) {
    const ruleOf = new Map(d.findings.map((id) => [id, (byId.get(id) || {}).rule]));
    for (const o of d.rules) {
      const cls = outcomeClass(o);
      if (!cls) continue;
      const fails = F.outcomeFails(o, {
        threshold: d.fail_on, families: doc.policy && doc.policy.fail_families, ruleOf,
        thresholded: Boolean((rowFor(o.rule) || {}).thresholded),
      });
      const keys = o.findings.length ? o.findings : [`${d.subject.id}\u0000${o.rule}\u0000${o.detail || ''}`];
      for (const key of keys) {
        const prev = shown.get(key);
        const worse = !prev || (fails && !prev.fails) || (fails === prev.fails && F.EFFECT_RANK[o.effect] < F.EFFECT_RANK[prev.o.effect]);
        if (worse) shown.set(key, { d, o, f: byId.get(key) || null, cls, fails });
      }
    }
  }
  // One line per cause. A launch with no exact version, or from an overridden
  // source, is the config's own finding; the gate's "nothing to compare it
  // against" on the same line (pin/missing, verify/unverified — not observed)
  // is a consequence of it, not a second problem. It is folded into the main
  // line's tag, so its effect and whether it fails stay visible; the document,
  // the JSON and the SARIF keep both findings, and decide() saw both.
  const CAUSES = new Set(['config/unpinned-launch', 'config/launch-source-override']);
  const CONSEQUENCES = new Set(['pin/missing', 'verify/unverified']);
  const caused = new Set(doc.findings.filter((f) => CAUSES.has(f.rule)).map((f) => f.subject.id));
  const folded = new Map();          // subject id -> [{ rule, effect, fails }]
  const entries = [];
  for (const e of shown.values()) {
    if (e.f && CONSEQUENCES.has(e.f.rule) && e.f.state !== 'observed' && caused.has(e.f.subject.id)) {
      const list = folded.get(e.f.subject.id) || [];
      list.push({ rule: e.f.rule, effect: e.o.effect, fails: e.fails });
      folded.set(e.f.subject.id, list);
    } else entries.push(e);
  }
  const items = [];
  for (const { d, o, f, cls, fails } of entries) {
    const where = locate(d.subject, doc, m.servers, cwd);
    const srv = m.servers.find((x) => rel(x.source, cwd) === where.path && x.line && x.line === where.line) || null;
    // The unpinned finding's message carries its advice; the advice gets its own line.
    const u = srv && f && f.rule === 'config/unpinned-launch' ? unpinnedLaunch(srv, { dbTools: [] }) : null;
    const what = (u ? u.message : (f ? f.message : (o.detail || o.rule)))
      .replace(/ \(use --fail-unverified to fail closed\)/g, '')
      .replace(/ The gate does not check it against the registry; .*$/, '');
    const also = f && CAUSES.has(f.rule) ? folded.get(f.subject.id) || [] : [];
    const failsHere = fails || also.some((x) => x.fails);
    const tag = `${f && o.rule !== f.rule ? `${o.rule} ← ${f.rule}` : o.rule}: ${o.effect}`
      + also.map((x) => `; so ${x.rule}: ${x.effect}`).join('');
    items.push({
      ...where, cls, fails: failsHere, effect: o.effect, rule: o.rule, tag,
      what: secrets.redact(what),
      fix: fixFor(o, f, { m, srv, policyPath, dbTools }),
    });
  }
  items.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) || ((a.line || 0) - (b.line || 0)) || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0));

  let lastFile = null; let lastLine = null;
  for (const it of items) {
    if (it.path !== lastFile) { out.push(`${B}${it.path || '(no file)'}${RS}`); lastFile = it.path; lastLine = undefined; }
    if (it.line !== lastLine) {
      out.push(`  ${it.line ? `${DM}:${it.line}${RS} ` : ''}${it.server ? `${B}${it.server}${RS}` : `${DM}(the config as a whole)${RS}`}`);
      lastLine = it.line;
    }
    const mark = it.fails ? `${RD}✗${RS}` : it.cls === 'unanswered' ? `${YL}?${RS}` : `${YL}!${RS}`;
    out.push(`    ${mark} ${it.what} ${DM}[${it.tag}${it.fails ? ', fails' : ''}]${RS}`);
    out.push(`      ${DM}fix:${RS} ${it.fix}`);
  }

  const failing = items.filter((i) => i.fails).length;
  const open = items.filter((i) => !i.fails && i.cls === 'unanswered').length;
  const notes = items.length - failing - open;
  const n = m.servers.length;
  const scope = `${n} server${n === 1 ? '' : 's'} in ${m.configs.length} config${m.configs.length === 1 ? '' : 's'}`;
  const tail = `${DM}fail on ${doc.policy ? doc.policy.fail_on : 'deny'} · ${opts.online ? 'online' : 'offline'}${RS}`;
  const head = m.exit === 1 ? `${RD}${B}FAIL${RS}` : m.exit === 2 ? `${YL}${B}INCOMPLETE${RS}` : notes ? `${YL}${B}PASS${RS}` : `${GN}${B}OK${RS}`;
  const parts = [];
  if (failing) parts.push(`${failing} failing`);
  if (open) parts.push(`${open} not checked`);
  if (notes) parts.push(`${notes} to look at${m.exit === 0 && !opts.strict ? ' (--strict fails on these)' : ''}`);
  if (!parts.length) parts.push('nothing to fix');
  if (items.length) out.push('');
  out.push(`${head} — ${parts.join(', ')} · ${scope} · ${tail}`);
  return out.join('\n') + '\n';
}

// ── main ───────────────────────────────────────────────────────────────────

function main(argv, { cwd = process.cwd(), stdout = process.stdout, stderr = process.stderr, env = process.env } = {}) {
  const clock = asOfFromArgv(argv);
  if (clock.error) { stderr.write(`check: ${clock.error}\n`); return 2; }
  const opts = parseArgs(argv);
  if (opts.error) { stderr.write(`check: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help) { stdout.write(HELP); return 0; }
  // A replay is over stored evidence; a live run observes today (docs/adr/0001).
  if (opts.online && clock.source === 'as-of') {
    stderr.write('check: --as-of replays stored evidence and cannot be combined with --online\n');
    return 2;
  }

  // The bar: the policy file(s), tightened by the flags — the same call, with
  // the same inputs, verify makes; checked against verify's below.
  const flags = flagsFromArgv(argv);
  if (opts.failOn === 'unknown') flags.failUnverified = true;
  if (opts.failOn === 'warn') flags.strict = true;
  const loaded = loadEffectivePolicy(cwd, { flags, file: opts.policy ? path.resolve(cwd, opts.policy) : null });
  if (!loaded.ok) {
    stderr.write(`check: policy error in ${loaded.path}:\n${(loaded.errors || []).map((e) => `  - ${e}\n`).join('')}`);
    return 2;
  }
  const policy = loaded.policy;

  const m = model({ cwd, opts, asOf: clock.asOf, iso: clock.iso, replay: clock.source === 'as-of', policy });
  if (m.error) { stderr.write(`check: ${m.error}\n`); return 2; }
  for (const l of m.internal || []) stderr.write(`${l}\n`);

  if (m.empty) {
    const looked = opts.paths.length ? opts.paths.join(', ') : projectConfigs(cwd).map((p) => rel(p, cwd)).join(', ');
    if (opts.sarif) stdout.write(`${JSON.stringify(F.toSarif([], { toolName: 'mcp-vault check' }), null, 2)}\n`);
    else if (opts.json) stdout.write(`${JSON.stringify(F.toJson(F.findingsDocument({ asOf: clock.asOf, scope: 'config', policy, facts: {} })), null, 2)}\n`);
    else stdout.write(`No MCP config found (looked for ${looked}) — nothing to check.\n`);
    return 0;
  }

  if (opts.sarif) {
    const ruleHelp = { ...ts.SARIF_RULE_HELP };
    for (const f of m.document.findings) {
      if (f.rule.startsWith('secrets/')) ruleHelp[f.rule] = 'A credential is written into an MCP config in plain text. Reference it from the environment instead, and rotate it if the file was ever shared or committed.';
    }
    stdout.write(`${JSON.stringify(F.toSarif(m.document.findings, {
      toolName: 'mcp-vault check', decisions: m.document.decisions, ruleHelp,
      dbPath: rel(DB_PATH, cwd),
    }), null, 2)}\n`);
  } else if (opts.json) {
    stdout.write(`${JSON.stringify(m.document, null, 2)}\n`);
  } else {
    const color = opts.color && Boolean(stdout.isTTY) && !env.NO_COLOR;
    stdout.write(render(m, { opts, policyPath: loaded.path ? rel(loaded.path, cwd) : null, cwd, color }));
    const fb = feedbackLine({ isTTY: Boolean(stdout.isTTY), env });
    if (fb) stdout.write(`${color ? '\x1b[2m' : ''}${fb}${color ? '\x1b[0m' : ''}\n`);
  }
  return m.exit;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, resolveConfigs, projectConfigs, main, HELP };
