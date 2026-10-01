#!/usr/bin/env node
/**
 * One command, one screen: what is installed, what is wrong with it, and what
 * this project would want.
 *
 * The quick start used to be six commands — `scan`, `audit --strict`,
 * `verify --offline`, `verify --installed`, `budget`, `doctor` — and a new
 * reader had to run all six before knowing whether anything was wrong. Four of
 * them answer questions about the same three inputs (the host configs, the DB,
 * the stored evidence), so this composes them in one process and prints the
 * findings rather than each check's full output.
 *
 * It is deliberately **offline and instant**. Every claim it makes comes from
 * evidence already on disk, and every block prints the date that evidence was
 * established rather than implying it was checked just now. `--live` is
 * available where a live answer is actually different in kind, and the footer
 * always names the command that goes deeper. A first command that takes a
 * minute is not a first command.
 *
 * Usage:
 *   node scripts/status.cjs [--cwd <dir>] [--json] [--strict] [--as-of <date>]
 *
 * Exit codes — the Decision's (docs/adr/0001: everything below is a finding,
 * decided once by decide() in mode `setup`; --strict is the policy's fail_on):
 *   0  nothing installed is blocked, and the environment can run this
 *   1  an installed server is blocked (gone / wrong bytes / live advisory),
 *      a plain-text secret in a host config, or a required environment check
 *      failed; with --strict, also drift, unvetted servers, stale evidence
 *   2  bad arguments / the DB could not be read / a host config could not be
 *      read (unless something else fails)
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const { exitAfterFlush }   = require('./lib/exit.cjs');
const { readInstalledServers, toInstallCmd } = require('./lib/installed.cjs');
const { trustScore }       = require('./lib/scores.cjs');
const { classifyEntry, evalIndex, currentArtifactId, packageKeyOfId, NAME_SCOPED } = require('./lib/tiers.cjs');
const {
  toTypedEntry, artifactId, comparableArtifactId, comparableId, packageKey, isExactArtifact,
} = require('./lib/entry_model.cjs');
const { staleDimensions, DEFAULT_MAX_AGE_DAYS, dbAsOf, evalResultsAsOf } = require('./lib/evidence.cjs');
const { asOfFromArgv, requireAsOf } = require('./lib/clock.cjs');
const budget               = require('./lib/budget.cjs');
const flows                = require('./lib/flows.cjs');
const { loadEffectivePolicy } = require('./lib/policy_rules.cjs');
const { subject, finding }  = require('./lib/finding.cjs');
const { classify, unanswered: unansweredFinding } = require('./lib/run_decision.cjs');
const { runDoctor, doctorFindings } = require('./doctor.cjs');
const orchestrate          = require('./orchestrate.cjs');
const auditSetup           = require('./audit_setup.cjs');
const { scanHostConfigs, redact, subjectPath } = require('./lib/secrets.cjs');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');
const CAPS_PATH = path.resolve(__dirname, '../assets/capabilities.json');
const PKG_PATH  = path.resolve(__dirname, '../../package.json');

const T  = process.stdout.isTTY && !process.env.NO_COLOR;
const B  = T ? '\x1b[1m'  : '';
const DM = T ? '\x1b[2m'  : '';
const RD = T ? '\x1b[31m' : '';
const GN = T ? '\x1b[32m' : '';
const YL = T ? '\x1b[33m' : '';
const RS = T ? '\x1b[0m'  : '';

const HELP = `mcp-vault status — one screen: what is installed, what is wrong, what is missing

  node scripts/status.cjs [--cwd <dir>] [--json] [--strict] [--as-of <date>]

  --cwd      project to read (default: the current directory)
  --json     machine-readable (schema mcp-vault/status@1)
  --strict   also exit 1 on drift, unvetted servers and stale evidence
  --as-of    judge the stored evidence as of this date (YYYY-MM-DD or an
             ISO-8601 instant) instead of now — for reproducing a past answer

Reads only what is already on disk, so it makes no network calls. The footer
names the commands that do.
`;

function parseArgs(argv) {
  const opts = { cwd: process.cwd(), json: false, strict: false, help: false, asOf: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--cwd') { opts.cwd = argv[++i]; if (!opts.cwd) return { error: '--cwd needs a directory' }; }
    else if (a === '--as-of' || a.startsWith('--as-of=')) { if (a === '--as-of') i++; }
    else return { error: `unknown argument: ${a}` };
  }
  // The clock is read here, once, and nowhere below (lib/clock.cjs).
  const clock = asOfFromArgv(argv);
  if (clock.error) return { error: clock.error };
  opts.asOf = clock.asOf;
  opts.asOfIso = clock.iso;
  return opts;
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

// ── the five questions ──────────────────────────────────────────────────────

/** Can this machine run any of it? Only the things that are not fine. */
function environment(cwd) {
  return environmentModel(cwd).block;
}

/** The environment block, and doctor's checks as findings (one subject). */
function environmentModel(cwd) {
  const doc = runDoctor({ cwd });
  const problems = doc.checks.filter((c) => c.level !== 'ok');
  return { model: doctorFindings(doc), block: {
    node: process.version,
    counts: doc.counts,
    // A `fail` is a blocker; a `warn` is an optional tool that is absent, and
    // an absent optional tool is not a finding about this project.
    failed:  problems.filter((c) => c.level === 'fail').map((c) => ({ check: c.name, detail: c.message })),
    // Optional tools that are absent. Not a finding about this project — but
    // worth one word, because a missing `uvx` silently limits what installs.
    missing: problems.filter((c) => c.level === 'warn' && c.optional).map((c) => c.name),
  } };
}

/**
 * Identity comparison lives in `lib/entry_model.cjs`, so the tier, the audit
 * and this command cannot disagree about what "the same artifact" means. They
 * did: this file folded PyPI names while the tier compared raw ids, so the
 * underscore spelling of a yanked package matched here and was then rejected
 * there as belonging to something else.
 */
/**
 * What the hosts actually launch, and what the DB knows about *that*.
 *
 * Matching is by package identity, never by the name in the config. The first
 * version used `budget.matchDbEntry`, which prefers the config key, and it was
 * wrong in both directions: a server called `mcp-server-aws` launching
 * `node ./innocent.js` inherited the real AWS entry's yanked status and failed
 * the run, while a server called `mcp-server-fetch` actually launching the
 * yanked AWS package passed. The config key is a label the user typed.
 *
 * The version is then compared separately, because stored evidence about
 * `x@1.0.0` is not a finding about `x@2.0.0` in either direction. Three
 * outcomes, and only the first carries a tier:
 *
 *   same       the evidence is about these bytes — tier and trust apply
 *   different  the vault verified another version — reported as drift, no tier
 *   unpinned   the command resolves at launch, so what runs is not knowable
 *              from here at all
 */
function installed({ cwd, db, evals, asOf }) {
  requireAsOf(asOf, 'status installed()');
  const unreadable = [];
  const servers = readInstalledServers({ cwd, onUnreadable: (loc) => unreadable.push(loc) });

  const byPackage = new Map();
  for (const tool of db.tools) {
    const typed = toTypedEntry(tool);
    const key = typed ? packageKey(typed.artifact) : null;
    if (key && !byPackage.has(key)) byPackage.set(key, tool);
  }

  const rows = [];
  for (const server of servers) {
    const withCmd = { ...server, install_cmd: server.install_cmd || toInstallCmd(server) };
    const typed   = toTypedEntry(withCmd);
    const key     = typed ? packageKey(typed.artifact) : null;
    const entry   = key ? byPackage.get(key) || null : null;
    const base    = { name: server.name, host: server.host, scope: server.scope || null, launches: redact(withCmd.install_cmd) || null };
    // The host-config line that launches it: what every finding about this
    // server is about (the subject `audit` uses for the same line). Kept off
    // the status@1 row.
    Object.defineProperty(base, 'subject', {
      enumerable: false,
      value: subject.hostConfig({
        path: subjectPath(server.source || server.name, cwd), line: server.line || null,
        host: server.host || null, scope: server.scope || null, server: server.name,
      }),
    });

    const keep = (row) => Object.defineProperty(row, 'subject', { enumerable: false, value: base.subject });
    if (!entry) {
      rows.push(keep({ ...base, in_db: false, package: key }));
      continue;
    }

    const installedId = artifactId(typed.artifact);
    const vaultId     = currentArtifactId(entry);
    const vaultTyped  = toTypedEntry(entry);
    // Equality is necessary and not sufficient: both sides must also *resolve*
    // to one artifact. `npx -y pkg` equals `npx -y pkg` and names nothing.
    const pinned      = isExactArtifact(typed.artifact);
    const vaultPinned = Boolean(vaultTyped && isExactArtifact(vaultTyped.artifact));
    const comparable  = comparableArtifactId(typed.artifact);
    const version_match = (!comparable || !vaultId) ? 'unknown'
      : (pinned && vaultPinned && comparable === vaultId ? 'same' : 'different');

    const row = keep({
      ...base,
      in_db: true,
      db_entry: entry.name,
      package: key,
      installed_artifact: installedId,
      vault_artifact: vaultId,
      version_match,
      pinned,
    });

    if (version_match !== 'same') {
      // One finding does survive a version change: an unpublished *name*. The
      // package is gone, and a free name can be claimed by somebody else, so
      // it applies to whatever version this host launches.
      const availability = (entry.trust_evidence && entry.trust_evidence.dimensions
        && entry.trust_evidence.dimensions.availability) || null;
      // Three packages have to agree, not two: what this host launches, what
      // the vault entry installs, and what the *evidence* was recorded
      // against. Comparing only the first two recreated the bug the tier had
      // just fixed — evidence saying `x` is gone produced Deprecated for an
      // entry that now installs `y`.
      const evidencePackage = packageKeyOfId(entry.trust_evidence && entry.trust_evidence.artifact_id);
      const hostPackage     = packageKey(typed.artifact);
      const vaultPackage    = packageKey(vaultTyped && vaultTyped.artifact);
      const nameGone = availability && NAME_SCOPED.has(availability.status)
        && Boolean(hostPackage) && hostPackage === vaultPackage && hostPackage === evidencePackage;

      // No tier: every other stored claim under this entry is about
      // `vault_artifact`, which is not what this host runs.
      row.tier = nameGone ? 'Deprecated' : null;
      row.tier_reason = nameGone
        ? `availability: ${availability.status} (as of ${availability.checked_at || 'unknown'}) — the package name itself, whatever version is launched`
        : (version_match === 'unknown'
          // A defect in the *vault's* entry, not drift in the user's setup:
          // reporting it as drift blamed the reader for our bad data and, with
          // --strict, failed their build for it.
          ? `the vault's own entry does not name one artifact (${vaultId || 'no id'}), so this host's ${installedId || 'launch command'} cannot be compared against it`
          : (!pinned
            ? `the launch command resolves at start-up (${installedId || 'unparseable'}), so what runs is not the ${vaultId} the vault verified`
            : `the vault verified ${vaultId}; this host launches ${installedId}`));
      rows.push(row);
      continue;
    }

    const tier  = classifyEntry(entry, evals.get(entry.name) || null, { now: asOf });
    const trust = trustScore(entry.trust_evidence || null, { now: asOf });
    const dims  = (entry.trust_evidence && entry.trust_evidence.dimensions) || {};
    const dates = Object.values(dims).map((d) => d.checked_at).filter(Boolean).sort();
    rows.push(keep({
      ...row,
      tier: tier.classification,
      tier_reason: tier.why,
      trust_gate: trust.gate,
      blocking: trust.blocking.map((b) => `${b.dimension}: ${b.status}`),
      oldest_evidence: dates[0] || null,
      stale: staleDimensions(entry.trust_evidence || null, DEFAULT_MAX_AGE_DAYS, asOf).map((s) => s.dimension),
    }));
  }
  // A host config that could not be read is not a host with no servers.
  for (const loc of unreadable) {
    rows.push(Object.defineProperty({
      name: `(${loc.host || loc.path})`,
      host: loc.host || null,
      in_db: false,
      unreadable: loc.error || 'unparseable',
      path: loc.path || null,
    }, 'subject', {
      enumerable: false,
      value: subject.hostConfig({ path: subjectPath(loc.path || loc.host || 'unknown', cwd), host: loc.host || null, scope: loc.scope || null }),
    }));
  }
  return rows;
}

/** What they cost on every request. */
const HEAVY_SHARE = 20;   // percent of the window one server may take quietly

function context(rows, db, evals) {
  // Every configured server, including the ones the DB has never heard of.
  // Filtering those out before `summarise` made `unknown_servers` read 0 and
  // turned "we did not count eleven of your servers" into "your config costs
  // this much" — the summary claiming more than its inputs support, which is
  // the one thing this command must not do. `estimateServer` already returns
  // `source: 'unknown'` with a null token count for an entry it cannot
  // measure, and `summarise` already counts those separately.
  // Which eval row, if any, is a measurement *of this artifact*. Checking the
  // host against the DB was not enough: the eval is indexed by name, so a
  // measurement taken against an older version was being spent on the current
  // one. And a truncated `tools/list` is a lower bound, not a total.
  const measurementFor = (r) => {
    if (!r.in_db || r.version_match !== 'same') return null;
    const row = evals.get(r.db_entry);
    // A run that failed is not a measurement of anything, however many bytes
    // it managed to emit first: a partial `tools/list` from a crashing server
    // was being spent as a token total.
    if (!row || row.status !== 'pass') return null;
    const recorded = row.identity && row.identity.artifact_id;
    if (!recorded || comparableId(recorded) !== r.vault_artifact) return null;
    return row;
  };

  const estimates = rows
    .filter((r) => !r.unreadable)
    .map((r) => {
      const row = measurementFor(r);
      const est = budget.estimateServer({
        name: r.name,
        // A server whose launched version differs from the DB's is not measured
        // by the DB's entry either: its tool surface is whatever that version
        // ships. Only an exact artifact match contributes a number.
        dbEntry: (r.in_db && r.version_match === 'same' && db.tools.find((t) => t.name === r.db_entry)) || null,
        evalEntry: row,
      });
      // A first page cannot be a total, so the number travels with the fact —
      // and `null` stays `null`: a row written before the field existed has
      // not established that its list was complete, and saying `false` would
      // be a claim nobody made.
      return { ...est, at_least: row ? (row.tools_truncated === undefined ? null : row.tools_truncated) : null };
    });
  const summary = budget.summarise(estimates);
  // "47% of your window" is a number; *which server* spent it is the finding.
  const heaviest = estimates
    .filter((e) => e.tokens !== null)
    .sort((a, b) => b.tokens - a.tokens)[0] || null;
  const share = heaviest ? Number(((heaviest.tokens / 200000) * 100).toFixed(1)) : null;

  // A server on a different version than the one we measured contributes no
  // number — but throwing the measurement away entirely loses a real finding
  // ("your hostinger server listed 396 tools") to protect against a small
  // one (it was a different version). So it is reported, as what it is: a
  // measurement of another artifact, named.
  //
  // Only real measurements appear here, labelled with the artifact the *eval*
  // recorded — not with the DB's current one. Labelling it with the DB artifact
  // invented the measurement's provenance, and including DB estimates made the
  // line claim a server "listed" tools when nothing had ever asked it.
  const elsewhere = rows
    .filter((r) => r.in_db && r.version_match !== 'same')
    .map((r) => {
      const row = evals.get(r.db_entry);
      if (!row || row.status !== 'pass') return null;
      const recorded = row.identity && row.identity.artifact_id;
      if (!recorded) return null;
      const e = budget.estimateServer({ name: r.name, dbEntry: null, evalEntry: row });
      if (e.tokens === null || e.source !== 'measured') return null;
      return {
        ...e,
        at_least: row.tools_truncated === undefined ? null : row.tools_truncated,
        measured_artifact: recorded,
        installed_artifact: r.installed_artifact,
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.tokens - a.tokens);

  return {
    ...summary,
    rows: estimates,
    heaviest: heaviest ? { ...heaviest, percent_of_context: share } : null,
    heavy: Boolean(share !== null && share >= HEAVY_SHARE),
    measured_on_another_version: elsewhere,
  };
}

/**
 * What the servers of one host can do *together* — lib/flows.cjs.
 *
 * Per host, because that is the unit that shares a context: a server in
 * Cursor and a server in Claude Code never see each other's output. Tool names
 * and hints come from the stored eval surface of the matched DB entry; when
 * the host launches another version than the one measured, the names are
 * still used (a rename is rarer than a leg) and the row says so.
 *
 * The findings go through decide() (rows `flows/*`, `shadowing/*`), and the
 * verdict below renders its Decisions.
 */
function setup({ installedRows, db, evals, capabilities, policy, asOf }) {
  const byHost = new Map();
  for (const r of installedRows) {
    if (r.unreadable) continue;
    const host = r.host || 'unknown';
    if (!byHost.has(host)) byHost.set(host, []);
    const dbEntry = r.in_db ? db.tools.find((t) => t.name === r.db_entry) || null : null;
    const evalEntry = dbEntry ? evals.get(dbEntry.name) || null : null;
    byHost.get(host).push(flows.memberFrom({
      name: r.name,
      dbEntry,
      evalEntry,
      capabilities,
      artifactIds: [r.installed_artifact, r.vault_artifact],
      launch: r.launches,
      note: dbEntry && r.version_match !== 'same' && evalEntry && evalEntry.surface
        ? `tool names measured on the vault's ${r.vault_artifact}, not ${r.installed_artifact || 'what this host launches'}`
        : null,
    }));
  }
  const sets = [...byHost.entries()].sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([host, members]) => ({ host, scope: 'installed', analysis: flows.analyseSet(members) }));
  const judged = flows.judgeSets(sets, policy, asOf);
  return {
    policy: { toxicFlows: policy.toxicFlows, toolShadowing: policy.toolShadowing },
    hosts: sets.map(({ host, analysis }) => ({ host, ...analysis, lines: judged.lines.filter((l) => l.host === host) })),
    judged,
  };
}

/** What this project's stack suggests that is not already installed. */
function project({ cwd, db, installedRows, asOf }) {
  const stack   = orchestrate.detectStack(cwd);
  const matched = orchestrate.matchDB(db, stack, null, asOf);
  const have    = new Set(installedRows.filter((r) => r.in_db).map((r) => r.db_entry));
  const missing = matched.filter((t) => !have.has(t.name));
  // `matchDB` always adds the universal three, so "no signals detected → 3
  // suggested" was a sentence that contradicted itself. They are worth
  // offering and they are not a statement about this project's stack.
  const universal = missing.filter((t) => orchestrate.UNIVERSAL_TOOLS.has(t.name)).map((t) => t.name);
  const forStack  = missing.filter((t) => !orchestrate.UNIVERSAL_TOOLS.has(t.name)).map((t) => t.name);
  return {
    signals: [...new Set([...stack.dbs, ...stack.infra, ...stack.langs])],
    suggested: matched.length,
    not_installed: missing.map((t) => t.name),
    not_installed_for_stack: forStack,
    not_installed_universal: universal,
  };
}

/**
 * Credentials written into the host configs in plain text. Same files as
 * `installed()`, so an unreadable one is already reported there. Findings
 * carry no value — type, file, path, length, a masked prefix.
 */
function secrets(cwd) {
  return secretsModel(cwd).block;
}

/** The scan, and its block (counts only: the findings are findings@1's). */
function secretsModel(cwd) {
  const r = scanHostConfigs({ cwd });
  return {
    scan: r,
    block: {
      files_read: r.files.length,
      tracked: r.findings.filter((f) => f.tracked === true).length,
      count: r.findings.length,
    },
  };
}

// ── verdict ─────────────────────────────────────────────────────────────────

/**
 * What in this picture should stop a pipeline — as findings, decided once.
 *
 * Every line below is a finding on a typed subject (docs/adr/0001): the
 * environment (doctor's checks), each configured server's host-config line
 * (unvetted, drift, a gone name, stale evidence — and what `audit` says about
 * the same line), the host configs (plain-text secrets, a config that would
 * not read), the policy file, and the cross-server flows. They go to
 * `audit`'s model (auditSetup.auditModel) with status's own beside them, so
 * one decide() call in mode `setup` answers for all of them, and the exit
 * code is that Decision's.
 *
 * The verdict is a view of it: a line is *blocking* when an outcome resting
 * on it denies, *worth knowing* when one warns or is unknown where --strict
 * reaches (fail_on), and *could not answer* when it is scope/unanswered.
 * Blocking and merely-worth-knowing are kept apart on purpose: an unvetted
 * server is a gap in *our* coverage, not a finding about the server, and a
 * default that failed on it would train people to pass --no-strict forever.
 */
function statusModel({
  cwd, envModel, env, installedRows, auditFindings, auditUnreadable = [], secretScan = null,
  setupReport = null, policyErrors = [], policyPath = null, policy, asOf,
}) {
  const findings = [];
  const subjects = [];
  // Rendered lines, in the order they were always printed, each resting on
  // the findings it was rendered from.
  const lines = [];
  const line = (text, ids) => lines.push({ text, ids });
  const own = (f) => { findings.push(f); return f.id; };

  // Plain-text credentials: one line for all of them. A tracked file is
  // named, because there the value is already in git history.
  const secretIds = [];
  if (secretScan) {
    const m = require('./lib/secrets.cjs').toFindings(secretScan, { cwd });
    for (const f of m.findings) if (f.rule !== 'scope/unreadable') secretIds.push(own(f));
    subjects.push(...m.subjects);
    const n = secretScan.findings.length;
    if (n) {
      const tracked = secretScan.findings.filter((f) => f.tracked);
      const trackedFiles = [...new Set(tracked.map((f) => path.basename(f.file)))];
      line(`${n} secret${n === 1 ? '' : 's'} in plain text in host configs`
        + (trackedFiles.length ? ` — ${tracked.length} in git-tracked ${trackedFiles.join(', ')}: rotate` : '')
        + ' (mcp-vault secrets)', secretIds);
    }
  }

  // This machine. A config that exists but does not parse is not a failing
  // environment, it is a question left unanswered — doctor says which.
  subjects.push(...envModel.subjects);
  for (const f of envModel.findings) findings.push(f);
  for (const c of env.failed) line(`environment: ${c.check} — ${c.detail}`, [envModel.ids[c.check]].filter(Boolean));

  // One line for all of them, not one line each: eleven near-identical rows
  // push the things that matter off the screen this command exists to fit.
  const unvetted = installedRows.filter((r) => !r.in_db && !r.unreadable);
  if (unvetted.length) {
    const ids = unvetted.map((r) => own(finding({
      rule: 'installed/not-in-vault', subject: r.subject, scope: 'installed', severity: 'medium', state: 'no-data',
      message: `${r.name}: not in the vault DB, so nothing here has checked it`,
    })));
    const names = unvetted.map((r) => r.name);
    line(`${names.length} configured server${names.length === 1 ? ' is' : 's are'} not in the vault DB, `
      + `so nothing here has checked ${names.length === 1 ? 'it' : 'them'}: ${names.slice(0, 8).join(', ')}`
      + (names.length > 8 ? `, +${names.length - 8}` : ''), ids);
  }

  for (const r of installedRows) {
    if (r.subject) subjects.push(r.subject);
    // A host config we could not read is not a host with nothing in it, and it
    // is not a finding about anybody's server either — it is the reason this
    // report is incomplete. Unanswered (exit 2), because "nothing blocked"
    // would be a claim about servers we never saw.
    if (r.unreadable) {
      line(`${r.path || r.name}: host config could not be read — ${r.unreadable}`,
        [own(unansweredFinding({ subject: r.subject, scope: 'installed', message: `${r.path || r.name}: host config could not be read — ${r.unreadable}` }))]);
      continue;
    }
    if (!r.in_db) continue;
    // Drift is a finding about *this host*, on every host — the audit below
    // only reads Claude Code's two files, so without this a Cursor-only setup
    // running an unpinned or superseded version came out clean.
    const text = `${r.name}: ${r.tier_reason}`;
    if (r.version_match === 'unknown') {
      // Our data, not theirs. Blaming a reader's setup for the vault's own
      // malformed entry — and failing their build for it under --strict — is
      // a finding pointed the wrong way: unanswered.
      line(text, [own(unansweredFinding({ subject: r.subject, scope: 'installed', message: text }))]);
      continue;
    }
    if (r.version_match !== 'same') {
      // A name that is gone applies whatever version is launched.
      line(text, [own(finding({
        rule: r.tier === 'Deprecated' ? 'installed/deprecated' : 'installed/drift', subject: r.subject, scope: 'installed',
        severity: r.tier === 'Deprecated' ? 'high' : 'medium', message: text,
      }))]);
      continue;
    }
    if (r.tier === 'Deprecated') {
      line(text, [own(finding({ rule: 'installed/deprecated', subject: r.subject, scope: 'installed', severity: 'high', message: text }))]);
    } else if (r.stale && r.stale.length) {
      const t = `${r.name}: ${r.stale.length} claim(s) past their shelf life (${r.stale.join(', ')})`;
      line(t, [own(finding({ rule: 'installed/stale', subject: r.subject, scope: 'installed', severity: 'medium', state: 'stale', message: t }))]);
    }
  }

  // A policy we could not read is not a policy with nothing in it — said out
  // loud, worth knowing (and so failing --strict, as `audit --strict` does).
  for (const e of policyErrors) line(`policy: ${e} — defaults in force for toxicFlows / toolShadowing`, []);

  // Cross-server findings, as decide() judged them (rows flows/*, shadowing/*):
  // a deny blocks, a warn is worth knowing; allow and unknown stay in --json.
  for (const l of (setupReport && setupReport.hosts || []).flatMap((h) => h.lines)) {
    line(`${l.host}: ${l.message}${l.rule.startsWith('flows/') && l.advice ? ` — ${l.advice}` : ''}`, l.findings);
  }

  // What `audit` says about the same configs, minus what it says about
  // servers this command already judged for every host (drift), and minus
  // what is not a finding here: a server the DB does not know is said once,
  // above; scope and version-unknown are informational.
  const legacy = auditFindings.filter((f) => {
    if (!['lookalike', 'drift', 'untrusted', 'heavy-unbounded'].includes(f.category)) return false;
    return !(f.category === 'drift' && installedRows.some((r) => r.name === f.server && r.version_match !== 'same'));
  });
  const model = auditSetup.auditModel({
    legacy, cwd, projectPath: path.join(cwd, '.mcp.json'), globalPath: path.join(process.env.HOME || '', '.claude.json'),
    setupJudged: setupReport && setupReport.judged, unreadable: auditUnreadable,
    policyErrors, policyPath, policy, asOf,
    extra: { findings, subjects },
  });
  // The policy-error lines rest on the audit model's own findings for them.
  let k = 0;
  for (const l of lines) if (l.text.startsWith('policy: ') && !l.ids.length) l.ids = model.idsOf(policyErrors[k++]);
  for (const u of auditUnreadable) {
    const text = `${u.path}: ${u.error}`;
    if (!lines.some((l) => l.text === text)) line(text, model.idsOf(u));
  }
  for (const f of legacy) {
    const text = `${f.server}: ${f.message}`;
    if (!lines.some((l) => l.text === text)) line(text, model.idsOf(f));
  }
  return { ...model, lines };
}

/**
 * The verdict: the model's lines, by what the Decision made of them. A
 * finding outranks an incomplete scope (exit 1 before 2), and everything is
 * printed either way.
 */
function verdict({ lines = [], decisions = [], exit = 0 }) {
  const out = { blocking: [], notable: [], unanswered: [] };
  const bucket = { blocking: out.blocking, notable: out.notable, unanswered: out.unanswered };
  for (const l of lines) {
    const c = classify(decisions, l.ids);
    if (c && !bucket[c].includes(l.text)) bucket[c].push(l.text);
  }
  return { ...out, exit_code: exit };
}

// ── report ──────────────────────────────────────────────────────────────────

const label = (s) => `${B}${String(s).padEnd(16)}${RS}`;

// The feedback line, under the same conditions as `check` (lib/feedback.cjs).
const { FEEDBACK_URL, feedbackLine } = require('./lib/feedback.cjs');

function printReport(r, { feedback = feedbackLine() } = {}) {
  const out = (s) => process.stdout.write(s);
  out(`\n${B}mcp-vault ${r.version}${RS} ${DM}· ${r.cwd} · as of ${r.as_of}${RS}\n\n`);

  // 1. environment
  const envBits = [`Node ${r.environment.node}`];
  if (r.environment.missing.length) envBits.push(`${YL}missing: ${r.environment.missing.join(', ')}${RS}`);
  out(`${label('Environment')}${envBits.join(' · ')}\n`);
  for (const f of r.environment.failed) out(`${' '.repeat(16)}${RD}✗ ${f.check}${RS} ${f.detail}\n`);

  // 2. installed
  const readable = r.installed.filter((x) => !x.unreadable);
  const matched  = readable.filter((x) => x.in_db && x.version_match === 'same');
  const drifted  = readable.filter((x) => x.in_db && x.version_match !== 'same');
  const unvetted = readable.filter((x) => !x.in_db);
  if (!readable.length) {
    out(`${label('Installed')}${DM}no MCP servers configured in any host this can read${RS}\n`);
  } else {
    out(`${label('Installed')}${readable.length} server${readable.length === 1 ? '' : 's'}`
      + ` ${DM}·${RS} ${matched.length} matched in the vault DB`
      + (drifted.length ? ` ${DM}·${RS} ${YL}${drifted.length} on another version${RS}` : '')
      + (unvetted.length ? ` ${DM}·${RS} ${YL}${unvetted.length} unvetted${RS}` : '') + '\n');
    const tiers = {};
    for (const x of matched) tiers[x.tier] = (tiers[x.tier] || 0) + 1;
    const tierLine = Object.entries(tiers).map(([t, n]) => `${n} ${t}`).join(' · ');
    if (tierLine) out(`${' '.repeat(16)}${DM}${tierLine}${RS}\n`);
  }

  // 3. evidence — with its date, never implying it was checked just now
  const dates = matched.map((x) => x.oldest_evidence).filter(Boolean).sort();
  if (dates.length) {
    out(`${label('Evidence')}oldest claim ${dates[0]} ${DM}(stored; nothing was re-checked just now)${RS}\n`);
  }

  // 4. context
  if (r.context.servers) {
    const c = r.context;
    // `null` is "we do not know whether that list was complete", and printing
    // "at least" for it turns an unknown into an affirmative lower bound — a
    // DB *estimate* of 100 tools became "at least 35,000 tokens".
    const lowerBound = (c.rows || []).some((e) => e.at_least === true && e.tokens !== null);
    out(`${label('Context')}${lowerBound ? 'at least ' : ''}${c.tokens.toLocaleString('en-US')} tokens on every request`
      + ` ${DM}·${RS} ${c.percent_of_context}% of a 200k window`
      + (c.unknown_servers ? ` ${DM}·${RS} ${YL}${c.unknown_servers} not measured${RS}` : '') + '\n');
    if (c.heavy) {
      out(`${' '.repeat(16)}${YL}${c.heaviest.name}${RS} alone is ${c.heaviest.percent_of_context}%`
        + ` ${DM}(${c.heaviest.tools} tools, ${c.heaviest.source}) — scope it with --toolsets or allowedTools${RS}\n`);
    }
    const big = (c.measured_on_another_version || [])[0];
    if (big) {
      out(`${' '.repeat(16)}${DM}not counted: ${big.name} listed ${big.at_least === true ? 'at least ' : ''}${big.tools} tools`
        + ` (~${big.tokens.toLocaleString('en-US')}) when we measured ${big.measured_artifact},`
        + ` but this host launches ${big.installed_artifact}${RS}\n`);
    }
  }

  // 5. what the set can do together
  for (const h of (r.setup && r.setup.hosts) || []) {
    const counted = (prefix) => h.lines.filter((l) => l.rule.startsWith(prefix) && (l.effect === 'deny' || l.effect === 'warn')).length;
    const high = counted('flows/');
    const shared = counted('shadowing/');
    const bits = [
      // "No toxic flow" about servers nobody could see into would be the
      // summary claiming more than its inputs support.
      high ? `${YL}${high} toxic flow${high === 1 ? '' : 's'}${RS}`
        : (h.no_data.length === h.servers.length ? `${DM}nothing known about these servers${RS}` : 'no toxic flow found'),
      shared ? `${YL}${shared} tool-name overlap${shared === 1 ? '' : 's'}${RS}` : null,
      h.no_data.length ? `${DM}${h.no_data.length} without data${RS}` : null,
    ].filter(Boolean);
    out(`${label('Flows')}${h.host}: ${bits.join(` ${DM}·${RS} `)}\n`);
  }

  // 6. this project
  const p = r.project;
  const suggestion = p.not_installed_for_stack.length
    ? ` ${DM}→${RS} ${p.not_installed_for_stack.length} matching server${p.not_installed_for_stack.length === 1 ? '' : 's'} not installed`
      + ` ${DM}(${p.not_installed_for_stack.slice(0, 3).join(', ')}${p.not_installed_for_stack.length > 3 ? ', …' : ''})${RS}`
    : (p.not_installed_universal.length ? ` ${DM}→ nothing stack-specific; ${p.not_installed_universal.length} universally useful not installed${RS}` : '');
  out(`${label('This project')}`
    + (p.signals.length ? `${p.signals.slice(0, 6).join(', ')}${p.signals.length > 6 ? `, +${p.signals.length - 6}` : ''}` : `${DM}no stack signals detected${RS}`)
    + suggestion + '\n');

  // findings
  if (r.verdict.unanswered.length) {
    out(`\n${YL}${B}Could not answer${RS}\n`);
    for (const line of r.verdict.unanswered) out(`  ${YL}?${RS} ${line}\n`);
    out(`  ${DM}so "nothing blocked" below is not a claim about whatever is in there${RS}\n`);
  }
  if (r.verdict.blocking.length) {
    out(`\n${RD}${B}Blocking${RS}\n`);
    for (const line of r.verdict.blocking) out(`  ${RD}✗${RS} ${line}\n`);
  }
  if (r.verdict.notable.length) {
    out(`\n${YL}${B}Worth knowing${RS}\n`);
    for (const line of r.verdict.notable.slice(0, 6)) out(`  ${YL}!${RS} ${line}\n`);
    if (r.verdict.notable.length > 6) out(`  ${DM}…and ${r.verdict.notable.length - 6} more (mcp-vault audit)${RS}\n`);
  }
  if (!r.verdict.blocking.length && !r.verdict.notable.length && !r.verdict.unanswered.length) {
    out(`\n${GN}Nothing blocked, nothing drifted.${RS}\n`);
  }

  // where to go deeper — the commands this one replaced, named so they stay
  // discoverable rather than hidden behind a summary.
  out(`\n${DM}Deeper:  verify --installed  re-hash what your hosts launch, live`);
  out(`\n         explain <name>      why one entry is allowed or denied`);
  out(`\n         scan                what to add for this stack`);
  out(`\n         audit --strict      every drift and scope finding in full`);
  out(`\n         secrets             plain-text credentials in host configs${RS}\n\n`);
  if (feedback) out(`${DM}${feedback}${RS}\n\n`);
}

// ── main ────────────────────────────────────────────────────────────────────

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`status: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }

  // A `--cwd` that does not exist is not a project with no signals in it.
  // Every block below would have reported cheerfully on nothing.
  try {
    if (!fs.statSync(opts.cwd).isDirectory()) throw new Error('not a directory');
  } catch (e) {
    process.stderr.write(`status: cannot read ${opts.cwd}: ${e.message}\n`);
    return 2;
  }

  const rawDb = readJson(DB_PATH);
  if (!rawDb || !Array.isArray(rawDb.tools)) {
    process.stderr.write(`status: DB not found or malformed: ${DB_PATH}\n`);
    return 2;
  }
  // The record as it stood at asOf: a look dated later did not exist then.
  const db = dbAsOf(rawDb, opts.asOf);
  const evals = evalIndex(evalResultsAsOf((readJson(EVAL_PATH) || {}).results, opts.asOf));
  const pkg   = readJson(PKG_PATH) || {};
  // The one policy loader (lib/policy_rules.cjs): the file, then --strict,
  // frozen. --strict is the decision's fail_on, not a branch below.
  const loadedPolicy = loadEffectivePolicy(opts.cwd, { flags: { strict: opts.strict } });

  const envModel      = environmentModel(opts.cwd);
  const env           = envModel.block;
  const installedRows = installed({ cwd: opts.cwd, db, evals, asOf: opts.asOf });
  // The audit's own reads can fail too, and its default settings are the
  // answer that *creates* heavy-unbounded findings, so an unreadable
  // `.claude/settings.json` must not silently become "nothing is scoped".
  const auditUnreadable = [];
  const auditFindings = auditSetup.audit({
    project:  auditSetup.readProjectMcpServers(opts.cwd, auditUnreadable),
    global:   auditSetup.readGlobalMcpServers(path.join(process.env.HOME || '', '.claude.json'), auditUnreadable),
    settings: auditSetup.readSettings(opts.cwd, auditUnreadable),
    db,
    evals,
  });
  const sec = secretsModel(opts.cwd);

  const report = {
    schema:  'mcp-vault/status@1',
    version: pkg.version || 'unknown',
    cwd:     opts.cwd,
    generated_at: opts.asOfIso,
    // Additive: the instant every stored claim below was judged at. The same
    // as `generated_at` unless `--as-of` replayed another one.
    as_of: opts.asOfIso,
    // Said once, out loud: nothing below was measured during this run.
    evidence_source: 'stored',
    max_age_days: DEFAULT_MAX_AGE_DAYS,
    environment: env,
    installed:   installedRows,
    context:     context(installedRows, db, evals),
    project:     project({ cwd: opts.cwd, db, installedRows, asOf: opts.asOf }),
    // Counts only (pre-1.0): each secret is a finding in `findings`.
    secrets:     sec.block,
  };
  const setupReport = setup({
    installedRows, db, evals, capabilities: readJson(CAPS_PATH) || { packages: {} },
    policy: loadedPolicy.policy, asOf: opts.asOf,
  });
  report.setup = { policy: setupReport.policy, hosts: setupReport.hosts };
  // Everything on this screen as findings, decided once (docs/adr/0001).
  const model = statusModel({
    cwd: opts.cwd, envModel: envModel.model, env, installedRows, auditFindings, auditUnreadable,
    secretScan: sec.scan, setupReport, policyErrors: loadedPolicy.errors, policyPath: loadedPolicy.path,
    policy: loadedPolicy.policy, asOf: opts.asOf,
  });
  // mcp-vault/findings@1: every finding above, the policy and facts it was
  // decided on, and the Decision per subject — the verdict is a view of it.
  report.findings = model.document;
  report.verdict = verdict(model);

  if (opts.json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else printReport(report);

  return report.verdict.exit_code;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, environment, installed, context, setup, project, secrets, statusModel, verdict, printReport, feedbackLine, FEEDBACK_URL, main };
