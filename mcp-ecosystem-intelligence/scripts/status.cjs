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
 *   node scripts/status.cjs [--cwd <dir>] [--json] [--strict]
 *
 * Exit codes:
 *   0  nothing installed is blocked, and the environment can run this
 *   1  an installed server is blocked (gone / wrong bytes / live advisory),
 *      or a required environment check failed; with --strict, also drift,
 *      unvetted servers and stale evidence
 *   2  bad arguments / the DB could not be read
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const { exitAfterFlush }   = require('./lib/exit.cjs');
const { readInstalledServers, toInstallCmd } = require('./lib/installed.cjs');
const { trustScore }       = require('./lib/scores.cjs');
const { classifyEntry, evalIndex, currentArtifactId } = require('./lib/tiers.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { isExactVersion } = require('./lib/install_cmd.cjs');
const { staleDimensions, DEFAULT_MAX_AGE_DAYS } = require('./lib/evidence.cjs');
const budget               = require('./lib/budget.cjs');
const { runDoctor }        = require('./doctor.cjs');
const orchestrate          = require('./orchestrate.cjs');
const auditSetup           = require('./audit_setup.cjs');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');
const PKG_PATH  = path.resolve(__dirname, '../../package.json');

const T  = process.stdout.isTTY && !process.env.NO_COLOR;
const B  = T ? '\x1b[1m'  : '';
const DM = T ? '\x1b[2m'  : '';
const RD = T ? '\x1b[31m' : '';
const GN = T ? '\x1b[32m' : '';
const YL = T ? '\x1b[33m' : '';
const RS = T ? '\x1b[0m'  : '';

const HELP = `mcp-vault status — one screen: what is installed, what is wrong, what is missing

  node scripts/status.cjs [--cwd <dir>] [--json] [--strict]

  --cwd      project to read (default: the current directory)
  --json     machine-readable (schema mcp-vault/status@1)
  --strict   also exit 1 on drift, unvetted servers and stale evidence

Reads only what is already on disk, so it makes no network calls. The footer
names the commands that do.
`;

function parseArgs(argv) {
  const opts = { cwd: process.cwd(), json: false, strict: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--cwd') { opts.cwd = argv[++i]; if (!opts.cwd) return { error: '--cwd needs a directory' }; }
    else return { error: `unknown argument: ${a}` };
  }
  return opts;
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

// ── the five questions ──────────────────────────────────────────────────────

/** Can this machine run any of it? Only the things that are not fine. */
function environment(cwd) {
  const doc = runDoctor({ cwd });
  const problems = doc.checks.filter((c) => c.level !== 'ok');
  return {
    node: process.version,
    counts: doc.counts,
    // A `fail` is a blocker; a `warn` is an optional tool that is absent, and
    // an absent optional tool is not a finding about this project.
    failed:  problems.filter((c) => c.level === 'fail').map((c) => ({ check: c.name, detail: c.message })),
    // Optional tools that are absent. Not a finding about this project — but
    // worth one word, because a missing `uvx` silently limits what installs.
    missing: problems.filter((c) => c.level === 'warn' && c.optional).map((c) => c.name),
  };
}

/**
 * PyPI project names are compared normalised (PEP 503): lowercase, with every
 * run of `-`, `_` and `.` folded to a single `-`.
 *
 * `awslabs_core_mcp_server` and `awslabs.core-mcp-server` are the same
 * distribution, and `uvx` installs either spelling. Comparing the raw strings
 * meant a host launching the underscore form of a yanked package came out as
 * an unvetted server nothing had checked — the finding was in the DB and the
 * match never happened. npm names are not folded this way: there, `a-b` and
 * `a.b` are genuinely different packages.
 */
function normalizePypiName(name) {
  return String(name).toLowerCase().replace(/[-_.]+/g, '-');
}

/**
 * The package identity of an artifact, with the version dropped.
 *
 * This is what "is this the same package?" means. `artifactId` deliberately
 * includes the version, because evidence about 1.2.3 says nothing about 1.2.4
 * — so matching needs the coarser key, and the version comparison happens
 * separately and explicitly.
 */
function packageKey(artifact) {
  if (!artifact) return null;
  switch (artifact.ecosystem) {
    case 'npm':  return artifact.package ? `npm:${artifact.package}` : null;
    case 'pypi': return artifact.package ? `pypi:${normalizePypiName(artifact.package)}` : null;
    case 'oci':  return artifact.image ? `oci:${artifact.image}` : null;
    case 'git':  return artifact.source ? `git:${artifact.source}` : null;
    default:     return null;
  }
}

/**
 * Does this artifact reference resolve to one set of bytes?
 *
 * Two references being *equal* only means the same bytes when each of them
 * names an exact artifact. `npx -y pkg` on both sides is equal and resolves to
 * whatever npm publishes at start-up; `pkg@latest` is equal and is a moving
 * tag. Treating either as "same" handed the DB's evidence to bytes nobody had
 * seen — the same error as matching by the config key, one level down.
 */
function isExactReference(artifact) {
  if (!artifact) return false;
  switch (artifact.ecosystem) {
    case 'npm':  return isExactVersion('npx', artifact.version || '');
    case 'pypi': return isExactVersion('uvx', artifact.version || '');
    case 'oci':  return Boolean(artifact.digest);
    // A git source install has no version to be exact about.
    case 'git':  return false;
    default:     return false;
  }
}

/** A comparable id that folds PyPI spellings, so two names for one distribution match. */
function comparableArtifactId(artifact) {
  const id = artifactId(artifact);
  if (!id || !artifact || artifact.ecosystem !== 'pypi') return id;
  return `pypi:${normalizePypiName(artifact.package)}${artifact.version ? `@${artifact.version}` : ''}`;
}

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
function installed({ cwd, db, evals }) {
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
    const base    = { name: server.name, host: server.host, scope: server.scope || null, launches: withCmd.install_cmd || null };

    if (!entry) {
      rows.push({ ...base, in_db: false, package: key });
      continue;
    }

    const installedId = artifactId(typed.artifact);
    const vaultId     = currentArtifactId(entry);
    const vaultTyped  = toTypedEntry(entry);
    // Equality is necessary and not sufficient: both sides must also *resolve*
    // to one artifact. `npx -y pkg` equals `npx -y pkg` and names nothing.
    const pinned      = isExactReference(typed.artifact);
    const vaultPinned = Boolean(vaultTyped && isExactReference(vaultTyped.artifact));
    const comparable  = comparableArtifactId(typed.artifact);
    const vaultComparable = vaultTyped ? comparableArtifactId(vaultTyped.artifact) : null;
    const version_match = (!comparable || !vaultComparable || !vaultId) ? 'unknown'
      : (pinned && vaultPinned && comparable === vaultComparable ? 'same' : 'different');

    const row = {
      ...base,
      in_db: true,
      db_entry: entry.name,
      package: key,
      installed_artifact: installedId,
      vault_artifact: vaultId,
      version_match,
      pinned,
    };

    if (version_match !== 'same') {
      // No tier: every stored claim under this entry is about `vault_artifact`.
      row.tier = null;
      row.tier_reason = !pinned
        ? `the launch command resolves at start-up (${installedId || 'unparseable'}), so what runs is not the ${vaultId || 'artifact'} the vault verified`
        : (!vaultPinned
          ? `the vault's own entry is not pinned to one artifact (${vaultId}), so there is nothing to compare this host's ${installedId} against`
          : `the vault verified ${vaultId}; this host launches ${installedId}`);
      rows.push(row);
      continue;
    }

    const tier  = classifyEntry(entry, evals.get(entry.name) || null);
    const trust = trustScore(entry.trust_evidence || null);
    const dims  = (entry.trust_evidence && entry.trust_evidence.dimensions) || {};
    const dates = Object.values(dims).map((d) => d.checked_at).filter(Boolean).sort();
    rows.push({
      ...row,
      tier: tier.classification,
      tier_reason: tier.why,
      trust_gate: trust.gate,
      blocking: trust.blocking.map((b) => `${b.dimension}: ${b.status}`),
      oldest_evidence: dates[0] || null,
      stale: staleDimensions(entry.trust_evidence || null).map((s) => s.dimension),
    });
  }
  // A host config that could not be read is not a host with no servers.
  for (const loc of unreadable) {
    rows.push({
      name: `(${loc.host || loc.path})`,
      host: loc.host || null,
      in_db: false,
      unreadable: loc.error || 'unparseable',
      path: loc.path || null,
    });
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
    if (!row) return null;
    const recorded = row.identity && row.identity.artifact_id;
    if (!recorded || recorded !== r.vault_artifact) return null;
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
      // A first page cannot be a total, so the number travels with the fact.
      return { ...est, at_least: Boolean(row && row.tools_truncated) };
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
      const recorded = row && row.identity && row.identity.artifact_id;
      if (!recorded) return null;
      const e = budget.estimateServer({ name: r.name, dbEntry: null, evalEntry: row });
      if (e.tokens === null || e.source !== 'measured') return null;
      return {
        ...e,
        at_least: Boolean(row.tools_truncated),
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

/** What this project's stack suggests that is not already installed. */
function project({ cwd, db, installedRows }) {
  const stack   = orchestrate.detectStack(cwd);
  const matched = orchestrate.matchDB(db, stack, null);
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

// ── verdict ─────────────────────────────────────────────────────────────────

/**
 * What in this picture should stop a pipeline.
 *
 * Blocking and merely-worth-knowing are kept apart on purpose: an unvetted
 * server is a gap in *our* coverage, not a finding about the server, and a
 * default that failed on it would train people to pass --no-strict forever.
 */
function verdict({ env, installedRows, auditFindings, strict }) {
  const blocking   = [];   // something installed must not run  → 1
  const notable    = [];   // worth knowing, not a blocker      → 1 only with --strict
  const unanswered = [];   // a question we could not answer    → 2

  for (const c of env.failed) {
    // A config file that exists but does not parse is not a failing
    // environment, it is a question left unanswered. Doctor reports both as
    // `fail`; only the parse failures belong in `unanswered`.
    (/parse failed/i.test(c.detail) ? unanswered : blocking)
      .push(`environment: ${c.check} — ${c.detail}`);
  }

  // One line for all of them, not one line each: eleven near-identical rows
  // push the things that matter off the screen this command exists to fit.
  const unvetted = installedRows.filter((r) => !r.in_db && !r.unreadable).map((r) => r.name);
  if (unvetted.length) {
    notable.push(`${unvetted.length} configured server${unvetted.length === 1 ? ' is' : 's are'} not in the vault DB, `
      + `so nothing here has checked ${unvetted.length === 1 ? 'it' : 'them'}: ${unvetted.slice(0, 8).join(', ')}`
      + (unvetted.length > 8 ? `, +${unvetted.length - 8}` : ''));
  }

  for (const r of installedRows) {
    // A host config we could not read is not a host with nothing in it, and it
    // is not a finding about anybody's server either — it is the reason this
    // report is incomplete. Exit 2, because "nothing blocked" would be a claim
    // about servers we never saw.
    if (r.unreadable) {
      unanswered.push(`${r.path || r.name}: host config could not be read — ${r.unreadable}`);
      continue;
    }
    if (!r.in_db) continue;
    // Drift is a finding about *this host*, on every host — the audit below
    // only reads Claude Code's two files, so without this a Cursor-only setup
    // running an unpinned or superseded version came out clean.
    if (r.version_match !== 'same') { notable.push(`${r.name}: ${r.tier_reason}`); continue; }
    if (r.tier === 'Deprecated') blocking.push(`${r.name}: ${r.tier_reason}`);
    else if (r.stale && r.stale.length) notable.push(`${r.name}: ${r.stale.length} claim(s) past their shelf life (${r.stale.join(', ')})`);
  }

  for (const f of auditFindings) {
    if (!auditSetup.STRICT_CATEGORIES.has(f.category)) continue;
    const line = `${f.server}: ${f.message}`;
    // The drift loop above already said it, for every host rather than two.
    if (f.category === 'drift' && installedRows.some((r) => r.name === f.server && r.version_match !== 'same')) continue;
    if (!notable.includes(line)) notable.push(line);
  }

  const code = unanswered.length ? 2 : (blocking.length ? 1 : (strict && notable.length ? 1 : 0));
  return { blocking, notable, unanswered, exit_code: code };
}

// ── report ──────────────────────────────────────────────────────────────────

const label = (s) => `${B}${String(s).padEnd(16)}${RS}`;

function printReport(r) {
  const out = (s) => process.stdout.write(s);
  out(`\n${B}mcp-vault ${r.version}${RS} ${DM}· ${r.cwd}${RS}\n\n`);

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
    const lowerBound = (c.rows || []).some((e) => e.at_least && e.tokens !== null);
    out(`${label('Context')}${lowerBound ? 'at least ' : ''}${c.tokens.toLocaleString('en-US')} tokens on every request`
      + ` ${DM}·${RS} ${c.percent_of_context}% of a 200k window`
      + (c.unknown_servers ? ` ${DM}·${RS} ${YL}${c.unknown_servers} not measured${RS}` : '') + '\n');
    if (c.heavy) {
      out(`${' '.repeat(16)}${YL}${c.heaviest.name}${RS} alone is ${c.heaviest.percent_of_context}%`
        + ` ${DM}(${c.heaviest.tools} tools, ${c.heaviest.source}) — scope it with --toolsets or allowedTools${RS}\n`);
    }
    const big = (c.measured_on_another_version || [])[0];
    if (big) {
      out(`${' '.repeat(16)}${DM}not counted: ${big.name} listed ${big.at_least ? 'at least ' : ''}${big.tools} tools`
        + ` (~${big.tokens.toLocaleString('en-US')}) when we measured ${big.measured_artifact},`
        + ` but this host launches ${big.installed_artifact}${RS}\n`);
    }
  }

  // 5. this project
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
  out(`\n         audit --strict      every drift and scope finding in full${RS}\n\n`);
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

  const db = readJson(DB_PATH);
  if (!db || !Array.isArray(db.tools)) {
    process.stderr.write(`status: DB not found or malformed: ${DB_PATH}\n`);
    return 2;
  }
  const evals = evalIndex((readJson(EVAL_PATH) || {}).results);
  const pkg   = readJson(PKG_PATH) || {};

  const env           = environment(opts.cwd);
  const installedRows = installed({ cwd: opts.cwd, db, evals });
  const auditFindings = auditSetup.audit({
    project:  auditSetup.readProjectMcpServers(opts.cwd),
    global:   auditSetup.readGlobalMcpServers(path.join(process.env.HOME || '', '.claude.json')),
    settings: auditSetup.readSettings(opts.cwd),
    db,
    evals,
  });

  const report = {
    schema:  'mcp-vault/status@1',
    version: pkg.version || 'unknown',
    cwd:     opts.cwd,
    generated_at: new Date().toISOString(),
    // Said once, out loud: nothing below was measured during this run.
    evidence_source: 'stored',
    max_age_days: DEFAULT_MAX_AGE_DAYS,
    environment: env,
    installed:   installedRows,
    context:     context(installedRows, db, evals),
    project:     project({ cwd: opts.cwd, db, installedRows }),
    audit:       auditFindings,
  };
  report.verdict = verdict({ env, installedRows, auditFindings, strict: opts.strict });

  if (opts.json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else printReport(report);

  return report.verdict.exit_code;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, environment, installed, context, project, verdict, main };
