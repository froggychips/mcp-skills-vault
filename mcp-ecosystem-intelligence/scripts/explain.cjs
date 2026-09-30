#!/usr/bin/env node
/**
 * mcp-vault explain <name> — why this entry is allowed, or why it is not.
 *
 * Everything needed to answer that already existed: dated evidence per
 * dimension, three scores, a policy file, a behavioural record. What did not
 * exist was a way to *ask*. The information was spread across a gate report, a
 * DB field, a scan's JSON and a policy nobody prints, so the answer to "why
 * can't I install this" was "read four outputs and work it out".
 *
 * Two audiences, one command:
 *
 *   a person   gets the decision, the rule that decided it, and the evidence
 *              with the date each claim was established
 *   a pipeline gets `--json`: a decision record with the policy, the rules
 *              evaluated, the evidence and a content digest. Appended to a file
 *              with `--record`, those records are the audit trail — "this was
 *              allowed on that date, under that policy, on that evidence" —
 *              which is the thing a policy engine is asked for six months later
 *              and cannot reconstruct.
 *
 * Offline by default, and says so: the answer comes from stored evidence, which
 * is dated, so a reader can see how old it is rather than being told a stale
 * claim as if it were current. `--verify` runs the live gate first for a
 * decision about now.
 *
 * Usage:
 *   node scripts/explain.cjs <name> [--json] [--verify] [--cwd <path>]
 *                                   [--record <file>] [--installed] [--as-of <date>]
 *                                   [--strict] [--fail-unverified]
 *
 * Exit codes — the gate's, for this entry (`verify` with the same policy,
 * flags and --as-of exits the same way):
 *   0  the decision does not fail at the policy's fail_on
 *   1  it does (deny always — including a name not in the vault but shaped
 *      like an entry that is; unknown under `unverified: fail` /
 *      --fail-unverified; warn under --strict)
 *   2  the entry could not be found / bad arguments
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb } = require('./lib/db_io.cjs');
const { DEFAULTS } = require('./lib/policy.cjs');
const { effectivePolicy, loadEffectivePolicy, flagsFromArgv, evidenceRuleOutcomes, rowFor } = require('./lib/policy_rules.cjs');
const { decide: decideFindings, findingsDocument, toJson, explainTrace, renderTrace } = require('./lib/finding.cjs');
const { hasOrgRules, loadOrgContext, orgModel } = require('./lib/org_policy.cjs');
const { subjectForTool, fromStoredEvidence, storedEvidenceFor, fromReportEntry } = require('./lib/findings_from.cjs');
const { trustScore, fitScore, behaviour, recommend } = require('./lib/scores.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { staleDimensions, DIMENSIONS, DEFAULT_MAX_AGE_DAYS, POSITIVE_STATUSES, maxAgeForPolicy, dbAsOf, evalResultsAsOf } = require('./lib/evidence.cjs');
const { estimateServer, matchDbEntry, wouldExceed, DEFAULT_CONTEXT } = require('./lib/budget.cjs');
const { readInstalledServers } = require('./lib/installed.cjs');
const { asOfFromArgv } = require('./lib/clock.cjs');
const { readLocalAudits, loadImportedAudits, auditsFor, auditObservations } = require('./lib/audits.cjs');
const flows = require('./lib/flows.cjs');
const { finding } = require('./lib/finding.cjs');
const { evalRowFindings } = require('./lib/tool_scan.cjs');
const lookalike = require('./lib/lookalike.cjs');

const DB_PATH    = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH  = path.resolve(__dirname, '../assets/eval_results.json');
const CAPS_PATH  = path.resolve(__dirname, '../assets/capabilities.json');
const VERIFY_CJS = path.resolve(__dirname, 'verify_integrity.cjs');

const T  = process.stdout.isTTY;
const B  = T ? '\x1b[1m'  : '';
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

function parseArgs(argv) {
  const opts = { name: null, json: false, verify: false, cwd: process.cwd(), record: null, help: false, asOf: null, flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--verify') opts.verify = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--cwd') opts.cwd = argv[++i] || opts.cwd;
    else if (a === '--record') opts.record = argv[++i] || null;
    else if (a === '--as-of') i++;
    else if (a === '--strict' || a === '--fail-unverified') { /* read below */ }
    else if (a.startsWith('--as-of=')) { /* read below */ }
    else if (a.startsWith('--')) return { ...opts, error: `unknown flag ${a}` };
    else if (!opts.name) opts.name = a;
    else return { ...opts, error: 'explain takes one entry name' };
  }
  if (!opts.name && !opts.help) return { ...opts, error: 'which entry? `mcp-vault explain <name>`' };
  // The one clock read for this run; see lib/clock.cjs.
  const clock = asOfFromArgv(argv);
  if (clock.error) return { ...opts, error: clock.error };
  // --verify runs the live gate, which observes today; a replayed instant
  // would date those answers in the past (verify refuses the same pair).
  if (opts.verify && clock.source === 'as-of') return { ...opts, error: '--as-of replays stored evidence and cannot be combined with --verify (a live gate run observes today)' };
  // The bar-raising switches verify takes, read by the same function, so the
  // threshold (fail_on) is the one verify would hold this entry to.
  return { ...opts, asOf: clock.asOf, asOfIso: clock.iso, asOfSource: clock.source, flags: flagsFromArgv(argv) };
}

const HELP = `explain — why this entry is allowed, or why it is not

  node scripts/explain.cjs <name> [--json] [--verify] [--record <file>]
                            [--strict] [--fail-unverified]

  --verify        run the live integrity gate first (network); otherwise the
                  answer comes from stored, dated evidence
  --record <file> append the decision record as one JSON line (audit trail)
  --cwd <path>    the project whose policy and configured servers apply
  --as-of <date>  judge the stored evidence as of this date (YYYY-MM-DD or an
                  ISO-8601 instant) instead of now
  --strict        warnings fail too (as for verify)
  --fail-unverified  "could not check" fails too (as for verify)

  Exit: 0 passes, 1 fails at the policy's fail_on — the same threshold and
  flags verify uses, so both exit alike for this entry; 2 bad arguments.
`;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

/** The live gate's own verdict for one entry, when --verify is given. */
function runGate(name, cwd, asOfIso = null, flags = {}) {
  // The gate judges at the same instant this decision does, or the two halves
  // of one record would be about different days.
  const args = [VERIFY_CJS, '--entry', name, '--json', '--cwd', cwd];
  if (asOfIso) args.push('--as-of', asOfIso);
  if (flags.strict) args.push('--strict');
  if (flags.failUnverified) args.push('--fail-unverified');
  const res = spawnSync(process.execPath, args, {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  if (res.error) return { ok: false, error: res.error.message };
  let report = null;
  try { report = JSON.parse(res.stdout); } catch { /* the gate printed something else */ }
  if (!report) return { ok: false, error: `the gate produced no JSON report (exit ${res.status})` };
  return { ok: true, exit: res.status, report };
}

/**
 * The policy rules that normally read a gate's findings, answered from stored
 * evidence instead — with `unknown` where the evidence is silent.
 *
 * Each rule has three possible answers and they are different claims:
 *   allow    the evidence establishes what the policy asks for
 *   deny     the evidence establishes the opposite
 *   unknown  nothing has been recorded about it; run `--verify`
 *
 * The middle one is the reason this function exists. `evaluateEntry` decides
 * from the *absence* of a finding, which is correct when a gate has just run
 * and wrong when no gate ran at all.
 *
 * The rules are rows in lib/policy_rules.cjs (evidence mode); this returns
 * their outcomes in the shape explain has always printed.
 */
function policyFromEvidence(policy, tool, evidence) {
  const ep = asEffective(policy);
  return evidenceRuleOutcomes({
    subject: null, findings: [], policy: ep, mode: 'evidence',
    facts: { entry: { install_cmd: tool.install_cmd || '' }, evidence },
  }).map((o) => ({ rule: o.rule, outcome: o.effect, detail: o.detail }));
}

// A policy object that did not come through `loadEffectivePolicy` (a test's
// literal, the DEFAULTS) is normalised the same way before anything reads it.
function asEffective(policy) {
  return policy && Object.isFrozen(policy) && policy.gate ? policy : effectivePolicy(policy, {}, { defaults: DEFAULTS });
}

/**
 * What this entry would take part in beside what is already configured —
 * lib/flows.cjs, per host — as findings about *this entry* (subject: the
 * entry; scope: the host, or `alone` when nothing is configured, which is
 * still the GitHub case: one server can hold every leg).
 *
 * A flow the host already had without this entry is not a finding about it:
 * it goes in `already_present`, for the record, and not to decide(). One this
 * entry closes by itself is always about it. Configured servers are matched to
 * the vault by what they launch, never by their config key.
 *
 * Returns { findings, meta, already_present } — `meta` maps a finding id to
 * the host, servers and advice a rendering shows beside it.
 */
function setupFindings({ tool, subject: s, db, evalBy, capabilities, installed }) {
  let typed = null;
  try { typed = toTypedEntry(tool); } catch { typed = null; }
  const self = flows.memberFrom({
    name: tool.name, dbEntry: tool, evalEntry: evalBy.get(tool.name) || null, capabilities,
    artifactIds: [typed ? artifactId(typed.artifact) : null], launch: tool.install_cmd,
  });
  const byHost = new Map();
  for (const srv of installed) {
    const dbEntry = flows.dbEntryForLaunch(db.tools || [], srv.install_cmd);
    // Already configured: the entry being explained takes its place.
    if (dbEntry && dbEntry.name === tool.name) continue;
    const host = srv.host || 'unknown';
    if (!byHost.has(host)) byHost.set(host, []);
    let t = null;
    try { t = dbEntry ? toTypedEntry(dbEntry) : null; } catch { t = null; }
    byHost.get(host).push(flows.memberFrom({
      name: srv.name, dbEntry, evalEntry: dbEntry ? evalBy.get(dbEntry.name) || null : null, capabilities,
      artifactIds: [t ? artifactId(t.artifact) : null], launch: srv.install_cmd,
    }));
  }
  if (!byHost.size) byHost.set(null, []);
  const findings = [];
  const meta = {};
  const alreadyPresent = [];
  for (const [host, members] of byHost) {
    const before = new Set(flows.conclusions(flows.analyseSet(members))
      .filter((c) => c.confidence === 'high').map((c) => c.rule));
    for (const c of flows.grouped(flows.conclusions(flows.analyseSet([...members, self])))) {
      if (!c.servers.includes(tool.name)) continue;
      const alone = c.servers.length === 1;
      if (c.rule.startsWith('flows/') && !alone && before.has(c.rule)) {
        alreadyPresent.push({ host, rule: c.rule, servers: c.servers, message: c.message });
        continue;
      }
      const f = finding({
        rule: c.rule, subject: s, scope: host || 'alone', severity: c.severity, confidence: c.confidence,
        message: `${host ? `${host}: ` : ''}${c.message}`,
      });
      findings.push(f);
      meta[f.id] = { host, rule: c.rule, servers: c.servers, advice: c.advice };
    }
  }
  return { findings, meta, already_present: alreadyPresent };
}

/**
 * The model for one entry: observations from the stored evidence, findings
 * from the evidence and — with `--verify` — from the live gate, and the one
 * Decision `decide()` makes over them. explain renders it; it decides nothing.
 */
function explainModel({ tool, policy, gateEntry = null, gateDoc = null, trust, behav, budget, evidence = null, evalRow = null, asOf, maxAgeDays = DEFAULT_MAX_AGE_DAYS, org = null, audits = [], setup = [] }) {
  const ep = asEffective(policy);
  const s = subjectForTool(tool);
  // The stored part of the decision, from the one producer verify --offline
  // uses too (lib/findings_from.cjs fromStoredEvidence).
  const ev = fromStoredEvidence(tool, { subject: s, asOf, maxAgeDays, evidence, trust: trust === undefined ? null : trust });
  // The gate's own findings, typed, when its report carries them; its tags
  // otherwise.
  const gateFindings = gateEntry
    // (org/* findings excepted: explain produces its own, below.)
    ? ((gateDoc && Array.isArray(gateDoc.findings)) ? gateDoc.findings.filter((f) => f.subject && f.subject.id === s.id && !f.rule.startsWith('org/'))
      : fromReportEntry(gateEntry, { subject: s }).findings)
    : [];
  // Organisation rules read their own facts (lib/org_policy.cjs orgModel);
  // tool approvals arrive as findings on this subject.
  const orgPart = org ? orgModel(tool, ep, org, { subject: s, asOf, evidence }) : null;
  // Who else looked (lib/audits.cjs): observations with their source, and
  // `audits/recorded` findings the table can only ever allow — visible in the
  // trace, never a lift (#121).
  const aud = auditObservations(audits, s);
  // What the configured set would do with it (rows flows/*, shadowing/*).
  const findings = [...ev.findings, ...gateFindings, ...(orgPart ? orgPart.findings : []), ...aud.findings, ...setup];
  // What the tool list tells the model (#124), from the eval row: findings on
  // the server's tools, held as a fact of this artifact so the `tool-scan/*`
  // row judges them here exactly as `mcp-vault tool-scan` does. No row, or a
  // run that never listed tools, says nothing; a row listed before the scan
  // existed is `not-run`, never clean.
  const scan = evalRow ? evalRowFindings(evalRow, {
    asOf, maxAgeDays: typeof maxAgeDays === 'number' ? maxAgeDays : (maxAgeDays || DEFAULT_MAX_AGE_DAYS).tool_descriptions,
  }) : null;
  const facts = {
    [s.id]: {
      mode: gateEntry ? 'gate' : 'evidence',
      legacy_status: gateEntry ? gateEntry.status : null,
      gate_status: gateEntry ? gateEntry.status : null,
      entry: {
        install_cmd:  (gateEntry && gateEntry.install_cmd) || tool.install_cmd || '',
        license:      tool.license ?? null,
        health_score: tool.health_score ?? null,
        trust:        tool.trust ?? null,
      },
      ...ev.facts,
      behaviour: behav ? { state: behav.state, reason: behav.reason } : null,
      budget: budget || null,
      ...(orgPart ? { org: orgPart.facts } : {}),
      tool_scan: scan ? { ...scan.facts, subject: scan.subject.id, findings: scan.findings } : null,
    },
  };
  // The threshold is the effective policy's fail_on — the one verify uses —
  // so one decision cannot pass here and fail there.
  const [decision] = decideFindings(findings, ep, asOf, { subjects: [s], facts });
  return { subject: s, observations: [...ev.observations, ...aud.observations], findings, decision, facts, policy: ep };
}

/**
 * The decision, as explain has always reported it.
 *
 * Trust gates, policy rules refuse, behaviour and budget advise — those are
 * rows in lib/policy_rules.cjs now, and `decide()` evaluates them. This is
 * the legacy view of the Decision: its rules in table order, with the outcome
 * words explain has always used, because the useful part of a denial is
 * which rule denied it.
 */
function decide({ tool, policy, gateEntry, gateDoc = null, trust, behav, budget, evidence = null, evalRow = null, asOf, maxAgeDays, org = null, audits = [], setup = [] }) {
  const m = explainModel({ tool, policy, gateEntry, gateDoc, trust, behav, budget, evidence, evalRow, asOf, maxAgeDays, org, audits, setup });
  const rules = m.decision.rules
    .filter((r) => { const row = rowFor(r.rule); return row && row.views.includes('explain'); })
    .map((r) => ({ rule: r.rule, outcome: r.effect, detail: r.detail }));
  return {
    decision: m.decision.effect === 'deny' ? 'deny' : 'allow',
    // The rule id that decided (docs/adr/0001): a string, the same one the
    // findings document's decision carries. Which layer and which position
    // of a list matched is in that rule's detail.
    decided_by: m.decision.decided_by,
    blocking: rules.filter((r) => r.outcome === 'deny').map((r) => r.rule),
    // Named separately so a caller can tell "allowed" from "allowed as far as
    // anyone has looked".
    unevaluated: rules.filter((r) => r.outcome === 'unknown').map((r) => r.rule),
    rules,
    model: m,
  };
}

/**
 * A name that is not in the vault, as a model: the lookalike finding on the
 * name, and the Decision decide() makes of it — or null when it resembles no
 * entry. A person asking about this name is asking to use it (`requested`).
 */
function lookalikeModel(name, tools, { policy, asOf }) {
  const hit = lookalike.checkName(name, name.includes('/') && !name.startsWith('@') ? 'oci' : 'npm', lookalike.buildIndex(tools));
  const f = lookalike.toFinding(hit, { scope: 'database' });
  if (!f) return null;
  const ep = asEffective(policy);
  const facts = { [f.subject.id]: lookalike.factsFor(hit, { intent: 'requested' }) };
  // The threshold is the policy's fail_on, as for an entry (#131).
  const [decision] = decideFindings([f], ep, asOf, { subjects: [f.subject], facts });
  const document = toJson(findingsDocument({ asOf, findings: [f], decisions: [decision], scope: 'database', policy: ep, facts }));
  return { hit, finding: f, decision, document };
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`explain: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }

  // The record as it stood at asOf: a look dated later did not exist then.
  const db = dbAsOf(readDb(DB_PATH).db, opts.asOf);
  const tool = (db.tools || []).find((t) => t.name === opts.name)
    || (db.tools || []).find((t) => t.name.toLowerCase().includes(opts.name.toLowerCase()));
  if (!tool) {
    // Not in the vault — but "no entry matching" is a poor answer for a name
    // one letter away from an entry that is. That one gets a decision, made
    // like any other: a `lookalike/*` finding on the name, and decide().
    const m = lookalikeModel(opts.name, db.tools || [], { policy: loadEffectivePolicy(opts.cwd).policy, asOf: opts.asOf });
    if (!m) {
      process.stderr.write(`explain: no entry matching "${opts.name}"\n`);
      return 2;
    }
    const rules = m.decision.rules
      .filter((r) => { const row = rowFor(r.rule); return row && row.views.includes('explain'); })
      .map((r) => ({ rule: r.rule, outcome: r.effect, detail: r.detail }));
    const record = {
      schema:       'mcp-vault/decision@1',
      evaluated_at: opts.asOfIso,
      as_of:        opts.asOfIso,
      subject:  { name: opts.name, artifact_id: null, launch: null, trust_field: null, in_vault: false },
      decision: m.decision.effect === 'deny' ? 'deny' : 'allow',
      blocking: rules.filter((r) => r.outcome === 'deny').map((r) => r.rule),
      rules,
      unevaluated: rules.filter((r) => r.outcome === 'unknown').map((r) => r.rule),
      lookalike: { candidate: m.hit.candidate, kind: m.hit.kind, matches: m.hit.matches },
      findings: m.document,
    };
    if (opts.record) {
      try { fs.appendFileSync(opts.record, `${JSON.stringify(record)}\n`); }
      catch (e) { process.stderr.write(`${YL}explain: could not write ${opts.record}: ${e.message}${RS}\n`); }
    }
    if (opts.json) {
      process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
      return m.decision.fails ? 1 : 0;
    }
    const head = record.decision === 'deny' ? `${RD}DENIED${RS}` : `${GN}ALLOWED${RS}`;
    process.stdout.write(`\n${head}  ${B}${opts.name}${RS}  ${DM}not in the vault · as of ${opts.asOfIso}${RS}\n\n`);
    for (const r of rules) {
      process.stdout.write(`  ${r.outcome === 'deny' ? `${RD}✗` : `${YL}!`} ${r.rule.padEnd(30)}${RS} ${r.detail}\n`);
    }
    for (const x of m.hit.matches) {
      process.stdout.write(`    ${DM}${x.confidence.padEnd(6)} ${x.technique.padEnd(18)} ${x.db_name}${x.package ? `  ${x.package}` : ''}${RS}\n`);
    }
    process.stdout.write(`\nIf you meant the vetted server: mcp-vault explain ${m.hit.matches[0].db_name}\n`);
    return m.decision.fails ? 1 : 0;
  }

  // The same loader every command uses (lib/policy_rules.cjs): `policy` is
  // the file as written, for the record; `loaded.policy` is the frozen
  // effective policy decide() receives.
  const loaded = loadEffectivePolicy(opts.cwd, { flags: opts.flags });
  const policy = loaded.file_policy;
  const typed  = toTypedEntry(tool);
  const currentId = typed ? artifactId(typed.artifact) : null;

  // Evidence only counts for the artifact it was collected on.
  const { evidence, forAnotherVersion: evidenceIsForAnotherVersion } = storedEvidenceFor(tool);

  // The same shelf lives verify holds this evidence to (lib/evidence.cjs).
  const maxAge = maxAgeForPolicy(policy);
  const trust  = trustScore(evidence, { maxAgeDays: maxAge, now: opts.asOf });
  const stale  = new Map(staleDimensions(evidence, maxAge, opts.asOf).map((s) => [s.dimension, s]));

  const evals  = evalResultsAsOf(readJson(EVAL_PATH, { results: [] }).results || [], opts.asOf);
  const evalBy = new Map(evals.map((r) => [r.name, r]));
  const evalRow = evalBy.get(tool.name) || null;
  const behav  = behaviour(evalRow);

  // Budget, if the policy has an opinion about context.
  const unreadableConfigs = [];
  let budget = null;
  if (policy.maxContextTokens !== null || policy.maxContextPercent !== null) {
    // Unreadable host configs make the budget a total of an unknown subset;
    // the decision record says so rather than presenting it as complete.
    const rows = readInstalledServers({ cwd: opts.cwd, onUnreadable: (loc) => unreadableConfigs.push(loc) }).map((srv) => {
      const dbEntry = matchDbEntry(srv, db.tools || []);
      return estimateServer({ name: srv.name, dbEntry, evalEntry: evalBy.get(srv.name) || (dbEntry && evalBy.get(dbEntry.name)) });
    });
    const adding = estimateServer({ name: tool.name, dbEntry: tool, evalEntry: evalBy.get(tool.name) });
    budget = wouldExceed({ rows, adding, policy, context: DEFAULT_CONTEXT });
    if (unreadableConfigs.length) budget = { ...budget, unreadable_configs: unreadableConfigs };
  }

  let gate = null;
  if (opts.verify) {
    gate = runGate(tool.name, opts.cwd, opts.asOfSource === 'as-of' ? opts.asOfIso : null, opts.flags);
    if (!gate.ok) process.stderr.write(`${YL}explain: could not run the live gate (${gate.error}); falling back to stored evidence${RS}\n`);
  }
  const gateEntry = gate && gate.ok
    ? (gate.report.entries || []).find((e) => e.name === tool.name) || null
    : null;

  // Organisation rules need the eval, the capability scan and the project's
  // lockfile (tool approvals) — read once, as of asOf, and only when the
  // policy has any.
  const org = hasOrgRules(loaded.policy)
    ? loadOrgContext({ cwd: opts.cwd, dbTools: db.tools || [], asOf: opts.asOf })
    : null;

  // Offline: the lock is what `audits fetch` verified; it is re-verified here.
  const localAudits = readLocalAudits(opts.cwd);
  const importedAudits = loadImportedAudits(opts.cwd);
  const audits = auditsFor(tool, { local: localAudits.audits, imported: importedAudits.audits });
  const auditErrors = [
    ...localAudits.errors.map((e) => ({ source: 'local', code: 'local', error: e })),
    ...importedAudits.errors,
  ];

  const setupUnreadable = [];
  const setup = setupFindings({
    tool, subject: subjectForTool(tool), db, evalBy,
    capabilities: readJson(CAPS_PATH, { packages: {} }),
    installed: readInstalledServers({ cwd: opts.cwd, onUnreadable: (loc) => setupUnreadable.push(loc) }),
  });
  const verdict = decide({
    tool, policy: loaded.policy, gateEntry, gateDoc: gate && gate.ok ? gate.report.findings : null,
    trust, behav, budget, evidence, evalRow, asOf: opts.asOf, maxAgeDays: maxAge, org, audits, setup: setup.findings,
  });
  const m = verdict.model;
  const trace = toJson(findingsDocument({
    asOf: opts.asOf, observations: m.observations, findings: m.findings, decisions: [m.decision],
    scope: 'database', policy: m.policy, facts: m.facts,
  }));
  const fit = null;   // fit is about a project's stack; `scan` is where that question lives

  const record = {
    schema:       'mcp-vault/decision@1',
    evaluated_at: opts.asOfIso,
    // Additive: the instant the evidence was judged at (docs/adr/0001).
    as_of: opts.asOfIso,
    subject: {
      name:        tool.name,
      artifact_id: currentId,
      launch:      tool.install_cmd,
      trust_field: tool.trust,
    },
    decision: verdict.decision,
    decided_by: verdict.decided_by,
    blocking: verdict.blocking,
    rules:    verdict.rules,
    unevaluated: verdict.unevaluated,
    policy: {
      path:   loaded.path,
      found:  loaded.found,
      // Every file that contributed, org layers first.
      sources: loaded.sources || [],
      valid:  loaded.ok,
      errors: loaded.errors,
      // The policy as applied, so a record from six months ago can be read
      // without guessing which defaults were in force.
      applied: policy,
    },
    evidence: {
      // Each dimension with the date it was established and whether that date
      // is still inside its shelf life. This is the whole point of the record.
      artifact_id: evidence ? evidence.artifact_id : null,
      for_another_version: evidenceIsForAnotherVersion,
      dimensions: DIMENSIONS.filter((d) => evidence && evidence.dimensions[d]).map((d) => {
        const v = evidence.dimensions[d];
        const s = stale.get(d);
        return {
          dimension:   d,
          status:      v.status,
          established: v.verified_at || (POSITIVE_STATUSES.has(v.status) ? v.checked_at : null),
          checked_at:  v.checked_at,
          stale:       Boolean(s),
          age_days:    s ? s.age_days : null,
          max_age_days: s ? s.max_age_days : (typeof maxAge === 'number' ? maxAge : maxAge[d]),
        };
      }),
      missing: DIMENSIONS.filter((d) => !evidence || !evidence.dimensions[d]),
      // Additive (#121). The audits themselves are observations in
      // `findings` (source `audit:…`); this says which sources could not be
      // read, so "no audit shown" is not mistaken for "nobody audited".
      audit_errors: auditErrors,
    },
    scores: {
      trust:     { score: trust.score, gate: trust.gate, reasons: trust.reasons },
      health:    Number.isFinite(tool.health_score) ? tool.health_score : null,
      behaviour: { state: behav.state, reason: behav.reason, tools: behav.tools },
      recommendation: recommend({ trust, health: tool.health_score, fit, behaviour: behav }),
    },
    budget,
    // The cross-server context of the flows/* and shadowing/* rules above:
    // which host and servers each finding is about, what to do, the flows a
    // host already had without this entry, and whether the set is complete.
    // The findings themselves are in `findings` (findings@1).
    setup: {
      context: setup.findings.map((f) => ({ finding: f.id, ...setup.meta[f.id] })),
      already_present: setup.already_present,
      unreadable_configs: setupUnreadable.map((u) => ({ path: u.path, error: u.error })),
    },
    live_gate: gate && gate.ok
      ? { ran: true, exit: gate.exit, status: gateEntry ? gateEntry.status : null, findings: gateEntry ? gateEntry.findings : [] }
      : { ran: false, reason: opts.verify ? (gate && gate.error) || 'unavailable' : 'not requested (--verify runs it)' },
    // Additive (mcp-vault/findings@1): observation → finding → decision for
    // this entry, with the policy and facts it was decided on. The legacy
    // `decision` and `rules` above are a view of `findings.decisions[0]`.
    findings: trace,
  };

  if (opts.record) {
    // One JSON object per line: appendable, greppable, and a diff shows exactly
    // which decisions changed.
    try {
      fs.appendFileSync(opts.record, `${JSON.stringify(record)}\n`);
      process.stderr.write(`Decision recorded in ${opts.record}\n`);
    } catch (e) {
      process.stderr.write(`${YL}explain: could not write ${opts.record}: ${e.message}${RS}\n`);
    }
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
    return m.decision.fails ? 1 : 0;
  }

  // ── human form ──
  const head = verdict.decision === 'deny' ? `${RD}DENIED${RS}` : `${GN}ALLOWED${RS}`;
  process.stdout.write(`\n${head}  ${B}${tool.name}${RS}  ${DM}${currentId || tool.install_cmd}${RS}\n`);
  process.stdout.write(`${DM}${loaded.found
    ? `policy: ${(loaded.sources.length ? loaded.sources : [{ path: loaded.path, role: 'local' }]).map((x) => `${x.path} (${x.role})`).join(' → ')}`
    : 'policy: none found — defaults in force'} · as of ${opts.asOfIso}${RS}\n`);
  if (!loaded.ok) process.stdout.write(`${RD}the policy file has errors: ${loaded.errors.join('; ')}${RS}\n`);
  process.stdout.write('\n');

  for (const r of record.evidence.dimensions) {
    const mark = POSITIVE_STATUSES.has(r.status) ? `${GN}✓${RS}` : `${YL}?${RS}`;
    const age  = r.stale ? ` ${YL}(${r.age_days}d old, shelf life ${r.max_age_days}d)${RS}` : ` ${DM}(${r.established || r.checked_at})${RS}`;
    process.stdout.write(`  ${mark} ${r.dimension.padEnd(15)} ${r.status}${age}\n`);
  }
  for (const d of record.evidence.missing) {
    process.stdout.write(`  ${DM}· ${d.padEnd(15)} never checked${RS}\n`);
  }
  for (const o of m.observations.filter((x) => x.source.startsWith('audit:'))) {
    process.stdout.write(`  ${GN}✓${RS} ${'audit'.padEnd(15)} ${o.status} — ${o.dimension.split('/').slice(2).join('/')} ${DM}(${o.observed_at}, ${o.source}; does not change trust)${RS}\n`);
  }
  for (const e of auditErrors) {
    process.stdout.write(`  ${YL}! ${'audit'.padEnd(15)} [${e.source || 'imports'}] ${e.error}${RS}\n`);
  }
  if (evidenceIsForAnotherVersion) {
    process.stdout.write(`\n${YL}The stored evidence describes ${tool.trust_evidence.artifact_id}, not ${currentId} — ignored.${RS}\n`);
  }

  process.stdout.write(`\n  trust ${trust.score}/100 (${trust.gate})`);
  if (Number.isFinite(tool.health_score)) process.stdout.write(`   health ${tool.health_score}`);
  process.stdout.write(`   behaviour ${behav.state}\n`);
  process.stdout.write(`  ${DM}${behav.reason}${RS}\n`);

  process.stdout.write('\nRules:\n');
  for (const r of verdict.rules) {
    const colour = r.outcome === 'deny' ? RD : (r.outcome === 'warn' ? YL : (r.outcome === 'unknown' ? DM : GN));
    const mark   = r.outcome === 'deny' ? '✗' : (r.outcome === 'warn' ? '!' : (r.outcome === 'unknown' ? '·' : '✓'));
    process.stdout.write(`  ${colour}${mark} ${r.rule.padEnd(30)}${RS} ${r.detail}\n`);
  }

  if (verdict.blocking.length) {
    process.stdout.write(`\n${RD}Blocking: ${verdict.blocking.join(', ')}${RS}\n`);
  }
  process.stdout.write(`${verdict.decision === 'deny' ? RD : DM}Decided by ${verdict.decided_by}${RS}\n`);
  if (verdict.unevaluated.length) {
    // Most of these need a gate run; `tool-scan/*` ones need a fresh eval.
    process.stdout.write(`${DM}Not evaluated: ${verdict.unevaluated.join(', ')}${RS}\n`);
  }
  // The chain behind the decision: which rule decided, on which findings, and
  // the dated observations those rest on — current or past their shelf life
  // at the instant above.
  process.stdout.write(`\n${DM}Trace:${RS}\n`);
  for (const line of renderTrace(explainTrace(trace))) process.stdout.write(`  ${DM}${line}${RS}\n`);

  if (!record.live_gate.ran) {
    process.stdout.write(`\n${DM}This is the stored evidence, with the date each claim was established.\n`
      + `Add --verify for a decision about the artifact as it is right now.${RS}\n`);
  }

  return m.decision.fails ? 1 : 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, decide, explainModel, lookalikeModel, runGate, policyFromEvidence, setupFindings };
