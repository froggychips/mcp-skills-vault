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
 *   1  it does (deny always; unknown under `unverified: fail` /
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
const { subjectForTool, fromEvidence, fromReportEntry } = require('./lib/findings_from.cjs');
const { trustScore, fitScore, behaviour, recommend } = require('./lib/scores.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { staleDimensions, DIMENSIONS, DEFAULT_MAX_AGE_DAYS, POSITIVE_STATUSES, requiredFor, dbAsOf, evalResultsAsOf } = require('./lib/evidence.cjs');
const { estimateServer, matchDbEntry, wouldExceed, DEFAULT_CONTEXT } = require('./lib/budget.cjs');
const { readInstalledServers } = require('./lib/installed.cjs');
const { asOfFromArgv } = require('./lib/clock.cjs');

const DB_PATH    = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH  = path.resolve(__dirname, '../assets/eval_results.json');
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
 * The model for one entry: observations from the stored evidence, findings
 * from the evidence and — with `--verify` — from the live gate, and the one
 * Decision `decide()` makes over them. explain renders it; it decides nothing.
 */
function explainModel({ tool, policy, gateEntry = null, gateDoc = null, trust, behav, budget, evidence = null, asOf, maxAgeDays = DEFAULT_MAX_AGE_DAYS }) {
  const ep = asEffective(policy);
  const s = subjectForTool(tool);
  let typed = null;
  try { typed = toTypedEntry(tool); } catch { typed = null; }
  const ev = fromEvidence(evidence, {
    subject: s, asOf, maxAgeDays, required: evidence ? requiredFor(typed ? typed.artifact.ecosystem : null) : [],
  });
  // The gate's own findings, typed, when its report carries them; its tags
  // otherwise.
  const gateFindings = gateEntry
    ? ((gateDoc && Array.isArray(gateDoc.findings)) ? gateDoc.findings.filter((f) => f.subject && f.subject.id === s.id)
      : fromReportEntry(gateEntry, { subject: s }).findings)
    : [];
  const findings = [...ev.findings, ...gateFindings];
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
      evidence: evidence || null,
      trust: trust ? { score: trust.score, gate: trust.gate, blocking: trust.blocking || [], reasons: trust.reasons || [] } : null,
      behaviour: behav ? { state: behav.state, reason: behav.reason } : null,
      budget: budget || null,
    },
  };
  // The threshold is the effective policy's fail_on — the one verify uses —
  // so one decision cannot pass here and fail there.
  const [decision] = decideFindings(findings, ep, asOf, { subjects: [s], facts });
  return { subject: s, observations: ev.observations, findings, decision, facts, policy: ep };
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
function decide({ tool, policy, gateEntry, gateDoc = null, trust, behav, budget, evidence = null, asOf, maxAgeDays }) {
  const m = explainModel({ tool, policy, gateEntry, gateDoc, trust, behav, budget, evidence, asOf, maxAgeDays });
  const rules = m.decision.rules
    .filter((r) => { const row = rowFor(r.rule); return row && row.views.includes('explain'); })
    .map((r) => ({ rule: r.rule, outcome: r.effect, detail: r.detail }));
  return {
    decision: m.decision.effect === 'deny' ? 'deny' : 'allow',
    blocking: rules.filter((r) => r.outcome === 'deny').map((r) => r.rule),
    // Named separately so a caller can tell "allowed" from "allowed as far as
    // anyone has looked".
    unevaluated: rules.filter((r) => r.outcome === 'unknown').map((r) => r.rule),
    rules,
    model: m,
  };
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
    process.stderr.write(`explain: no entry matching "${opts.name}"\n`);
    return 2;
  }

  // The same loader every command uses (lib/policy_rules.cjs): `policy` is
  // the file as written, for the record; `loaded.policy` is the frozen
  // effective policy decide() receives.
  const loaded = loadEffectivePolicy(opts.cwd, { flags: opts.flags });
  const policy = loaded.file_policy;
  const typed  = toTypedEntry(tool);
  const currentId = typed ? artifactId(typed.artifact) : null;

  // Evidence only counts for the artifact it was collected on.
  const evidence = tool.trust_evidence
    && (!tool.trust_evidence.artifact_id || !currentId || tool.trust_evidence.artifact_id === currentId)
    ? tool.trust_evidence
    : null;
  const evidenceIsForAnotherVersion = Boolean(tool.trust_evidence && !evidence);

  const maxAge = policy.maxEvidenceAgeDays || DEFAULT_MAX_AGE_DAYS;
  const trust  = trustScore(evidence, { maxAgeDays: maxAge, now: opts.asOf });
  const stale  = new Map(staleDimensions(evidence, maxAge, opts.asOf).map((s) => [s.dimension, s]));

  const evals  = evalResultsAsOf(readJson(EVAL_PATH, { results: [] }).results || [], opts.asOf);
  const evalBy = new Map(evals.map((r) => [r.name, r]));
  const behav  = behaviour(evalBy.get(tool.name) || null);

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

  const verdict = decide({
    tool, policy: loaded.policy, gateEntry, gateDoc: gate && gate.ok ? gate.report.findings : null,
    trust, behav, budget, evidence, asOf: opts.asOf, maxAgeDays: maxAge,
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
    blocking: verdict.blocking,
    rules:    verdict.rules,
    unevaluated: verdict.unevaluated,
    policy: {
      path:   loaded.path,
      found:  loaded.found,
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
    },
    scores: {
      trust:     { score: trust.score, gate: trust.gate, reasons: trust.reasons },
      health:    Number.isFinite(tool.health_score) ? tool.health_score : null,
      behaviour: { state: behav.state, reason: behav.reason, tools: behav.tools },
      recommendation: recommend({ trust, health: tool.health_score, fit, behaviour: behav }),
    },
    budget,
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
  process.stdout.write(`${DM}${loaded.found ? `policy: ${loaded.path}` : 'policy: none found — defaults in force'} · as of ${opts.asOfIso}${RS}\n`);
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
  if (verdict.unevaluated.length) {
    process.stdout.write(`${DM}Not evaluated without a gate run: ${verdict.unevaluated.join(', ')}${RS}\n`);
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

module.exports = { parseArgs, decide, explainModel, runGate, policyFromEvidence };
