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
 *                                   [--record <file>] [--installed]
 *
 * Exit codes:
 *   0  allow
 *   1  deny
 *   2  the entry could not be found / bad arguments
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb } = require('./lib/db_io.cjs');
const { loadPolicy, evaluateEntry } = require('./lib/policy.cjs');
const { trustScore, fitScore, behaviour, recommend } = require('./lib/scores.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { staleDimensions, DIMENSIONS, DEFAULT_MAX_AGE_DAYS, POSITIVE_STATUSES } = require('./lib/evidence.cjs');
const { estimateServer, matchDbEntry, wouldExceed, DEFAULT_CONTEXT } = require('./lib/budget.cjs');
const { readInstalledServers } = require('./lib/installed.cjs');

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
  const opts = { name: null, json: false, verify: false, cwd: process.cwd(), record: null, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--verify') opts.verify = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--cwd') opts.cwd = argv[++i] || opts.cwd;
    else if (a === '--record') opts.record = argv[++i] || null;
    else if (a.startsWith('--')) return { ...opts, error: `unknown flag ${a}` };
    else if (!opts.name) opts.name = a;
    else return { ...opts, error: 'explain takes one entry name' };
  }
  if (!opts.name && !opts.help) return { ...opts, error: 'which entry? `mcp-vault explain <name>`' };
  return opts;
}

const HELP = `explain — why this entry is allowed, or why it is not

  node scripts/explain.cjs <name> [--json] [--verify] [--record <file>]

  --verify        run the live integrity gate first (network); otherwise the
                  answer comes from stored, dated evidence
  --record <file> append the decision record as one JSON line (audit trail)
  --cwd <path>    the project whose policy and configured servers apply
`;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

/** The live gate's own verdict for one entry, when --verify is given. */
function runGate(name, cwd) {
  const res = spawnSync(process.execPath, [VERIFY_CJS, '--entry', name, '--json', '--cwd', cwd], {
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
 */
function policyFromEvidence(policy, tool, evidence) {
  const dims = (evidence && evidence.dimensions) || {};
  const out = [];
  const isNpm = /^npx\s/.test(tool.install_cmd || '');
  const isDocker = /^docker\s+run/.test(tool.install_cmd || '');

  const three = (rule, dim, { ok, bad, require: required, message }) => {
    const value = dims[dim];
    if (!value) {
      if (!required) return;
      out.push({ rule, outcome: 'unknown', detail: `${dim} has never been checked — run with --verify` });
      return;
    }
    if (ok.includes(value.status)) {
      out.push({ rule, outcome: 'allow', detail: `${dim}: ${value.status} (as of ${value.verified_at || value.checked_at})` });
      return;
    }
    if (bad.includes(value.status)) {
      out.push({ rule, outcome: required ? 'deny' : 'warn', detail: message(value) });
      return;
    }
    out.push({ rule, outcome: 'unknown', detail: `${dim} is "${value.status}", which this rule cannot judge — run with --verify` });
  };

  if (isNpm) {
    three('policy/signatures', 'signature', {
      ok: ['verified'], bad: ['absent', 'mismatch'],
      require: policy.signatures === 'require',
      message: (v) => (v.status === 'mismatch'
        ? 'the registry signature does not verify'
        : 'the registry published no signature for this version'),
    });
    three('policy/provenance', 'provenance', {
      ok: ['bound', 'claimed'], bad: ['absent', 'unreadable', 'mismatch'],
      require: policy.provenance === 'require' || policy.provenance === 'bound',
      message: (v) => `provenance is ${v.status}`,
    });
    // The stricter bar asks for a binding, so a mere claim does not clear it.
    if (policy.provenance === 'bound' && dims.provenance && dims.provenance.status === 'claimed') {
      out.push({ rule: 'policy/provenance', outcome: 'deny', detail: 'policy requires provenance bound to the artifact digest; this one is only claimed' });
    }
  }

  three('policy/dependency-hooks', 'dependencies', {
    ok: ['clean'], bad: ['hooks'],
    require: policy.dependencyHooks === 'fail',
    message: () => 'a dependency runs install-time scripts',
  });
  three('policy/dependency-advisories', 'dependencies', {
    ok: ['clean', 'hooks'], bad: ['advisories-present'],
    require: policy.dependencyAdvisories === 'fail',
    message: () => 'an advisory affects a package in the dependency tree',
  });
  three('policy/unverified', 'artifact', {
    ok: ['verified'], bad: ['unverified', 'mismatch'],
    require: policy.unverified === 'fail',
    message: (v) => (v.status === 'mismatch'
      ? 'the artifact does not match its pin'
      : 'nothing about this artifact could be verified'),
  });

  // The package's own install hooks are not an evidence dimension: only a gate
  // run sees them. Saying so beats guessing either way.
  if (policy.installHooks === 'fail') {
    out.push({ rule: 'policy/install-hooks', outcome: 'unknown', detail: 'whether this package runs install-time scripts is only visible to a gate run — use --verify' });
  }
  if (isDocker && policy.docker === 'digest') {
    const pinned = /@sha256:[a-f0-9]{64}(\s|$)/.test(tool.install_cmd || '');
    out.push(pinned
      ? { rule: 'policy/docker-digest', outcome: 'allow', detail: 'the image is pinned by @sha256 digest' }
      : { rule: 'policy/docker-digest', outcome: 'deny', detail: 'container image is not pinned by digest' });
  }
  return out;
}

/**
 * The decision.
 *
 * Trust gates, policy rules refuse, behaviour and budget advise. Kept as an
 * ordered list of *rules with outcomes* rather than a single boolean, because
 * the useful part of a denial is which rule denied it.
 */
function decide({ tool, policy, gateEntry, trust, behav, budget, evidence = null }) {
  const rules = [];
  const add = (rule, outcome, detail) => rules.push({ rule, outcome, detail });

  // 1. Trust is the gate.
  if (trust.gate === 'block') {
    // One rule per blocking dimension, named. "trust/blocked: artifact:
    // verified" was what this printed when `reasons[0]` happened to be a
    // positive finding.
    const blockers = trust.blocking && trust.blocking.length
      ? trust.blocking
      : [{ dimension: 'trust', status: 'blocked', checked_at: null }];
    for (const b of blockers) {
      add(`trust/${b.dimension}`, 'deny', `${b.dimension} is ${b.status}${b.checked_at ? ` (as of ${b.checked_at})` : ''}`);
    }
  }
  else if (trust.gate === 'thin') add('trust/thin', 'warn', trust.reasons[0] || `only ${trust.score}/100 of the trust evidence is established`);
  else add('trust/ok', 'allow', `artifact verified and nothing contradicts it (${trust.score}/100)`);

  // 2. Policy rules, from the file that applies to this directory.
  //
  // Without a live gate there are no *findings* to judge, and handing
  // `evaluateEntry` an empty list made it read "no SIG finding" as "no
  // signature": `explain gitlab-mcp` denied on `policy/signatures` while the
  // stored evidence said `signature: verified`, and the same command with
  // `--verify` did not. A check that did not run had produced a finding — the
  // usual bug, pointing the other way.
  //
  // So the rules that depend on gate findings are answered from the evidence
  // when it exists, and reported as `unknown` when it does not. `unknown` never
  // blocks: it is an invitation to run `--verify`, not a verdict.
  if (gateEntry) {
    for (const f of evaluateEntry(gateEntry, policy, tool)) {
      add(f.rule, f.level === 'fail' ? 'deny' : 'warn', f.message);
    }
  } else {
    for (const r of policyFromEvidence(policy, tool, evidence)) add(r.rule, r.outcome, r.detail);
    // The rules that are properties of the entry rather than of a scan —
    // licence lists, a health floor, accepted trust tiers — need no gate and
    // are judged the same way in both paths.
    const entryOnly = new Set(['policy/license', 'policy/health', 'policy/trust']);
    for (const f of evaluateEntry({ status: 'SKIP', findings: [], install_cmd: tool.install_cmd }, policy, tool)) {
      if (!entryOnly.has(f.rule)) continue;
      add(f.rule, f.level === 'fail' ? 'deny' : 'warn', f.message);
    }
  }

  // 3. The live gate's own exit code, when we ran it.
  if (gateEntry && gateEntry.status === 'FAIL') add('gate/fail', 'deny', 'the integrity gate failed this entry');
  if (gateEntry && gateEntry.status === 'UNVERIFIED' && policy.unverified === 'fail') {
    add('gate/unverified', 'deny', 'nothing about this entry could be verified, and the policy fails closed');
  }

  // 4. Behaviour and budget: advisory. A server that does not start is not a
  //    security refusal, and neither is a context ceiling — both change what a
  //    reader should do, not whether they are permitted to.
  if (behav.state === 'never-started')     add('behaviour/never-started', 'warn', behav.reason);
  if (behav.state === 'needs-credentials') add('behaviour/needs-credentials', 'warn', behav.reason);
  if (behav.state === 'needs-arguments')   add('behaviour/needs-arguments', 'warn', behav.reason);
  if (budget && budget.over) {
    add('budget/over', policy.contextBudget === 'fail' ? 'deny' : 'warn',
      `this config would inject ≈${budget.after.toLocaleString('en-US')} tokens per request, over the ceiling of ${budget.limit.toLocaleString('en-US')}`);
  }

  const denials = rules.filter((r) => r.outcome === 'deny');
  const unknowns = rules.filter((r) => r.outcome === 'unknown');
  return {
    decision: denials.length ? 'deny' : 'allow',
    blocking: denials.map((r) => r.rule),
    // Named separately so a caller can tell "allowed" from "allowed as far as
    // anyone has looked".
    unevaluated: unknowns.map((r) => r.rule),
    rules,
  };
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`explain: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }

  const { db } = readDb(DB_PATH);
  const tool = (db.tools || []).find((t) => t.name === opts.name)
    || (db.tools || []).find((t) => t.name.toLowerCase().includes(opts.name.toLowerCase()));
  if (!tool) {
    process.stderr.write(`explain: no entry matching "${opts.name}"\n`);
    return 2;
  }

  const loaded = loadPolicy(opts.cwd);
  const policy = loaded.policy;
  const typed  = toTypedEntry(tool);
  const currentId = typed ? artifactId(typed.artifact) : null;

  // Evidence only counts for the artifact it was collected on.
  const evidence = tool.trust_evidence
    && (!tool.trust_evidence.artifact_id || !currentId || tool.trust_evidence.artifact_id === currentId)
    ? tool.trust_evidence
    : null;
  const evidenceIsForAnotherVersion = Boolean(tool.trust_evidence && !evidence);

  const maxAge = policy.maxEvidenceAgeDays || DEFAULT_MAX_AGE_DAYS;
  const trust  = trustScore(evidence, { maxAgeDays: maxAge });
  const stale  = new Map(staleDimensions(evidence, maxAge).map((s) => [s.dimension, s]));

  const evals  = readJson(EVAL_PATH, { results: [] }).results || [];
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
    gate = runGate(tool.name, opts.cwd);
    if (!gate.ok) process.stderr.write(`${YL}explain: could not run the live gate (${gate.error}); falling back to stored evidence${RS}\n`);
  }
  const gateEntry = gate && gate.ok
    ? (gate.report.entries || []).find((e) => e.name === tool.name) || null
    : null;

  const verdict = decide({ tool, policy, gateEntry, trust, behav, budget, evidence });
  const fit = null;   // fit is about a project's stack; `scan` is where that question lives

  const record = {
    schema:       'mcp-vault/decision@1',
    evaluated_at: new Date().toISOString(),
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
    return verdict.decision === 'deny' ? 1 : 0;
  }

  // ── human form ──
  const head = verdict.decision === 'deny' ? `${RD}DENIED${RS}` : `${GN}ALLOWED${RS}`;
  process.stdout.write(`\n${head}  ${B}${tool.name}${RS}  ${DM}${currentId || tool.install_cmd}${RS}\n`);
  process.stdout.write(`${DM}${loaded.found ? `policy: ${loaded.path}` : 'policy: none found — defaults in force'}${RS}\n`);
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
  if (!record.live_gate.ran) {
    process.stdout.write(`\n${DM}This is the stored evidence, with the date each claim was established.\n`
      + `Add --verify for a decision about the artifact as it is right now.${RS}\n`);
  }

  return verdict.decision === 'deny' ? 1 : 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, decide, runGate, policyFromEvidence };
