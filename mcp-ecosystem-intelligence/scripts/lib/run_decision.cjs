'use strict';
/**
 * A command's own run, decided the one way (docs/adr/0001, step 3).
 *
 * status, audit, doctor, budget and the observers (availability, identity,
 * posture, capabilities, upgrade, docker-drift, license-drift, eval) each
 * used to keep a ladder of "blocking → 1, --strict and notable → 1, nothing
 * answered → 2". The ladder is gone. A command now says what it found, as
 * lib/finding.cjs findings on typed subjects, and this file hands them to
 * decide() under the command's mode (lib/policy_rules.cjs ORDER):
 *
 *   blocking        an observed high finding          → deny     (exit 1)
 *   worth knowing   an observed medium finding        → warn     (exit 1 at fail_on warn: --strict)
 *                   a claim nobody could make (no-data, not-run, stale)
 *                                                     → unknown  (exit 1 at fail_on unknown)
 *   not covered     `unchecked/<command>`             → unknown  (never fails)
 *   unanswered      `scope/unanswered`                → unknown, `unanswered` (exit 2 unless something fails)
 *
 * The mode is written into each subject's facts, so the findings@1 document
 * reproduces its decisions from its own inputs — the property
 * tests/decision_consistency.test.cjs checks for every command.
 *
 * API:
 *   commandPolicy(flags, base)                 -> frozen policy: the vault's rules, the command's flags
 *   decideRun({ findings, subjects, policy, asOf, mode, facts, scope })
 *        -> { decisions, document, exit }
 *   classify(decisions, findingIds)            -> 'blocking' | 'notable' | 'unanswered' | null
 *   outcomeClass(ruleOutcome)                  -> the same, for one outcome
 *   unanswered({ subject, message, scope })    -> a scope/unanswered finding
 */

const { finding, decide, exitCode, findingsDocument, toJson } = require('./finding.cjs');
const { effectivePolicy, rowFor } = require('./policy_rules.cjs');

/**
 * The policy a command that asks a question of the vault DB or of this
 * machine decides under: the vault's own rules (no project policy file — it
 * never read one), and the command's switches. `base` is what the command's
 * own arguments set (`budget --budget 20` is a ceiling of 20%).
 */
function commandPolicy(flags = {}, base = null) {
  const { DEFAULTS } = require('./policy.cjs');
  return effectivePolicy(base, flags, { defaults: DEFAULTS, policyRules: false });
}

/**
 * findings → decide() → { decisions, document (findings@1, canonical), exit }.
 * Every subject named, and every finding's subject, is decided; `facts` adds
 * to what each subject's row reads, and `mode` is written into each.
 */
function decideRun({ findings = [], subjects = [], policy, asOf, mode, facts = {}, scope = null } = {}) {
  const all = new Map();
  for (const s of subjects) if (s && !all.has(s.id)) all.set(s.id, s);
  for (const f of findings) if (!all.has(f.subject.id)) all.set(f.subject.id, f.subject);
  const fx = {};
  for (const id of all.keys()) fx[id] = { ...(facts[id] || {}), mode: (facts[id] && facts[id].mode) || mode };
  const decisions = decide(findings, policy, asOf, { subjects: [...all.values()], facts: fx });
  const document = toJson(findingsDocument({ asOf, findings, decisions, scope, policy, facts: fx }));
  return { decisions, document, exit: exitCode(decisions) };
}

const CLASS_RANK = { blocking: 0, notable: 1, unanswered: 2 };

/**
 * Where a rendered line belongs, read off the Decisions — never off the
 * finding: the gate outcomes that rest on any of `ids`. A deny is blocking; a
 * warn or unknown from a row the threshold can reach (`--strict`) is worth
 * knowing; scope/unanswered is a question left open. Allow, context and an
 * unknown no threshold reaches (flows/no-data, unchecked/*) are not shown.
 */
function classify(decisions, ids) {
  const want = new Set(ids || []);
  let best = null;
  const take = (c) => { if (c && (!best || CLASS_RANK[c] < CLASS_RANK[best])) best = c; };
  for (const d of decisions || []) {
    for (const o of d.rules || []) {
      if (!(o.findings || []).some((id) => want.has(id))) continue;
      take(outcomeClass(o));
    }
  }
  return best;
}

/**
 * One rule outcome's class, by the same reading `classify` makes: for a
 * renderer that lists outcomes rather than findings (`check` also shows a
 * policy outcome that rests on no finding). A policy row's warning that no
 * threshold reaches is not shown, as it is not by `classify`; its deny is.
 */
function outcomeClass(o) {
  if (!o || o.role === 'context') return null;
  if (o.effect === 'deny') return 'blocking';
  if (o.rule === 'scope/unanswered') return 'unanswered';
  if (o.effect === 'warn' || o.effect === 'unknown') {
    const row = rowFor(o.rule);
    if (row && row.thresholded) return 'notable';
  }
  return null;
}

/** A question this run could not answer, about `subject`. */
function unanswered({ subject, message, scope = null }) {
  return finding({ rule: 'scope/unanswered', subject, scope, severity: 'medium', state: 'no-data', message });
}

module.exports = { commandPolicy, decideRun, classify, outcomeClass, unanswered };
