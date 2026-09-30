'use strict';
/**
 * One model for what every check concludes: Observation → Finding → Decision.
 *
 * Each command grew its own shape for "something is wrong here". The gate had
 * report tags (FAIL/CVE/HOOK/…), explain had rules with outcomes, and the open
 * feature work added a dozen more: secrets with `severity` and `confidence`,
 * tool-scan with `rule` and `location`, flows with `level` and `servers`, org
 * policy with `outcome`. Each one re-decided how a finding is named, where it
 * points, what "could not check" looks like and how SARIF renders it — and each
 * got some of it wrong in its own way. docs/adr/0001-findings-and-time.md is
 * the decision; this file is its code.
 *
 *   Observation  a dated fact: what a check saw, when, from where, and until
 *                when it may be relied on. The evidence dimensions are these.
 *   Finding      what a rule concludes from observations. Typed subject,
 *                severity, confidence, and a *state* — because "no data" is not
 *                "clean", and the shape has to be able to say so. A finding
 *                carries no policy effect: whether it blocks is not its call.
 *   Decision     policy × findings → allow | warn | deny | unknown, with the
 *                rule that decided it and the instant it was decided at.
 *
 *   result = f(db, evidence, policy, asOf, rules_version)
 *
 * Everything here is deterministic: no clock (asOf is an argument), no
 * randomness, and a canonical JSON form with sorted keys and a stable sort —
 * string comparison, never `localeCompare`, whose order depends on the locale
 * of the machine running it.
 *
 * API:
 *   subject.artifact({ entry, version, integrity })       -> Subject  id `entry@version+integrity`
 *   subject.tool({ server, tool, location })              -> Subject  id `server/tool`
 *   subject.hostConfig({ path, line, host, scope })       -> Subject  id `path:line`
 *   subject.setup({ host, scope })                        -> Subject  id `host`
 *   subject.name({ name, ecosystem })                     -> Subject  id `ecosystem:name`
 *   observation({ subject, dimension, status, observed_at, … })   -> Observation
 *   observationsFromEvidence(evidence, { subject, source, maxAgeDays, freshDimensions })
 *   observationState(obs, asOf)                            -> 'current' | 'stale'
 *   finding({ rule, subject, scope, severity, confidence, state, refs, message })
 *   decision({ subject, effect, decided_by, as_of, findings, rules, fails })
 *   decide(findings, policy, asOf, { subjects, facts })    -> [Decision]   (the only effect computation)
 *   outcomeFails(outcome, { threshold, families, ruleOf }) -> does this rule outcome fail the run
 *   exitCode(decisions)                                    -> 0 | 1 | 2
 *   findingsDocument({ asOf, observations, findings, decisions }) -> mcp-vault/findings@1
 *   toJson(doc) / canonicalJson(value) / sortFindings(list)
 *   toSarif(findings, opts)                                -> SARIF 2.1.0 (opts.decisions: + finding-less outcomes)
 *   explainTrace(doc, subjectId) / renderTrace(trace)      -> observation → finding → decision
 */

const crypto = require('crypto');
const { requireAsOf, isoInstant, DAY_MS } = require('./clock.cjs');

const SCHEMA = 'mcp-vault/findings@1';

// The rules are the code, so the code's version is the rules' version. Two
// runs at the same asOf over the same inputs agree byte for byte only when
// this agrees too, and the document says which one produced it.
const RULES_VERSION = (() => {
  try { return `mcp-vault@${require('../../../package.json').version}`; } catch { return 'mcp-vault@unknown'; }
})();

const SUBJECT_TYPES = ['artifact', 'tool', 'host-config', 'setup', 'name'];
const SEVERITIES    = ['critical', 'high', 'medium', 'low', 'info'];
const CONFIDENCES   = ['high', 'medium', 'low'];
// `observed` is the only state in which a finding is a statement about the
// subject. The other three are statements about *us*: the check did not run,
// it ran and had nothing to look at, or what it looked at has aged out. None
// of them is "clean", and a consumer that treats an unknown state as a pass
// is the bug this list exists to prevent.
const STATES        = ['observed', 'not-run', 'no-data', 'stale'];
const EFFECTS       = ['allow', 'warn', 'deny', 'unknown'];
// Worst first. `unknown` outranks `warn`: "nobody looked" is not a softer
// answer than "somebody looked and did not like it".
const EFFECT_RANK   = { deny: 0, unknown: 1, warn: 2, allow: 3 };

const RULE_ID = /^[a-z0-9][a-z0-9-]*(\/[a-z0-9][a-z0-9.-]*)+$/;

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const str = (v) => (v === null || v === undefined ? '' : String(v));

function fail(what, why) {
  throw new TypeError(`${what}: ${why}`);
}

// ── subjects ───────────────────────────────────────────────────────────────

/**
 * What a finding is about, typed — because where it points decides where
 * SARIF anchors it and what a reader is meant to go and look at. An id is
 * derived, never supplied, so two producers cannot spell the same subject two
 * ways.
 */
const subject = {
  artifact({ entry, version = null, integrity = null, artifact_id = null } = {}) {
    if (!entry) fail('subject.artifact', 'entry is required');
    // Every part that is known, in order. A missing version or hash is left
    // out rather than written as a placeholder that could collide.
    const id = `${entry}${version ? `@${version}` : ''}${integrity ? `+${integrity}` : ''}`;
    return { type: 'artifact', id, entry: String(entry), version: version || null, integrity: integrity || null, artifact_id: artifact_id || null };
  },
  tool({ server, tool, location = null } = {}) {
    if (!server || !tool) fail('subject.tool', 'server and tool are required');
    return { type: 'tool', id: `${server}/${tool}${location ? `#${location}` : ''}`, server: String(server), tool: String(tool), location: location || null };
  },
  hostConfig({ path: file, line = null, host = null, scope = null, server = null } = {}) {
    if (!file) fail('subject.hostConfig', 'path is required');
    const ln = Number.isInteger(line) && line > 0 ? line : null;
    return { type: 'host-config', id: `${file}${ln ? `:${ln}` : ''}`, path: String(file), line: ln, host: host || null, scope: scope || null, server: server || null };
  },
  setup({ host, scope = null } = {}) {
    if (!host) fail('subject.setup', 'host is required');
    return { type: 'setup', id: String(host), host: String(host), scope: scope || null };
  },
  // A name that is not (yet) an artifact: a lookalike candidate, a config key
  // that matches nothing. Distinct from `artifact` because there are no bytes.
  name({ name, ecosystem = null } = {}) {
    if (!name) fail('subject.name', 'name is required');
    return { type: 'name', id: `${ecosystem ? `${ecosystem}:` : ''}${name}`, name: String(name), ecosystem: ecosystem || null };
  },
};

function validateSubject(s, where = 'subject') {
  if (!s || typeof s !== 'object') fail(where, 'a typed subject is required (lib/finding.cjs subject.*)');
  if (!SUBJECT_TYPES.includes(s.type)) fail(where, `unknown subject type ${JSON.stringify(s.type)} (one of ${SUBJECT_TYPES.join(', ')})`);
  if (!s.id || typeof s.id !== 'string') fail(where, 'subject has no id');
  return s;
}

// ── observations ───────────────────────────────────────────────────────────

const dayStart = (isoLike) => Date.parse(`${String(isoLike).slice(0, 10)}T00:00:00Z`);

/**
 * A dated fact. `observed_at` is when the check looked; `confirmed_at` when
 * it last came back affirmative — the one that ages (see lib/evidence.cjs on
 * `verified_at`). `expires_at` is the first instant it is stale: the same
 * boundary `staleDimensions` draws, written down so a reader need not know the
 * TTL table to see it.
 */
function observation({
  subject: subj, dimension, status, observed_at, confirmed_at = null,
  ttl_days = null, source = 'stored', artifact_id = null, detail = null,
} = {}) {
  const s = validateSubject(subj, 'observation');
  if (!dimension) fail('observation', 'dimension is required');
  if (!status)    fail('observation', 'status is required');
  if (!observed_at || Number.isNaN(dayStart(observed_at))) fail('observation', `observed_at must be a date (got ${JSON.stringify(observed_at)})`);
  const base = confirmed_at || observed_at;
  const expires = Number.isFinite(ttl_days) ? isoInstant(dayStart(base) + (ttl_days + 1) * DAY_MS) : null;
  const obs = {
    id: `obs:${s.id}#${dimension}@${String(observed_at).slice(0, 10)}`,
    subject: s.id,
    artifact_id: artifact_id || null,
    dimension: String(dimension),
    status: String(status),
    observed_at: String(observed_at).slice(0, 10),
    confirmed_at: confirmed_at ? String(confirmed_at).slice(0, 10) : null,
    ttl_days: Number.isFinite(ttl_days) ? ttl_days : null,
    expires_at: expires,
    source: String(source),
  };
  if (detail !== null && detail !== undefined) obs.detail = String(detail);
  return obs;
}

/** 'stale' from `expires_at` on; an observation with no TTL does not age. */
function observationState(obs, asOf) {
  const at = requireAsOf(asOf, 'observationState');
  if (!obs || !obs.expires_at) return 'current';
  return at >= Date.parse(obs.expires_at) ? 'stale' : 'current';
}

/**
 * The evidence record, as observations. `freshDimensions` names the ones this
 * run established (source `run`); the rest came from the DB (`stored`).
 */
function observationsFromEvidence(evidence, { subject: subj, source = 'stored', maxAgeDays = {}, freshDimensions = null, positive = () => false } = {}) {
  const dims = (evidence && evidence.dimensions) || {};
  const out = [];
  for (const [dimension, v] of Object.entries(dims)) {
    if (!v || !v.status) continue;
    const ttl = typeof maxAgeDays === 'number' ? maxAgeDays : maxAgeDays[dimension];
    out.push(observation({
      subject: subj,
      dimension,
      status: v.status,
      observed_at: v.checked_at || '1970-01-01',
      // Same rule as staleDimensions: the confirmation date, or the look if
      // the status was affirmative and predates `verified_at`.
      confirmed_at: v.verified_at || (positive(dimension, v.status) ? v.checked_at : null),
      ttl_days: Number.isFinite(ttl) ? ttl : null,
      source: freshDimensions && freshDimensions.has(dimension) ? 'run' : source,
      artifact_id: evidence.artifact_id || null,
    }));
  }
  return out;
}

// ── findings ───────────────────────────────────────────────────────────────

const shortHash = (value) => crypto.createHash('sha256').update(canonicalJson(value)).digest('hex').slice(0, 16);

/**
 * A rule's conclusion. Validated here, once, so that no producer can emit a
 * finding with a free-text severity, an untyped subject or — the one this
 * model exists to prevent — a policy effect smuggled in as a field.
 */
function finding({
  rule, subject: subj, scope = null, severity, confidence = 'high', state = 'observed',
  refs = [], message, ...rest
} = {}) {
  for (const k of ['effect', 'outcome', 'decision', 'level']) {
    if (k in rest) fail('finding', `"${k}" is a decision, not a finding — see decide()`);
  }
  if (!RULE_ID.test(String(rule || ''))) fail('finding', `rule must be "<family>/<rule>" in lower case (got ${JSON.stringify(rule)})`);
  const s = validateSubject(subj, 'finding');
  if (!SEVERITIES.includes(severity))    fail('finding', `severity must be one of ${SEVERITIES.join(', ')} (got ${JSON.stringify(severity)})`);
  if (!CONFIDENCES.includes(confidence)) fail('finding', `confidence must be one of ${CONFIDENCES.join(', ')} (got ${JSON.stringify(confidence)})`);
  if (!STATES.includes(state))           fail('finding', `state must be one of ${STATES.join(', ')} (got ${JSON.stringify(state)})`);
  if (typeof message !== 'string' || !message.trim()) fail('finding', 'message is required');
  const msg = message.replace(/\s*\n\s*/g, ' ').trim();
  return {
    // Stable across runs and across evidence dates: what was concluded about
    // what, not when. SARIF fingerprints and cross-run diffs key on it.
    id: `f:${shortHash({ rule, subject: s.id, scope, state, message: msg })}`,
    rule: String(rule),
    subject: s,
    scope: scope || null,
    severity,
    confidence,
    state,
    refs: [...new Set((refs || []).map(String))].sort(cmp),
    message: msg,
  };
}

const findingKey = (f) => [f.subject.id, f.rule, f.state, f.message, f.id];

function sortFindings(list) {
  return [...(list || [])].sort((a, b) => {
    const ka = findingKey(a), kb = findingKey(b);
    for (let i = 0; i < ka.length; i++) { const c = cmp(str(ka[i]), str(kb[i])); if (c) return c; }
    return 0;
  });
}

// ── decisions ──────────────────────────────────────────────────────────────

function decision({
  subject: subj, effect, decided_by, as_of, findings: ids = [], rules = [],
  fails = effect === 'deny', fail_on = 'deny', unanswered = false,
} = {}) {
  const s = validateSubject(subj, 'decision');
  if (!EFFECTS.includes(effect)) fail('decision', `effect must be one of ${EFFECTS.join(', ')} (got ${JSON.stringify(effect)})`);
  if (!decided_by || !RULE_ID.test(decided_by)) fail('decision', `decided_by must name the rule that decided (got ${JSON.stringify(decided_by)})`);
  return {
    subject: s,
    effect,
    decided_by,
    as_of: isoInstant(requireAsOf(typeof as_of === 'string' ? Date.parse(as_of) : as_of, 'decision')),
    // Whether this decision fails the run at the policy's threshold. `deny`
    // always does; `unknown` and `warn` do when `fail_on` reaches them — in
    // both cases only among the policy's `fail_families`, when it names any.
    fails: Boolean(fails),
    fail_on,
    // A question this run could not answer (an unreadable config): exit 2
    // when nothing fails, because "no findings" would be a claim about
    // something nobody saw.
    unanswered: Boolean(unanswered),
    findings: [...new Set(ids)].sort(cmp),
    // Every rule that had something to say, in table order, with what it
    // said — the trace `explain` prints and the audit record keeps.
    rules: rules.map((r) => ({
      rule: r.rule, effect: r.effect, detail: r.detail || null, findings: [...new Set(r.findings || [])].sort(cmp),
    })),
  };
}

const failsAt = (effect, failOn) => effect === 'deny'
  || (failOn === 'unknown' && effect === 'unknown')
  || (failOn === 'warn' && (effect === 'unknown' || effect === 'warn'));

/**
 * Whether one rule outcome fails the run: `deny` always, `unknown` / `warn`
 * from a thresholded row when `threshold` (fail_on) reaches them — and, when
 * the policy names `fail_families`, only an outcome of one of them: by its
 * own rule id, or by a finding it rests on (`ruleOf`: finding id -> rule).
 * decide() computes `fails` with this; a renderer that must say *which*
 * outcome failed (verify's report lines) asks the same function.
 */
function outcomeFails(o, { threshold = 'deny', families = null, ruleOf = new Map(), thresholded = o.thresholded } = {}) {
  const fam = Array.isArray(families) && families.length ? families : null;
  const inFamily = (rule) => fam.some((f) => rule === f || String(rule).startsWith(`${f}/`));
  if (fam && !inFamily(o.rule) && !(o.findings || []).some((id) => ruleOf.has(id) && inFamily(ruleOf.get(id)))) return false;
  return o.effect === 'deny' || Boolean(thresholded && failsAt(o.effect, threshold));
}

/**
 * policy × findings → one Decision per subject. The only function in the
 * project that computes an effect (docs/adr/0001, "one place decides").
 *
 *   findings  lib/finding.cjs findings, any subjects
 *   policy    the frozen effective policy (lib/policy_rules.cjs); an ad-hoc
 *             object is refused, because a policy assembled on the way is how
 *             two commands came to enforce two different bars
 *   asOf      the instant decided at
 *   subjects  everything examined — a subject with no findings is an
 *             explicit allow, not an absence
 *   facts     subject id -> what rules may read that is not a finding
 *             (entry licence/health/trust, stored evidence, trust score,
 *             behaviour, budget, live gate status, `mode`)
 *   failOn    override the policy's exit threshold for this question
 *
 * Rules come from the table in lib/policy_rules.cjs, in its order. The worst
 * effect wins (deny > unknown > warn > allow); `decided_by` is the first rule
 * in table order that produced it.
 */
function decide(findings, policy, asOf, { subjects = [], facts = {}, mode = 'gate', failOn = null } = {}) {
  const at = requireAsOf(asOf, 'decide');
  if (!policy || typeof policy !== 'object' || !Object.isFrozen(policy)) {
    fail('decide', 'policy must be the frozen effective policy from lib/policy_rules.cjs (effectivePolicy / loadEffectivePolicy)');
  }
  // Required here rather than at the top: lib/policy_rules.cjs reads this
  // module's constants and must be loadable without it.
  const { rulesFor } = require('./policy_rules.cjs');
  // The threshold is the policy's (flags already applied). `failOn` exists
  // for a caller that must ask a different question; explain and verify do
  // not pass it, so one decision exits the same way from both.
  const threshold = failOn || policy.fail_on || 'deny';

  const bySubject = new Map();
  const slot = (s) => {
    if (!bySubject.has(s.id)) bySubject.set(s.id, { subject: s, findings: [] });
    return bySubject.get(s.id);
  };
  for (const s of subjects) slot(validateSubject(s, 'decide'));
  for (const f of findings || []) slot(validateSubject(f.subject, 'decide')).findings.push(f);

  const out = [];
  for (const { subject: s, findings: unsorted } of bySubject.values()) {
    // Canonical order, so the decision does not depend on the order a
    // producer happened to emit its findings in.
    const fs = sortFindings(unsorted);
    const subjectFacts = (facts && facts[s.id]) || {};
    // `asOf` is in the context so that a rule judging an age (org/evidence/*)
    // reads the decision's instant, never the clock.
    const ctx = { subject: s, findings: fs, policy, facts: subjectFacts, mode: subjectFacts.mode || mode, asOf: at };
    const outcomes = [];
    for (const row of rulesFor(ctx.mode)) {
      // --no-policy drops the policy file's rules; the gate's own stay.
      if (!policy.policy_rules && row.id.startsWith('policy/')) continue;
      for (const o of row.evaluate(ctx)) {
        outcomes.push({ rule: o.rule || row.id, effect: o.effect, detail: o.detail, findings: o.findings || [], thresholded: row.thresholded });
      }
    }
    const ruleOf = new Map(fs.map((f) => [f.id, f.rule]));
    let worst = null;
    for (const o of outcomes) if (!worst || EFFECT_RANK[o.effect] < EFFECT_RANK[worst.effect]) worst = o;
    const effect = worst ? worst.effect : 'allow';
    out.push(decision({
      subject: s,
      effect,
      decided_by: worst ? worst.rule : 'finding/none',
      as_of: at,
      findings: outcomes.filter((o) => o.effect === effect).flatMap((o) => o.findings),
      rules: outcomes,
      fails: outcomes.some((o) => outcomeFails(o, { threshold, families: policy.fail_families, ruleOf })),
      fail_on: threshold,
      unanswered: fs.some((f) => f.rule.startsWith('scope/')),
    }));
  }
  return out.sort((a, b) => cmp(a.subject.id, b.subject.id));
}

/** The exit code the decisions imply: 1 a failure, 2 unanswered, else 0. */
function exitCode(decisions) {
  if ((decisions || []).some((d) => d.fails)) return 1;
  if ((decisions || []).some((d) => d.unanswered)) return 2;
  return 0;
}

// ── documents ──────────────────────────────────────────────────────────────

/** Recursively sorted keys; arrays keep their (already sorted) order. */
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort(cmp)) {
      if (value[k] === undefined) continue;
      out[k] = canonicalize(value[k]);
    }
    return out;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

/**
 * The findings@1 document. It carries its own inputs — the effective policy
 * and the per-subject facts — next to the decisions, so that
 * `decide(doc.findings, policy, doc.as_of, { subjects, facts: doc.facts })`
 * reproduces `doc.decisions` from the document alone. That is the property
 * the cross-command consistency test checks, and the one an auditor needs
 * six months later.
 */
function findingsDocument({ asOf, observations = [], findings = [], decisions = [], scope = null, policy = null, facts = {} } = {}) {
  const at = requireAsOf(asOf, 'findingsDocument');
  return {
    schema: SCHEMA,
    as_of: isoInstant(at),
    rules_version: RULES_VERSION,
    scope: scope || null,
    policy: policy ? JSON.parse(JSON.stringify(policy)) : null,
    facts: JSON.parse(JSON.stringify(facts || {})),
    observations: [...observations].sort((a, b) => cmp(a.subject, b.subject) || cmp(a.dimension, b.dimension) || cmp(a.id, b.id)),
    findings: sortFindings(findings),
    decisions: [...decisions].sort((a, b) => cmp(a.subject.id, b.subject.id)),
  };
}

/** Subjects of a document: every decision's, and every finding's. */
function documentSubjects(doc) {
  const seen = new Map();
  for (const d of doc.decisions || []) seen.set(d.subject.id, d.subject);
  for (const f of doc.findings || []) if (!seen.has(f.subject.id)) seen.set(f.subject.id, f.subject);
  return [...seen.values()];
}

/** The `--json` form: canonical, so equal inputs are equal bytes. */
function toJson(doc) {
  return canonicalize(doc);
}

// ── SARIF ──────────────────────────────────────────────────────────────────

function sarifLevel(f) {
  if (f.severity === 'critical' || f.severity === 'high') return 'error';
  if (f.severity === 'medium') return 'warning';
  return 'note';
}

/**
 * Where a finding lives, by subject type. An artifact is a row in the DB; a
 * host config is a file and a line; a tool, a setup and a bare name have no
 * file of ours to point at, so they get a logical location instead of a
 * fabricated line 1.
 */
function sarifLocation(s, { dbPath, lineOf }) {
  switch (s.type) {
    case 'artifact':
      return { physicalLocation: { artifactLocation: { uri: dbPath }, region: { startLine: lineOf(s.entry) } } };
    case 'host-config':
      return {
        physicalLocation: { artifactLocation: { uri: s.path }, ...(s.line ? { region: { startLine: s.line } } : {}) },
      };
    case 'tool':
      return { logicalLocations: [{ fullyQualifiedName: `${s.server}/${s.tool}`, kind: 'function' }] };
    case 'setup':
      return { logicalLocations: [{ name: s.host, kind: 'module' }] };
    default:
      return { logicalLocations: [{ name: s.id, kind: 'package' }] };
  }
}

/**
 * `decisions` (optional): also render each rule outcome that is not `allow`
 * and rests on no finding — a policy licence deny, a missing signature the
 * policy requires — at its subject. Those decide the run but are not
 * findings, so without them the annotations would not explain a red job.
 * A rendering of the Decision: the level is read off its effect, not decided.
 */
function toSarif(findings, {
  toolName = 'mcp-vault', dbPath = 'mcp-ecosystem-intelligence/assets/tools_database.json',
  lineOf = () => 1, includeNotes = false, ruleHelp = {}, decisions = null,
} = {}) {
  const results = [];
  const used = new Map();
  for (const d of [...(decisions || [])].sort((a, b) => cmp(a.subject.id, b.subject.id))) {
    for (const o of d.rules || []) {
      if (o.effect === 'allow' || (o.findings && o.findings.length)) continue;
      const level = o.effect === 'deny' ? 'error' : 'warning';
      used.set(o.rule, level === 'error' || used.get(o.rule) === 'error' ? 'error' : 'warning');
      results.push({
        ruleId: o.rule,
        level,
        message: { text: o.detail || o.rule },
        locations: [sarifLocation(d.subject, { dbPath, lineOf })],
        partialFingerprints: { decisionId: `d:${shortHash({ rule: o.rule, subject: d.subject.id, detail: o.detail || null })}` },
        properties: { effect: o.effect, subject: d.subject.id },
      });
    }
  }
  for (const f of sortFindings(findings)) {
    const level = sarifLevel(f);
    if (level === 'note' && !includeNotes) continue;
    used.set(f.rule, level === 'error' || used.get(f.rule) === 'error' ? 'error' : 'warning');
    results.push({
      ruleId: f.rule,
      level,
      message: { text: f.message },
      locations: [sarifLocation(f.subject, { dbPath, lineOf })],
      partialFingerprints: { findingId: f.id },
      properties: { state: f.state, severity: f.severity, confidence: f.confidence, subject: f.subject.id },
    });
  }
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: toolName,
          informationUri: 'https://github.com/froggychips/mcp-skills-vault',
          rules: [...used.keys()].sort(cmp).map((id) => ({
            id,
            shortDescription: { text: id },
            fullDescription:  { text: ruleHelp[id] || id },
            help:             { text: ruleHelp[id] || id },
            defaultConfiguration: { level: used.get(id) },
          })),
        },
      },
      results,
    }],
  };
}

// ── explain ────────────────────────────────────────────────────────────────

/**
 * observation → finding → decision, for one subject (or all). The part of a
 * denial worth reading is the chain: which rule decided, on which findings,
 * resting on which dated facts — and whether those facts are still current at
 * the instant the decision was made.
 */
function explainTrace(doc, subjectId = null) {
  const at = Date.parse(doc.as_of);
  const obsById = new Map((doc.observations || []).map((o) => [o.id, o]));
  const fById = new Map((doc.findings || []).map((f) => [f.id, f]));
  return (doc.decisions || [])
    .filter((d) => !subjectId || d.subject.id === subjectId)
    .map((d) => ({
      subject: d.subject.id,
      effect: d.effect,
      decided_by: d.decided_by,
      as_of: d.as_of,
      fails: d.fails,
      rules: d.rules.map((r) => ({
        rule: r.rule,
        effect: r.effect,
        detail: r.detail || null,
        findings: r.findings.map((id) => fById.get(id)).filter(Boolean).map((f) => ({
          id: f.id, rule: f.rule, state: f.state, severity: f.severity, message: f.message,
          observations: f.refs.map((id) => obsById.get(id)).filter(Boolean).map((o) => ({
            id: o.id, dimension: o.dimension, status: o.status, observed_at: o.observed_at,
            expires_at: o.expires_at, source: o.source, state: observationState(o, at),
          })),
        })),
      })),
    }));
}

function renderTrace(trace) {
  const lines = [];
  for (const d of trace) {
    lines.push(`${d.effect.toUpperCase()}  ${d.subject}  — decided by ${d.decided_by} as of ${d.as_of}${d.fails ? ' (fails the run)' : ''}`);
    for (const r of d.rules) {
      lines.push(`  ${r.effect.padEnd(7)} ${r.rule}${r.detail ? ` — ${r.detail}` : ''}`);
      for (const f of r.findings) {
        lines.push(`    ← ${f.rule} [${f.state}, ${f.severity}] ${f.message}`);
        for (const o of f.observations) {
          lines.push(`        ← ${o.dimension}: ${o.status} (${o.source}, observed ${o.observed_at}${o.expires_at ? `, ${o.state === 'stale' ? 'stale since' : 'stale from'} ${o.expires_at.slice(0, 10)}` : ''})`);
        }
      }
    }
  }
  return lines;
}

module.exports = {
  failsAt, outcomeFails,
  SCHEMA, RULES_VERSION, SUBJECT_TYPES, SEVERITIES, CONFIDENCES, STATES, EFFECTS, EFFECT_RANK,
  subject, validateSubject,
  observation, observationState, observationsFromEvidence,
  finding, sortFindings,
  decision, decide, exitCode,
  canonicalize, canonicalJson, findingsDocument, documentSubjects, toJson,
  toSarif, sarifLevel, sarifLocation,
  explainTrace, renderTrace,
};
