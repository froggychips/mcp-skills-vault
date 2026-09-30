'use strict';
/**
 * Producers: what each existing check concluded, as findings.
 *
 * lib/finding.cjs is the shape; this file is where today's outputs are read
 * into it, so that every command decides over the same kind of input:
 *
 *   fromVerifyResults   the gate's per-entry results (tags, typed `checks`,
 *                       stored evidence) — what `verify` saw this run
 *   fromReportEntry     one entry of a `verify --json` report — what `explain
 *                       --verify` gets back from the live gate
 *   fromEvidence        stored, dated evidence alone — what `explain` has
 *                       when no gate ran
 *
 * Each returns `{ observations, findings }` over typed subjects. None of them
 * decides anything: that is `decide()`, over the table in lib/policy_rules.cjs.
 *
 * API:
 *   subjectForTool(tool)                                  -> Subject
 *   fromVerifyResults(results, { asOf, maxAgeDays, scope })
 *        -> { observations, findings, subjects: [Subject per result] }
 *   fromReportEntry(entry, { subject, scope })            -> { observations: [], findings }
 *   fromEvidence(evidence, { subject, asOf, maxAgeDays, required, scope })
 */

const { subject, observationsFromEvidence, observationState, finding } = require('./finding.cjs');
const { modelForLine, TAG_MODEL } = require('./legacy_tags.cjs');
const { buildEvidence, mergeEvidence, isPositive, POSITIVE_STATUSES } = require('./evidence.cjs');
const { toTypedEntry, artifactId } = require('./entry_model.cjs');
const { blocks } = require('./scores.cjs');
const { requireAsOf } = require('./clock.cjs');

/** A DB entry or an installed server, as a typed subject. */
function subjectForTool(tool) {
  const inst = tool && tool._installed;
  // A host config that did not parse is not an artifact: point at the file.
  if (inst && inst.kind === 'unreadable') {
    return subject.hostConfig({ path: inst.source || tool.name, host: inst.host || null, scope: inst.scope || null });
  }
  let id = null;
  try { const t = toTypedEntry(tool); id = t ? artifactId(t.artifact) : null; } catch { id = null; }
  return subject.artifact({ entry: tool && tool.name ? tool.name : '(unnamed)', version: tool && tool.version, integrity: tool && tool.pkg_integrity, artifact_id: id });
}

// Which observations a tag's finding rests on. `null` means "whatever on this
// subject is negative" (a FAIL can come from several checks).
const TAG_DIMENSIONS = {
  FAIL: null, CVE: ['advisories'], UNVERIFIED: null, MISS: ['artifact'],
  WARN: ['source_binding', 'provenance'], HOOK: [], DIGEST: ['artifact'], DEEP: ['artifact'],
  SIG: ['signature'], PROV: ['provenance'], PROVBOUND: ['provenance'],
  DEPS: ['dependencies'], DEPHOOK: ['dependencies'], DEPCVE: ['dependencies'], NOTE: [],
};

function refsFor(tag, model, observations, asOf) {
  if (model.state === 'stale') return observations.filter((o) => observationState(o, asOf) === 'stale').map((o) => o.id);
  const dims = TAG_DIMENSIONS[tag];
  if (dims === null) {
    return observations
      .filter((o) => (model.state === 'observed' ? !POSITIVE_STATUSES.has(o.status) && o.status !== 'unverified' : !isPositive(o.dimension, o.status)))
      .map((o) => o.id);
  }
  return observations.filter((o) => (dims || []).includes(o.dimension)).map((o) => o.id);
}

/**
 * The gate's results → observations and findings. `maxAgeDays` is the TTL
 * table in force (verify's `evidenceMaxAge()`), so an observation's
 * `expires_at` is the same boundary the stale line was drawn at.
 */
function fromVerifyResults(results, { asOf, maxAgeDays = {}, scope = 'database' } = {}) {
  const at = requireAsOf(asOf, 'fromVerifyResults');
  const observations = [];
  const findings = [];
  const subjects = [];
  for (const r of results || []) {
    if (!r || !r.tool) { subjects.push(null); continue; }
    const s = subjectForTool(r.tool);
    subjects.push(s);
    if (r.status === 'UPD') continue;

    // The evidence this run judged: what it established, over what was stored.
    let typed = null;
    try { typed = toTypedEntry(r.tool); } catch { typed = null; }
    const stored = r.tool.trust_evidence || null;
    const fresh = buildEvidence(r.checks, { artifactId: typed ? artifactId(typed.artifact) : null, now: at });
    const freshDims = new Set(Object.keys(fresh.dimensions));
    const effective = freshDims.size ? mergeEvidence(stored, fresh) : stored;
    const obs = s.type === 'artifact'
      ? observationsFromEvidence(effective, { subject: s, source: 'stored', maxAgeDays, freshDimensions: freshDims, positive: isPositive })
      : [];
    observations.push(...obs);

    const lines = r.lines || [];
    for (const line of lines) {
      const model = modelForLine(line);
      if (!model) continue;   // a POLICY-* line is a decision, rendered from decide()
      findings.push(finding({
        rule: model.rule, subject: s, scope, severity: model.severity, state: model.state,
        refs: refsFor(line[0], model, obs, at), message: String(line[1] || line[0]),
      }));
    }
    // The status line carries the verdict for single-line results: an entry
    // that could not be routed, an image reference that did not parse.
    if (!lines.length && (r.status === 'UNVERIFIED' || r.status === 'SKIP')) {
      const unreadable = r.tool._installed && r.tool._installed.kind === 'unreadable';
      const base = r.status === 'SKIP' ? TAG_MODEL.SKIP : TAG_MODEL.UNVERIFIED;
      findings.push(finding({
        rule: unreadable ? 'scope/unreadable' : base.rule, subject: s, scope,
        severity: unreadable ? 'medium' : base.severity,
        state: unreadable ? 'no-data' : base.state,
        message: String(r.msg || r.status),
      }));
    }
  }
  return { observations, findings, subjects };
}

/** One `verify --json` entry (tags only, no third element) → findings. */
function fromReportEntry(entry, { subject: s, scope = 'database' } = {}) {
  const findings = [];
  for (const f of (entry && entry.findings) || []) {
    const model = modelForLine([f.tag, f.message]);
    if (!model) continue;
    findings.push(finding({ rule: model.rule, subject: s, scope, severity: model.severity, state: model.state, message: String(f.message || f.tag) }));
  }
  return { observations: [], findings };
}

/**
 * Stored evidence alone → observations and one finding per dimension that
 * says something a decision can use. A blocking status is high; any other
 * negative status is medium; a claim past its shelf life is `stale`; a
 * required dimension never checked is `no-data`. Affirmative, current
 * dimensions produce no finding — they are observations, and the trace shows
 * them where a rule cites them.
 */
function fromEvidence(evidence, { subject: s, asOf, maxAgeDays = {}, required = [], scope = 'database' } = {}) {
  const at = requireAsOf(asOf, 'fromEvidence');
  const observations = evidence
    ? observationsFromEvidence(evidence, { subject: s, source: 'stored', maxAgeDays, positive: isPositive })
    : [];
  const findings = [];
  for (const o of observations) {
    const stale = observationState(o, at) === 'stale';
    if (blocks(o.dimension, o.status)) {
      findings.push(finding({ rule: `evidence/${o.dimension.replace(/_/g, '-')}`, subject: s, scope, severity: 'high', state: 'observed', refs: [o.id], message: `${o.dimension}: ${o.status} (as of ${o.observed_at})` }));
    } else if (stale) {
      findings.push(finding({ rule: 'evidence/stale', subject: s, scope, severity: 'medium', state: 'stale', refs: [o.id], message: `${o.dimension}: ${o.status}, established ${o.confirmed_at || o.observed_at}, past its shelf life since ${o.expires_at.slice(0, 10)}` }));
    } else if (['mismatch', 'fail', 'contradicted', 'withdrawn'].includes(o.status)) {
      findings.push(finding({ rule: `evidence/${o.dimension.replace(/_/g, '-')}`, subject: s, scope, severity: 'medium', state: 'observed', refs: [o.id], message: `${o.dimension}: ${o.status} (as of ${o.observed_at})` }));
    }
  }
  const have = new Set(observations.map((o) => o.dimension));
  for (const dim of required) {
    if (!have.has(dim)) {
      findings.push(finding({ rule: 'evidence/missing', subject: s, scope, severity: 'medium', state: 'no-data', message: `${dim} has never been checked for this artifact` }));
    }
  }
  return { observations, findings };
}

module.exports = { subjectForTool, fromVerifyResults, fromReportEntry, fromEvidence, TAG_DIMENSIONS };
