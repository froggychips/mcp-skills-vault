'use strict';
/**
 * Trust as dated evidence, not as one word.
 *
 * `trust: "verified"` collapses several different claims with different
 * lifetimes into a single field: that a hash matched, that the repo URL agreed,
 * that the licence was OSI, that no advisory applied, that the server actually
 * booted. Those were true on different days. A hash match is good until the
 * pin changes; "no advisories" is good until the next disclosure — which can be
 * tomorrow. Read as one word, the oldest and least durable claim silently
 * inherits the confidence of the newest.
 *
 * So each dimension carries its own status and timestamp, and the single word
 * becomes a derived value:
 *
 *   trust_evidence: {
 *     artifact:       { status: 'verified',  checked_at: '2026-09-17', method: 'deep-hash' },
 *     signature:      { status: 'verified',  checked_at: '2026-09-17', keyid: 'SHA256:…' },
 *     provenance:     { status: 'claimed',   checked_at: '2026-09-17', repository: '…' },
 *     source_binding: { status: 'verified',  checked_at: '2026-09-17' },
 *     license:        { status: 'osi',       checked_at: '2026-09-17', value: 'MIT' },
 *     advisories:     { status: 'clean',     checked_at: '2026-09-17' },
 *     dependencies:   { status: 'hooks',     checked_at: '2026-09-17', count: 608 },
 *     smoke:          { status: 'pass',      checked_at: '2026-09-10', tools: 29 }
 *   }
 *
 * Evidence is keyed to an artifact id (ecosystem:package@version), so it is
 * discarded rather than inherited when the version moves: what we learned about
 * 1.2.3 says nothing about 1.2.4.
 *
 * API:
 *   buildEvidence(checks, opts)               -> { artifact_id, dimensions }
 *   mergeEvidence(existing, fresh)            -> merged   (per-dimension, newest wins)
 *   staleDimensions(evidence, maxAgeDays, now)-> [names]
 *   deriveTrust(evidence, opts)               -> 'verified' | 'candidate' | 'unverified'
 *   DIMENSIONS                                -> ordered list of dimension names
 */

const DIMENSIONS = [
  'artifact',        // the bytes match the pin
  'signature',       // the registry vouched for that pin
  'provenance',      // a build claims to have produced it
  'source_binding',  // the registry's repo agrees with ours
  'license',         // what the licence actually says
  'advisories',      // nothing known against this version
  'dependencies',    // what the tree contains
  'smoke',           // it starts and lists tools
];

// How long each kind of claim stays meaningful, in days. An advisory result is
// the perishable one: "clean" means "clean as of that date", and disclosures
// do not wait. A hash match, by contrast, is about bytes that do not change.
const DEFAULT_MAX_AGE_DAYS = {
  artifact:       90,
  signature:      90,
  provenance:     90,
  source_binding: 60,
  license:        30,
  advisories:     7,
  dependencies:   14,
  smoke:          30,
};

const today = (now = Date.now()) => new Date(now).toISOString().slice(0, 10);

// What counts as an answer in the affirmative, per dimension vocabulary. Used
// where "did this actually check out?" is being asked, so that a new status
// added later defaults to "not established" rather than to "fine".
const POSITIVE_STATUSES = new Set(['verified', 'clean', 'claimed', 'pass', 'hooks', 'advisories-present', 'osi']);

/**
 * Turn one run's *typed check results* into dated evidence.
 *
 * This deliberately does not look at report prose. Deriving evidence by
 * matching messages meant a check that never ran was indistinguishable from a
 * check that passed: a digest-pinned docker entry came back `OK` without the
 * manifest ever being fetched, and that `OK` was recorded as artifact,
 * source_binding and advisories all verified. A processor now says what it
 * established, and anything it did not examine is simply absent — which is what
 * lets a later run fill it in without overwriting a real answer.
 */
function buildEvidence(checks, { now = Date.now(), artifactId = null } = {}) {
  const at = today(now);
  const dimensions = {};
  const put = (name, status, extra = {}) => {
    dimensions[name] = { status, checked_at: at, ...extra };
  };

  const c = checks || {};

  if (c.artifact) {
    put('artifact', c.artifact.state, c.artifact.method ? { method: c.artifact.method } : {});
  }
  if (c.signature) {
    put('signature', c.signature.state, c.signature.keyid ? { keyid: c.signature.keyid } : {});
  }
  if (c.provenance) {
    put('provenance', c.provenance.state, c.provenance.repository ? { repository: c.provenance.repository } : {});
  }
  if (c.source_binding) put('source_binding', c.source_binding.state);
  if (c.advisories)     put('advisories', c.advisories.state);
  if (c.dependencies) {
    put('dependencies', c.dependencies.state, Number.isFinite(c.dependencies.count) ? { count: c.dependencies.count } : {});
  }
  if (c.license) put('license', c.license.state, c.license.value ? { value: c.license.value } : {});

  return { artifact_id: artifactId, dimensions };
}

/** Evidence from a behavioural run, which is a separate stream. */
function smokeEvidence(evalResult, { now = Date.now() } = {}) {
  if (!evalResult || !evalResult.status) return null;
  return {
    status:     evalResult.status === 'pass' ? 'pass' : (evalResult.status === 'skip' ? 'skipped' : 'fail'),
    checked_at: (evalResult.checked_at || new Date(now).toISOString()).slice(0, 10),
    tools:      Number.isFinite(evalResult.tool_count) ? evalResult.tool_count : null,
    error:      evalResult.error_code || undefined,
  };
}

/**
 * Merge fresh evidence over existing, per dimension.
 *
 * Existing evidence for a *different* artifact id is dropped: it described a
 * different release. Within the same id, a dimension the fresh run didn't
 * examine keeps its previous (dated) answer — that is the point of the dates.
 */
function mergeEvidence(existing, fresh) {
  const sameArtifact = existing && fresh && existing.artifact_id && fresh.artifact_id
    && existing.artifact_id === fresh.artifact_id;
  const base = sameArtifact ? (existing.dimensions || {}) : {};
  const merged = { ...base };
  for (const [name, value] of Object.entries((fresh && fresh.dimensions) || {})) {
    if (!value) continue;
    const prev = merged[name];
    // Newest wins; equal dates prefer the fresh answer.
    if (!prev || !prev.checked_at || String(value.checked_at) >= String(prev.checked_at)) merged[name] = value;
  }
  const ordered = {};
  for (const name of DIMENSIONS) if (merged[name]) ordered[name] = merged[name];
  return { artifact_id: (fresh && fresh.artifact_id) || (existing && existing.artifact_id) || null, dimensions: ordered };
}

function daysBetween(fromIso, now) {
  const then = Date.parse(`${String(fromIso).slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(then)) return Infinity;
  return Math.floor((now - then) / 86400000);
}

/**
 * Dimensions whose answer is too old to rely on.
 * `maxAgeDays` may be a number (same bar for all) or a per-dimension object.
 */
function staleDimensions(evidence, maxAgeDays = DEFAULT_MAX_AGE_DAYS, now = Date.now()) {
  const dims = (evidence && evidence.dimensions) || {};
  const out = [];
  for (const [name, value] of Object.entries(dims)) {
    const limit = typeof maxAgeDays === 'number' ? maxAgeDays : (maxAgeDays[name] ?? DEFAULT_MAX_AGE_DAYS[name]);
    if (!Number.isFinite(limit)) continue;
    const age = daysBetween(value.checked_at, now);
    if (age > limit) out.push({ dimension: name, age_days: age, max_age_days: limit, checked_at: value.checked_at });
  }
  return out;
}

/**
 * The single word, derived.
 *
 * 'verified' requires the artifact to have been verified, nothing to have
 * failed, and no dimension that matters to be stale. Anything actively bad is
 * 'unverified' rather than 'candidate': candidate means "not vetted yet", not
 * "vetted and found wanting".
 */
const REQUIRED_BY_ECOSYSTEM = {
  npm:  ['artifact', 'advisories'],
  pypi: ['artifact', 'advisories'],
  oci:  ['artifact'],                 // no advisory feed keyed by image digest
  git:  [],                           // nothing to verify; never reaches 'verified'
};

/** Which dimensions must be affirmative for a given ecosystem. */
function requiredFor(ecosystem) {
  return REQUIRED_BY_ECOSYSTEM[ecosystem] || ['artifact'];
}

function deriveTrust(evidence, { maxAgeDays = DEFAULT_MAX_AGE_DAYS, now = Date.now(), require: required = ['artifact'] } = {}) {
  const dims = (evidence && evidence.dimensions) || {};
  const bad = ['mismatch', 'vulnerable', 'fail'];   // actively wrong, not merely unknown
  for (const value of Object.values(dims)) {
    if (bad.includes(value.status)) return 'unverified';
  }
  for (const name of required) {
    const dim = dims[name];
    // 'unverified' and 'absent' both mean nothing was established. So does a
    // status the vocabulary doesn't recognise as a positive result.
    if (!dim || !POSITIVE_STATUSES.has(dim.status)) return 'candidate';
  }
  if (staleDimensions(evidence, maxAgeDays, now).some((s) => required.includes(s.dimension) || s.dimension === 'advisories')) {
    return 'candidate';
  }
  // An ecosystem with nothing checkable (a git source install) cannot reach
  // 'verified' by having no requirements to fail.
  if (!required.length) return 'candidate';
  return 'verified';
}

module.exports = {
  DIMENSIONS, DEFAULT_MAX_AGE_DAYS, POSITIVE_STATUSES, REQUIRED_BY_ECOSYSTEM, requiredFor,
  buildEvidence, smokeEvidence, mergeEvidence, staleDimensions, deriveTrust,
};
