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
 *     availability:   { status: 'present',   checked_at: '2026-09-17' },
 *     artifact:       { status: 'verified',  checked_at: '2026-09-17', method: 'deep-hash' },
 *     signature:      { status: 'verified',  checked_at: '2026-09-17', keyid: 'SHA256:…' },
 *     provenance:     { status: 'bound',     checked_at: '2026-09-17', identity: '…' },
 *     source_binding: { status: 'verified',  checked_at: '2026-09-17' },
 *     registry:       { status: 'listed',    checked_at: '2026-09-17', server_id: 'io.github.o/r' },
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
 *   maxAgeForPolicy(filePolicy)               -> per-dimension shelf lives under a policy
 *   deriveTrust(evidence, opts)               -> 'verified' | 'candidate' | 'unverified'
 *   evidenceAsOf / entryAsOf / dbAsOf / evalResultsAsOf (…, asOf)
 *                                             -> the record without looks dated after asOf
 *
 * `now` is required wherever it appears (opts.now for the object forms). It
 * used to default to `Date.now()`, which made every verdict here a function of
 * the day it happened to run; lib/clock.cjs says where the instant comes from.
 *   DIMENSIONS                                -> ordered list of dimension names
 */

const DIMENSIONS = [
  'availability',    // the package is still published at all
  'artifact',        // the bytes match the pin
  'signature',       // the registry vouched for that pin
  'provenance',      // a build claims to have produced it
  'source_binding',  // the package registry's repo agrees with ours
  'registry',        // the official MCP registry's ownership-verified listing
  'repository_posture', // how the upstream repo is run (OpenSSF Scorecard)
  'license',         // what the licence actually says
  'advisories',      // nothing known against this version
  'dependencies',    // what the tree contains
  'smoke',           // it starts and lists tools
];

// How long each kind of claim stays meaningful, in days. An advisory result is
// the perishable one: "clean" means "clean as of that date", and disclosures
// do not wait. A hash match, by contrast, is about bytes that do not change.
const DEFAULT_MAX_AGE_DAYS = {
  // As perishable as an advisory: a package can be unpublished today, and the
  // name then becomes claimable by someone else.
  availability:   7,
  artifact:       90,
  signature:      90,
  provenance:     90,
  source_binding: 60,
  registry:       30,
  // Scorecard reruns weekly at most, and branch protection does not change often.
  repository_posture: 60,
  license:        30,
  advisories:     7,
  dependencies:   14,
  smoke:          30,
};

const { requireAsOf } = require('./clock.cjs');

const today = (now, where) => new Date(requireAsOf(now, where)).toISOString().slice(0, 10);

// What counts as an answer in the affirmative, per dimension vocabulary. Used
// where "did this actually check out?" is being asked, so that a new status
// added later defaults to "not established" rather than to "fine".
const POSITIVE_STATUSES = new Set(['verified', 'clean', 'claimed', 'bound', 'present', 'listed', 'pass', 'hooks', 'advisories-present', 'osi']);

/**
 * Which positive words belong to which dimension.
 *
 * `POSITIVE_STATUSES` is one flat vocabulary, and asking it "is this a good
 * result?" without saying *for what* accepted words from the wrong check:
 * `artifact: clean` and `advisories: verified` are not statuses either check
 * emits, and both satisfied a requirement neither had met. Evidence arrives
 * from pull requests, so a required dimension has to be satisfied by a word
 * that dimension can actually produce.
 */
const POSITIVE_BY_DIMENSION = {
  availability:       new Set(['present']),
  artifact:           new Set(['verified']),
  signature:          new Set(['verified']),
  provenance:         new Set(['bound', 'claimed']),
  source_binding:     new Set(['verified']),
  registry:           new Set(['listed']),
  advisories:         new Set(['clean', 'advisories-present']),
  dependencies:       new Set(['clean', 'hooks', 'advisories-present']),
  license:            new Set(['osi']),
  smoke:              new Set(['pass']),
  repository_posture: new Set(['clean']),
};

/** Is `status` an affirmative result *for this dimension*? */
function isPositive(dimension, status) {
  const set = POSITIVE_BY_DIMENSION[dimension];
  // An unrecognised dimension falls back to the flat vocabulary rather than
  // silently answering "no": a new check must not read as a failing one before
  // this table learns about it. Adding a dimension without adding it here is
  // caught by tests/evidence.test.cjs.
  return set ? set.has(status) : POSITIVE_STATUSES.has(status);
}

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
function buildEvidence(checks, { now, artifactId = null } = {}) {
  const at = today(now, 'buildEvidence');
  const dimensions = {};
  const put = (name, status, extra = {}) => {
    // `checked_at` is when we looked; `verified_at` is when it last checked
    // out. Only the second ages: an offline run that records
    // `unverified (offline-pin-present)` was a look, not a confirmation, and
    // letting it refresh the date made stale evidence look current by running
    // a check that verifies nothing.
    const entry = { status, checked_at: at, ...extra };
    if (POSITIVE_STATUSES.has(status)) entry.verified_at = at;
    dimensions[name] = entry;
  };

  const c = checks || {};

  if (c.availability) {
    const extra = {};
    if (c.availability.detail)  extra.detail = c.availability.detail;
    if (c.availability.replacement) extra.replacement = c.availability.replacement;
    put('availability', c.availability.state, extra);
  }
  if (c.artifact) {
    put('artifact', c.artifact.state, c.artifact.method ? { method: c.artifact.method } : {});
  }
  if (c.signature) {
    put('signature', c.signature.state, c.signature.keyid ? { keyid: c.signature.keyid } : {});
  }
  if (c.provenance) {
    const extra = {};
    if (c.provenance.repository) extra.repository = c.provenance.repository;
    // The signing identity is what makes a 'bound' result checkable later.
    if (c.provenance.identity) extra.identity = c.provenance.identity;
    put('provenance', c.provenance.state, extra);
  }
  if (c.source_binding) put('source_binding', c.source_binding.state);
  if (c.repository_posture) {
    const extra = {};
    if (c.repository_posture.checks)      extra.checks = c.repository_posture.checks;
    if (c.repository_posture.report_date) extra.report_date = c.repository_posture.report_date;
    put('repository_posture', c.repository_posture.state, extra);
  }
  if (c.registry) {
    const extra = {};
    if (c.registry.server_id) extra.server_id = c.registry.server_id;
    if (c.registry.detail)    extra.detail = c.registry.detail;
    put('registry', c.registry.state, extra);
  }
  if (c.advisories)     put('advisories', c.advisories.state);
  if (c.dependencies) {
    put('dependencies', c.dependencies.state, Number.isFinite(c.dependencies.count) ? { count: c.dependencies.count } : {});
  }
  if (c.license) put('license', c.license.state, c.license.value ? { value: c.license.value } : {});

  return { artifact_id: artifactId, dimensions };
}

/** Evidence from a behavioural run, which is a separate stream. */
function smokeEvidence(evalResult, { now } = {}) {
  requireAsOf(now, 'smokeEvidence');
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
  // Inheriting requires a positive match. Treating a missing id as "probably
  // the same" let evidence recorded with no identity — an older format, or a
  // run that could not name the artifact — attach itself to whatever came
  // next: stored `{artifact_id: null, advisories: clean}` merged into
  // `npm:other@2.0.0` and handed it an advisory result nothing had checked.
  const freshId = fresh && fresh.artifact_id;
  const existingId = existing && existing.artifact_id;
  const sameArtifact = Boolean(freshId && existingId && freshId === existingId)
    // Both unknown: nothing has been asserted about identity either way, and
    // the caller is looking at one entry.
    || (!freshId && !existingId && Boolean(existing));
  const base = sameArtifact ? ((existing && existing.dimensions) || {}) : {};
  const merged = { ...base };
  for (const [name, value] of Object.entries((fresh && fresh.dimensions) || {})) {
    if (!value) continue;
    const prev = merged[name];
    // Newest wins; equal dates prefer the fresh answer.
    if (!prev || !prev.checked_at || String(value.checked_at) >= String(prev.checked_at)) {
      // Carry the last confirmation forward. A fresh negative or inconclusive
      // result replaces the status but must not erase when the thing last
      // actually checked out — that date is what staleness is measured on.
      // Records written before `verified_at` existed only have `checked_at`,
      // and for a positive status that date *was* the confirmation; without
      // this, a two-year-old `verified` became current the moment an offline
      // run looked at it.
      const priorConfirmation = prev
        ? (prev.verified_at || (POSITIVE_STATUSES.has(prev.status) ? prev.checked_at : null))
        : null;
      const carried = value.verified_at || priorConfirmation || null;
      merged[name] = carried ? { ...value, verified_at: carried } : { ...value };
    }
  }
  const ordered = {};
  for (const name of DIMENSIONS) if (merged[name]) ordered[name] = merged[name];
  return { artifact_id: (fresh && fresh.artifact_id) || (existing && existing.artifact_id) || null, dimensions: ordered };
}

/**
 * The shelf lives a policy file implies: its `maxEvidenceAgeDays` caps every
 * dimension, and each keeps its own default below that. A policy raises the
 * bar; it does not lower it — `maxEvidenceAgeDays: 30` applied flatly would
 * have *extended* the 7-day advisory window. One function, so that `verify`
 * and `explain` judge the same evidence against the same dates.
 */
function maxAgeForPolicy(filePolicy) {
  const fromPolicy = filePolicy ? filePolicy.maxEvidenceAgeDays : null;
  if (!Number.isFinite(fromPolicy)) return DEFAULT_MAX_AGE_DAYS;
  const merged = {};
  for (const [dimension, dflt] of Object.entries(DEFAULT_MAX_AGE_DAYS)) merged[dimension] = Math.min(dflt, fromPolicy);
  return merged;
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
function staleDimensions(evidence, maxAgeDays = DEFAULT_MAX_AGE_DAYS, now) {
  requireAsOf(now, 'staleDimensions');
  const dims = (evidence && evidence.dimensions) || {};
  const out = [];
  for (const [name, value] of Object.entries(dims)) {
    const limit = typeof maxAgeDays === 'number' ? maxAgeDays : (maxAgeDays[name] ?? DEFAULT_MAX_AGE_DAYS[name]);
    if (!Number.isFinite(limit)) continue;
    // Age is measured from the last *confirmation*, not the last look.
    const age = daysBetween(value.verified_at || (POSITIVE_STATUSES.has(value.status) ? value.checked_at : null) || value.checked_at, now);
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

function deriveTrust(evidence, { maxAgeDays = DEFAULT_MAX_AGE_DAYS, now, require: required = ['artifact'] } = {}) {
  requireAsOf(now, 'deriveTrust');
  const dims = (evidence && evidence.dimensions) || {};
  // Actively wrong, not merely unknown. A package that is no longer published
  // belongs here rather than in 'candidate': candidate means "not vetted yet",
  // and an unpublished name is worse than unvetted — it may now belong to
  // somebody else.
  const bad = ['mismatch', 'vulnerable', 'fail', 'gone', 'version-gone', 'yanked'];
  for (const value of Object.values(dims)) {
    if (bad.includes(value.status)) return 'unverified';
  }
  for (const name of required) {
    const dim = dims[name];
    // 'unverified' and 'absent' both mean nothing was established. So does a
    // status this *dimension* cannot produce: `artifact: clean` is not an
    // artifact verification, however positive the word sounds.
    if (!dim || !isPositive(name, dim.status)) return 'candidate';
  }
  if (staleDimensions(evidence, maxAgeDays, now).some((s) => required.includes(s.dimension) || s.dimension === 'advisories')) {
    return 'candidate';
  }
  // An ecosystem with nothing checkable (a git source install) cannot reach
  // 'verified' by having no requirements to fail.
  if (!required.length) return 'candidate';
  return 'verified';
}

// ── the record as it stood at an instant ──────────────────────────────────
//
// `--as-of` replays a decision at another instant, but the DB only holds the
// latest look at each dimension. A look dated after `asOf` did not exist
// then, so a replay must not lean on it: staleness alone cannot say so (its
// age is negative, and a negative age is "fresh"). The honest reading of such
// a dimension is "never checked", which is what dropping it gives every
// consumer — trust, tiers, findings and the printed evidence alike. The
// comparison is by day, the grain `checked_at` is written at, so a look on
// the `asOf` day itself stands. At the wall clock nothing is later than now,
// and each of these returns its input unchanged (the same object).

const lookedAfter = (checkedAt, asOf) => {
  if (!checkedAt) return false;
  const day = Date.parse(`${String(checkedAt).slice(0, 10)}T00:00:00Z`);
  return Number.isFinite(day) && day > asOf;
};

/** `evidence` without the dimensions first looked at after `asOf`. */
function evidenceAsOf(evidence, asOf) {
  requireAsOf(asOf, 'evidenceAsOf');
  if (!evidence || !evidence.dimensions) return evidence;
  const kept = Object.entries(evidence.dimensions).filter(([, v]) => !(v && lookedAfter(v.checked_at, asOf)));
  if (kept.length === Object.keys(evidence.dimensions).length) return evidence;
  return { ...evidence, dimensions: Object.fromEntries(kept) };
}

/** A DB entry whose `trust_evidence` is read as of `asOf` (a copy only if it changes). */
function entryAsOf(tool, asOf) {
  if (!tool || !tool.trust_evidence) return tool;
  const ev = evidenceAsOf(tool.trust_evidence, asOf);
  return ev === tool.trust_evidence ? tool : { ...tool, trust_evidence: ev };
}

/** `db.tools` read as of `asOf`; accepts the DB object or its `tools` array. */
function dbAsOf(db, asOf) {
  requireAsOf(asOf, 'dbAsOf');
  if (Array.isArray(db)) {
    const tools = db.map((t) => entryAsOf(t, asOf));
    return tools.every((t, i) => t === db[i]) ? db : tools;
  }
  if (!db || !Array.isArray(db.tools)) return db;
  const tools = dbAsOf(db.tools, asOf);
  return tools === db.tools ? db : { ...db, tools };
}

/** Behavioural results (eval_results.json `results`) that existed at `asOf`. */
function evalResultsAsOf(results, asOf) {
  requireAsOf(asOf, 'evalResultsAsOf');
  if (!Array.isArray(results)) return results;
  const kept = results.filter((r) => !(r && lookedAfter(r.checked_at, asOf)));
  return kept.length === results.length ? results : kept;
}

module.exports = {
  DIMENSIONS, DEFAULT_MAX_AGE_DAYS, POSITIVE_STATUSES, POSITIVE_BY_DIMENSION, isPositive,
  REQUIRED_BY_ECOSYSTEM, requiredFor, daysBetween, maxAgeForPolicy,
  buildEvidence, smokeEvidence, mergeEvidence, staleDimensions, deriveTrust,
  evidenceAsOf, entryAsOf, dbAsOf, evalResultsAsOf,
};
