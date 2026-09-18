'use strict';
/**
 * What tier an entry is in, derived from measured evidence.
 *
 * The tier used to be a threshold on `health_score`, and `health_score`
 * contained `+30 if in_registry` — a hand-set boolean that disagreed with the
 * live registry for 26 of 114 entries and outweighed every measured term put
 * together. The first thing a reader saw about an entry was mostly a field
 * nobody had checked.
 *
 * Removing that term and rescaling the thresholds was measured and rejected:
 * the remaining terms are stars, recency, "has an install command" and a
 * licence penalty, and this DB is curated — everything in it is popular and
 * recently committed. Scores then ran 40–80 with a median of 75, and *91 of 114
 * entries* landed in the top tier. A label 80% of rows share is not a label.
 *
 * So the tier answers the question a reader is actually asking:
 *
 *   Core          the artifact is verified, the evidence is about *these*
 *                 bytes, and a run bound to these bytes started and listed tools
 *   Recommended   the artifact is verified and current; either nothing has
 *                 watched it run, or what watched it cannot be tied to this
 *                 artifact
 *   Experimental  too little is known — a required check never happened, a
 *                 claim has aged out, or the stored evidence is about a
 *                 different artifact than the one this entry now installs
 *   Deprecated    do not install: nothing to install, or something failed
 *                 (wrong bytes, a live advisory, a repository that disagrees)
 *
 * Four rules, each of them a reviewer's finding against the first version of
 * this file:
 *
 *   1. **`trust` is decided by `deriveTrust`, not re-derived here.** The first
 *      version used `trustScore().gate === 'ok'`, which is "artifact verified
 *      plus 55 points" — so `artifact: verified` (40) with `signature:
 *      verified` (20) and *no advisory or availability check at all* cleared it
 *      and reached Core, and enough positive points outweighed a
 *      `source_binding: mismatch`. Omitted checks were making an entry look
 *      stronger. `deriveTrust` with `requiredFor(ecosystem)` is the function
 *      whose job this is: it demands the dimensions that matter for the
 *      ecosystem, refuses anything with a failed status, and treats a claim
 *      past its shelf life as not current.
 *
 *   2. **The evidence has to be about this artifact.** `trust_evidence` carries
 *      the `artifact_id` it was recorded against. Change an entry from `x@1` to
 *      `x@2` and the stored "verified" is a statement about bytes that are no
 *      longer being installed. `mergeEvidence` already refuses to inherit
 *      across ids; the tier now refuses to read across them too.
 *
 *   3. **So does the handshake.** An eval row is indexed by name, and a passing
 *      result for `x@1` says nothing about `x@2`. Core requires the eval's
 *      recorded `identity.artifact_id` to be this artifact. Today *no* row in
 *      the shipped snapshot carries an identity, so nothing reaches Core from
 *      it — which is the honest answer, and the same one `surfaceDrift` already
 *      gives for a snapshot with no identity recorded.
 *
 *   4. **Behaviour promotes, never demotes.** 59 verified entries did not
 *      complete a handshake, and the sandbox runs with an empty environment:
 *      `@azure/mcp`, `@heroku/mcp-server` and their kind exit 1 because no API
 *      key was present, in prose the failure classifier does not recognise.
 *      Demoting them would record our sandbox's limits as a fact about the
 *      server.
 *
 * And it is computed, not stored: staleness makes it a function of today, so a
 * stored copy would go quietly wrong while the file sat unchanged — which is
 * exactly what `in_registry` and `last_checked` both did.
 *
 * API:
 *   classifyEntry(tool, evalResult, opts) -> { classification, why, bound }
 *   evalIndex(results)                    -> Map<name, result>
 *   TIERS, TIER_ORDER
 */

const { behaviour, blocks } = require('./scores.cjs');
const { deriveTrust, requiredFor, staleDimensions, isPositive, DEFAULT_MAX_AGE_DAYS } = require('./evidence.cjs');
const { toTypedEntry, comparableArtifactId, comparableId, packageKey } = require('./entry_model.cjs');

const TIERS = ['Core', 'Recommended', 'Experimental', 'Deprecated'];
const TIER_ORDER = { Core: 0, Recommended: 1, Experimental: 2, Deprecated: 3 };

// There is no artifact to install under any of these.
const NOTHING_TO_INSTALL = new Set(['gone', 'version-gone', 'yanked']);

// `gone` means the *name* is not published at all, which is true whatever
// version an entry moves to — and worse than unpublished, because a free name
// can be claimed by somebody else. `version-gone` and `yanked` are statements
// about one version and do not survive a version change.
const NAME_SCOPED = new Set(['gone']);

/** Index an `eval_results.json` `results` array by entry name. */
function evalIndex(results) {
  return new Map((Array.isArray(results) ? results : []).map((r) => [r.name, r]));
}

/**
 * The artifact this entry installs *now*, as an id, or null when that cannot be
 * established.
 *
 * `toTypedEntry` resolves the version from the DB's `version` field in
 * preference to the one written in `install_cmd`, and records a warning when
 * they disagree. Reading the winner and ignoring the warning meant an entry
 * whose command says `x@2.0.0` while its `version` field says `1.0.0` reported
 * its identity as `x@1.0.0` — so evidence for 1.0.0 bound cleanly to an entry
 * that installs 2.0.0, which is the exact comparison this function exists to
 * make safe. A disagreement is not a version; it is two, and the honest answer
 * is that we do not know which runs.
 */
function currentArtifactId(tool) {
  try {
    const typed = toTypedEntry(tool);
    if (!typed) return null;
    if ((typed.warnings || []).some((w) => /launch command asks for|no version anywhere/.test(w))) return null;
    // Comparable, not literal: a PyPI pin written `1.0.27.0` and one written
    // `1.0.27` are the same release, and `a_b` and `a.b` are one distribution.
    return comparableArtifactId(typed.artifact);
  } catch {
    return null;
  }
}

/** The package, without the version — for a finding that is about the name. */
function currentPackageKey(tool) {
  try {
    const typed = toTypedEntry(tool);
    return typed ? packageKey(typed.artifact) : null;
  } catch {
    return null;
  }
}

/** The package half of a stored artifact id, comparably. */
function packageKeyOfId(id) {
  const c = comparableId(id);
  if (typeof c !== 'string') return null;
  const at = c.lastIndexOf('@');
  // `@scope/pkg` has an `@` at position 4 in `npm:@scope/pkg`; a version's `@`
  // is always the last one and never the first character of the remainder.
  if (at <= c.indexOf(':')) return c;
  return c.slice(0, at);
}

/**
 * Is the stored evidence about the artifact this entry installs today?
 *
 * Returns 'yes' | 'no' | 'unknown'. `unknown` is not `yes`: an entry whose
 * install command cannot be parsed, or evidence recorded before ids existed,
 * has not established that the two are the same thing.
 */
function evidenceBinding(tool) {
  const recorded = tool && tool.trust_evidence && tool.trust_evidence.artifact_id;
  const current  = currentArtifactId(tool);
  if (!recorded || !current) return { state: 'unknown', recorded: recorded || null, current };
  return { state: comparableId(recorded) === current ? 'yes' : 'no', recorded, current };
}

/**
 * Is the stored evidence about the same *package*, whatever the version?
 *
 * `availability: gone` is the one finding that survives a version change — the
 * name is unpublished, and a free name can be claimed by somebody else — but
 * it does not survive a change of *package*. Evidence saying `x` is gone is
 * not a finding about `y`.
 */
function packageBinding(tool) {
  const recorded = packageKeyOfId(tool && tool.trust_evidence && tool.trust_evidence.artifact_id);
  const current  = currentPackageKey(tool);
  if (!recorded || !current) return { state: 'unknown', recorded, current };
  return { state: recorded === current ? 'yes' : 'no', recorded, current };
}

/** Is this eval result about the artifact this entry installs today? */
function behaviourBinding(tool, evalResult) {
  const recorded = evalResult && evalResult.identity && evalResult.identity.artifact_id;
  const current  = currentArtifactId(tool);
  if (!recorded || !current) return { state: 'unknown', recorded: recorded || null, current };
  return { state: comparableId(recorded) === current ? 'yes' : 'no', recorded, current };
}

/**
 * @param tool        one `tools_database.json` entry
 * @param evalResult  its `eval_results.json` row, or null/undefined if none
 * @returns {{classification: string, why: string, bound: object}}
 */
function classifyEntry(tool, evalResult = null, opts = {}) {
  const { now = Date.now(), maxAgeDays = DEFAULT_MAX_AGE_DAYS } = opts;
  const evidence = (tool && tool.trust_evidence) || null;
  const dims = (evidence && evidence.dimensions) || {};
  const typed = toTypedEntry(tool);
  const ecosystem = typed ? typed.artifact.ecosystem : null;

  const bound = {
    evidence:  evidenceBinding(tool),
    package:   packageBinding(tool),
    behaviour: behaviourBinding(tool, evalResult),
  };
  const out = (classification, why) => ({ classification, why, bound });

  // ── 1. the package name itself is gone ──
  // Checked before the binding, and only for the name-scoped status: an
  // unpublished *name* is unpublished whatever version the entry moves to.
  const avail = dims.availability && dims.availability.status;
  if (NAME_SCOPED.has(avail) && bound.package.state === 'yes') {
    return out('Deprecated', `availability: ${avail} (as of ${dims.availability.checked_at || 'unknown'})`);
  }

  // ── 2. everything below is a statement about bytes, so the evidence has to
  //       be about *these* bytes. A precondition, not a fallback: the first
  //       version only asked this when the trust verdict was already weak, so
  //       complete evidence with no recorded identity — or a `yanked` recorded
  //       against the version before this one — sailed past it in both
  //       directions.
  if (bound.evidence.state === 'no') {
    return out('Experimental',
      `the recorded evidence is about ${bound.evidence.recorded}, and this entry now installs ${bound.evidence.current}`);
  }
  if (bound.evidence.state === 'unknown' && Object.keys(dims).length) {
    return out('Experimental', bound.evidence.current
      ? 'the stored evidence is not tied to a named artifact, so it cannot be read as being about this one'
      : "this entry does not name one artifact: the launch command and the verified version disagree, or neither states a version");
  }

  // ── 3. a finding that means "do not run this" ──
  //
  // The set is `scores.cjs`'s `BLOCKING`, deliberately, so the tier and the
  // trust gate cannot disagree about what blocks. The first version used
  // `deriveTrust(...) === 'unverified'`, which is a wider net: it includes
  // `smoke: fail` — turning "our sandbox could not start it" into "must not
  // run", flatly contradicting the rule that behaviour never demotes — and
  // `source_binding: mismatch`, which `BLOCKING` excludes on purpose, because
  // a metadata disagreement is something to read rather than a refusal.
  const blocking = Object.entries(dims).find(([name, v]) => blocks(name, v.status));
  if (blocking) {
    return out('Deprecated', `${blocking[0]}: ${blocking[1].status} (as of ${blocking[1].checked_at || 'unknown'})`);
  }

  const trust = deriveTrust(evidence, { now, maxAgeDays, require: requiredFor(ecosystem) });

  // ── 4. not enough was established, or it has aged out ──
  //
  // Ordered most-specific-first, because the reason is the useful part: "never
  // checked: advisories" and "past its shelf life: artifact" send a reader to
  // different places, and "no evidence at all" should not be described as an
  // identity problem.
  if (trust !== 'verified') {
    if (!Object.keys(dims).length) {
      return out('Experimental', 'no evidence recorded for this entry');
    }
    const required = requiredFor(ecosystem);
    const missing = required.filter((name) => !dims[name]);
    if (missing.length) {
      return out('Experimental', `never checked for this entry: ${missing.join(', ')}`);
    }
    // Present but not affirmative — including a status the dimension cannot
    // produce, which is how `artifact: clean` used to satisfy a requirement
    // the artifact check had never met.
    const inconclusive = required.filter((name) => dims[name] && !isPositive(name, dims[name].status));
    if (inconclusive.length) {
      return out('Experimental',
        inconclusive.map((n) => `${n}: ${dims[n].status}`).join(', ') + ' — not an affirmative result');
    }
    const stale = staleDimensions(evidence, maxAgeDays, now).map((s) => s.dimension);
    if (stale.length) {
      return out('Experimental', `past its shelf life: ${stale.join(', ')}`);
    }
    // Everything required checked out and nothing is stale, so what is left is
    // a dimension that failed without blocking — `smoke: fail`, a
    // `source_binding: mismatch`, a withdrawn registry record.
    const failed = Object.entries(dims)
      .find(([, v]) => ['mismatch', 'vulnerable', 'fail', 'contradicted', 'withdrawn'].includes(v.status));
    if (failed) {
      return out('Experimental', `${failed[0]}: ${failed[1].status} (as of ${failed[1].checked_at || 'unknown'})`);
    }
    return out('Experimental', ecosystem === 'git'
      ? 'a git-source install has nothing a registry can verify'
      : 'too little was established to call this verified');
  }

  // ── 5. did anyone watch it run, and was it this artifact? ──
  const behav = behaviour(evalResult || null);
  if (behav.state === 'starts' && bound.behaviour.state === 'yes') {
    return out('Core', behav.reason);
  }
  if (behav.state === 'starts') {
    return out('Recommended', bound.behaviour.recorded
      ? `a run started and listed tools, but against ${bound.behaviour.recorded} rather than ${bound.behaviour.current}`
      : 'a run started and listed tools, but it did not record which artifact it launched');
  }
  return out('Recommended', behav.reason);
}

module.exports = {
  classifyEntry, evalIndex, currentArtifactId, currentPackageKey, packageKeyOfId,
  evidenceBinding, packageBinding, behaviourBinding,
  TIERS, TIER_ORDER, NOTHING_TO_INSTALL, NAME_SCOPED,
};
