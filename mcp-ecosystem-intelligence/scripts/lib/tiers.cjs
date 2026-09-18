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

const { behaviour } = require('./scores.cjs');
const { deriveTrust, requiredFor, staleDimensions, DEFAULT_MAX_AGE_DAYS } = require('./evidence.cjs');
const { toTypedEntry, artifactId } = require('./entry_model.cjs');

const TIERS = ['Core', 'Recommended', 'Experimental', 'Deprecated'];
const TIER_ORDER = { Core: 0, Recommended: 1, Experimental: 2, Deprecated: 3 };

// There is no artifact to install under any of these.
const NOTHING_TO_INSTALL = new Set(['gone', 'version-gone', 'yanked']);

/** Index an `eval_results.json` `results` array by entry name. */
function evalIndex(results) {
  return new Map((Array.isArray(results) ? results : []).map((r) => [r.name, r]));
}

/** The artifact this entry installs *now*, as an id, or null if unparseable. */
function currentArtifactId(tool) {
  try {
    const typed = toTypedEntry(tool);
    return typed ? artifactId(typed.artifact) : null;
  } catch {
    return null;
  }
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
  return { state: recorded === current ? 'yes' : 'no', recorded, current };
}

/** Is this eval result about the artifact this entry installs today? */
function behaviourBinding(tool, evalResult) {
  const recorded = evalResult && evalResult.identity && evalResult.identity.artifact_id;
  const current  = currentArtifactId(tool);
  if (!recorded || !current) return { state: 'unknown', recorded: recorded || null, current };
  return { state: recorded === current ? 'yes' : 'no', recorded, current };
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
    behaviour: behaviourBinding(tool, evalResult),
  };
  const out = (classification, why) => ({ classification, why, bound });

  // ── 1. nothing to install ──
  const avail = dims.availability && dims.availability.status;
  if (NOTHING_TO_INSTALL.has(avail)) {
    return out('Deprecated', `availability: ${avail} (as of ${dims.availability.checked_at || 'unknown'})`);
  }

  // ── 2. the evidence has to be about these bytes ──
  if (bound.evidence.state === 'no') {
    return out('Experimental',
      `the recorded evidence is about ${bound.evidence.recorded}, and this entry now installs ${bound.evidence.current}`);
  }

  const trust = deriveTrust(evidence, { now, maxAgeDays, require: requiredFor(ecosystem) });

  // ── 3. something failed ──
  if (trust === 'unverified') {
    const failed = Object.entries(dims)
      .find(([, v]) => ['mismatch', 'vulnerable', 'fail', 'gone', 'version-gone', 'yanked'].includes(v.status));
    return out('Deprecated', failed
      ? `${failed[0]}: ${failed[1].status} (as of ${failed[1].checked_at || 'unknown'})`
      : 'a check failed');
  }

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
    const missing = requiredFor(ecosystem).filter((name) => !dims[name]);
    if (missing.length) {
      return out('Experimental', `never checked for this entry: ${missing.join(', ')}`);
    }
    if (bound.evidence.state === 'unknown') {
      return out('Experimental', bound.current
        ? 'the stored evidence is not tied to a named artifact, so it cannot be read as being about this one'
        : "this entry's install command does not name an artifact anything could be checked against");
    }
    const stale = staleDimensions(evidence, maxAgeDays, now).map((s) => s.dimension);
    if (stale.length) {
      return out('Experimental', `past its shelf life: ${stale.join(', ')}`);
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
  classifyEntry, evalIndex, currentArtifactId, evidenceBinding, behaviourBinding,
  TIERS, TIER_ORDER, NOTHING_TO_INSTALL,
};
