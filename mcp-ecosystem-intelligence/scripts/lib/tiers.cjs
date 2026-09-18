'use strict';
/**
 * What tier an entry is in, derived from measured evidence.
 *
 * The tier used to be a threshold on `health_score`, and `health_score`
 * contained `+30 if in_registry` — a hand-set boolean that disagreed with the
 * live registry for 26 of 114 entries and dominated every other term. So the
 * label a reader saw first was mostly a function of a field nobody measured.
 *
 * Removing that term and rescaling the thresholds was measured and rejected:
 * the remaining terms are stars, recency, "has an install command" and a
 * licence penalty, and this DB is curated — everything in it is popular and
 * recently committed. Scores then ran 40–80 with a median of 75, and *91 of 114
 * entries* landed in the top tier. A label that 80% of the rows share is not a
 * label. The formula never discriminated; the registry bonus was doing all the
 * separating, badly.
 *
 * So the tier is no longer a function of health at all. `health_score` keeps
 * its own question — is this project maintained? — and the tier answers the one
 * a reader is actually asking before installing something:
 *
 *   Core          the artifact is verified and we watched it start and list tools
 *   Recommended   the artifact is verified and nothing contradicts it; it has
 *                 not been observed to start (most of these want credentials)
 *   Experimental  too little is known — the artifact was never verified, or so
 *                 few dimensions were measured that "verified" stands alone
 *   Deprecated    do not install: nothing to install, wrong bytes, or a known
 *                 vulnerability at the pinned version
 *
 * Two deliberate asymmetries:
 *
 *   **Behaviour promotes, never demotes.** 59 verified entries did not complete
 *   a handshake in the sandbox, and the sandbox runs with an empty environment:
 *   `@azure/mcp`, `@heroku/mcp-server`, `@browserstack/mcp-server` and their
 *   kind exit 1 because no API key was present, and they say so in prose the
 *   failure classifier does not recognise. Demoting them would be recording our
 *   sandbox's limits as a fact about the server — the same error as reading a
 *   check that did not happen as a check that passed.
 *
 *   **It is computed, not stored.** `trustScore` discounts a claim past its
 *   shelf life, so the tier is a function of *today's* evidence and today's
 *   date. A stored copy would be a value that goes quietly wrong while the file
 *   sits unchanged — which is what `in_registry` and `last_checked` both did.
 *
 * API:
 *   classifyEntry(tool, evalResult, opts) -> { classification, why }
 *   evalIndex(results)                    -> Map<name, result>
 *   TIERS, TIER_ORDER
 */

const { trustScore, behaviour } = require('./scores.cjs');

const TIERS = ['Core', 'Recommended', 'Experimental', 'Deprecated'];
const TIER_ORDER = { Core: 0, Recommended: 1, Experimental: 2, Deprecated: 3 };

// There is no artifact to install under any of these.
const NOTHING_TO_INSTALL = new Set(['gone', 'version-gone', 'yanked']);

/** Index an `eval_results.json` `results` array by entry name. */
function evalIndex(results) {
  return new Map((Array.isArray(results) ? results : []).map((r) => [r.name, r]));
}

/**
 * @param tool        one `tools_database.json` entry
 * @param evalResult  its `eval_results.json` row, or null/undefined if none
 * @returns {{classification: string, why: string}}
 */
function classifyEntry(tool, evalResult = null, opts = {}) {
  const dims = (tool && tool.trust_evidence && tool.trust_evidence.dimensions) || {};

  const avail = dims.availability && dims.availability.status;
  if (NOTHING_TO_INSTALL.has(avail)) {
    return {
      classification: 'Deprecated',
      why: `availability: ${avail} (as of ${dims.availability.checked_at || 'unknown'})`,
    };
  }

  const trust = trustScore((tool && tool.trust_evidence) || null, opts);
  if (trust.gate === 'block') {
    return { classification: 'Deprecated', why: trust.reasons[0] || 'a blocking finding applies' };
  }
  if (trust.gate !== 'ok') {
    return { classification: 'Experimental', why: trust.reasons[0] || 'no evidence recorded' };
  }

  const behav = behaviour(evalResult || null);
  return behav.state === 'starts'
    ? { classification: 'Core', why: behav.reason }
    : { classification: 'Recommended', why: behav.reason };
}

module.exports = { classifyEntry, evalIndex, TIERS, TIER_ORDER, NOTHING_TO_INSTALL };
