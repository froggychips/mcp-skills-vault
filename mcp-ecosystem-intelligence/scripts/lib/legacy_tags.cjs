'use strict';
/**
 * The gate's report tags, read as findings.
 *
 * `verify` has always spoken in tags — FAIL, CVE, UNVERIFIED, HOOK, … — and
 * those tags are frozen in `mcp-vault/verify-report@1` and in its SARIF. They
 * are also a mixture: some name a check (HOOK), some a verdict (FAIL), and one
 * (UNVERIFIED) covers "the check did not run", "there was nothing to compare"
 * and "the stored answer aged out" alike. This table is the one place that
 * says what each tag means in the findings model (lib/finding.cjs), so the
 * legacy outputs and the model are two renderings of the same thing.
 *
 * A report line may carry a third element, `{ rule, state, severity }`, when
 * the processor that wrote it knows more than its tag says — the stale line
 * knows it is `stale`, a missing pin knows it is `no-data`. The legacy
 * renderers ignore it. POLICY-FAIL / POLICY-WARN are not findings at all:
 * they are decisions (lib/policy_rules.cjs), rendered as lines.
 *
 * The `verify/*` family is the honest name for "a gate line we have not typed
 * more finely yet": `verify/check-failed` is every FAIL, whichever check
 * raised it. Typing them per check is migration work (docs/adr/0001).
 *
 * API:
 *   TAG_MODEL                     tag -> { rule, severity, state }
 *   DECISION_TAGS                 tags that are decisions, not findings
 *   modelForLine([tag, text, meta]) -> { rule, severity, state } | null
 */

const TAG_MODEL = Object.freeze({
  FAIL:       { rule: 'verify/check-failed',            severity: 'high',   state: 'observed' },
  CVE:        { rule: 'advisories/known-vulnerability', severity: 'high',   state: 'observed' },
  UNVERIFIED: { rule: 'verify/unverified',              severity: 'medium', state: 'not-run' },
  MISS:       { rule: 'pin/missing',                    severity: 'medium', state: 'no-data' },
  WARN:       { rule: 'metadata/mismatch',              severity: 'medium', state: 'observed' },
  HOOK:       { rule: 'install/hook',                   severity: 'medium', state: 'observed' },
  DIGEST:     { rule: 'oci/unpinned-image',             severity: 'medium', state: 'observed' },
  DEEP:       { rule: 'artifact/deep-verified',         severity: 'info',   state: 'observed' },
  SIG:        { rule: 'signature/verified',             severity: 'info',   state: 'observed' },
  PROV:       { rule: 'provenance/claimed',             severity: 'info',   state: 'observed' },
  PROVBOUND:  { rule: 'provenance/bound',               severity: 'info',   state: 'observed' },
  DEPS:       { rule: 'dependencies/tree',              severity: 'info',   state: 'observed' },
  // Low, not medium: neither has ever failed the gate on its own, not even
  // under --strict. The policy rules for them (dependencyHooks,
  // dependencyAdvisories) are what turn them into a refusal.
  DEPHOOK:    { rule: 'dependencies/install-hook',      severity: 'low',    state: 'observed' },
  DEPCVE:     { rule: 'dependencies/advisory',          severity: 'low',    state: 'observed' },
  // A rendering of a `lookalike/<technique>` finding on the server's *name*
  // (lib/lookalike.cjs), written after the decision. Read back from a report,
  // the technique is gone, so the family is all the tag can say.
  LOOKALIKE:  { rule: 'lookalike/name',                 severity: 'low',    state: 'observed' },
  // A rendering of `config/unpinned-launch` on the server's host-config line
  // (verify --installed / --config), written after the decision.
  UNPINNED:   { rule: 'config/unpinned-launch',         severity: 'medium', state: 'observed' },
  NOTE:       { rule: 'verify/note',                    severity: 'info',   state: 'observed' },
  SKIP:       { rule: 'verify/skipped',                 severity: 'info',   state: 'not-run' },
});

const DECISION_TAGS = new Set(['POLICY-FAIL', 'POLICY-WARN']);

function modelForLine(line) {
  const [tag, , meta] = line || [];
  if (DECISION_TAGS.has(tag)) return null;
  const base = TAG_MODEL[tag] || TAG_MODEL.NOTE;
  const m = meta && typeof meta === 'object' ? meta : {};
  return {
    rule:     m.rule || base.rule,
    severity: m.severity || base.severity,
    state:    m.state || base.state,
  };
}

module.exports = { TAG_MODEL, DECISION_TAGS, modelForLine };
