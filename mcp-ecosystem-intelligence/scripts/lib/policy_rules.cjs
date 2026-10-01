'use strict';
/**
 * Every rule that turns findings into an effect, in one table.
 *
 * Policy semantics used to live wherever a command needed them. `verify`
 * counted failures inside each processor and consulted `evaluateEntry`;
 * `explain` re-derived the same rules from stored evidence in its own
 * `decide()`; `status` and `audit` each had an exit-code ladder. The open
 * feature work was about to add org allow/deny lists, tier floors, evidence
 * age, capabilities, tool approval, toxic flows, shadowing and lookalikes —
 * each wired into two or three commands by hand, each mapping `unknown` to a
 * level its own way. Two commands answering the same question differently is
 * the failure this file exists to make impossible.
 *
 * So (docs/adr/0001-findings-and-time.md):
 *
 *   - A rule is a row here with a stable id. That id is what `decided_by`
 *     says, in every command, forever — it is part of the contract.
 *   - `decide()` in lib/finding.cjs is the only caller. Commands build
 *     findings and facts, call `decide`, and render the Decision.
 *   - `--strict`, `--fail-unverified` and friends are not command logic: they
 *     tighten the effective policy (`effectivePolicy`), and the threshold
 *     that turns an effect into a failing exit code (`fail_on`) is part of it.
 *   - The effective policy is built by one function, is normalised, and is
 *     frozen: nothing downstream can loosen it by accident.
 *
 * A row:
 *   id          stable rule id, `<family>/<rule>`; `*` marks a family whose
 *               last segment is data (`trust/<dimension>`)
 *   status      'active' | 'reserved' — reserved ids are claimed for the open
 *               feature PRs so that they land here and nowhere else
 *   thresholded whether a non-deny effect from this rule can fail the run
 *               under `fail_on` (a gate warning under --strict can; a policy
 *               "no licence recorded" note never could, and still cannot)
 *   views       legacy renderings that show this rule: 'explain' (explain's
 *               `rules` list), 'policy-line' (verify's POLICY-FAIL/WARN)
 *   evaluate    (ctx) -> [{ rule?, effect, detail, findings? }]
 *
 * ctx: { subject, findings, policy, facts, mode }
 *   findings  this subject's findings (lib/finding.cjs)
 *   facts     what a rule may read that is not a finding: the DB entry's
 *             licence/health/trust, the stored evidence and trust score,
 *             behaviour, budget, the live gate's status
 *   mode      'gate' when findings come from a gate run, 'evidence' when only
 *             stored evidence is available (explain without --verify)
 *
 * API:
 *   RULES, RULE_BY_ID, ORDER, RANK, EFFECTS
 *   rulesFor(mode)                       -> ordered active rows
 *   effectivePolicy(base, flags, opts)   -> frozen, normalised policy
 *   loadEffectivePolicy(startDir, opts)  -> { ok, policy, path, found, errors, sources }
 *   flagsFromArgv(argv)                  -> { strict, failUnverified, … }
 *   entryRuleOutcomes(ctx)               -> legacy evaluateEntry outcomes
 */

const EFFECTS = ['allow', 'warn', 'deny', 'unknown'];

// Weakest first. The stricter end wins whenever two sources set the same key —
// a flag over a file, and (lib/org_policy.cjs, #127) a project over its org.
const RANK = {
  unverified:           ['warn', 'fail'],
  installHooks:         ['allow', 'warn', 'fail'],
  dependencyHooks:      ['allow', 'warn', 'fail'],
  dependencyAdvisories: ['allow', 'warn', 'fail'],
  signatures:           ['prefer', 'require'],
  provenance:           ['prefer', 'require', 'bound'],
  docker:               ['tag', 'digest'],
  contextBudget:        ['warn', 'fail'],
  // The exit threshold: which effects fail the run. `deny` always does.
  fail_on:              ['deny', 'unknown', 'warn'],
};

const stricter = (key, a, b) => {
  const r = RANK[key];
  return r.indexOf(b) > r.indexOf(a) ? b : a;
};

// ── facts helpers ──────────────────────────────────────────────────────────

const has = (ctx, ...rules) => ctx.findings.some((f) => rules.includes(f.rule));
const ids = (ctx, ...rules) => ctx.findings.filter((f) => rules.includes(f.rule)).map((f) => f.id);
const entryOf = (ctx) => (ctx.facts && ctx.facts.entry) || {};
const isNpx = (ctx) => String(entryOf(ctx).install_cmd || '').startsWith('npx');
const isDocker = (ctx) => /^docker\s+run/.test(entryOf(ctx).install_cmd || '');
const out = (effect, detail, findings = [], rule = undefined) => ({ rule, effect, detail, findings });

// ── rules over findings (any command) ──────────────────────────────────────

const findingRules = [
  {
    id: 'finding/severity', status: 'active', thresholded: true, views: [],
    doc: 'An observed finding refuses at high/critical severity and warns at medium.',
    evaluate(ctx) {
      const res = [];
      for (const f of ctx.findings) {
        if (f.state !== 'observed') continue;
        if (f.severity === 'critical' || f.severity === 'high') res.push(out('deny', f.message, [f.id]));
        else if (f.severity === 'medium') res.push(out('warn', f.message, [f.id]));
      }
      return res;
    },
  },
  {
    id: 'finding/incomplete', status: 'active', thresholded: true, views: [],
    doc: 'A check that did not run, had nothing to look at, or aged out is unknown — never allow.',
    evaluate(ctx) {
      return ctx.findings.filter((f) => f.state !== 'observed').map((f) => out('unknown', f.message, [f.id]));
    },
  },
  {
    id: 'gate/require-provenance', status: 'active', thresholded: true, views: [],
    doc: 'Under a provenance requirement, an attestation that does not describe the artifact refuses.',
    evaluate(ctx) {
      if (!(ctx.policy.gate && ctx.policy.gate.require_provenance)) return [];
      return ctx.findings.filter((f) => f.rule === 'provenance/mismatch').map((f) => out('deny', f.message, [f.id]));
    },
  },
  {
    id: 'gate/fail-dep-advisories', status: 'active', thresholded: true, views: [],
    doc: 'Under --fail-dep-advisories, a high/critical advisory in the dependency tree refuses.',
    evaluate(ctx) {
      if (!(ctx.policy.gate && ctx.policy.gate.fail_dep_advisories)) return [];
      return ctx.findings.filter((f) => f.rule === 'dependencies/high-advisory').map((f) => out('deny', f.message, [f.id]));
    },
  },
];

// ── the policy file's rules (mcp-vault/policy@1) ───────────────────────────
//
// Messages are the ones `evaluateEntry` has always printed: verify renders
// them as POLICY-FAIL / POLICY-WARN lines, and those lines are frozen until a
// schema major. In gate mode a rule reads findings; in evidence mode (explain
// without a gate run) it reads stored evidence and says `unknown` where the
// evidence is silent — `evaluateEntry` decided from the *absence* of a
// finding, which is right after a gate run and wrong when none happened.

const fromEvidence = (ctx, dim, { ok, bad, require: required, message }) => {
  const dims = (ctx.facts && ctx.facts.evidence && ctx.facts.evidence.dimensions) || {};
  const value = dims[dim];
  if (!value) return required ? [out('unknown', `${dim} has never been checked — run with --verify`)] : [];
  if (ok.includes(value.status)) return [out('allow', `${dim}: ${value.status} (as of ${value.verified_at || value.checked_at})`)];
  if (bad.includes(value.status)) return [out(required ? 'deny' : 'warn', message(value))];
  return [out('unknown', `${dim} is "${value.status}", which this rule cannot judge — run with --verify`)];
};

const policyRules = [
  {
    id: 'policy/install-hooks', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      if (ctx.mode === 'evidence') {
        // Not an evidence dimension: only a gate run sees the package's hooks.
        return ctx.policy.installHooks === 'fail'
          ? [out('unknown', 'whether this package runs install-time scripts is only visible to a gate run — use --verify')] : [];
      }
      return ctx.policy.installHooks === 'fail' && has(ctx, 'install/hook')
        ? [out('deny', 'package runs install-time scripts, which this policy does not allow', ids(ctx, 'install/hook'))] : [];
    },
  },
  {
    id: 'policy/dependency-hooks', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      if (ctx.mode === 'evidence') {
        return fromEvidence(ctx, 'dependencies', {
          ok: ['clean'], bad: ['hooks'], require: ctx.policy.dependencyHooks === 'fail',
          message: () => 'a dependency runs install-time scripts',
        });
      }
      return ctx.policy.dependencyHooks === 'fail' && has(ctx, 'dependencies/install-hook')
        ? [out('deny', 'a dependency runs install-time scripts, which this policy does not allow', ids(ctx, 'dependencies/install-hook'))] : [];
    },
  },
  {
    id: 'policy/dependency-advisories', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      if (ctx.mode === 'evidence') {
        return fromEvidence(ctx, 'dependencies', {
          ok: ['clean', 'hooks'], bad: ['advisories-present'], require: ctx.policy.dependencyAdvisories === 'fail',
          message: () => 'an advisory affects a package in the dependency tree',
        });
      }
      const hit = ids(ctx, 'dependencies/advisory', 'dependencies/high-advisory');
      return ctx.policy.dependencyAdvisories === 'fail' && hit.length
        ? [out('deny', 'an advisory affects a package in the dependency tree', hit)] : [];
    },
  },
  {
    id: 'policy/signatures', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      if (ctx.mode === 'evidence') {
        if (!/^npx\s/.test(entryOf(ctx).install_cmd || '')) return [];
        return fromEvidence(ctx, 'signature', {
          ok: ['verified'], bad: ['absent', 'mismatch'], require: ctx.policy.signatures === 'require',
          message: (v) => (v.status === 'mismatch' ? 'the registry signature does not verify' : 'the registry published no signature for this version'),
        });
      }
      return ctx.policy.signatures === 'require' && !has(ctx, 'signature/verified') && isNpx(ctx)
        ? [out('deny', 'no verifiable registry signature')] : [];
    },
  },
  {
    id: 'policy/provenance', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      if (ctx.mode === 'evidence') {
        if (!/^npx\s/.test(entryOf(ctx).install_cmd || '')) return [];
        const res = fromEvidence(ctx, 'provenance', {
          ok: ['bound', 'claimed'], bad: ['absent', 'unreadable', 'mismatch'],
          require: ctx.policy.provenance === 'require' || ctx.policy.provenance === 'bound',
          message: (v) => `provenance is ${v.status}`,
        });
        // The stricter bar asks for a binding, so a mere claim does not clear it.
        const dims = (ctx.facts.evidence && ctx.facts.evidence.dimensions) || {};
        if (ctx.policy.provenance === 'bound' && dims.provenance && dims.provenance.status === 'claimed') {
          res.push(out('deny', 'policy requires provenance bound to the artifact digest; this one is only claimed'));
        }
        return res;
      }
      // `require` asks for a PROV (claimed) line specifically — a PROVBOUND
      // alone has always failed this rule, and that is preserved rather than
      // changed quietly underneath a frozen output.
      return ctx.policy.provenance === 'require' && !has(ctx, 'provenance/claimed') && isNpx(ctx)
        ? [out('deny', 'no provenance attestation')] : [];
    },
  },
  {
    id: 'policy/docker-digest', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      if (ctx.mode === 'evidence') {
        if (!(isDocker(ctx) && ctx.policy.docker === 'digest')) return [];
        return /@sha256:[a-f0-9]{64}(\s|$)/.test(entryOf(ctx).install_cmd || '')
          ? [out('allow', 'the image is pinned by @sha256 digest')]
          : [out('deny', 'container image is not pinned by digest')];
      }
      return ctx.policy.docker === 'digest' && isDocker(ctx) && has(ctx, 'oci/unpinned-image')
        ? [out('deny', 'container image is not pinned by digest', ids(ctx, 'oci/unpinned-image'))] : [];
    },
  },
  {
    id: 'policy/unverified', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      if (ctx.mode === 'evidence') {
        return fromEvidence(ctx, 'artifact', {
          ok: ['verified'], bad: ['unverified', 'mismatch'], require: ctx.policy.unverified === 'fail',
          message: (v) => (v.status === 'mismatch' ? 'the artifact does not match its pin' : 'nothing about this artifact could be verified'),
        });
      }
      return ctx.policy.unverified === 'fail' && ctx.facts.legacy_status === 'UNVERIFIED'
        ? [out('deny', 'nothing about this entry could be verified')] : [];
    },
  },
  {
    id: 'policy/license', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      const p = ctx.policy;
      if (!p.licenses) return [];
      const license = entryOf(ctx).license || null;
      if (!license) return [out('warn', 'no license recorded for this entry')];
      if (p.licenses.deny && p.licenses.deny.includes(license)) return [out('deny', `license ${license} is on this policy's deny list`)];
      if (p.licenses.allow && !p.licenses.allow.includes(license)) return [out('deny', `license ${license} is not on this policy's allow list`)];
      return [];
    },
  },
  {
    id: 'policy/health', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      const p = ctx.policy;
      if (p.minHealthScore === null || p.minHealthScore === undefined) return [];
      const score = Number(entryOf(ctx).health_score);
      if (!Number.isFinite(score)) return [out('warn', 'no health score recorded for this entry')];
      return score < p.minHealthScore
        ? [out('deny', `health score ${score} is below the policy minimum of ${p.minHealthScore}`)] : [];
    },
  },
  {
    id: 'policy/trust', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    evaluate(ctx) {
      const p = ctx.policy;
      if (!p.trust) return [];
      const trust = entryOf(ctx).trust || null;
      return !trust || !p.trust.includes(trust)
        ? [out('deny', `trust tier ${trust || '(none)'} is not accepted by this policy (accepts: ${p.trust.join(', ')})`)] : [];
    },
  },
  {
    id: 'budget/over', status: 'active', thresholded: false, views: ['explain'],
    evaluate(ctx) {
      const b = ctx.facts && ctx.facts.budget;
      if (!b || !b.over) return [];
      return [out(ctx.policy.contextBudget === 'fail' ? 'deny' : 'warn',
        `this config would inject ≈${b.after.toLocaleString('en-US')} tokens per request, over the ceiling of ${b.limit.toLocaleString('en-US')}`)];
    },
  },
];

// ── explain's evidence-level rules ─────────────────────────────────────────

const explainRules = [
  {
    id: 'trust/*', status: 'active', thresholded: false, views: ['explain'],
    doc: 'Trust gates: one rule per blocking dimension, then thin or ok.',
    evaluate(ctx) {
      const trust = ctx.facts && ctx.facts.trust;
      if (!trust) return [];
      if (trust.gate === 'block') {
        // One rule per blocking dimension, named. "trust/blocked: artifact:
        // verified" was what this printed when `reasons[0]` happened to be a
        // positive finding.
        const blockers = trust.blocking && trust.blocking.length
          ? trust.blocking : [{ dimension: 'trust', status: 'blocked', checked_at: null }];
        return blockers.map((b) => out('deny', `${b.dimension} is ${b.status}${b.checked_at ? ` (as of ${b.checked_at})` : ''}`, [], `trust/${b.dimension}`));
      }
      if (trust.gate === 'thin') return [out('warn', trust.reasons[0] || `only ${trust.score}/100 of the trust evidence is established`, [], 'trust/thin')];
      return [out('allow', `artifact verified and nothing contradicts it (${trust.score}/100)`, [], 'trust/ok')];
    },
  },
  {
    id: 'gate/fail', status: 'active', thresholded: false, views: ['explain'],
    evaluate(ctx) {
      return ctx.facts && ctx.facts.gate_status === 'FAIL' ? [out('deny', 'the integrity gate failed this entry')] : [];
    },
  },
  {
    id: 'gate/unverified', status: 'active', thresholded: false, views: ['explain'],
    evaluate(ctx) {
      return ctx.facts && ctx.facts.gate_status === 'UNVERIFIED' && ctx.policy.unverified === 'fail'
        ? [out('deny', 'nothing about this entry could be verified, and the policy fails closed')] : [];
    },
  },
  {
    id: 'behaviour/*', status: 'active', thresholded: false, views: ['explain'],
    doc: 'Advisory: a server that does not start is not a security refusal.',
    evaluate(ctx) {
      const b = ctx.facts && ctx.facts.behaviour;
      if (!b) return [];
      return ['never-started', 'needs-credentials', 'needs-arguments'].includes(b.state)
        ? [out('warn', b.reason, [], `behaviour/${b.state}`)] : [];
    },
  },
];

// ── reserved for the open feature PRs ──────────────────────────────────────
//
// Claimed here so that each lands as a row in this table — with this id in
// `decided_by` — rather than as a branch in whichever command needed it first.

const reserved = (id, owner, doc) => ({ id, status: 'reserved', owner, doc, thresholded: false, views: [], evaluate: () => [] });
const reservedRules = [
  reserved('org/denylist', '#127', 'a server matched by any deny rule, in any layer'),
  reserved('org/allowlist', '#127', 'default deny: a server must match an allow rule in every layer'),
  reserved('org/min-tier', '#127', 'tier floor (reads the tier as a fact)'),
  reserved('org/evidence/*', '#127', 'a dimension that must be on record, within an age'),
  reserved('org/capability/*', '#127', 'a denied capability found by the scan, unless excused by the same layer'),
  reserved('org/capabilities', '#127', 'the capability scan the rule needs is missing → unknown'),
  reserved('org/tool-approval', '#127', 'every tool of the server approved in mcp.lock.json'),
  reserved('flows/lethal-trifecta', '#123', 'private data + untrusted content + exfiltration in one session'),
  reserved('flows/untrusted-destructive', '#123', 'untrusted content next to a destructive tool'),
  reserved('shadowing/*', '#123', 'tool names that shadow one another across servers'),
  reserved('tool-scan/*', '#124', 'poisoning patterns in tool descriptions and schemas'),
  reserved('lookalike/*', '#125', 'a name one edit away from a vault entry'),
  reserved('secrets/*', '#122', 'plain-text secrets in host configs'),
];

const RULES = Object.freeze([...explainRules, ...policyRules, ...findingRules, ...reservedRules].map((r) => Object.freeze(r)));
const RULE_BY_ID = new Map(RULES.map((r) => [r.id, r]));

// Evaluation order, per mode. It is the order the legacy views have always
// listed rules in (explain's `rules`, verify's POLICY lines), so that moving
// the rules here changed no byte of either. `decided_by` does not depend on
// it: the worst effect wins, and ties go to the first row in this order.
const ORDER = Object.freeze({
  gate: Object.freeze([
    'trust/*',
    'policy/install-hooks', 'policy/dependency-hooks', 'policy/dependency-advisories',
    'policy/signatures', 'policy/provenance', 'policy/docker-digest', 'policy/unverified',
    'policy/license', 'policy/health', 'policy/trust',
    'gate/fail', 'gate/unverified', 'behaviour/*', 'budget/over',
    'gate/require-provenance', 'gate/fail-dep-advisories', 'finding/severity', 'finding/incomplete',
  ]),
  evidence: Object.freeze([
    'trust/*',
    'policy/signatures', 'policy/provenance', 'policy/dependency-hooks', 'policy/dependency-advisories',
    'policy/unverified', 'policy/install-hooks', 'policy/docker-digest',
    'policy/license', 'policy/health', 'policy/trust',
    'gate/fail', 'gate/unverified', 'behaviour/*', 'budget/over',
    'gate/require-provenance', 'gate/fail-dep-advisories', 'finding/severity', 'finding/incomplete',
  ]),
});

function rulesFor(mode) {
  const order = ORDER[mode] || ORDER.gate;
  return order.map((id) => RULE_BY_ID.get(id)).filter((r) => r && r.status === 'active');
}

/** The table row an emitted rule id belongs to (`trust/artifact` → `trust/*`). */
function rowFor(ruleId) {
  if (RULE_BY_ID.has(ruleId)) return RULE_BY_ID.get(ruleId);
  const family = String(ruleId).split('/').slice(0, -1).join('/');
  return RULE_BY_ID.get(`${family}/*`) || null;
}

// ── the effective policy ───────────────────────────────────────────────────

function deepFreeze(o) {
  if (o && typeof o === 'object' && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const v of Object.values(o)) deepFreeze(v);
  }
  return o;
}

/**
 * The CLI switches that raise the bar, read once. They are policy, not
 * command logic: each one is an input to `effectivePolicy`.
 */
function flagsFromArgv(argv = []) {
  const a = new Set(argv);
  // --fail-families a,b (or =a,b): the rule families whose outcomes may fail
  // the run. Absent, every family may.
  let families = null;
  for (let i = 0; i < argv.length; i++) {
    const arg = String(argv[i]);
    if (arg === '--fail-families') families = String(argv[i + 1] || '');
    else if (arg.startsWith('--fail-families=')) families = arg.slice('--fail-families='.length);
  }
  return {
    failFamilies:             families === null ? null : families.split(',').map((x) => x.trim().replace(/\/\*?$/, '')).filter(Boolean),
    strict:                   a.has('--strict'),
    failUnverified:           a.has('--fail-unverified'),
    requireSignatures:        a.has('--require-signatures'),
    requireProvenance:        a.has('--require-provenance'),
    requireProvenanceBinding: a.has('--require-provenance-binding'),
    failDepAdvisories:        a.has('--fail-dep-advisories'),
    deep:                     a.has('--deep'),
    deps:                     a.has('--deps'),
  };
}

/**
 * base (a normalised policy@1 object, or null for "no policy file applies")
 * plus the flags, as one frozen object. Two layers, kept apart on purpose:
 *
 *   the file's keys   exactly as the policy file says (defaults filled in).
 *                     The `policy/*` rules read these, and nothing else —
 *                     `--require-signatures` has never added a POLICY-FAIL
 *                     line, it made the gate itself refuse.
 *   gate              the switches the gate's own rules read, each the
 *                     stricter of its flag and what the file implies. A flag
 *                     can raise a bar and can never lower one.
 *
 * and three derived keys, snake_case so they cannot collide with a file key:
 *   fail_on           'deny' | 'unknown' | 'warn' — which effects fail the
 *                     run. deny always does; --fail-unverified (or
 *                     `unverified: fail`) adds unknown; --strict adds warn.
 *                     This threshold *is* what --strict means now: a
 *                     parameter of the decision, not a branch in a command.
 *   fail_families     null, or the rule families (`integrity`, `pin`, …) whose
 *                     outcomes may fail the run (`--fail-families`). An outcome
 *                     belongs to a family by its own rule id or by a finding
 *                     it rests on. Everything is still decided and reported;
 *                     this says which part of it the exit code is about — the
 *                     seeded-DB smoke asks "is the DB consistent", not "is
 *                     every entry installable today"
 *   policy_rules      false under --no-policy: the file's rules do not apply,
 *                     the gate's still do
 */
function effectivePolicy(base, flags = {}, { defaults = {}, policyRules = true } = {}) {
  const p = { ...defaults, ...(base || {}) };
  const bound   = Boolean(flags.requireProvenanceBinding) || p.provenance === 'bound';
  const gate = {
    strict:                     Boolean(flags.strict),
    // --strict implies --fail-unverified: a run that refuses every warning
    // cannot accept "we could not check".
    fail_unverified:            Boolean(flags.failUnverified || flags.strict) || p.unverified === 'fail',
    require_signatures:         Boolean(flags.requireSignatures) || p.signatures === 'require',
    // Asking for a *bound* attestation is asking for an attestation.
    require_provenance:         Boolean(flags.requireProvenance) || bound || p.provenance === 'require',
    require_provenance_binding: bound,
    fail_dep_advisories:        Boolean(flags.failDepAdvisories) || p.dependencyAdvisories === 'fail',
    deep:                       Boolean(flags.deep) || p.deep === true,
    // A policy that forbids dependency hooks or advisories cannot be judged
    // without the tree, so requiring either implies resolving it.
    deps:                       Boolean(flags.deps) || p.deps === true
      || p.dependencyHooks === 'fail' || p.dependencyAdvisories === 'fail',
  };
  let failOn = 'deny';
  if (gate.fail_unverified) failOn = stricter('fail_on', failOn, 'unknown');
  if (gate.strict) failOn = stricter('fail_on', failOn, 'warn');
  // Which rule families may fail the run at all (null: every one). A
  // narrower *question*, not a lower bar: the findings are still made,
  // decided and reported; only the exit code is about these families.
  const families = Array.isArray(flags.failFamilies) && flags.failFamilies.length
    ? [...new Set(flags.failFamilies)].sort() : null;
  return deepFreeze({ ...p, gate, fail_on: failOn, fail_families: families, policy_rules: Boolean(policyRules) });
}

/**
 * The one way a command gets a policy: the file(s) that apply to `startDir`
 * (lib/policy.cjs `loadPolicy` — the org layers of #127 plug in there), then
 * the flags. `noPolicy` keeps the gate's own rules and drops the file's.
 */
function loadEffectivePolicy(startDir, { flags = {}, noPolicy = false } = {}) {
  // Required lazily: lib/policy.cjs is an adapter over this module.
  const { loadPolicy, DEFAULTS } = require('./policy.cjs');
  const loaded = noPolicy
    ? { ok: true, policy: null, path: null, errors: [], found: false, sources: [] }
    : loadPolicy(startDir);
  const policy = effectivePolicy(loaded.policy, flags, { defaults: DEFAULTS, policyRules: !noPolicy });
  return {
    ok: loaded.ok, found: loaded.found, path: loaded.path, errors: loaded.errors,
    sources: loaded.sources || (loaded.path ? [{ path: loaded.path, role: 'local' }] : []),
    file_policy: loaded.policy ? deepFreeze({ ...loaded.policy }) : null,
    policy,
  };
}

/**
 * The policy-file rules in gate mode, as `evaluateEntry` has always returned
 * them. lib/policy.cjs keeps that function as an adapter over this one, so the
 * two cannot drift apart.
 */
function entryRuleOutcomes(ctx) {
  const res = [];
  for (const row of rulesFor('gate')) {
    if (!row.views.includes('policy-line')) continue;
    for (const o of row.evaluate(ctx)) res.push({ rule: o.rule || row.id, effect: o.effect, detail: o.detail, findings: o.findings || [] });
  }
  return res;
}

// The evidence-mode policy rows explain's `policyFromEvidence` has always
// returned, in its order.
const EVIDENCE_POLICY_RULES = ['policy/signatures', 'policy/provenance', 'policy/dependency-hooks',
  'policy/dependency-advisories', 'policy/unverified', 'policy/install-hooks', 'policy/docker-digest'];

function evidenceRuleOutcomes(ctx) {
  const res = [];
  for (const id of EVIDENCE_POLICY_RULES) {
    for (const o of RULE_BY_ID.get(id).evaluate({ ...ctx, mode: 'evidence' })) {
      res.push({ rule: o.rule || id, effect: o.effect, detail: o.detail, findings: o.findings || [] });
    }
  }
  return res;
}

module.exports = {
  EFFECTS, RANK, RULES, RULE_BY_ID, ORDER,
  rulesFor, rowFor, stricter, deepFreeze,
  flagsFromArgv, effectivePolicy, loadEffectivePolicy, entryRuleOutcomes, evidenceRuleOutcomes,
};
