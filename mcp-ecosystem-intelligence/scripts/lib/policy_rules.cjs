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
 *   role        'gate' (the default) | 'context', or { <mode>: role } with
 *               'gate' for a mode not named. A gate outcome is part of the
 *               answer to "does the install gate pass this subject": it sets
 *               the effect, `decided_by` and `fails`. A context outcome is
 *               printed and kept in the trace (`rules`, marked `role:
 *               'context'`) and decides nothing — it is what explain shows
 *               beside the gate's answer: the behaviour record, the context
 *               budget, the tool-description scan, what the configured set
 *               would do, and a stored-evidence reading the policy does not
 *               require. So `explain` and `verify` exit alike on the same
 *               inputs (#131). An outcome may say `role` itself where the row
 *               cannot know in advance (a policy row in evidence mode is gate
 *               only when the policy requires what it reads).
 *   evaluate    (ctx) -> [{ rule?, effect, detail, findings? }]
 *   claims      optional: a finding-rule prefix only this row decides; the
 *               generic finding/* rows skip those findings (#121)
 *
 * ctx: { subject, findings, policy, facts, mode, asOf }
 *   findings  this subject's findings (lib/finding.cjs)
 *   facts     what a rule may read that is not a finding: the DB entry's
 *             licence/health/trust, the stored evidence and trust score,
 *             behaviour, budget, the live gate's status
 *   mode      'gate' when findings come from a gate run, 'evidence' when only
 *             stored evidence is available (explain without --verify),
 *             'live' for explain --verify (gate semantics; explain's own
 *             inputs stay context), 'approval', 'setup'
 *
 * API:
 *   RULES, RULE_BY_ID, ORDER, RANK, EFFECTS
 *   rulesFor(mode)                       -> ordered active rows
 *   roleOf(row, mode)                    -> 'gate' | 'context'
 *   effectivePolicy(base, flags, opts)   -> frozen, normalised policy
 *   loadEffectivePolicy(startDir, opts)  -> { ok, policy, path, found, errors, sources }  (opts.file: a named policy)
 *   flagsFromArgv(argv)                  -> { strict, failUnverified, failFamilies, failFamiliesError, … }
 *   parseFailFamilies(argv)              -> { families, error }  (FINDING_FAMILIES: what it accepts)
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
  // Organisation keys (#127, lib/org_policy.cjs): an allow list implies deny.
  default:              ['allow', 'deny'],
  toolApproval:         ['off', 'require'],
  toxicFlows:           ['allow', 'warn', 'fail'],
  toolShadowing:        ['allow', 'warn', 'fail'],
  unpinnedLaunch:       ['allow', 'warn', 'fail'],
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
// An outcome that is shown and traced but is not part of the gate's answer.
const context = (o) => ({ ...o, role: 'context' });
// Explain's own inputs — what the configured set would do, the tool list's
// scan — are context in explain (offline or --verify) and the whole question
// in the command that asks it (tool-scan, status / audit).
const EXPLAIN_CONTEXT = Object.freeze({ evidence: 'context', live: 'context' });
// A finding family whose own row decides it is judged by that row alone, not
// by the generic finding/* rows: a row that `claims` a rule prefix (#121:
// `db/signature-*`, `audits/import-*`), or one that `owns_findings` of the
// rules it matches (#123: flows/*, shadowing/*: the policy key it reads, not
// the severity bar). Read at call time: RULES is defined below.
const claimed = (f) => {
  if (RULES.some((r) => r.claims && r.status === 'active' && f.rule.startsWith(r.claims))) return true;
  const row = rowFor(f.rule);
  return Boolean(row && row.owns_findings);
};

// ── plain-text secrets in host configs (#122) ───────────────────────────────

const secretRules = [
  {
    id: 'secrets/*', status: 'active', thresholded: false, views: [],
    doc: 'A credential written in plain text into a host config refuses, tracked by git or not: anything that reads the file has it. Tracked only raises the severity (rotate).',
    evaluate(ctx) {
      return ctx.findings.filter((f) => f.state === 'observed' && f.rule.startsWith('secrets/'))
        .map((f) => out('deny', f.message, [f.id], f.rule));
    },
  },
];

// The entry rules (licence, health, trust tier) judge a DB entry's fields. A
// subject with no entry behind it — a bare name (#125) — has none of them to
// be missing, so "no licence recorded" would be a claim about nothing.
const hasEntry = (ctx) => Boolean(ctx.facts && ctx.facts.entry);

// ── rules over findings (any command) ──────────────────────────────────────

const findingRules = [
  {
    id: 'finding/severity', status: 'active', thresholded: true, views: [],
    doc: 'An observed finding refuses at high/critical severity and warns at medium.',
    evaluate(ctx) {
      const res = [];
      for (const f of ctx.findings) {
        if (f.state !== 'observed' || claimed(f)) continue;
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
      return ctx.findings.filter((f) => f.state !== 'observed' && !claimed(f)).map((f) => out('unknown', f.message, [f.id]));
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

//
// What the stored record says is part of the gate's answer only where the
// policy requires it (`signatures: require`, …). Under the defaults (`prefer`)
// the gate has never refused or warned on it — `verify` prints no POLICY line
// for a missing provenance attestation it merely prefers — so the reading is
// shown as context: "provenance is absent" is worth knowing, and is not a
// warning that fails `explain --strict` while `verify --strict` passes (#131).
const fromEvidence = (ctx, dim, { ok, bad, require: required, message }) => {
  const dims = (ctx.facts && ctx.facts.evidence && ctx.facts.evidence.dimensions) || {};
  const value = dims[dim];
  const role = (o) => (required ? o : context(o));
  // Required and not on record: the requirement is not met, as for
  // org/evidence/* — a refusal, not an open question. Offline this is the
  // answer `verify` has always given (it saw no signature, so it refused).
  if (!value) return required ? [out('deny', `no ${dim} evidence is on record for this artifact, and this policy requires it — run with --verify`)] : [];
  if (ok.includes(value.status)) return [role(out('allow', `${dim}: ${value.status} (as of ${value.verified_at || value.checked_at})`))];
  if (bad.includes(value.status)) return [role(out(required ? 'deny' : 'warn', message(value)))];
  return [role(out('unknown', `${dim} is "${value.status}", which this rule cannot judge — run with --verify`))];
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
      if (!p.licenses || !hasEntry(ctx)) return [];
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
      if (p.minHealthScore === null || p.minHealthScore === undefined || !hasEntry(ctx)) return [];
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
      if (!p.trust || !hasEntry(ctx)) return [];
      const trust = entryOf(ctx).trust || null;
      return !trust || !p.trust.includes(trust)
        ? [out('deny', `trust tier ${trust || '(none)'} is not accepted by this policy (accepts: ${p.trust.join(', ')})`)] : [];
    },
  },
  {
    id: 'budget/over', status: 'active', thresholded: false, views: ['explain'], role: 'context',
    doc: 'Context: `install` checks the budget itself (--allow-over-budget); the integrity gate does not.',
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
    id: 'behaviour/*', status: 'active', thresholded: false, views: ['explain'], role: 'context',
    doc: 'Context: a server that does not start is not a security refusal, and the gate never reads it.',
    evaluate(ctx) {
      const b = ctx.facts && ctx.facts.behaviour;
      if (!b) return [];
      return ['never-started', 'needs-credentials', 'needs-arguments'].includes(b.state)
        ? [out('warn', b.reason, [], `behaviour/${b.state}`)] : [];
    },
  },
];

// ── organisation rules (#127) ──────────────────────────────────────────────
//
// Which servers may run at all, and the org's bar (lib/org_policy.cjs has the
// keys, the layering and the facts producer). The rows read `ctx.facts.org`,
// which `orgModel` writes: what a rule can match on (`subject`), the tier and
// the capability scan as of `asOf`, and the stored evidence. Tool approval is
// the one input that arrives as findings (`org/tool-approval`, on the
// server), because `approve` and `lock --check` report it too. Each outcome's
// detail names the layer and the position of the rule that matched it, so
// `decided_by` can stay a rule id.

const orgOf = (ctx) => (ctx.policy.policy_rules && ctx.facts && ctx.facts.org) || null;
const orgLib = () => require('./org_policy.cjs');

const orgRules = [
  {
    id: 'org/denylist', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    doc: 'a server matched by any deny rule, in any layer — first and final',
    evaluate(ctx) {
      const org = orgOf(ctx);
      if (!org || !org.subject) return [];
      const { ruleMatches, describeRule } = orgLib();
      const res = [];
      for (const layer of ctx.policy.deny || []) {
        const hit = layer.rules.find((r) => ruleMatches(r, org.subject, false));
        if (hit) res.push(out('deny', `denied by deny[${hit.index}] (${describeRule(hit)}) in ${layer.source}; the denylist outranks any allow rule`));
      }
      return res;
    },
  },
  {
    id: 'org/allowlist', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    doc: 'default deny: a server must match an allow rule in every layer',
    evaluate(ctx) {
      const org = orgOf(ctx);
      if (!org || !org.subject) return [];
      const { ruleMatches, describeRule } = orgLib();
      const facts = org.subject;
      // A denylisted server is not also "allowed": the denylist is final.
      if ((ctx.policy.deny || []).some((l) => l.rules.some((r) => ruleMatches(r, facts, false)))) return [];
      const layers = ctx.policy.allow || [];
      if (ctx.policy.default === 'deny' && !layers.length) return [out('deny', 'the policy denies by default and allows nothing')];
      return layers.map((layer) => {
        const hit = layer.rules.find((r) => ruleMatches(r, facts, true));
        if (hit) return out('allow', `allowed by allow[${hit.index}] (${describeRule(hit)}) in ${layer.source}`);
        // Say what almost matched: an unbound GitHub owner is a different fix
        // from not being on the list at all.
        const near = layer.rules.find((r) => ruleMatches(r, facts, false));
        const why = near
          ? `allow[${near.index}] (${describeRule(near)}) names it, but the match is not established — ${near.match === 'githubOwner' ? 'source_binding has not verified the repository' : near.match === 'registryNamespace' ? 'the registry record is not "listed"' : 'the artifact bytes are not known to be the named ones'}`
          : (facts.in_vault ? 'no allow rule matches it' : `it is not in the vault DB and no allow rule names ${facts.raw_artifact_id || facts.name}`);
        return out('deny', `not on the allowlist in ${layer.source} (default: deny): ${why}`);
      });
    },
  },
  {
    id: 'org/min-tier', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    doc: 'tier floor; the tier is a fact computed at asOf, and a server outside the vault has none',
    evaluate(ctx) {
      const org = orgOf(ctx);
      const floor = ctx.policy.minTier;
      if (!org || !org.subject || !floor) return [];
      if (!org.tier) return [out('deny', `not in the vault DB, so it has no tier (policy floor: ${floor})`)];
      const { TIER_ORDER } = require('./tiers.cjs');
      const ok = TIER_ORDER[org.tier.classification] <= TIER_ORDER[floor];
      return [out(ok ? 'allow' : 'deny', `tier ${org.tier.classification} ${ok ? 'meets' : 'is below'} the ${floor} floor — ${org.tier.why}`)];
    },
  },
  {
    id: 'org/evidence/*', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    doc: 'a dimension that must be on record, positive, and no older than its limit at asOf',
    evaluate(ctx) {
      const org = orgOf(ctx);
      if (!org || !org.subject || !ctx.policy.requireEvidence) return [];
      const { DEFAULT_MAX_AGE_DAYS, isPositive, daysBetween } = require('./evidence.cjs');
      const ev = org.evidence || null;
      const dims = ev && ev.for_this_artifact ? ev.dimensions || {} : {};
      const res = [];
      // Sorted: a findings@1 document carries the policy with sorted keys, and
      // decide() over the document must list the rules in the same order.
      for (const dim of Object.keys(ctx.policy.requireEvidence).sort()) {
        const age = ctx.policy.requireEvidence[dim];
        const rule = `org/evidence/${dim}`;
        const limit = age ?? DEFAULT_MAX_AGE_DAYS[dim];
        const v = dims[dim];
        // The requirement is that it be on record; a missing record is the
        // answer, not a missing input.
        if (!v) { res.push(out('deny', ev && !ev.for_this_artifact ? `the stored evidence is about ${ev.artifact_id}, not this artifact` : `${dim} has never been established for this artifact`, [], rule)); continue; }
        if (!isPositive(dim, v.status)) { res.push(out('deny', `${dim} is ${v.status} (as of ${v.checked_at || 'unknown'})`, [], rule)); continue; }
        const when = v.verified_at || v.checked_at;
        const days = daysBetween(when, ctx.asOf);
        res.push(days > limit
          ? out('deny', `${dim}: ${v.status} was established ${days}d ago (${when}); the policy accepts ${limit}d`, [], rule)
          : out('allow', `${dim}: ${v.status} as of ${when} (within ${limit}d)`, [], rule));
      }
      return res;
    },
  },
  {
    id: 'org/capabilities', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    doc: 'the capability scan a denyCapabilities rule needs: missing → unknown, clear → allow',
    evaluate(ctx) {
      const org = orgOf(ctx);
      const layers = ctx.policy.denyCapabilities || [];
      if (!org || !org.subject || !layers.length) return [];
      const denied = [...new Set(layers.flatMap((l) => l.capabilities))];
      const scan = org.capabilities;
      // Absence is never recorded (lib/capabilities.cjs), and an unscanned
      // package is an input that is missing — not a verdict either way.
      if (!scan) return [out('unknown', `${org.subject.raw_artifact_id || org.subject.name} has not been scanned for ${denied.join(', ')} — run \`mcp-vault capabilities --write\``)];
      const clear = denied.filter((c) => !(c in scan.found));
      return clear.length
        ? [out('allow', `${clear.join(', ')} not found in the scan of ${scan.artifact_id} (${scan.checked_at || 'undated'}) — a scan cannot prove absence`)] : [];
    },
  },
  {
    id: 'org/capability/*', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    doc: 'a denied capability found by the scan, unless excused by an exception from the same layer',
    evaluate(ctx) {
      const org = orgOf(ctx);
      const scan = org && org.capabilities;
      if (!scan || !org.subject) return [];
      const entry = org.subject.entry;
      const res = [];
      for (const layer of ctx.policy.denyCapabilities || []) {
        for (const cap of layer.capabilities) {
          if (!(cap in scan.found)) continue;
          const excused = (ctx.policy.capabilityExceptions || []).some((x) => x.source === layer.source
            && entry && (x.exceptions[entry] || []).includes(cap));
          const where = scan.found[cap];
          const at = where ? ` (${where.file}:${where.line})` : '';
          res.push(out(excused ? 'allow' : 'deny', excused
            ? `${cap} found${at}, excused for ${entry} by capabilityExceptions in ${layer.source}`
            : `${cap} found${at}, and ${layer.source} denies it without an exception for ${entry || org.subject.name}`, [], `org/capability/${cap}`));
        }
      }
      return res;
    },
  },
  {
    id: 'org/tool-approval', status: 'active', thresholded: false, views: ['explain', 'policy-line'],
    doc: 'every tool the server offers approved in mcp.lock.json, for the artifact it launches',
    evaluate(ctx) {
      if (!ctx.policy.policy_rules || ctx.policy.toolApproval !== 'require') return [];
      // A bare name (#125: a lookalike nobody launched from the vault) has no
      // server behind it whose tools could be approved; the question is not
      // asked of it, as no other org/* row reads facts it does not have.
      if (ctx.subject && ctx.subject.type === 'name') return [];
      const ta = ctx.facts && ctx.facts.org && ctx.facts.org.tool_approval;
      const fs = ctx.findings.filter((f) => f.rule === 'org/tool-approval');
      // `toolApproval: require` asks for an approved surface to be on record:
      // one nobody observed is not approved, so it refuses (fail closed).
      const missing = fs.filter((f) => f.state !== 'observed');
      if (missing.length) return missing.map((f) => out('deny', f.message, [f.id]));
      if (fs.length) {
        const n = ta && Number.isInteger(ta.pending) ? ta.pending : fs.length;
        const server = ta ? ta.server : ctx.subject.id;
        const head = ta && ta.rebind
          ? `the approval of ${ta.approved_at} is for ${ta.approved_artifact_id || 'an unrecorded artifact'}, and ${server} now launches ${ta.current_artifact_id}`
          : ta && !ta.approved_at && ta.count
            ? `none of ${server}'s ${ta.count} tools are approved`
            : `${n} tool${n === 1 ? '' : 's'} not approved${ta && ta.approved_at ? ` since ${ta.approved_at}` : ''}`;
        return [out('deny', `${head}: ${fs.map((f) => f.message).join('; ')} — \`mcp-vault approve ${server}\``, fs.map((f) => f.id))];
      }
      if (!ta) return [out('unknown', 'tool approval was not evaluated for this subject')];
      return [out('allow', `all ${ta.count} tools match the approval of ${ta.approved_at}${ta.removed ? ` (${ta.removed} approved tool(s) no longer offered)` : ''}`)];
    },
  },
];

// ── what the configured set does together (#123, lib/flows.cjs) ────────────
//
// Findings on a `setup` subject (a host's session) or a `tool` subject (a
// colliding tool), or — in explain — on the entry that would close the flow.
// The level is the policy's: `toxicFlows` / `toolShadowing` = fail | warn |
// allow, default warn, and `warn` fails the run only under --strict (these
// rows are thresholded, so `fail_on: warn` reaches them). A low-confidence
// conclusion — a flow that needs a code capability to close, a near-miss
// name — is reported and never enforced: it is `allow`, said so in the trace.

const SET_EFFECT = { fail: 'deny', warn: 'warn', allow: 'allow' };
const setJudged = (ctx, match, key) => ctx.findings
  .filter((f) => match(f.rule) && f.state === 'observed')
  .map((f) => {
    if (f.confidence === 'low') return out('allow', `${f.message} (low confidence: reported, not enforced)`, [f.id], f.rule);
    const level = SET_EFFECT[ctx.policy[key]] ? ctx.policy[key] : 'warn';
    return out(SET_EFFECT[level], level === 'allow' ? `${f.message} (${key}: allow)` : f.message, [f.id], f.rule);
  });
const setupRules = [
  {
    id: 'flows/lethal-trifecta', status: 'active', thresholded: true, owns_findings: true, role: EXPLAIN_CONTEXT, views: ['explain'],
    doc: 'private data + untrusted content + an outward sink in one session; the level is policy.toxicFlows',
    evaluate: (ctx) => setJudged(ctx, (r) => r === 'flows/lethal-trifecta', 'toxicFlows'),
  },
  {
    id: 'flows/untrusted-destructive', status: 'active', thresholded: true, owns_findings: true, role: EXPLAIN_CONTEXT, views: ['explain'],
    doc: 'untrusted content next to a destructive tool; the level is policy.toxicFlows',
    evaluate: (ctx) => setJudged(ctx, (r) => r === 'flows/untrusted-destructive', 'toxicFlows'),
  },
  {
    id: 'shadowing/*', status: 'active', thresholded: true, owns_findings: true, role: EXPLAIN_CONTEXT, views: ['explain'],
    doc: 'tool names that shadow one another across servers; the level is policy.toolShadowing',
    evaluate: (ctx) => setJudged(ctx, (r) => r.startsWith('shadowing/'), 'toolShadowing'),
  },
  {
    id: 'flows/no-data', status: 'active', thresholded: false, owns_findings: true, role: EXPLAIN_CONTEXT, views: [],
    doc: 'a server nobody could see into: unknown, never clean — and, as before, never a failing exit',
    evaluate(ctx) {
      return ctx.findings.filter((f) => (f.rule.startsWith('flows/') || f.rule.startsWith('shadowing/')) && f.state !== 'observed')
        .map((f) => out('unknown', f.message, [f.id], 'flows/no-data'));
    },
  },
];
const SETUP_ORDER = ['flows/lethal-trifecta', 'flows/untrusted-destructive', 'shadowing/*', 'flows/no-data'];

// ── tool-scan (#124) ───────────────────────────────────────────────────────
//
// What a server's tool list tells the model (lib/tool_scan.cjs). The findings
// are on `tool` subjects; explain, deciding about the artifact, reads them from
// `facts.tool_scan` (this server's scan, as findings) instead. One row either
// way, so `tool-scan` and `explain` cannot read the same scan differently.

const toolScanRules = [
  {
    id: 'tool-scan/*', status: 'active', thresholded: true, role: EXPLAIN_CONTEXT, views: ['explain'],
    doc: 'Tool descriptions: an observed high finding refuses, medium warns, low is listed only; a scan that did not run, did not cover the list or aged out is unknown.',
    evaluate(ctx) {
      const held = ctx.facts && ctx.facts.tool_scan;
      const fs = [...ctx.findings, ...((held && held.findings) || [])].filter((f) => f.rule.startsWith('tool-scan/'));
      if (!fs.length && !(held && held.scanned)) return [];
      const { RULE_BY_ID: TS } = require('./tool_scan.cjs');
      const byRule = new Map();
      for (const f of fs) { if (!byRule.has(f.rule)) byRule.set(f.rule, []); byRule.get(f.rule).push(f); }
      const res = [];
      let fired = false;
      for (const [rule, group] of byRule) {
        const pending = group.filter((f) => f.state !== 'observed');
        if (pending.length) res.push(out('unknown', pending[0].message, pending.map((f) => f.id), rule));
        const seen = group.filter((f) => f.state === 'observed' && f.severity !== 'low' && f.severity !== 'info');
        if (!seen.length) continue;
        fired = true;
        const where = seen.map((f) => f.subject.id);
        const row = TS.get(rule.slice('tool-scan/'.length));
        const detail = `${row ? row.summary : rule} — ${where.slice(0, 3).join('; ')}${where.length > 3 ? `; +${where.length - 3} more` : ''}`;
        const severe = seen.some((f) => f.severity === 'critical' || f.severity === 'high');
        res.push(out(severe ? 'deny' : 'warn', detail, seen.map((f) => f.id), rule));
      }
      // Only where the whole scan is in view (explain's fact); in `tool-scan`
      // a quiet server is a subject with no findings, and allows as such.
      if (held && held.scanned && Array.isArray(held.findings) && !fired) {
        res.push(out('allow', `no high or medium rule fired over ${held.tools} tools (rules v${held.rules_version}); absence of a match is not proof of intent`, [], 'tool-scan/quiet'));
      }
      return res;
    },
  },
];

// ── names shaped like a vault entry's (#125, lib/lookalike.cjs) ─────────────

const lookalikeRules = [
  {
    id: 'lookalike/*', status: 'active', thresholded: true, views: ['explain'],
    doc: 'A name shaped like a vault entry: refused when a person asks for it by name (install, explain); '
      + 'a warning when a host config launches it, so it fails under --strict; allowed, still reported, '
      + 'when --allow-lookalike names it. One outcome per finding, named lookalike/<technique>.',
    evaluate(ctx) {
      const l = (ctx.facts && ctx.facts.lookalike) || {};
      const allow = new Set(l.allow || []);
      const vouched = (l.names || []).find((n) => allow.has(n));
      return ctx.findings.filter((f) => f.rule.startsWith('lookalike/') && f.state === 'observed').map((f) => {
        if (vouched) return out('allow', `${f.message} (allowed by --allow-lookalike ${vouched})`, [f.id], f.rule);
        return out(l.intent === 'requested' ? 'deny' : 'warn', f.message, [f.id], f.rule);
      });
    },
  },
];

// ── what a host config launches (lib/installed.cjs unpinnedLaunch) ─────────
//
// A finding about the *config*, on its host-config line: it launches a
// registry package with no exact version, so each start runs whatever is
// latest. Not a fact about the vault's DB, and not the gate's "could not
// verify" — a config that pins the vault's version passes both. The level is
// `policy.unpinnedLaunch` (fail | warn | allow, default warn: fails only
// under --strict, as a default does not get stricter in a minor).

const configRules = [
  {
    id: 'config/unpinned-launch', status: 'active', thresholded: true, owns_findings: true, views: [],
    doc: 'A host config that launches a registry package without an exact version (none, a tag, a range); the level is policy.unpinnedLaunch.',
    evaluate: (ctx) => setJudged(ctx, (r) => r === 'config/unpinned-launch', 'unpinnedLaunch'),
  },
  {
    // A launch whose package comes from somewhere else than the public
    // registry (--registry, an npmrc, a uv index/project, pipx --path, or the
    // same through the environment). The gate did not check what runs, so
    // the answer is `unknown`, with the reason — never `allow`, and never a
    // check against the public registry standing in for the real source.
    id: 'config/launch-source-override', status: 'active', thresholded: true, owns_findings: true, views: [],
    doc: 'A host config that launches a package from an overridden source (registry, npmrc, index, local path): unknown, with the reason.',
    evaluate(ctx) {
      return ctx.findings.filter((f) => f.rule === 'config/launch-source-override')
        .map((f) => out('unknown', f.message, [f.id], f.rule));
    },
  },
];

// ── reserved for the open feature PRs ──────────────────────────────────────
//
// Claimed here so that each lands as a row in this table — with this id in
// `decided_by` — rather than as a branch in whichever command needed it first.

const reserved = (id, owner, doc) => ({ id, status: 'reserved', owner, doc, thresholded: false, views: [], evaluate: () => [] });
const reservedRules = [
];

// ── #121: the DB signature and audits ─────────────────────────────────────
//
// Three rows. The signature and import rows *claim* their finding family
// (`claims`): the generic finding/* rows skip a claimed finding, so the row
// that knows the context is the only one that decides it — the dev escape
// hatch turns a refusal into a warning, and `finding/severity` would turn it
// straight back. `audits/recorded` can only ever say `allow`: worst effect
// wins, so an audit is visible in the trace and cannot lift a decision
// anywhere (docs/adr/0001-addendum-121-signed-db.md).

const signatureRules = [
  {
    id: 'db/signature', status: 'active', thresholded: true, views: [], claims: 'db/signature-',
    doc: 'The DB must verify against the shipped keyring. A missing signature refuses only where one is required (an installed package, not a git checkout).',
    evaluate(ctx) {
      const f = ctx.facts || {};
      const res = [];
      for (const x of ctx.findings) {
        if (!x.rule.startsWith('db/signature-')) continue;
        if (x.rule === 'db/signature-verified') res.push(out('allow', x.message, [x.id]));
        // A keyring nobody can read is "someone broke the thing that says
        // who signs": no escape hatch reaches it.
        else if (x.rule === 'db/signature-keyring-invalid') res.push(out('deny', x.message, [x.id]));
        else if (x.state !== 'observed') res.push(out('unknown', x.message, [x.id]));
        else if (x.rule === 'db/signature-absent' && !f.required) res.push(out('allow', `${x.message} — not required in a ${f.context || 'git checkout'}`, [x.id]));
        else if (f.allow_unsigned) res.push(out('warn', `${x.message} — accepted because --allow-unsigned-db / MCP_VAULT_ALLOW_UNSIGNED_DB is set`, [x.id]));
        else res.push(out('deny', x.message, [x.id]));
      }
      return res;
    },
  },
  {
    id: 'audits/import', status: 'active', thresholded: true, views: [], claims: 'audits/import-',
    doc: 'Every configured audit source verifies against the key in the config; one that does not, or was never fetched, refuses.',
    evaluate(ctx) {
      return ctx.findings.filter((x) => x.rule.startsWith('audits/import-'))
        .map((x) => out(x.rule === 'audits/import-verified' ? 'allow' : 'deny', x.message, [x.id]));
    },
  },
  {
    id: 'audits/recorded', status: 'active', thresholded: false, views: [],
    doc: 'An audit (local or imported) is shown with its source; it never changes the effect.',
    evaluate(ctx) {
      return ctx.findings.filter((x) => x.rule === 'audits/recorded')
        .map((x) => out('allow', `${x.message} — does not change trust`, [x.id]));
    },
  },
];

const RULES = Object.freeze([...explainRules, ...policyRules, ...secretRules, ...findingRules, ...lookalikeRules, ...configRules, ...toolScanRules, ...orgRules, ...setupRules, ...reservedRules, ...signatureRules].map((r) => Object.freeze(r)));
const RULE_BY_ID = new Map(RULES.map((r) => [r.id, r]));

// Evaluation order, per mode. It is the order the legacy views have always
// listed rules in (explain's `rules`, verify's POLICY lines), so that moving
// the rules here changed no byte of either. `decided_by` does not depend on
// it: the worst effect wins, and ties go to the first row in this order.
const ORDER = Object.freeze({
  gate: Object.freeze([
    'org/denylist', 'org/allowlist', 'org/min-tier', 'org/evidence/*', 'org/capabilities', 'org/capability/*', 'org/tool-approval',
    'trust/*',
    'policy/install-hooks', 'policy/dependency-hooks', 'policy/dependency-advisories',
    'policy/signatures', 'policy/provenance', 'policy/docker-digest', 'policy/unverified',
    'policy/license', 'policy/health', 'policy/trust',
    'gate/fail', 'gate/unverified', 'tool-scan/*', 'behaviour/*', 'budget/over', ...SETUP_ORDER,
    'secrets/*',
    'gate/require-provenance', 'gate/fail-dep-advisories', 'finding/severity', 'finding/incomplete',
    'lookalike/*', 'config/unpinned-launch', 'config/launch-source-override',
    'audits/recorded',
    'db/signature', 'audits/import',
  ]),
  evidence: Object.freeze([
    'org/denylist', 'org/allowlist', 'org/min-tier', 'org/evidence/*', 'org/capabilities', 'org/capability/*', 'org/tool-approval',
    'trust/*',
    'policy/signatures', 'policy/provenance', 'policy/dependency-hooks', 'policy/dependency-advisories',
    'policy/unverified', 'policy/install-hooks', 'policy/docker-digest',
    'policy/license', 'policy/health', 'policy/trust',
    'gate/fail', 'gate/unverified', 'tool-scan/*', 'behaviour/*', 'budget/over', ...SETUP_ORDER,
    'secrets/*',
    'gate/require-provenance', 'gate/fail-dep-advisories', 'finding/severity', 'finding/incomplete',
    'lookalike/*', 'config/unpinned-launch', 'config/launch-source-override',
    'audits/recorded',
    'db/signature', 'audits/import',
  ]),
  // `approve` and `lock --check` ask one question — has somebody approved
  // what this server offers, and is it what was locked — so only these rows
  // answer it; the entry-quality rows need facts those commands do not have.
  approval: Object.freeze(['org/tool-approval', 'finding/severity', 'finding/incomplete']),
  // status / audit over a host's session: only what the set does together.
  setup: Object.freeze([...SETUP_ORDER]),
});
// explain --verify: the gate's rows in the gate's order; explain's own inputs
// are context (EXPLAIN_CONTEXT), so its exit is the live gate's.
const ORDER_LIVE = ORDER.gate;
const ROLES = ['gate', 'context'];

/** A row's role in a mode: `role` as a string, or per mode (default gate). */
function roleOf(row, mode) {
  const r = row && row.role;
  const role = !r ? 'gate' : typeof r === 'string' ? r : (r[mode] || 'gate');
  if (!ROLES.includes(role)) throw new TypeError(`policy_rules: row ${row.id} has role ${JSON.stringify(role)} (one of ${ROLES.join(', ')})`);
  return role;
}

function rulesFor(mode) {
  const order = mode === 'live' ? ORDER_LIVE : (ORDER[mode] || ORDER.gate);
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
// The rule families a finding or an outcome can belong to: the first segment
// of every row id here, and of every finding rule the producers emit
// (lib/legacy_tags.cjs, lib/findings_from.cjs and the commands). What
// `--fail-families` may name — a name outside it matches nothing, and a
// security gate whose filter matches nothing passes everything (#134).
// tests/decision_consistency.test.cjs checks that no producer emits a family
// missing here.
const FINDING_FAMILIES = Object.freeze([
  'advisories', 'artifact', 'audits', 'config', 'db', 'dependencies', 'evidence', 'flows', 'install', 'integrity',
  'license', 'lock', 'lookalike', 'metadata', 'oci', 'org', 'pin', 'provenance', 'registry', 'scope',
  'secrets', 'shadowing', 'signature', 'tool-scan', 'verify',
]);
const familiesKnown = () => new Set([...FINDING_FAMILIES, ...RULES.map((r) => r.id.split('/')[0])]);

/**
 * `--fail-families a,b` / `--fail-families=a,b` -> { families, error }.
 * Absent: { families: null } (every family may fail the run). A missing
 * value, a value that is another switch, an empty list or a family nobody
 * emits is an error: each would otherwise narrow the question to nothing and
 * exit 0 on a decision that denies.
 */
function parseFailFamilies(argv = []) {
  let raw = null;
  let error = null;
  for (let i = 0; i < argv.length; i++) {
    const arg = String(argv[i]);
    if (arg === '--fail-families') {
      const next = argv[i + 1];
      if (next === undefined || String(next).startsWith('-')) {
        error = '--fail-families needs a comma-separated list of rule families (e.g. integrity,pin)';
        raw = '';
        continue;
      }
      raw = String(next);
      i++;
    } else if (arg.startsWith('--fail-families=')) raw = arg.slice('--fail-families='.length);
  }
  if (raw === null) return { families: null, error: null };
  const families = raw.split(',').map((x) => x.trim().replace(/\/\*?$/, '')).filter(Boolean);
  if (error) return { families: [], error };
  if (!families.length) return { families: [], error: `--fail-families names no family (got ${JSON.stringify(raw)})` };
  const known = familiesKnown();
  const unknown = families.filter((f) => !known.has(f.split('/')[0]));
  if (unknown.length) {
    return { families, error: `--fail-families: unknown rule famil${unknown.length === 1 ? 'y' : 'ies'} ${unknown.map((f) => JSON.stringify(f)).join(', ')} (known: ${[...known].sort().join(', ')})` };
  }
  return { families, error: null };
}

function flagsFromArgv(argv = []) {
  const a = new Set(argv);
  // --fail-families a,b (or =a,b): the rule families whose outcomes may fail
  // the run. Absent, every family may. A malformed one is `failFamiliesError`,
  // which the command refuses with exit 2 — never a filter that matches nothing.
  const ff = parseFailFamilies(argv);
  return {
    failFamilies:             ff.families,
    failFamiliesError:        ff.error,
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
 * (lib/policy.cjs `loadPolicy`: the org layers — `extends`, MCP_VAULT_ORG_POLICY —
 * merged stricter-wins by lib/org_policy.cjs `mergeStricter`), then
 * the flags. `noPolicy` keeps the gate's own rules and drops the file's.
 */
function loadEffectivePolicy(startDir, { flags = {}, noPolicy = false, file = null } = {}) {
  // Required lazily: lib/policy.cjs is an adapter over this module.
  const { loadPolicy, loadPolicyFile, DEFAULTS } = require('./policy.cjs');
  // `file`: a policy named outright (verify --policy, #120) instead of the
  // search upwards from startDir; a missing one comes back not-ok, never as
  // the defaults.
  const loaded = noPolicy
    ? { ok: true, policy: null, path: null, errors: [], found: false, sources: [] }
    : (file ? loadPolicyFile(file) : loadPolicy(startDir));
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
  rulesFor, rowFor, roleOf, stricter, deepFreeze,
  flagsFromArgv, parseFailFamilies, FINDING_FAMILIES, effectivePolicy, loadEffectivePolicy, entryRuleOutcomes, evidenceRuleOutcomes,
};
