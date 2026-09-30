'use strict';
/**
 * Organisation policy: which MCP servers may run at all, and an organisation's
 * bar that a project can raise and cannot lower.
 *
 * The rest of the policy file is about *how good* an artifact has to be. An
 * organisation also needs to say *which* ones — the tenant-level allowlist in
 * the MCP security guidance, with "allow all" switched off. That is these keys,
 * all optional and all additive to `mcp-vault/policy@1`:
 *
 *   "extends": "../org/.mcp-vault.policy.json",   // an org policy this file sits on
 *   "default": "deny",                            // allow | deny
 *   "allow": [ { "npmScope": "@modelcontextprotocol" },
 *              { "githubOwner": "github" },
 *              { "registryNamespace": "io.github.mongodb-js" },
 *              { "entry": "playwright-mcp" },
 *              { "artifact": "npm:@acme/mcp@1.4.0", "integrity": "sha512-…" } ],
 *   "deny":  [ { "npmScope": "@evil" } ],
 *   "minTier": "Recommended",                     // Core | Recommended | Experimental
 *   "requireEvidence": { "signature": 30, "provenance": null },   // dimension → max age (null: its default)
 *   "denyCapabilities": ["shell", "dynamic_code"],
 *   "capabilityExceptions": { "desktop-commander": ["shell"] },
 *   "toolApproval": "require"                     // off | require — see lib/tool_approval.cjs
 *
 * Four decisions, each the one that fails closed:
 *
 *   1. **An allow list means "only these".** Writing an allow list and
 *      forgetting `default: deny` would enforce nothing, which is the typo this
 *      file refuses everywhere else — so an allow list implies `deny`, and an
 *      explicit `default: allow` next to one is an error.
 *   2. **The denylist outranks the allowlist.** A server matched by any deny
 *      rule, in any layer, is denied whatever allows it.
 *   3. **An allow match needs evidence; a deny match does not.** `githubOwner`
 *      reads the DB's `source_url`, which is a claim; it admits a server only
 *      when `source_binding` verified that the registry agrees, while a deny
 *      rule matches on the claim alone. `registryNamespace` admits only a
 *      `listed` registry record. `entry` admits only a launch that installs the
 *      same package as that DB entry: a host config can call anything "github".
 *   4. **A project can only tighten.** An org policy (`extends`, or the
 *      `MCP_VAULT_ORG_POLICY` path, which is how a managed machine sets one)
 *      is a layer the local file is merged over by `mergeStricter`: scalars
 *      take the stricter value, lists of what is permitted intersect, lists of
 *      what is refused unite, and allow lists are checked *per layer* — a
 *      server has to be on the org's list and on the project's. A local value
 *      that is looser than the org's is a policy error (exit 2), not a quiet
 *      clamp: a file that says one thing and enforces another is the bug.
 *
 * URLs are refused for `extends`: the gate runs offline, and a policy fetched
 * at check time would make the bar depend on a network the air-gapped install
 * does not have. Vendor the org policy into the repo, or point the env var at a
 * managed path.
 *
 * API:
 *   ORG_DEFAULTS, ORG_KEYS
 *   normalizeOrgKey(key, value, source)    -> { value } | { error }
 *   finishOrg(policy, raw, errors)         -> void (cross-key checks)
 *   mergeStricter(base, over, explicit, o) -> { policy, conflicts }
 *   hasOrgRules(policy)                    -> boolean
 *   subjectFacts(tool, dbEntry)            -> { … what a rule can match }
 *   evaluateOrg(tool, policy, ctx)         -> [{ rule, outcome, detail, source?, index? }]
 *   loadOrgContext({ cwd, … })             -> shared lookups, read once
 *   contextFor(shared, tool, extra)        -> ctx for evaluateOrg
 */

const fs   = require('fs');
const path = require('path');
const { toTypedEntry, artifactId, comparableArtifactId, comparableId, packageKey } = require('./entry_model.cjs');
const { githubOwner } = require('./repo_url.cjs');
const { DIMENSIONS, DEFAULT_MAX_AGE_DAYS, isPositive } = require('./evidence.cjs');
const { CAPABILITIES } = require('./capabilities.cjs');
const { TIERS, TIER_ORDER, classifyEntry } = require('./tiers.cjs');
const { APPROVALS_KEY, observationFromSurface, pendingTools, describePending, describeLines } = require('./tool_approval.cjs');

const ORG_DEFAULTS = {
  extends:              null,
  default:              'allow',
  allow:                null,
  deny:                 null,
  minTier:              null,
  requireEvidence:      null,
  denyCapabilities:     null,
  capabilityExceptions: null,
  toolApproval:         'off',
};
const ORG_KEYS = new Set(Object.keys(ORG_DEFAULTS));

const ORG_ENUMS = {
  default:      ['allow', 'deny'],
  toolApproval: ['off', 'require'],
};

const SELECTORS = ['entry', 'npmScope', 'githubOwner', 'registryNamespace', 'artifact'];
const RULE_KEYS = new Set([...SELECTORS, 'integrity', 'reason']);
// The tiers a floor can be set at. Deprecated is "do not install", so a floor
// there would be no floor.
const FLOOR_TIERS = TIERS.filter((t) => t !== 'Deprecated');

const label = (source) => source || 'policy';

function normalizeRule(rule, i, key) {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return { error: `"${key}[${i}]" must be an object such as { "npmScope": "@org" }` };
  const unknown = Object.keys(rule).filter((k) => !RULE_KEYS.has(k));
  if (unknown.length) return { error: `"${key}[${i}]" has unknown key${unknown.length > 1 ? 's' : ''} ${unknown.map((k) => `"${k}"`).join(', ')} (selectors: ${SELECTORS.join(', ')})` };
  const present = SELECTORS.filter((s) => rule[s] !== undefined);
  if (present.length !== 1) return { error: `"${key}[${i}]" must name exactly one of ${SELECTORS.join(', ')}` };
  const match = present[0];
  const value = rule[match];
  if (typeof value !== 'string' || !value.trim()) return { error: `"${key}[${i}].${match}" must be a non-empty string` };
  if (match === 'npmScope' && !/^@[a-z0-9][a-z0-9._~-]*$/i.test(value)) return { error: `"${key}[${i}].npmScope" must look like "@scope"` };
  if (match === 'artifact' && !/^(npm|pypi|oci|git):.+/.test(value)) return { error: `"${key}[${i}].artifact" must be an artifact id such as "npm:pkg@1.2.3" or "oci:image@sha256:…"` };
  if (rule.integrity !== undefined && match !== 'artifact') return { error: `"${key}[${i}].integrity" only applies to an "artifact" rule` };
  if (rule.integrity !== undefined && (typeof rule.integrity !== 'string' || !rule.integrity)) return { error: `"${key}[${i}].integrity" must be a string such as "sha512-…"` };
  if (rule.reason !== undefined && typeof rule.reason !== 'string') return { error: `"${key}[${i}].reason" must be a string` };
  return { value: { match, value: value.trim(), integrity: rule.integrity || null, reason: rule.reason || null, index: i } };
}

/** One org key from a raw policy file. `source` is the file it came from. */
function normalizeOrgKey(key, value, source = null) {
  if (ORG_ENUMS[key]) {
    if (!ORG_ENUMS[key].includes(value)) return { error: `"${key}" must be one of ${ORG_ENUMS[key].join(' | ')} (got ${JSON.stringify(value)})` };
    return { value };
  }
  if (value === null) return { value: null };
  switch (key) {
    case 'extends': {
      if (typeof value !== 'string' || !value.trim()) return { error: '"extends" must be a path to the organisation policy file' };
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value) && !/^file:\/\//i.test(value)) {
        return { error: '"extends" must be a local path: the gate runs offline, so an org policy has to be on disk (vendor it into the repo or set MCP_VAULT_ORG_POLICY to a managed path)' };
      }
      return { value: value.replace(/^file:\/\//i, '') };
    }
    case 'allow':
    case 'deny': {
      if (!Array.isArray(value)) return { error: `"${key}" must be an array of rules` };
      const rules = [];
      for (let i = 0; i < value.length; i++) {
        const r = normalizeRule(value[i], i, key);
        if (r.error) return { error: r.error };
        rules.push(r.value);
      }
      // A layer, not a flat list: allow lists from different files are ANDed.
      return { value: [{ source: label(source), rules }] };
    }
    case 'minTier': {
      const tier = FLOOR_TIERS.find((t) => t.toLowerCase() === String(value).toLowerCase());
      if (!tier) return { error: `"minTier" must be one of ${FLOOR_TIERS.join(' | ')}` };
      return { value: tier };
    }
    case 'requireEvidence': {
      const obj = Array.isArray(value) ? Object.fromEntries(value.map((d) => [d, null])) : value;
      if (!obj || typeof obj !== 'object') return { error: '"requireEvidence" must be an object of dimension → max age in days (or null for its default), or an array of dimensions' };
      const out = {};
      for (const [dim, age] of Object.entries(obj)) {
        if (!DIMENSIONS.includes(dim)) return { error: `"requireEvidence.${dim}" is not an evidence dimension (${DIMENSIONS.join(', ')})` };
        if (age !== null && (!Number.isInteger(age) || age < 1)) return { error: `"requireEvidence.${dim}" must be a positive whole number of days, or null` };
        out[dim] = age;
      }
      return { value: out };
    }
    case 'denyCapabilities': {
      if (!Array.isArray(value)) return { error: '"denyCapabilities" must be an array of capability names' };
      const bad = value.filter((c) => !(c in CAPABILITIES));
      if (bad.length) return { error: `"denyCapabilities": unknown capabilit${bad.length > 1 ? 'ies' : 'y'} ${bad.join(', ')} (known: ${Object.keys(CAPABILITIES).join(', ')})` };
      return { value: [{ source: label(source), capabilities: [...new Set(value)].sort() }] };
    }
    case 'capabilityExceptions': {
      if (typeof value !== 'object' || Array.isArray(value)) return { error: '"capabilityExceptions" must be an object of entry name → [capabilities]' };
      const exceptions = {};
      for (const [entry, caps] of Object.entries(value)) {
        if (!Array.isArray(caps)) return { error: `"capabilityExceptions.${entry}" must be an array of capability names` };
        const bad = caps.filter((c) => !(c in CAPABILITIES));
        if (bad.length) return { error: `"capabilityExceptions.${entry}": unknown capability ${bad.join(', ')}` };
        exceptions[entry] = [...new Set(caps)].sort();
      }
      return { value: [{ source: label(source), exceptions }] };
    }
    default:
      return { error: `unknown policy key "${key}"` };
  }
}

/** Checks that need more than one key. */
function finishOrg(policy, raw, errors) {
  const hasAllow = Array.isArray(policy.allow) && policy.allow.length > 0;
  if (hasAllow && raw.default === 'allow') {
    // Otherwise the allow list is decoration: everything not on it is allowed too.
    errors.push('"allow" lists what is permitted, which means "default": "deny"; remove "default": "allow" or the list');
  }
  if (hasAllow) policy.default = 'deny';
}

// ── merging an org layer with a project's override ──────────────────────────

// Weakest first. A key missing here and set in both layers is a conflict unless
// the two values are equal: we cannot tell which is stricter, so neither wins.
const RANK = {
  unverified:           ['warn', 'fail'],
  installHooks:         ['allow', 'warn', 'fail'],
  dependencyHooks:      ['allow', 'warn', 'fail'],
  dependencyAdvisories: ['allow', 'warn', 'fail'],
  signatures:           ['prefer', 'require'],
  provenance:           ['prefer', 'require', 'bound'],
  docker:               ['tag', 'digest'],
  contextBudget:        ['warn', 'fail'],
  default:              ['allow', 'deny'],
  toolApproval:         ['off', 'require'],
};
const HIGHER_IS_STRICTER = new Set(['minHealthScore']);
const LOWER_IS_STRICTER  = new Set(['maxContextTokens', 'maxContextPercent', 'maxEvidenceAgeDays']);
const BOOLEAN_STRICT     = new Set(['deep', 'deps']);
const LAYERED            = new Set(['allow', 'deny', 'denyCapabilities', 'capabilityExceptions']);

const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * `over` on top of `base`, keeping whichever is stricter per key.
 *
 * `explicit` is the set of keys the override file actually wrote: a default
 * filled in by normalisation is not an attempt to loosen anything. Every
 * explicit loosening is returned in `conflicts`, and the merged policy keeps the
 * base's value regardless — the caller reports, and nothing is enforced weaker
 * in the meantime.
 */
function mergeStricter(base, over, explicit = new Set(), { baseSource = 'org policy', baseExplicit = null } = {}) {
  const out = { ...base };
  const conflicts = [];
  const loosen = (key, detail) => conflicts.push(`"${key}" ${detail} — a local policy can only tighten ${baseSource}`);

  for (const key of explicit) {
    if (key === 'extends' || key === '$schema' || key === 'comment') continue;
    const b = base[key];
    const o = over[key];

    if (RANK[key]) {
      const rb = RANK[key].indexOf(b);
      const ro = RANK[key].indexOf(o);
      if (ro >= rb) out[key] = o;
      else loosen(key, `is ${JSON.stringify(o)}, looser than ${JSON.stringify(b)}`);
      continue;
    }
    if (HIGHER_IS_STRICTER.has(key) || LOWER_IS_STRICTER.has(key)) {
      if (b === null || b === undefined) { out[key] = o; continue; }
      if (o === null) { loosen(key, `removes the limit of ${b}`); continue; }
      const stricter = HIGHER_IS_STRICTER.has(key) ? o >= b : o <= b;
      if (stricter) out[key] = o;
      else loosen(key, `is ${o}, looser than ${b}`);
      continue;
    }
    if (BOOLEAN_STRICT.has(key)) {
      if (o) out[key] = true;
      else if (b) loosen(key, 'turns off what the org policy turns on');
      continue;
    }
    if (key === 'minTier') {
      if (!b) { out[key] = o; continue; }
      if (!o) { loosen(key, `removes the ${b} floor`); continue; }
      if (TIER_ORDER[o] <= TIER_ORDER[b]) out[key] = o;
      else loosen(key, `is ${o}, below the ${b} floor`);
      continue;
    }
    if (key === 'trust') {
      if (!b) { out[key] = o; continue; }
      if (!o) { loosen(key, 'removes the accepted-tier list'); continue; }
      const extra = o.filter((t) => !b.includes(t));
      if (extra.length) loosen(key, `accepts ${extra.join(', ')}, which the org policy does not`);
      out[key] = b.filter((t) => o.includes(t));
      continue;
    }
    if (key === 'licenses') {
      if (!b) { out[key] = o; continue; }
      if (!o) { loosen(key, 'removes the license lists'); continue; }
      let allow = b.allow;
      if (o.allow) {
        if (b.allow) {
          const extra = o.allow.filter((l) => !b.allow.includes(l));
          if (extra.length) loosen('licenses.allow', `allows ${extra.join(', ')}, which the org policy does not`);
          allow = b.allow.filter((l) => o.allow.includes(l));
        } else {
          allow = o.allow;
        }
      }
      const deny = (b.deny || o.deny) ? [...new Set([...(b.deny || []), ...(o.deny || [])])] : null;
      out[key] = { allow, deny };
      continue;
    }
    if (key === 'requireEvidence') {
      if (!b) { out[key] = o; continue; }
      if (!o) { continue; }   // null adds nothing and cannot remove the base's layer
      const merged = { ...b };
      for (const [dim, age] of Object.entries(o)) {
        if (!(dim in b)) { merged[dim] = age; continue; }
        const ageB = b[dim] ?? DEFAULT_MAX_AGE_DAYS[dim];
        const ageO = age ?? DEFAULT_MAX_AGE_DAYS[dim];
        if (ageO <= ageB) merged[dim] = age;
        else loosen(`requireEvidence.${dim}`, `accepts ${ageO}-day-old evidence, older than ${ageB}`);
      }
      out[key] = merged;
      continue;
    }
    if (LAYERED.has(key)) {
      if (o === null) {
        if (b) loosen(key, 'is null, which cannot remove the org policy\'s rules');
        continue;
      }
      if (key === 'capabilityExceptions') {
        // An exception from this file excuses only what this file denies.
        const baseDenied = new Set((base.denyCapabilities || []).flatMap((l) => l.capabilities));
        for (const layer of o) {
          for (const [entry, caps] of Object.entries(layer.exceptions)) {
            const excused = caps.filter((c) => baseDenied.has(c));
            if (excused.length) loosen(`capabilityExceptions.${entry}`, `excuses ${excused.join(', ')}, which the org policy denies`);
          }
        }
      }
      out[key] = [...(b || []), ...o];
      continue;
    }
    // A key this function does not know how to rank — a newer rule, or one
    // added beside this one. Set on one side it applies; set on both it must
    // agree, because picking either could be the looser one.
    const baseSet = baseExplicit ? baseExplicit.has(key) : true;
    if (b === undefined || b === null || eq(b, o) || !baseSet) { out[key] = o; continue; }
    loosen(key, `is set to ${JSON.stringify(o)} here and ${JSON.stringify(b)} there, and this version cannot tell which is stricter`);
  }
  return { policy: out, conflicts };
}

function hasOrgRules(policy) {
  if (!policy) return false;
  return policy.default === 'deny'
    || Boolean(policy.allow && policy.allow.length)
    || Boolean(policy.deny && policy.deny.length)
    || Boolean(policy.minTier)
    || Boolean(policy.requireEvidence && Object.keys(policy.requireEvidence).length)
    || Boolean(policy.denyCapabilities && policy.denyCapabilities.length)
    || policy.toolApproval === 'require';
}

// ── what a rule can see about a server ──────────────────────────────────────

function safeTyped(tool) {
  try { return toTypedEntry(tool); } catch { return null; }
}

/**
 * The facts a rule matches on, for the server as it is *launched*.
 *
 * `tool` is what runs (a DB entry, or a configured server); `dbEntry` is the
 * vault's record for it, if any. The DB's claims — its name, `source_url`, its
 * evidence — are used only when the launched package is the DB entry's package.
 */
function subjectFacts(tool, dbEntry = null) {
  const typed = safeTyped(tool);
  const a = typed ? typed.artifact : null;
  const dbTyped = dbEntry ? safeTyped(dbEntry) : null;
  const samePackage = Boolean(a && dbTyped && packageKey(a) && packageKey(a) === packageKey(dbTyped.artifact));
  const vault = samePackage ? dbEntry : null;
  const dims = (vault && vault.trust_evidence && vault.trust_evidence.dimensions) || {};
  const reg = dims.registry && dims.registry.server_id ? dims.registry : null;
  return {
    name:         tool ? tool.name : null,
    in_vault:     Boolean(vault),
    entry:        vault ? vault.name : null,
    ecosystem:    a ? a.ecosystem : null,
    package:      a ? (a.package || a.image || null) : null,
    npm_scope:    a && a.ecosystem === 'npm' && a.package && a.package.startsWith('@') ? a.package.split('/')[0] : null,
    artifact_id:  a ? comparableArtifactId(a) : null,
    raw_artifact_id: a ? artifactId(a) : null,
    integrity:    a ? (a.integrity || null) : null,
    digest:       a ? (a.digest || null) : null,
    github_owner: vault ? githubOwner(vault.source_url) : null,
    github_owner_bound: Boolean(vault && dims.source_binding && dims.source_binding.status === 'verified'),
    registry_id:  reg ? reg.server_id : null,
    registry_listed: Boolean(reg && reg.status === 'listed'),
  };
}

/** Does one rule match? `forAllow` is the stricter reading (see decision 3). */
function ruleMatches(rule, facts, forAllow) {
  const v = rule.value;
  switch (rule.match) {
    case 'entry':
      return facts.entry !== null && facts.entry === v;
    case 'npmScope':
      return facts.npm_scope !== null && facts.npm_scope.toLowerCase() === v.toLowerCase();
    case 'githubOwner':
      if (!facts.github_owner || facts.github_owner.toLowerCase() !== v.toLowerCase()) return false;
      return forAllow ? facts.github_owner_bound : true;
    case 'registryNamespace': {
      if (!facts.registry_id) return false;
      const hit = facts.registry_id === v || facts.registry_id.startsWith(`${v}/`);
      return hit && (forAllow ? facts.registry_listed : true);
    }
    case 'artifact': {
      if (!facts.artifact_id || comparableId(v) !== facts.artifact_id) return false;
      if (!rule.integrity) return true;
      const have = facts.integrity || facts.digest;
      // Named bytes: an allow needs the same bytes; a deny holds unless the
      // bytes are known to be different ones.
      if (!have) return !forAllow;
      return have === rule.integrity;
    }
    default:
      return false;
  }
}

const describeRule = (r) => `${r.match} ${r.value}${r.integrity ? ` (${r.integrity.slice(0, 19)}…)` : ''}${r.reason ? ` — ${r.reason}` : ''}`;

function daysSince(iso, now) {
  const then = Date.parse(`${String(iso).slice(0, 10)}T00:00:00Z`);
  return Number.isNaN(then) ? Infinity : Math.floor((now - then) / 86400000);
}

/**
 * Judge one server against the organisation rules.
 *
 * ctx: { dbEntry, evidence, evalResult, capabilities, lock, surface, now }
 * Every rule is returned with its outcome — allow, deny, warn or unknown — and
 * the layer (`source`) and position (`index`) of the rule that decided, which
 * is what `explain` prints.
 */
function evaluateOrg(tool, policy, ctx = {}) {
  const out = [];
  if (!hasOrgRules(policy)) return out;
  const now = ctx.now || Date.now();
  const dbEntry = ctx.dbEntry === undefined ? tool : ctx.dbEntry;
  const facts = subjectFacts(tool, dbEntry);
  const add = (rule, outcome, detail, extra = {}) => out.push({ rule, outcome, detail, ...extra });

  // 1. The denylist, first and final.
  let denied = false;
  for (const layer of policy.deny || []) {
    const hit = layer.rules.find((r) => ruleMatches(r, facts, false));
    if (hit) {
      denied = true;
      add('org/denylist', 'deny', `denied by deny[${hit.index}] (${describeRule(hit)}) in ${layer.source}; the denylist outranks any allow rule`,
        { source: layer.source, index: hit.index });
    }
  }

  // 2. The allowlist, per layer.
  if (!denied) {
    const layers = (policy.allow || []);
    if (policy.default === 'deny' && !layers.length) {
      add('org/allowlist', 'deny', 'the policy denies by default and allows nothing', { source: null, index: null });
    }
    for (const layer of layers) {
      const hit = layer.rules.find((r) => ruleMatches(r, facts, true));
      if (hit) {
        add('org/allowlist', 'allow', `allowed by allow[${hit.index}] (${describeRule(hit)}) in ${layer.source}`, { source: layer.source, index: hit.index });
      } else {
        // Say what almost matched: an unbound GitHub owner is a different fix
        // from not being on the list at all.
        const near = layer.rules.find((r) => ruleMatches(r, facts, false));
        const why = near
          ? `allow[${near.index}] (${describeRule(near)}) names it, but the match is not established — ${near.match === 'githubOwner' ? 'source_binding has not verified the repository' : near.match === 'registryNamespace' ? 'the registry record is not "listed"' : 'the artifact bytes are not known to be the named ones'}`
          : (facts.in_vault ? 'no allow rule matches it' : `it is not in the vault DB and no allow rule names ${facts.raw_artifact_id || facts.name}`);
        add('org/allowlist', 'deny', `not on the allowlist in ${layer.source} (default: deny): ${why}`, { source: layer.source, index: near ? near.index : null });
      }
    }
  }

  // 3. A tier floor. A server the vault does not know has no tier at all.
  if (policy.minTier) {
    if (!facts.in_vault) {
      add('org/min-tier', 'deny', `not in the vault DB, so it has no tier (policy floor: ${policy.minTier})`);
    } else {
      const tier = classifyEntry(dbEntry, ctx.evalResult || null, { now });
      const ok = TIER_ORDER[tier.classification] <= TIER_ORDER[policy.minTier];
      add('org/min-tier', ok ? 'allow' : 'deny', `tier ${tier.classification} ${ok ? 'meets' : 'is below'} the ${policy.minTier} floor — ${tier.why}`);
    }
  }

  // 4. Evidence that must be on record, and how old it may be.
  if (policy.requireEvidence) {
    const evidence = ctx.evidence !== undefined ? ctx.evidence : (facts.in_vault ? dbEntry.trust_evidence : null);
    const idOk = evidence && (!evidence.artifact_id || !facts.artifact_id || comparableId(evidence.artifact_id) === facts.artifact_id);
    const dims = idOk ? (evidence.dimensions || {}) : {};
    for (const [dim, age] of Object.entries(policy.requireEvidence)) {
      const rule = `org/evidence/${dim}`;
      const limit = age ?? DEFAULT_MAX_AGE_DAYS[dim];
      const v = dims[dim];
      // The requirement is that it be on record; a missing record is the
      // answer, not a missing input.
      if (!v) { add(rule, 'deny', evidence && !idOk ? `the stored evidence is about ${evidence.artifact_id}, not this artifact` : `${dim} has never been established for this artifact`); continue; }
      if (!isPositive(dim, v.status)) { add(rule, 'deny', `${dim} is ${v.status} (as of ${v.checked_at || 'unknown'})`); continue; }
      const when = v.verified_at || v.checked_at;
      const days = daysSince(when, now);
      if (days > limit) add(rule, 'deny', `${dim}: ${v.status} was established ${days}d ago (${when}); the policy accepts ${limit}d`);
      else add(rule, 'allow', `${dim}: ${v.status} as of ${when} (within ${limit}d)`);
    }
  }

  // 5. Capabilities the organisation refuses, unless excused by the same layer.
  if (policy.denyCapabilities && policy.denyCapabilities.length) {
    const scans = (ctx.capabilities && ctx.capabilities.packages) || {};
    const scan = facts.raw_artifact_id ? scans[facts.raw_artifact_id] : null;
    if (!scan) {
      // Absence is never recorded (lib/capabilities.cjs), and an unscanned
      // package is an input that is missing — not a verdict either way.
      const caps = [...new Set(policy.denyCapabilities.flatMap((l) => l.capabilities))];
      add('org/capabilities', 'unknown', `${facts.raw_artifact_id || facts.name} has not been scanned for ${caps.join(', ')} — run \`mcp-vault capabilities --write\``);
    } else {
      const found = new Set(Object.keys(scan.found || {}));
      const denied = [...new Set(policy.denyCapabilities.flatMap((l) => l.capabilities))];
      const clear = denied.filter((c) => !found.has(c));
      if (clear.length) {
        add('org/capabilities', 'allow', `${clear.join(', ')} not found in the scan of ${facts.raw_artifact_id} (${scan.checked_at || 'undated'}) — a scan cannot prove absence`);
      }
      for (const layer of policy.denyCapabilities) {
        for (const cap of layer.capabilities) {
          const rule = `org/capability/${cap}`;
          if (!found.has(cap)) continue;
          const excused = (policy.capabilityExceptions || []).find((x) => x.source === layer.source
            && facts.entry && (x.exceptions[facts.entry] || []).includes(cap));
          const where = scan.found[cap][0];
          const at = where ? ` (${where.file}:${where.line})` : '';
          add(rule, excused ? 'allow' : 'deny', excused
            ? `${cap} found${at}, excused for ${facts.entry} by capabilityExceptions in ${layer.source}`
            : `${cap} found${at}, and ${layer.source} denies it without an exception for ${facts.entry || facts.name}`,
          { source: layer.source });
        }
      }
    }
  }

  // 6. Tools approved one by one.
  if (policy.toolApproval === 'require') {
    const name = facts.name;
    const approvals = (ctx.lock && ctx.lock[APPROVALS_KEY]) || {};
    const approved = approvals[name] || null;
    const observation = ctx.surface ? observationFromSurface(ctx.surface) : null;
    if (!observation) {
      add('org/tool-approval', 'unknown', `no tool surface has been observed for ${name} — run \`mcp-vault eval --name ${name} --sandbox\``);
    } else if (!approved) {
      add('org/tool-approval', 'deny', `none of ${name}'s ${observation.fingerprint.count} tools are approved — \`mcp-vault approve ${name}\``);
    } else {
      const pending = pendingTools(approved, observation);
      const n = pending.added.length + pending.changed.length;
      if (n) {
        const lines = describeLines(describePending(pending, approved, observation));
        add('org/tool-approval', 'deny', `${n} tool${n === 1 ? '' : 's'} not approved since ${approved.approved_at}: ${lines.map((l) => l.trim()).join('; ')} — \`mcp-vault approve ${name}\``);
      } else {
        add('org/tool-approval', 'allow', `all ${observation.fingerprint.count} tools match the approval of ${approved.approved_at}${pending.removed.length ? ` (${pending.removed.length} approved tool(s) no longer offered)` : ''}`);
      }
    }
  }

  return out;
}

// ── the lookups a rule needs, read once ─────────────────────────────────────

const ASSETS = path.resolve(__dirname, '../../assets');

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

function loadOrgContext({ cwd = process.cwd(), evalPath = path.join(ASSETS, 'eval_results.json'),
  capsPath = path.join(ASSETS, 'capabilities.json'), lockFile = null, dbTools = null } = {}) {
  const evals = readJson(evalPath, { results: [] }).results || [];
  return {
    evalByName:   new Map(evals.map((r) => [r.name, r])),
    capabilities: readJson(capsPath, { packages: {} }),
    lock:         readJson(lockFile || path.join(cwd, 'mcp.lock.json'), null),
    dbByName:     dbTools ? new Map(dbTools.map((t) => [t.name, t])) : null,
  };
}

function contextFor(shared, tool, extra = {}) {
  let dbEntry = extra.dbEntry !== undefined
    ? extra.dbEntry
    : (shared.dbByName ? shared.dbByName.get(tool.name) || null : tool);
  // A configured server that shares a DB entry's name but launches another
  // package is not that entry, and neither its eval nor its surface applies.
  if (dbEntry && dbEntry !== tool && !subjectFacts(tool, dbEntry).in_vault) dbEntry = null;
  const evalResult = shared.evalByName.get((dbEntry && dbEntry.name) || tool.name) || null;
  return {
    evalResult,
    capabilities: shared.capabilities,
    lock:         shared.lock,
    surface:      evalResult && evalResult.surface && evalResult.surface.tools ? evalResult.surface : null,
    ...extra,
    dbEntry,
  };
}

module.exports = {
  ORG_DEFAULTS, ORG_KEYS, SELECTORS, RANK,
  normalizeOrgKey, finishOrg, mergeStricter, hasOrgRules,
  subjectFacts, ruleMatches, evaluateOrg, loadOrgContext, contextFor,
};
