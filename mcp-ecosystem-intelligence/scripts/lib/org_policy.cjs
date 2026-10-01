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
 *   ruleMatches(rule, facts, forAllow)     -> boolean
 *   loadOrgContext({ cwd, dbTools, asOf }) -> shared lookups, read once, as of asOf
 *   orgModel(tool, policy, shared, o)      -> { subject, facts, findings }  (facts → facts[id].org)
 *   toolApprovalModel({ subject, server, approved, observation, currentArtifactId, asOf })
 *                                          -> { fact, findings }   (org/tool-approval findings)
 *
 * The rules are rows `org/*` in lib/policy_rules.cjs and `decide()` evaluates
 * them (docs/adr/0001): this file produces their inputs and decides nothing.
 */

const fs   = require('fs');
const path = require('path');
const { toTypedEntry, artifactId, comparableArtifactId, comparableId, packageKey } = require('./entry_model.cjs');
const { githubOwner } = require('./repo_url.cjs');
const { entryForLaunch } = require('./entry_match.cjs');
const { DIMENSIONS, DEFAULT_MAX_AGE_DAYS, evalResultsAsOf } = require('./evidence.cjs');
const { CAPABILITIES } = require('./capabilities.cjs');
const { TIERS, TIER_ORDER, classifyEntry } = require('./tiers.cjs');
const { requireAsOf } = require('./clock.cjs');
const { RANK } = require('./policy_rules.cjs');
const {
  APPROVALS_KEY, observationFromSurface, pendingTools, approvalFor, describePending, describeLines,
} = require('./tool_approval.cjs');

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

// Weakest first, from the one table (lib/policy_rules.cjs RANK). A key missing
// there and set in both layers is a conflict unless the two values are equal:
// we cannot tell which is stricter, so neither wins.
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
      // An explicit null is an attempt to drop the org's requirements.
      if (!o) { loosen(key, 'is null, which cannot remove the org policy\'s evidence requirements'); continue; }
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

// ── the facts the org rows read (lib/policy_rules.cjs `org/*`) ──────────────
//
// The rules themselves are rows in lib/policy_rules.cjs, evaluated by
// `decide()` like every other rule; nothing here produces an effect. What
// lives here is the part that needs files and lookups: which vault entry a
// launch is, its tier and capability scan as of `asOf`, the stored evidence,
// and — for `toolApproval` — the approval state as findings on the server.
// Everything written into `facts` is plain JSON, so a findings@1 document
// carries it and `decide()` over the document reproduces the decision.

const ASSETS = path.resolve(__dirname, '../../assets');
const dayStart = (iso) => Date.parse(`${String(iso).slice(0, 10)}T00:00:00Z`);
// A look dated after the instant decided at did not exist then.
const after = (iso, asOf) => Boolean(iso) && dayStart(iso) > asOf;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

/** The lookups a rule needs, read once per run, as they stood at `asOf`. */
function loadOrgContext({ cwd = process.cwd(), evalPath = path.join(ASSETS, 'eval_results.json'),
  capsPath = path.join(ASSETS, 'capabilities.json'), lockFile = null, dbTools = null, asOf } = {}) {
  const at = requireAsOf(asOf, 'loadOrgContext');
  const evals = evalResultsAsOf(readJson(evalPath, { results: [] }).results || [], at);
  return {
    asOf:         at,
    evalByName:   new Map(evals.map((r) => [r.name, r])),
    capabilities: readJson(capsPath, { packages: {} }),
    lock:         readJson(lockFile || path.join(cwd, 'mcp.lock.json'), null),
    dbTools:      dbTools || null,
  };
}

/**
 * The vault entry a launch *is*. A host config names a server whatever it
 * likes (`"docs": npx context7@…`), so the name decides nothing: the package
 * the launch runs does, by the matcher every command uses
 * (lib/entry_match.cjs) — an entry of the same name that installs another
 * package is not this server, and an entry of another name that installs
 * this one is.
 */
function vaultEntryFor(shared, tool, explicit) {
  if (explicit !== undefined) return explicit && subjectFacts(tool, explicit).in_vault ? explicit : null;
  if (!shared || !shared.dbTools) return tool;
  return entryForLaunch(shared.dbTools, tool && tool.install_cmd);
}

/**
 * Tool approval for one server, as findings on `subject` plus the fact the
 * row reads. One finding per tool that is new or changed since it was
 * approved (`observed`), or one `no-data` finding when no surface can be
 * relied on — under `toolApproval: require` that refuses, because an
 * approval nobody could check is not an approval.
 *
 * An approval is for the artifact it was made on (`artifact_id`): after an
 * upgrade the old approval does not carry over, and neither does an eval
 * surface recorded for another artifact.
 */
function toolApprovalModel({ subject: subj, server, approved = null, observation = null, currentArtifactId = null, asOf, missing = null }) {
  const at = requireAsOf(asOf, 'toolApprovalModel');
  const { finding } = require('./finding.cjs');
  const mk = (state, message) => finding({ rule: 'org/tool-approval', subject: subj, severity: 'info', confidence: 'high', state, message });
  // Only what had been approved by `asOf`.
  let dated = null;
  if (approved && !after(approved.approved_at, at)) {
    const tools = Object.fromEntries(Object.entries(approved.tools || {}).filter(([, t]) => !after(t && t.approved_at, at)));
    dated = { ...approved, tools };
  }
  const approvedId = dated ? dated.artifact_id || null : null;
  const fact = {
    server, observed: Boolean(observation), count: observation ? observation.fingerprint.count : 0,
    approved_at: dated ? dated.approved_at : null, approved_artifact_id: approvedId,
    current_artifact_id: currentArtifactId || null, rebind: false, pending: 0, removed: 0,
  };
  if (!observation) {
    return { fact, findings: [mk('no-data', missing || `no tool surface has been observed for ${server} — run \`mcp-vault eval --name ${server} --sandbox\``)] };
  }
  const bound = approvalFor(dated, currentArtifactId);
  fact.rebind = Boolean(dated && !bound);
  const pending = pendingTools(bound, observation);
  fact.pending = pending.added.length + pending.changed.length;
  fact.removed = pending.removed.length;
  const lines = describeLines(describePending({ ...pending, removed: [] }, bound, observation))
    .filter((l) => /^[+~]/.test(l)).map((l) => l.trim());
  return { fact, findings: lines.map((l) => mk('observed', l)) };
}

/**
 * The org part of one subject's decision inputs: `{ subject, facts, findings }`,
 * where `facts` goes under `facts[subject.id].org`.
 *
 * `tool` is what runs (a DB entry, or a configured server). `dbEntry` pins the
 * vault record (null: none); left out, it is looked up in `shared`.
 * `evidence` overrides the stored evidence (verify passes what the run
 * established merged over it); `surface` overrides the eval's tool surface.
 */
function orgModel(tool, policy, shared = {}, { subject: subj = null, dbEntry, evidence, surface, asOf } = {}) {
  const at = requireAsOf(asOf === undefined ? shared.asOf : asOf, 'orgModel');
  const s = subj || require('./findings_from.cjs').subjectForTool(tool);
  const vault = vaultEntryFor(shared, tool, dbEntry);
  const facts = { subject: subjectFacts(tool, vault) };
  const findings = [];
  const evalRow = vault && shared.evalByName ? shared.evalByName.get(vault.name) || null : null;

  if (policy.minTier && facts.subject.in_vault) {
    const t = classifyEntry(vault, evalRow, { now: at });
    facts.tier = { classification: t.classification, why: t.why };
  }

  if (policy.requireEvidence) {
    const ev = evidence !== undefined ? evidence : (vault ? vault.trust_evidence : null);
    if (!ev) {
      facts.evidence = null;
    } else {
      const forThis = !ev.artifact_id || !facts.subject.artifact_id || comparableId(ev.artifact_id) === facts.subject.artifact_id;
      const dims = {};
      for (const dim of Object.keys(policy.requireEvidence)) {
        const v = ev.dimensions && ev.dimensions[dim];
        if (v) dims[dim] = { status: v.status, checked_at: v.checked_at || null, verified_at: v.verified_at || null };
      }
      facts.evidence = { artifact_id: ev.artifact_id || null, for_this_artifact: forThis, dimensions: dims };
    }
  }

  if (policy.denyCapabilities && policy.denyCapabilities.length) {
    const scans = (shared.capabilities && shared.capabilities.packages) || {};
    const scan = facts.subject.raw_artifact_id ? scans[facts.subject.raw_artifact_id] : null;
    if (!scan || after(scan.checked_at, at)) {
      facts.capabilities = null;
    } else {
      const denied = [...new Set(policy.denyCapabilities.flatMap((l) => l.capabilities))];
      const found = {};
      for (const cap of denied) {
        if (!scan.found || !(cap in scan.found)) continue;
        const where = scan.found[cap] && scan.found[cap][0];
        found[cap] = where ? { file: where.file || null, line: where.line || null } : null;
      }
      facts.capabilities = { artifact_id: facts.subject.raw_artifact_id, checked_at: scan.checked_at || null, found };
    }
  }

  if (policy.toolApproval === 'require') {
    const approvals = (shared.lock && shared.lock[APPROVALS_KEY]) || {};
    const approved = approvals[tool.name] || (vault && approvals[vault.name]) || null;
    let surf = surface;
    let missing = null;
    if (surf === undefined) {
      surf = evalRow && evalRow.surface && evalRow.surface.tools ? evalRow.surface : null;
      // A surface recorded against another artifact says nothing about this one.
      const recorded = evalRow && evalRow.identity && evalRow.identity.artifact_id;
      if (surf && recorded && facts.subject.artifact_id && comparableId(recorded) !== facts.subject.artifact_id) {
        missing = `the observed tool surface is for ${recorded}, and ${tool.name} launches ${facts.subject.artifact_id} — run \`mcp-vault eval --name ${vault.name} --sandbox\``;
        surf = null;
      }
    }
    const m = toolApprovalModel({
      subject: s, server: tool.name, approved, observation: surf ? observationFromSurface(surf) : null,
      currentArtifactId: facts.subject.artifact_id, asOf: at, missing,
    });
    facts.tool_approval = m.fact;
    findings.push(...m.findings);
  }
  return { subject: s, facts, findings };
}

module.exports = {
  ORG_DEFAULTS, ORG_KEYS, SELECTORS,
  normalizeOrgKey, finishOrg, mergeStricter, hasOrgRules,
  subjectFacts, ruleMatches, describeRule, vaultEntryFor,
  loadOrgContext, orgModel, toolApprovalModel,
};
