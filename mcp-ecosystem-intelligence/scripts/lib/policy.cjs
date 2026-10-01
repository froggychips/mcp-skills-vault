'use strict';
/**
 * Policy file: the bar a project holds MCP servers to, written down once.
 *
 * The gate grew a flag per question — --strict, --fail-unverified, --deep,
 * --deps, --require-signatures, --require-provenance, --fail-dep-advisories.
 * That is a reasonable CLI and an unreasonable thing to keep correct across a
 * workflow file, a pre-commit hook and whatever a developer types by hand. A
 * policy file states the bar once, and CI and humans run the same bar.
 *
 * `.mcp-vault.policy.json`, resolved from the working directory upwards (so a
 * monorepo can keep one at the root):
 *
 *   {
 *     "$schema": "mcp-vault/policy@1",
 *     "unverified": "fail",            // fail | warn      (default warn)
 *     "installHooks": "warn",          // fail | warn | allow
 *     "dependencyHooks": "warn",       // fail | warn | allow
 *     "dependencyAdvisories": "warn",  // fail | warn | allow
 *     "signatures": "require",         // require | prefer  (default prefer)
 *     "provenance": "prefer",          // require | prefer
 *     "docker": "digest",              // digest | tag      (default digest)
 *     "licenses": { "allow": ["MIT", "Apache-2.0"], "deny": ["BUSL-1.1"] },
 *     "minHealthScore": 60,
 *     "maxContextTokens": 40000,       // tool surface ceiling for a config
 *     "maxContextPercent": 20,         // …or as a share of the context window
 *     "contextBudget": "warn",         // fail | warn      (default warn)
 *     "maxEvidenceAgeDays": 30,       // stored evidence older than this is stale
 *     "toxicFlows": "warn",            // fail | warn | allow  (default warn)
 *     "toolShadowing": "warn",         // fail | warn | allow  (default warn)
 *     "trust": ["verified"],           // acceptable trust tiers
 *     "deep": true,                    // hash artifacts locally
 *     "deps": true                     // resolve and check dependency trees
 *   }
 *
 * Organisations add which servers may run at all — `extends`, `default`,
 * `allow`, `deny`, `minTier`, `requireEvidence`, `denyCapabilities`,
 * `capabilityExceptions`, `toolApproval` — documented in lib/org_policy.cjs.
 * An org policy (`extends`, or the MCP_VAULT_ORG_POLICY path) is a layer the
 * local file can tighten and cannot loosen.
 *
 * Every key is optional. An unknown key is an error rather than a silent
 * no-op: a typo in a policy that then quietly does nothing is worse than no
 * policy, because it reads as a bar that is being enforced.
 *
 * API:
 *   findPolicyFile(startDir)      -> path | null
 *   loadPolicy(startDir, opts)    -> { ok, policy, path, errors, sources }
 *   normalizePolicy(raw)          -> { ok, policy, errors }
 *   policyToFlags(policy)         -> ["--fail-unverified", …]
 *   evaluateEntry(entry, policy)  -> [{ level, rule, message }]
 */

const fs   = require('fs');
const path = require('path');
const { ORG_DEFAULTS, ORG_KEYS, normalizeOrgKey, finishOrg, mergeStricter } = require('./org_policy.cjs');

const POLICY_FILENAMES = ['.mcp-vault.policy.json', '.mcp-vault.policy'];

const DEFAULTS = {
  unverified:           'warn',
  installHooks:         'warn',
  dependencyHooks:      'warn',
  dependencyAdvisories: 'warn',
  signatures:           'prefer',
  provenance:           'prefer',
  docker:               'digest',
  licenses:             null,
  minHealthScore:       null,
  // A tool surface ceiling for the whole config. Every enabled server injects
  // its tool list into every request, so this is a property of the set, not of
  // any one entry — which is why it is checked at install time, when the set
  // changes, rather than per entry by the gate.
  maxContextTokens:     null,
  maxContextPercent:    null,
  contextBudget:        'warn',
  maxEvidenceAgeDays:   null,
  // Properties of the set, like the context ceiling: lib/flows.cjs finds a
  // session that can read untrusted content, reach private data and send it
  // out, and tools two servers both claim. `warn` reports them (and fails
  // only under --strict); `fail` makes them blocking; `allow` keeps them in
  // --json and out of the verdict.
  toxicFlows:           'warn',
  toolShadowing:        'warn',
  trust:                null,
  deep:                 false,
  deps:                 false,
  // Organisation rules: lib/org_policy.cjs.
  ...ORG_DEFAULTS,
};

const ENUMS = {
  unverified:           ['fail', 'warn'],
  installHooks:         ['fail', 'warn', 'allow'],
  dependencyHooks:      ['fail', 'warn', 'allow'],
  dependencyAdvisories: ['fail', 'warn', 'allow'],
  signatures:           ['require', 'prefer'],
  provenance:           ['require', 'prefer'],
  docker:               ['digest', 'tag'],
  contextBudget:        ['fail', 'warn'],
  toxicFlows:           ['fail', 'warn', 'allow'],
  toolShadowing:        ['fail', 'warn', 'allow'],
};

/** Nearest policy file at or above `startDir`. */
function findPolicyFile(startDir = process.cwd()) {
  let dir = path.resolve(startDir);
  for (;;) {
    for (const name of POLICY_FILENAMES) {
      const candidate = path.join(dir, name);
      if (fs.existsSync(candidate)) return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function normalizePolicy(raw, { source = null } = {}) {
  const errors = [];
  // Which keys the file actually wrote, so a merge can tell "left at its
  // default" from "set to something looser".
  const explicit = new Set();
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, policy: { ...DEFAULTS }, errors: ['policy must be a JSON object'], explicit };
  }

  const policy = { ...DEFAULTS };
  for (const [key, value] of Object.entries(raw)) {
    if (key === '$schema' || key === 'comment') continue;
    if (!(key in DEFAULTS)) {
      // Loudly, on purpose: a policy with a typo that silently enforces nothing
      // is worse than no policy at all.
      errors.push(`unknown policy key "${key}"`);
      continue;
    }
    explicit.add(key);
    if (ORG_KEYS.has(key)) {
      const r = normalizeOrgKey(key, value, source);
      if (r.error) errors.push(r.error);
      else policy[key] = r.value;
      continue;
    }
    if (ENUMS[key]) {
      if (!ENUMS[key].includes(value)) {
        errors.push(`"${key}" must be one of ${ENUMS[key].join(' | ')} (got ${JSON.stringify(value)})`);
        continue;
      }
      policy[key] = value;
      continue;
    }
    if (key === 'licenses') {
      if (value === null) { policy.licenses = null; continue; }
      if (typeof value !== 'object' || Array.isArray(value)) { errors.push('"licenses" must be an object with "allow" and/or "deny" arrays'); continue; }
      const allow = value.allow ?? null;
      const deny  = value.deny ?? null;
      if (allow !== null && !Array.isArray(allow)) { errors.push('"licenses.allow" must be an array'); continue; }
      if (deny  !== null && !Array.isArray(deny))  { errors.push('"licenses.deny" must be an array'); continue; }
      policy.licenses = { allow: allow ? allow.map(String) : null, deny: deny ? deny.map(String) : null };
      continue;
    }
    if (key === 'maxEvidenceAgeDays') {
      if (value === null) { policy.maxEvidenceAgeDays = null; continue; }
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) { errors.push('"maxEvidenceAgeDays" must be a positive whole number of days'); continue; }
      policy.maxEvidenceAgeDays = n;
      continue;
    }
    if (key === 'maxContextTokens') {
      if (value === null) { policy.maxContextTokens = null; continue; }
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) { errors.push('"maxContextTokens" must be a positive whole number of tokens'); continue; }
      policy.maxContextTokens = n;
      continue;
    }
    if (key === 'maxContextPercent') {
      if (value === null) { policy.maxContextPercent = null; continue; }
      const n = Number(value);
      if (!Number.isFinite(n) || n <= 0 || n > 100) { errors.push('"maxContextPercent" must be a percentage between 0 and 100'); continue; }
      policy.maxContextPercent = n;
      continue;
    }
    if (key === 'minHealthScore') {
      if (value === null) { policy.minHealthScore = null; continue; }
      const n = Number(value);
      if (!Number.isFinite(n) || n < 0 || n > 100) { errors.push('"minHealthScore" must be a number between 0 and 100'); continue; }
      policy.minHealthScore = n;
      continue;
    }
    if (key === 'trust') {
      if (value === null) { policy.trust = null; continue; }
      if (!Array.isArray(value)) { errors.push('"trust" must be an array of acceptable trust tiers'); continue; }
      policy.trust = value.map(String);
      continue;
    }
    if (key === 'deep' || key === 'deps') {
      if (typeof value !== 'boolean') { errors.push(`"${key}" must be true or false`); continue; }
      policy[key] = value;
      continue;
    }
  }

  finishOrg(policy, raw, errors);
  if (policy.default !== DEFAULTS.default) explicit.add('default');

  return { ok: errors.length === 0, policy, errors, explicit };
}

function readLayer(file) {
  let raw;
  try { raw = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return { ok: false, raw: null, policy: null, explicit: new Set(), errors: [`could not read ${file}: ${e.message}`] }; }
  const n = normalizePolicy(raw, { source: file });
  return { ok: n.ok, raw, policy: n.policy, explicit: n.explicit, errors: n.errors };
}

/**
 * The policy in force for `startDir`: the nearest local file, over any org
 * policy it sits on.
 *
 * An org policy comes from `extends` in the local file (resolved against that
 * file's directory) and/or from `MCP_VAULT_ORG_POLICY`. One that is named and
 * cannot be read makes the whole policy invalid: an org bar that silently
 * failed to load would be enforced by nobody.
 */
function loadPolicy(startDir = process.cwd(), { env = process.env } = {}) {
  const file = findPolicyFile(startDir);
  const envOrg = env && env.MCP_VAULT_ORG_POLICY ? path.resolve(env.MCP_VAULT_ORG_POLICY) : null;
  if (!file && !envOrg) return { ok: true, policy: { ...DEFAULTS }, path: null, errors: [], found: false, sources: [] };

  let local = null;
  if (file) {
    local = readLayer(file);
    // As before org layers existed: a local file that does not parse is
    // reported as that file's problem, and nothing else is read.
    if (!local.raw) return { ok: false, policy: { ...DEFAULTS }, path: file, errors: local.errors, found: true, sources: [{ path: file, role: 'local' }] };
  }

  const orgFiles = [];
  if (envOrg) orgFiles.push(envOrg);
  if (local && local.policy.extends) {
    const ext = path.resolve(path.dirname(file), local.policy.extends);
    if (!orgFiles.includes(ext)) orgFiles.push(ext);
  }
  // The env var pointing at the project's own file is one layer, not two.
  if (file && orgFiles.includes(path.resolve(file))) orgFiles.splice(orgFiles.indexOf(path.resolve(file)), 1);

  const errors = [];
  const sources = [];
  let merged = null;
  let mergedFrom = null;
  const mergedExplicit = new Set();
  for (const org of orgFiles) {
    const layer = readLayer(org);
    sources.push({ path: org, role: 'org' });
    errors.push(...layer.errors.map((e) => (e.startsWith('could not read') ? e : `${org}: ${e}`)));
    if (!layer.policy) continue;
    if (layer.raw && layer.raw.extends) {
      errors.push(`${org}: an org policy cannot itself use "extends" — one layer of inheritance keeps the bar in one place`);
    }
    if (!merged) {
      merged = layer.policy;
      mergedFrom = org;
    } else {
      const m = mergeStricter(merged, layer.policy, layer.explicit, { baseSource: mergedFrom, baseExplicit: mergedExplicit });
      merged = m.policy;
      errors.push(...m.conflicts.map((c) => `${org}: ${c}`));
    }
    for (const k of layer.explicit) mergedExplicit.add(k);
  }

  if (local) {
    sources.push({ path: file, role: 'local' });
    errors.push(...local.errors);
    if (!merged) {
      merged = local.policy;
    } else {
      const m = mergeStricter(merged, local.policy, local.explicit, { baseSource: mergedFrom, baseExplicit: mergedExplicit });
      merged = m.policy;
      errors.push(...m.conflicts.map((c) => `${file}: ${c}`));
    }
  }

  const policy = { ...(merged || DEFAULTS), extends: local ? local.policy.extends : null };
  return { ok: errors.length === 0, policy, path: file || orgFiles[0], errors, found: true, sources };
}

/**
 * The CLI flags a policy implies, so `verify` can be driven by one without
 * every call site learning the mapping.
 */
function policyToFlags(policy = DEFAULTS) {
  const flags = [];
  if (policy.unverified === 'fail')            flags.push('--fail-unverified');
  if (policy.signatures === 'require')         flags.push('--require-signatures');
  if (policy.provenance === 'require')         flags.push('--require-provenance');
  if (policy.dependencyAdvisories === 'fail')  flags.push('--fail-dep-advisories');
  if (policy.deep)                             flags.push('--deep');
  if (policy.deps || policy.dependencyHooks === 'fail' || policy.dependencyAdvisories !== 'allow') {
    // Dependency rules cannot be judged without the tree.
    if (policy.deps) flags.push('--deps');
  }
  return flags;
}

/**
 * Judge one report entry (from `verify --json`) against a policy.
 *
 * Returns findings the *policy* adds, on top of what the gate already said —
 * license and trust rules, plus the "allow" downgrades the gate has no opinion
 * about. Each has a level of 'fail' or 'warn'.
 *
 * The rules themselves live in lib/policy_rules.cjs, which is what `decide()`
 * runs; this is the legacy view of the same rows, kept so that nothing that
 * called it has to change and so that the two cannot disagree.
 */
function evaluateEntry(entry, policy = DEFAULTS, dbEntry = null) {
  // Required lazily: lib/policy_rules.cjs loads this module the same way.
  const { entryRuleOutcomes } = require('./policy_rules.cjs');
  const { modelForLine } = require('./legacy_tags.cjs');
  const source = dbEntry || entry || {};
  const findings = ((entry && entry.findings) || [])
    .map((f) => modelForLine([f.tag, f.message]))
    .filter(Boolean)
    .map((m, i) => ({ id: `legacy:${i}`, rule: m.rule, state: m.state, severity: m.severity }));
  const ctx = {
    findings,
    policy: { ...DEFAULTS, ...(policy || {}) },
    facts: {
      entry: {
        install_cmd:  (entry && entry.install_cmd) || source.install_cmd || '',
        license:      source.license,
        health_score: source.health_score,
        trust:        source.trust,
      },
      legacy_status: entry && entry.status,
    },
    mode: 'gate',
  };
  return entryRuleOutcomes(ctx)
    .filter((o) => o.effect === 'deny' || o.effect === 'warn')
    .map((o) => ({ level: o.effect === 'deny' ? 'fail' : 'warn', rule: o.rule, message: o.detail }));
}

module.exports = {
  DEFAULTS, POLICY_FILENAMES,
  findPolicyFile, loadPolicy, normalizePolicy, policyToFlags, evaluateEntry,
};
