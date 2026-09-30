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
 *     "trust": ["verified"],           // acceptable trust tiers
 *     "deep": true,                    // hash artifacts locally
 *     "deps": true                     // resolve and check dependency trees
 *   }
 *
 * Every key is optional. An unknown key is an error rather than a silent
 * no-op: a typo in a policy that then quietly does nothing is worse than no
 * policy, because it reads as a bar that is being enforced.
 *
 * API:
 *   findPolicyFile(startDir)      -> path | null
 *   loadPolicy(startDir)          -> { ok, policy, path, errors }
 *   normalizePolicy(raw)          -> { ok, policy, errors }
 *   policyToFlags(policy)         -> ["--fail-unverified", …]
 *   evaluateEntry(entry, policy)  -> [{ level, rule, message }]
 */

const fs   = require('fs');
const path = require('path');

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
  trust:                null,
  deep:                 false,
  deps:                 false,
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

function normalizePolicy(raw) {
  const errors = [];
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, policy: { ...DEFAULTS }, errors: ['policy must be a JSON object'] };
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

  return { ok: errors.length === 0, policy, errors };
}

function loadPolicy(startDir = process.cwd()) {
  const file = findPolicyFile(startDir);
  if (!file) return { ok: true, policy: { ...DEFAULTS }, path: null, errors: [], found: false };
  let raw;
  try { raw = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) {
    return { ok: false, policy: { ...DEFAULTS }, path: file, errors: [`could not read ${file}: ${e.message}`], found: true };
  }
  const { ok, policy, errors } = normalizePolicy(raw);
  return { ok, policy, path: file, errors, found: true };
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
