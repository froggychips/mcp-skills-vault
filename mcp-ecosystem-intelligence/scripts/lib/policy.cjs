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
 */
function evaluateEntry(entry, policy = DEFAULTS, dbEntry = null) {
  const out = [];
  const tags = new Set((entry.findings || []).map((f) => f.tag));
  const add = (level, rule, message) => out.push({ level, rule, message });

  if (policy.installHooks === 'fail' && tags.has('HOOK')) {
    add('fail', 'policy/install-hooks', 'package runs install-time scripts, which this policy does not allow');
  }
  if (policy.dependencyHooks === 'fail' && tags.has('DEPHOOK')) {
    add('fail', 'policy/dependency-hooks', 'a dependency runs install-time scripts, which this policy does not allow');
  }
  if (policy.dependencyAdvisories === 'fail' && tags.has('DEPCVE')) {
    add('fail', 'policy/dependency-advisories', 'an advisory affects a package in the dependency tree');
  }
  if (policy.signatures === 'require' && !tags.has('SIG') && (entry.install_cmd || '').startsWith('npx')) {
    add('fail', 'policy/signatures', 'no verifiable registry signature');
  }
  if (policy.provenance === 'require' && !tags.has('PROV') && (entry.install_cmd || '').startsWith('npx')) {
    add('fail', 'policy/provenance', 'no provenance attestation');
  }
  if (policy.docker === 'digest' && /^docker\s+run/.test(entry.install_cmd || '') && tags.has('DIGEST')) {
    add('fail', 'policy/docker-digest', 'container image is not pinned by digest');
  }
  if (policy.unverified === 'fail' && entry.status === 'UNVERIFIED') {
    add('fail', 'policy/unverified', 'nothing about this entry could be verified');
  }

  const source = dbEntry || entry;
  if (policy.licenses) {
    const license = source.license || null;
    if (!license) {
      add('warn', 'policy/license', 'no license recorded for this entry');
    } else {
      if (policy.licenses.deny && policy.licenses.deny.includes(license)) {
        add('fail', 'policy/license', `license ${license} is on this policy's deny list`);
      } else if (policy.licenses.allow && !policy.licenses.allow.includes(license)) {
        add('fail', 'policy/license', `license ${license} is not on this policy's allow list`);
      }
    }
  }
  if (policy.minHealthScore !== null) {
    const score = Number(source.health_score);
    if (!Number.isFinite(score)) add('warn', 'policy/health', 'no health score recorded for this entry');
    else if (score < policy.minHealthScore) {
      add('fail', 'policy/health', `health score ${score} is below the policy minimum of ${policy.minHealthScore}`);
    }
  }
  if (policy.trust) {
    const trust = source.trust || null;
    if (!trust || !policy.trust.includes(trust)) {
      add('fail', 'policy/trust', `trust tier ${trust || '(none)'} is not accepted by this policy (accepts: ${policy.trust.join(', ')})`);
    }
  }

  return out;
}

module.exports = {
  DEFAULTS, POLICY_FILENAMES,
  findPolicyFile, loadPolicy, normalizePolicy, policyToFlags, evaluateEntry,
};
