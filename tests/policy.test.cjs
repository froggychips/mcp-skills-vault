'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

const pol = require('../mcp-ecosystem-intelligence/scripts/lib/policy.cjs');

test('normalizePolicy: fills defaults, keeps valid values', () => {
  const { ok, policy, errors } = pol.normalizePolicy({
    $schema: 'mcp-vault/policy@1',
    unverified: 'fail',
    signatures: 'require',
    deps: true,
    minHealthScore: 70,
    trust: ['verified'],
    licenses: { allow: ['MIT'], deny: ['BUSL-1.1'] },
  });
  assert.equal(ok, true);
  assert.deepEqual(errors, []);
  assert.equal(policy.unverified, 'fail');
  assert.equal(policy.signatures, 'require');
  assert.equal(policy.deps, true);
  assert.equal(policy.minHealthScore, 70);
  assert.deepEqual(policy.trust, ['verified']);
  assert.deepEqual(policy.licenses, { allow: ['MIT'], deny: ['BUSL-1.1'] });
  // Untouched keys keep their defaults.
  assert.equal(policy.installHooks, 'warn');
  assert.equal(policy.docker, 'digest');
});

test('normalizePolicy: an unknown key is an error, not a no-op', () => {
  // A typo that silently enforces nothing is worse than no policy, because it
  // reads as a bar that is being enforced.
  const { ok, errors } = pol.normalizePolicy({ unverfied: 'fail' });
  assert.equal(ok, false);
  assert.match(errors[0], /unknown policy key "unverfied"/);
});

test('normalizePolicy: rejects out-of-range and wrong-typed values', () => {
  const cases = [
    [{ unverified: 'maybe' }, /must be one of fail \| warn/],
    [{ signatures: 'nice-to-have' }, /require \| prefer/],
    [{ docker: 'whatever' }, /digest \| tag/],
    [{ minHealthScore: 150 }, /between 0 and 100/],
    [{ minHealthScore: 'high' }, /between 0 and 100/],
    [{ trust: 'verified' }, /must be an array/],
    [{ licenses: ['MIT'] }, /must be an object/],
    [{ licenses: { allow: 'MIT' } }, /allow" must be an array/],
    [{ deps: 'yes' }, /must be true or false/],
  ];
  for (const [input, pattern] of cases) {
    const { ok, errors } = pol.normalizePolicy(input);
    assert.equal(ok, false, JSON.stringify(input));
    assert.match(errors.join(' '), pattern, JSON.stringify(input));
  }
  assert.equal(pol.normalizePolicy(null).ok, false);
  assert.equal(pol.normalizePolicy([]).ok, false);
});

test('findPolicyFile / loadPolicy: nearest file at or above the directory', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-policy-'));
  const nested = path.join(root, 'a', 'b');
  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(path.join(root, '.mcp-vault.policy.json'), JSON.stringify({ unverified: 'fail' }));

  // A monorepo keeps one at the root; a subdirectory inherits it.
  assert.equal(pol.findPolicyFile(nested), path.join(root, '.mcp-vault.policy.json'));
  const loaded = pol.loadPolicy(nested);
  assert.equal(loaded.ok, true);
  assert.equal(loaded.found, true);
  assert.equal(loaded.policy.unverified, 'fail');

  // A nearer file wins.
  fs.writeFileSync(path.join(nested, '.mcp-vault.policy.json'), JSON.stringify({ unverified: 'warn' }));
  assert.equal(pol.loadPolicy(nested).policy.unverified, 'warn');
  fs.rmSync(root, { recursive: true, force: true });
});

test('loadPolicy: no file is fine; an unreadable file is not', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-policy-none-'));
  const none = pol.loadPolicy(path.join(dir, 'nowhere'));
  assert.equal(none.ok, true);
  assert.equal(none.found, false);
  assert.deepEqual(none.policy, pol.DEFAULTS);

  fs.writeFileSync(path.join(dir, '.mcp-vault.policy.json'), '{ not json');
  const broken = pol.loadPolicy(dir);
  assert.equal(broken.ok, false);
  assert.equal(broken.found, true);
  assert.match(broken.errors[0], /could not read/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('policyToFlags: maps a policy onto the flags verify understands', () => {
  assert.deepEqual(pol.policyToFlags(pol.DEFAULTS), []);
  assert.deepEqual(
    pol.policyToFlags({ ...pol.DEFAULTS, unverified: 'fail', signatures: 'require', provenance: 'require', deep: true, deps: true, dependencyAdvisories: 'fail' }).sort(),
    ['--deep', '--deps', '--fail-dep-advisories', '--fail-unverified', '--require-provenance', '--require-signatures'],
  );
});

const entryWith = (tags, extra = {}) => ({
  name: 'e', status: 'OK', install_cmd: 'npx -y e@1.0.0',
  findings: tags.map(tag => ({ tag, level: 'note', rule: 'x', message: 'm' })),
  ...extra,
});

test('evaluateEntry: hook and dependency rules', () => {
  const strictHooks = { ...pol.DEFAULTS, installHooks: 'fail', dependencyHooks: 'fail', dependencyAdvisories: 'fail' };
  const v = pol.evaluateEntry(entryWith(['HOOK', 'DEPHOOK', 'DEPCVE']), strictHooks);
  assert.deepEqual(v.map(x => x.rule).sort(), ['policy/dependency-advisories', 'policy/dependency-hooks', 'policy/install-hooks']);
  assert.ok(v.every(x => x.level === 'fail'));
  // Default policy warns rather than failing, so the same entry is clean.
  assert.deepEqual(pol.evaluateEntry(entryWith(['HOOK', 'DEPHOOK', 'DEPCVE']), pol.DEFAULTS), []);
});

test('evaluateEntry: signatures and provenance only apply to npm entries', () => {
  const require_ = { ...pol.DEFAULTS, signatures: 'require', provenance: 'require' };
  const bare = pol.evaluateEntry(entryWith([]), require_);
  assert.deepEqual(bare.map(x => x.rule).sort(), ['policy/provenance', 'policy/signatures']);
  // Present → nothing to say.
  assert.deepEqual(pol.evaluateEntry(entryWith(['SIG', 'PROV']), require_), []);
  // A docker entry has neither concept.
  const docker = pol.evaluateEntry(entryWith([], { install_cmd: 'docker run -i img@sha256:x' }), require_);
  assert.deepEqual(docker, []);
});

test('evaluateEntry: docker digest rule', () => {
  const entry = entryWith(['DIGEST'], { install_cmd: 'docker run -i img:latest' });
  assert.deepEqual(pol.evaluateEntry(entry, pol.DEFAULTS).map(x => x.rule), ['policy/docker-digest']);
  assert.deepEqual(pol.evaluateEntry(entry, { ...pol.DEFAULTS, docker: 'tag' }), []);
});

test('evaluateEntry: license allow and deny lists', () => {
  const deny  = { ...pol.DEFAULTS, licenses: { allow: null, deny: ['BUSL-1.1'] } };
  const allow = { ...pol.DEFAULTS, licenses: { allow: ['MIT'], deny: null } };
  assert.match(pol.evaluateEntry(entryWith([]), deny,  { license: 'BUSL-1.1' })[0].message, /deny list/);
  assert.deepEqual(pol.evaluateEntry(entryWith([]), deny,  { license: 'MIT' }), []);
  assert.match(pol.evaluateEntry(entryWith([]), allow, { license: 'GPL-3.0' })[0].message, /allow list/);
  assert.deepEqual(pol.evaluateEntry(entryWith([]), allow, { license: 'MIT' }), []);
  // No license recorded is a warning, not a pass and not a failure.
  const none = pol.evaluateEntry(entryWith([]), allow, { license: null });
  assert.equal(none[0].level, 'warn');
});

test('evaluateEntry: health floor and trust tiers', () => {
  const p = { ...pol.DEFAULTS, minHealthScore: 60, trust: ['verified'] };
  const low = pol.evaluateEntry(entryWith([]), p, { health_score: 40, trust: 'candidate' });
  assert.deepEqual(low.map(x => x.rule).sort(), ['policy/health', 'policy/trust']);
  assert.deepEqual(pol.evaluateEntry(entryWith([]), p, { health_score: 90, trust: 'verified' }), []);
  // Missing data warns instead of silently passing.
  assert.equal(pol.evaluateEntry(entryWith([]), p, { trust: 'verified' })[0].level, 'warn');
});

test('evaluateEntry: unverified upgrade', () => {
  const p = { ...pol.DEFAULTS, unverified: 'fail' };
  const e = entryWith([], { status: 'UNVERIFIED' });
  assert.deepEqual(pol.evaluateEntry(e, p).map(x => x.rule), ['policy/unverified']);
  assert.deepEqual(pol.evaluateEntry(e, pol.DEFAULTS), []);
});
