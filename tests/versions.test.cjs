'use strict';
/**
 * Version ordering.
 *
 * This exists because "which version fixes this" is an ordering question and
 * string comparison answers it wrongly in exactly the case that matters:
 * `"2.1.9" > "2.1.10"` lexically, so an upgrade plan built on string compare
 * recommends a version that is still affected.
 *
 * The other property under test is abstention. Both comparators return null for
 * anything they do not fully understand, and callers treat null as "cannot
 * compute" rather than as equal-or-lower. A comparator that guesses produces a
 * confident recommendation onto a vulnerable release.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const v = require('../mcp-ecosystem-intelligence/scripts/lib/versions.cjs');

test('semver: numeric fields compare as numbers, not as text', () => {
  assert.equal(v.compareSemver('2.1.9', '2.1.10'), -1, 'the case that breaks string comparison');
  assert.equal(v.compareSemver('2.0.0', '10.0.0'), -1);
  assert.equal(v.compareSemver('1.2.3', '1.2.3'), 0);
  assert.equal(v.compareSemver('1.10.0', '1.9.0'), 1);
});

test('semver: the precedence chain from the spec, §11', () => {
  // 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2
  //   < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0
  const chain = [
    '1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta',
    '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0',
  ];
  for (let i = 0; i < chain.length - 1; i++) {
    assert.equal(v.compareSemver(chain[i], chain[i + 1]), -1, `${chain[i]} should precede ${chain[i + 1]}`);
    assert.equal(v.compareSemver(chain[i + 1], chain[i]), 1);
  }
});

test('semver: build metadata is ignored, as the spec requires', () => {
  assert.equal(v.compareSemver('1.0.0+build.1', '1.0.0'), 0);
  assert.equal(v.compareSemver('1.0.0+a', '1.0.0+b'), 0);
  assert.equal(v.compareSemver('v1.0.0', '1.0.0'), 0, 'a leading v is common in tags');
});

test('versions too large for a JS number are still ordered exactly', () => {
  // `Number('9007199254740993')` is 9007199254740992, so two different
  // versions compared *equal* and maxVersion could keep the lower one.
  assert.equal(v.compareSemver('9007199254740992.0.0', '9007199254740993.0.0'), -1);
  assert.equal(v.compareSemver('1.0.0-9007199254740993', '1.0.0-9007199254740992'), 1);
  assert.equal(v.comparePep440('9007199254740993.0', '9007199254740992.0'), 1);
  assert.equal(v.maxVersion(['9007199254740992.0.0', '9007199254740993.0.0'], v.compareSemver), '9007199254740993.0.0');
});

test('semver: an invalid pre-release identifier is refused, not ordered', () => {
  // semver §9: a numeric identifier may not carry a leading zero, and an
  // empty identifier is not an identifier. Both used to receive a confident
  // ordering, against this module's own contract.
  assert.equal(v.compareSemver('1.0.0-01', '1.0.0-1'), null);
  assert.equal(v.compareSemver('1.0.0-a..b', '1.0.0-a'), null);
  assert.equal(v.compareSemver('1.0.0-', '1.0.0'), null);
  // A non-numeric identifier that merely starts with a zero is fine — and by
  // §11 an alphanumeric identifier outranks a numeric one, so it sorts above
  // `-1` rather than below it.
  assert.equal(v.compareSemver('1.0.0-0alpha', '1.0.0-1'), 1);
  assert.equal(v.compareSemver('1.0.0-0', '1.0.0-1'), -1, 'a bare zero is a valid numeric identifier');
});

test('semver: a partial or non-version string is refused, not ranked', () => {
  // `1.2` and `1.x` are ranges wearing a version's clothes, and "latest" is not
  // a version at all. Ranking them would produce a plan.
  for (const bad of ['1.2', '1', '1.x', '^1.2.3', 'latest', '', null, undefined, 'next']) {
    assert.equal(v.compareSemver(bad, '1.0.0'), null, `${JSON.stringify(bad)} must not be ordered`);
    assert.equal(v.compareSemver('1.0.0', bad), null);
  }
});

test('pep440: release segments of different length compare field by field', () => {
  assert.equal(v.comparePep440('1.0', '1.0.0'), 0);
  assert.equal(v.comparePep440('0.21.1', '0.21.10'), -1);
  assert.equal(v.comparePep440('1.0.0', '1.0.1'), -1);
});

test('pep440: the canonical ordering example from the spec, in full', () => {
  // Straight out of PEP 440. Every *combination* of suffixes used to order
  // wrongly, because the first implementation reduced a version to one rank
  // (dev / pre / final / post) and then compared only that field:
  //   1.0.post1.dev2 == 1.0.post1, 1.0a1.post1 == 1.0a1, and
  //   1.0a1.post1.dev2 < 1.0a1 — reversed.
  const chain = [
    '1.0.dev456', '1.0a1', '1.0a2.dev456', '1.0a12.dev456', '1.0a12',
    '1.0b1.dev456', '1.0b2', '1.0b2.post345.dev456', '1.0b2.post345',
    '1.0rc1.dev456', '1.0rc1', '1.0', '1.0.post456.dev34', '1.0.post456', '1.1.dev1',
  ];
  for (let i = 0; i < chain.length - 1; i++) {
    assert.equal(v.comparePep440(chain[i], chain[i + 1]), -1, `${chain[i]} should precede ${chain[i + 1]}`);
    assert.equal(v.comparePep440(chain[i + 1], chain[i]), 1, `and the reverse`);
  }
});

test('pep440: a dev release with no pre and no post precedes every pre-release', () => {
  // The subtle rule, and the one a rewrite lost: `1.0.dev1` is a development
  // release *of 1.0*, so it sorts below 1.0a1 rather than next to 1.0.
  assert.equal(v.comparePep440('1.0.dev1', '1.0a1'), -1);
  assert.equal(v.comparePep440('1.0.dev1', '1.0rc9'), -1);
  // But a dev release *of a pre-release* stays with its pre-release.
  assert.equal(v.comparePep440('1.0a1.dev1', '1.0a1'), -1);
  assert.equal(v.comparePep440('1.0a1.dev1', '1.0.dev1'), 1);
});

test('pep440: maxVersion cannot pick the lower of a suffix pair', () => {
  assert.equal(v.maxVersion(['1.0a1', '1.0a1.post1'], v.comparePep440), '1.0a1.post1');
  assert.equal(v.maxVersion(['1.0.post1', '1.0.post1.dev2'], v.comparePep440), '1.0.post1');
  assert.equal(v.maxVersion(['1.0.dev9', '1.0a1'], v.comparePep440), '1.0a1');
});

test('pep440: an epoch outranks the release segment', () => {
  assert.equal(v.comparePep440('1!1.0', '2.0'), 1, 'an epoch bump is a deliberate reset of the numbering');
  assert.equal(v.comparePep440('1.0', '1!0.1'), -1);
});

test('pep440: a local version does not change ordering', () => {
  assert.equal(v.comparePep440('1.0+ubuntu1', '1.0'), 0);
});

test('pep440: separators and long spellings normalise', () => {
  assert.equal(v.comparePep440('1.0-alpha1', '1.0a1'), 0);
  assert.equal(v.comparePep440('1.0_beta2', '1.0b2'), 0);
  assert.equal(v.comparePep440('1.0.rc1', '1.0rc1'), 0);
});

test('pep440: anything unrecognised is refused', () => {
  for (const bad of ['not-a-version', '', null, '>=1.0']) {
    assert.equal(v.comparePep440(bad, '1.0'), null);
  }
});

test('maxVersion: picks the largest, and abstains if anything is unorderable', () => {
  assert.equal(v.maxVersion(['2.1.27', '2.1.30', '2.1.27'], v.compareSemver), '2.1.30');
  assert.equal(v.maxVersion(['1.0.0'], v.compareSemver), '1.0.0');
  assert.equal(v.maxVersion([], v.compareSemver), null);
  // One unparsable member means the answer is unknown, not "the best of the
  // rest": the caller is asking which version is safe.
  assert.equal(v.maxVersion(['1.0.0', 'garbage'], v.compareSemver), null);
});

test('isPrerelease: a pre-release is not an upgrade target by default', () => {
  assert.equal(v.isPrerelease('1.0.0-rc.1'), true);
  assert.equal(v.isPrerelease('1.0.0'), false);
  assert.equal(v.isPrerelease('1.0rc1', 'pypi'), true);
  assert.equal(v.isPrerelease('1.0.dev3', 'pypi'), true);
  assert.equal(v.isPrerelease('1.0', 'pypi'), false);
  assert.equal(v.isPrerelease('nonsense'), false, 'unparsable is not a pre-release claim either');
});

test('comparatorFor: only the ecosystems with an ordering we implement', () => {
  assert.equal(v.comparatorFor('npm'), v.compareSemver);
  assert.equal(v.comparatorFor('pypi'), v.comparePep440);
  assert.equal(v.comparatorFor('PyPI'), v.comparePep440);
  assert.equal(v.comparatorFor('oci'), null, 'an image digest has no ordering');
  assert.equal(v.comparatorFor('git'), null);
});
