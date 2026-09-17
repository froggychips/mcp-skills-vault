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

test('pep440: dev < pre < final < post, within one release', () => {
  const chain = ['1.0.dev1', '1.0a1', '1.0a2', '1.0b1', '1.0rc1', '1.0', '1.0.post1', '1.0.post2'];
  for (let i = 0; i < chain.length - 1; i++) {
    assert.equal(v.comparePep440(chain[i], chain[i + 1]), -1, `${chain[i]} should precede ${chain[i + 1]}`);
  }
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
