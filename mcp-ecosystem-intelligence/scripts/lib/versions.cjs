'use strict';
/**
 * Version comparison for npm (semver 2.0.0) and PyPI (a subset of PEP 440).
 *
 * Needed because "which version fixes this" is an ordering question: OSV gives
 * a `fixed` version per advisory, and the answer is the *largest* of them that
 * the registry actually published. String comparison gets that wrong in the
 * way that matters — `"2.1.9" > "2.1.10"` lexically, so a plan built on it
 * would recommend a version that is still vulnerable.
 *
 * Zero dependencies is a constraint of this repo, so this is written out. What
 * it does and does not do is stated rather than implied:
 *
 * npm — semver 2.0.0 §11, complete for the release and pre-release fields:
 *   numeric core compared field by field; a pre-release sorts *before* its
 *   release; pre-release identifiers compared one by one, numeric numerically,
 *   numeric below alphanumeric, and a longer identifier list wins when every
 *   preceding one is equal. Build metadata (`+sha`) is ignored, as the spec
 *   requires.
 *
 * PyPI — a *subset* of PEP 440: epoch, release segment, one pre-release marker
 *   (a/b/rc), post-releases and dev-releases, with local versions ignored.
 *   Not supported: `.postN.devM` combinations in unusual orders, arbitrary
 *   equality, and the full normalisation rules (`alpha` → `a`, `-`/`_`
 *   separators are handled; anything else is refused).
 *
 * Both return `null` for a string they do not fully understand, and every
 * caller treats null as "cannot compute", never as "equal" or "lower". A
 * comparator that guesses is worse than one that abstains: the output here is
 * an upgrade recommendation, and a wrong one moves someone onto a version that
 * is still affected.
 *
 * API:
 *   compareSemver(a, b)        -> -1 | 0 | 1 | null
 *   comparePep440(a, b)        -> -1 | 0 | 1 | null
 *   comparatorFor(ecosystem)   -> function | null
 *   maxVersion(list, compare)  -> string | null
 *   isPrerelease(v, ecosystem) -> boolean
 */

const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseSemver(v) {
  const m = SEMVER_RE.exec(String(v || '').trim());
  if (!m) return null;
  return {
    core: [Number(m[1]), Number(m[2]), Number(m[3])],
    pre:  m[4] ? m[4].split('.') : [],
  };
}

/** semver 2.0.0 §11. */
function compareSemver(a, b) {
  const x = parseSemver(a);
  const y = parseSemver(b);
  if (!x || !y) return null;

  for (let i = 0; i < 3; i++) {
    if (x.core[i] !== y.core[i]) return x.core[i] < y.core[i] ? -1 : 1;
  }
  // "1.0.0-rc.1" precedes "1.0.0"; having no pre-release is the higher version.
  if (!x.pre.length && !y.pre.length) return 0;
  if (!x.pre.length) return 1;
  if (!y.pre.length) return -1;

  const n = Math.max(x.pre.length, y.pre.length);
  for (let i = 0; i < n; i++) {
    const p = x.pre[i];
    const q = y.pre[i];
    // A shorter set of identifiers sorts lower when all preceding are equal.
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pNum = /^\d+$/.test(p);
    const qNum = /^\d+$/.test(q);
    if (pNum && qNum) {
      const d = Number(p) - Number(q);
      if (d !== 0) return d < 0 ? -1 : 1;
      continue;
    }
    // Numeric identifiers always have lower precedence than alphanumeric ones.
    if (pNum !== qNum) return pNum ? -1 : 1;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

// epoch!release[pre][post][dev][+local] — the shapes actually published on PyPI.
const PEP440_RE = /^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?(?:[-_.]?(post|rev|r)[-_.]?(\d+)?)?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+[0-9A-Za-z.]+)?$/i;

const PRE_ORDER = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

function parsePep440(v) {
  const m = PEP440_RE.exec(String(v || '').trim().toLowerCase());
  if (!m) return null;
  return {
    epoch:   Number(m[1] || 0),
    release: m[2].split('.').map(Number),
    // Ordering within a release: dev < pre < (nothing) < post. Encoded as a
    // rank so the comparison below stays a plain lexicographic walk.
    pre:     m[3] ? [PRE_ORDER[m[3]] ?? 2, Number(m[4] || 0)] : null,
    post:    m[5] ? Number(m[6] || 0) : null,
    dev:     m[7] ? Number(m[8] || 0) : null,
  };
}

function comparePep440(a, b) {
  const x = parsePep440(a);
  const y = parsePep440(b);
  if (!x || !y) return null;
  if (x.epoch !== y.epoch) return x.epoch < y.epoch ? -1 : 1;

  const n = Math.max(x.release.length, y.release.length);
  for (let i = 0; i < n; i++) {
    const p = x.release[i] || 0;
    const q = y.release[i] || 0;
    if (p !== q) return p < q ? -1 : 1;
  }

  // Within one release: .devN < aN < bN < rcN < (final) < .postN
  const rank = (z) => {
    if (z.dev !== null && z.pre === null && z.post === null) return -2;
    if (z.pre !== null) return -1;
    if (z.post !== null) return 1;
    return 0;
  };
  const rx = rank(x);
  const ry = rank(y);
  if (rx !== ry) return rx < ry ? -1 : 1;

  if (rx === -1) {
    if (x.pre[0] !== y.pre[0]) return x.pre[0] < y.pre[0] ? -1 : 1;
    if (x.pre[1] !== y.pre[1]) return x.pre[1] < y.pre[1] ? -1 : 1;
    // A pre-release with a dev suffix precedes the same pre-release.
    const dx = x.dev === null ? 1 : 0;
    const dy = y.dev === null ? 1 : 0;
    if (dx !== dy) return dx < dy ? -1 : 1;
    if (x.dev !== null && y.dev !== null && x.dev !== y.dev) return x.dev < y.dev ? -1 : 1;
    return 0;
  }
  if (rx === 1 && x.post !== y.post) return x.post < y.post ? -1 : 1;
  if (rx === -2 && x.dev !== y.dev) return x.dev < y.dev ? -1 : 1;
  return 0;
}

function comparatorFor(ecosystem) {
  if (ecosystem === 'npm') return compareSemver;
  if (ecosystem === 'pypi' || ecosystem === 'PyPI') return comparePep440;
  return null;
}

/** The largest version in a list, or null if any comparison is undecidable. */
function maxVersion(list, compare) {
  let best = null;
  for (const v of list || []) {
    if (best === null) { best = v; continue; }
    const c = compare(v, best);
    // An undecidable comparison must not silently keep the current best: the
    // caller is asking which version is safe.
    if (c === null) return null;
    if (c > 0) best = v;
  }
  return best;
}

function isPrerelease(v, ecosystem = 'npm') {
  if (ecosystem === 'npm') {
    const p = parseSemver(v);
    return Boolean(p && p.pre.length);
  }
  const p = parsePep440(v);
  return Boolean(p && (p.pre !== null || p.dev !== null));
}

module.exports = {
  compareSemver, comparePep440, comparatorFor, maxVersion, isPrerelease,
  parseSemver, parsePep440,
};
