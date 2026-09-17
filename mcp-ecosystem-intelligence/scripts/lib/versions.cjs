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
 *   (a/b/rc), post-releases and dev-releases, in the documented order, with
 *   local versions ignored as the spec allows for ordering. Combinations are
 *   ordered by the spec's own key (a dev release of a post release precedes
 *   it, a post release of a pre-release follows it). Not supported: arbitrary
 *   equality, and normalisation beyond `alpha`→`a` and `-`/`_` separators —
 *   anything else is refused.
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

/**
 * Compare two strings of digits as numbers, without becoming numbers.
 *
 * `Number('9007199254740993')` is 9007199254740992, so two different versions
 * compared equal and `maxVersion` could keep the lower one. Length first, then
 * lexicographically, which is exact for arbitrary digit strings.
 */
function compareDigits(a, b) {
  const x = String(a).replace(/^0+(?=\d)/, '');
  const y = String(b).replace(/^0+(?=\d)/, '');
  if (x.length !== y.length) return x.length < y.length ? -1 : 1;
  return x === y ? 0 : (x < y ? -1 : 1);
}

// A pre-release identifier is alphanumeric-with-hyphens, and a *numeric* one
// may not carry a leading zero (semver §9). An empty identifier (`1.0.0-a..b`)
// is not valid either. Both used to be ordered anyway, against the module's own
// contract that anything it does not fully understand returns null.
function validPreIdentifiers(ids) {
  return ids.every((id) => id.length > 0
    && /^[0-9A-Za-z-]+$/.test(id)
    && !(/^\d+$/.test(id) && id.length > 1 && id.startsWith('0')));
}

function parseSemver(v) {
  const m = SEMVER_RE.exec(String(v || '').trim());
  if (!m) return null;
  const pre = m[4] ? m[4].split('.') : [];
  if (pre.length && !validPreIdentifiers(pre)) return null;
  return {
    core: [m[1], m[2], m[3]],
    pre,
  };
}

/** semver 2.0.0 §11. */
function compareSemver(a, b) {
  const x = parseSemver(a);
  const y = parseSemver(b);
  if (!x || !y) return null;

  for (let i = 0; i < 3; i++) {
    const c = compareDigits(x.core[i], y.core[i]);
    if (c !== 0) return c;
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
      const d = compareDigits(p, q);
      if (d !== 0) return d;
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
    epoch:   m[1] || '0',
    release: m[2].split('.'),
    pre:     m[3] ? [PRE_ORDER[m[3]] ?? 2, m[4] || '0'] : null,
    post:    m[5] ? (m[6] || '0') : null,
    dev:     m[7] ? (m[8] || '0') : null,
  };
}

/**
 * PEP 440 §"Summary of permitted suffixes and relative ordering".
 *
 * The first version of this reduced a version to a single rank — dev, pre,
 * final, post — and compared only the field that rank named, so every
 * *combination* ordered wrongly:
 *
 *   1.0.post1.dev2 == 1.0.post1   (it precedes it: a dev release of the post)
 *   1.0a1.post1    == 1.0a1       (it follows it)
 *   1.0a1.post1.dev2 < 1.0a1      (reversed)
 *
 * and `maxVersion(['1.0a1', '1.0a1.post1'])` could pick the lower one — which
 * in an upgrade plan means recommending a version below the advisory's fix.
 *
 * The spec's ordering is a tuple compared field by field, with three rules
 * about *absent* segments that are the whole subtlety (and match CPython's
 * `packaging._cmpkey`):
 *
 *   - a version with a dev segment and no pre and no post sorts before every
 *     pre-release of the same release: `1.0.dev1 < 1.0a1`. That is the case the
 *     rewrite lost and this comment exists for.
 *   - otherwise, no pre-release sorts *after* any pre-release: `1.0a1 < 1.0`.
 *   - no post sorts before any post; no dev sorts after any dev.
 *
 * Those "absent" positions are represented as explicit low/high sentinels
 * rather than as numbers, so there is no value a version string could contain
 * that collides with them.
 */
const LOW  = { sentinel: -1 };
const HIGH = { sentinel: 1 };

function pep440Key(p) {
  const pre = (p.pre === null && p.post === null && p.dev !== null) ? LOW
    : (p.pre === null ? HIGH : p.pre);
  return {
    epoch:   p.epoch,
    release: p.release,
    pre,
    post:    p.post === null ? LOW : p.post,
    dev:     p.dev === null ? HIGH : p.dev,
  };
}

/** Compare two key fields, either of which may be a sentinel. */
function compareField(a, b) {
  const aS = a && a.sentinel !== undefined;
  const bS = b && b.sentinel !== undefined;
  if (aS && bS) return a.sentinel === b.sentinel ? 0 : (a.sentinel < b.sentinel ? -1 : 1);
  if (aS) return a.sentinel < 0 ? -1 : 1;
  if (bS) return b.sentinel < 0 ? 1 : -1;
  if (Array.isArray(a) && Array.isArray(b)) {
    // [pre-release letter rank, number]
    if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
    return compareDigits(a[1], b[1]);
  }
  return compareDigits(a, b);
}

function comparePep440(a, b) {
  const x = parsePep440(a);
  const y = parsePep440(b);
  if (!x || !y) return null;

  const kx = pep440Key(x);
  const ky = pep440Key(y);

  const epoch = compareDigits(kx.epoch, ky.epoch);
  if (epoch !== 0) return epoch;

  const n = Math.max(kx.release.length, ky.release.length);
  for (let i = 0; i < n; i++) {
    const c = compareDigits(kx.release[i] || '0', ky.release[i] || '0');
    if (c !== 0) return c;
  }

  for (const field of ['pre', 'post', 'dev']) {
    const c = compareField(kx[field], ky[field]);
    if (c !== 0) return c;
  }
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
