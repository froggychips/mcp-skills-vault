'use strict';
/**
 * OpenSSF Scorecard, as evidence about the upstream repository.
 *
 * Everything else in this repo asks about the *artifact*: are these the bytes
 * we verified, is the signature good, does anything know a CVE for this
 * version. Scorecard asks about the *process that produced it* — is the default
 * branch protected, is code reviewed, does the release workflow have dangerous
 * triggers, are the CI dependencies pinned, are releases signed. For a
 * supply-chain decision that is a different and useful axis: an artifact can be
 * perfectly verified and come out of a repository anybody can push to.
 *
 * Two deliberate departures from how Scorecard is usually consumed:
 *
 *   1. **The dimensions, not the score.** A single 0–10 number averages
 *      "there's a SECURITY.md" with "the release workflow can be triggered by
 *      a fork", and this repo's whole position is that averaging a gate with a
 *      nice-to-have is how a bad pin gets outvoted by stars. So the checks are
 *      recorded individually as found / absent / unknown, and a policy can ask
 *      about the one it cares about.
 *
 *   2. **`-1` is `unknown`, never `absent`.** Scorecard returns -1 for a check
 *      it could not run — no releases to inspect, no packaging workflow to
 *      find. Reading that as "not signed" would be the recurring bug in this
 *      repo: a check that did not happen presented as a check that failed.
 *
 * Coverage is the honest caveat. Scorecard only has reports for repositories
 * somebody ran it on: **4 of the 114 entries in this DB**, measured. For the
 * other 110 the answer is "no report" and nothing is recorded. That is still
 * worth running — those four are vendor repositories that plenty of people
 * install from — but it is not a check that covers this database.
 *
 * Source: deps.dev (api.deps.dev/v3alpha/projects/…), which embeds the latest
 * Scorecard report and does not need a token. api.securityscorecards.dev serves
 * the same data with narrower coverage.
 *
 * API:
 *   projectUrl(slug)                -> string
 *   fetchPosture(slug, opts)        -> { ok, posture, date, error? }
 *   mapChecks(scorecard)            -> { branch_protection: 'found', … }
 *   POSTURE_CHECKS                  -> the checks we map, and why each matters
 */

const { getJson } = require('./http.cjs');

// Scorecard check name → our field, with the reason it is worth recording.
// Only checks whose meaning survives being reduced to found/absent are here:
// "Binary-Artifacts" and "Fuzzing" are informative but not decidable this way.
const POSTURE_CHECKS = {
  'Branch-Protection':  { field: 'branch_protection',  good: 'found',  why: 'anyone who can push to the default branch can change what gets released' },
  'Code-Review':        { field: 'code_review',        good: 'found',  why: 'changes reviewed by someone other than the author' },
  'Dangerous-Workflow': { field: 'dangerous_workflows', good: 'absent', why: 'a workflow trigger a fork can reach is how a repository gets its own secrets stolen' },
  'Token-Permissions':  { field: 'token_permissions',  good: 'found',  why: 'CI jobs scoped to what they need, rather than write-all' },
  'Pinned-Dependencies': { field: 'actions_pinned',    good: 'found',  why: 'a mutable action tag is an unreviewed dependency in the release path' },
  'Signed-Releases':    { field: 'release_signing',    good: 'found',  why: 'releases signed at the point of publication' },
  'Security-Policy':    { field: 'security_policy',    good: 'found',  why: 'somewhere to report a vulnerability that is not a public issue' },
  Maintained:           { field: 'maintained',         good: 'found',  why: 'recent commits and issue activity' },
  SAST:                 { field: 'sast',               good: 'found',  why: 'static analysis in CI' },
};

// Scorecard scores are 0–10. 7 is the threshold Scorecard's own documentation
// uses for "this check substantially passes"; below that the check found real
// problems, which for our purposes is not a pass.
const PASS_AT = 7;

function projectUrl(slug) {
  return `https://api.deps.dev/v3alpha/projects/${encodeURIComponent(`github.com/${slug}`)}`;
}

/**
 * One Scorecard report → our per-check fields.
 *
 * The inversion for `Dangerous-Workflow` is the subtle one: Scorecard scores it
 * 10 when it found *no* dangerous workflow, so a high score means the thing is
 * absent. Recording it as "found" would invert the meaning of the field a
 * policy reads.
 */
function mapChecks(scorecard) {
  const out = {};
  const checks = (scorecard && scorecard.checks) || [];
  for (const check of checks) {
    const spec = POSTURE_CHECKS[check.name];
    if (!spec) continue;
    const score = Number(check.score);
    if (!Number.isFinite(score) || score < 0) {
      // -1: Scorecard could not run this check. Not a failure.
      out[spec.field] = 'unknown';
      continue;
    }
    const passed = score >= PASS_AT;
    // `good: 'absent'` means a passing check asserts the thing is *not* there.
    out[spec.field] = spec.good === 'absent'
      ? (passed ? 'absent' : 'found')
      : (passed ? 'found' : 'absent');
  }
  for (const spec of Object.values(POSTURE_CHECKS)) {
    if (!(spec.field in out)) out[spec.field] = 'unknown';
  }
  return out;
}

/** github.com/owner/repo (any URL form) → "owner/repo". */
function repoSlug(url) {
  // Anchored at the start of the string on purpose. An unanchored
// `github\.com[:/]+…` matched anywhere, so
// `https://evil.example/github.com/acme/server` produced the slug
// `acme/server` — an attacker-chosen URL in a DB entry could borrow another
// project's identity for every check that compares repositories.
  const m = String(url || '').match(/^(?:git\+)?(?:https?:\/\/|ssh:\/\/git@|git@)?(?:www\.)?github\.com[:/]+([^/]+)\/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$/i);
  return m ? `${m[1]}/${m[2]}` : null;
}

/**
 * The posture of one repository.
 *
 * `{ ok: true, posture: null }` means deps.dev answered and has no Scorecard
 * report for this repository — a real answer, and different from
 * `{ ok: false }`, which means we could not ask. Callers record neither as a
 * finding, but only the first is worth remembering.
 */
async function fetchPosture(slug, { get = getJson, cacheTtlMs = 24 * 60 * 60 * 1000 } = {}) {
  if (!slug) return { ok: false, error: 'no GitHub repository to look up', posture: null };
  const res = await get(projectUrl(slug), { cacheTtlMs, timeoutMs: 15000, retries: 1 });
  // A 404 is an answer: deps.dev has no project record for this repository, so
  // there is certainly no Scorecard report. Counting it as "unreachable" put 31
  // entries in the same bucket as a network failure and made the coverage
  // figure look like an outage.
  if (!res.ok && res.status === 404) {
    return { ok: true, posture: null, reason: 'deps.dev has no record of this repository' };
  }
  if (!res.ok) return { ok: false, error: res.error || `HTTP ${res.status}`, posture: null };

  const sc = res.data && res.data.scorecard;
  if (!sc) return { ok: true, posture: null, reason: 'no Scorecard report for this repository' };

  return {
    ok: true,
    posture: mapChecks(sc),
    date: sc.date ? String(sc.date).slice(0, 10) : null,
    overall: Number.isFinite(sc.overallScore) ? sc.overallScore : null,
    // Passed through for context, never used as a threshold: see the note about
    // averaging a gate with a nice-to-have.
    stars: Number.isFinite(res.data.starsCount) ? res.data.starsCount : null,
  };
}

/**
 * Turn per-check fields into one evidence status.
 *
 *   clean       nothing we map came back bad
 *   weak        at least one check found a real problem
 *   unknown     no report, or every check was inconclusive
 *
 * `weak` is not a blocking state anywhere: an unprotected branch upstream is a
 * reason to look closer, not a reason this artifact is wrong.
 */
function summarisePosture(posture) {
  if (!posture) return { state: 'unknown', bad: [], good: [] };
  const bad = [];
  const good = [];
  for (const [name, spec] of Object.entries(POSTURE_CHECKS)) {
    const value = posture[spec.field];
    if (value === 'unknown') continue;
    if (value === spec.good) good.push(spec.field);
    else bad.push({ field: spec.field, why: spec.why, name });
  }
  if (!bad.length && !good.length) return { state: 'unknown', bad, good };
  return { state: bad.length ? 'weak' : 'clean', bad, good };
}

module.exports = { POSTURE_CHECKS, PASS_AT, projectUrl, mapChecks, fetchPosture, summarisePosture, repoSlug };
