'use strict';
/**
 * One place that decides what a repository URL means.
 *
 * There were six copies of "GitHub URL → owner/repo", written at different
 * times, and four of them matched `github\.com/([^/]+)/([^/]+)` *unanchored* —
 * so `https://evil.example/github.com/acme/server` produced the slug
 * `acme/server`. Every consumer of that slug then talked about the wrong
 * project: the health scorer fetched its stars, the licence-drift check read
 * its licence, the availability check asked whether it had moved, and the
 * registry cross-reference compared identities. A `source_url` in a pull
 * request is attacker-supplied text, and this is the function that decides what
 * it names.
 *
 * CodeQL found the newest copy (`js/regex/missing-regexp-anchor`); the older
 * ones were the same bug waiting for a different input.
 *
 * API:
 *   githubSlug(url)       -> "owner/repo" | null       (lowercased)
 *   githubOwner(url)      -> "owner" | null
 *   isGithubUrl(url)      -> boolean
 *   normalizeGitUrl(url)  -> canonical https URL | null
 *   githubRepoUrl(url)    -> "https://github.com/owner/repo" | null
 */

// Anchored at both ends. The forms that appear in real package metadata:
//   https://github.com/o/r          https://www.github.com/o/r
//   https://github.com/o/r.git      https://github.com/o/r/tree/main/pkg
//   git+https://github.com/o/r.git  git+ssh://git@github.com/o/r.git
//   git@github.com:o/r.git          ssh://git@github.com/o/r
//
// A trailing path (`/tree/main/x`, `#readme`, `?tab=readme`) is allowed and
// ignored, because monorepo entries legitimately point at a subdirectory. What
// is *not* allowed is anything before the host.
const GITHUB_URL = /^(?:git\+)?(?:(?:https?|ssh):\/\/)?(?:git@)?(?:www\.)?github\.com[:/]+([A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?)\/([A-Za-z0-9._-]+?)(?:\.git)?(?:[/#?].*)?$/i;

function match(url) {
  if (!url || typeof url !== 'string') return null;
  const m = GITHUB_URL.exec(url.trim());
  if (!m) return null;
  // A repository cannot be named `.` or `..`, and npm metadata does contain
  // odd values; refusing them here keeps them out of API paths.
  if (m[2] === '.' || m[2] === '..') return null;
  return { owner: m[1], repo: m[2] };
}

function githubSlug(url) {
  const m = match(url);
  return m ? `${m.owner}/${m.repo}`.toLowerCase() : null;
}

function githubOwner(url) {
  const m = match(url);
  return m ? m.owner.toLowerCase() : null;
}

function isGithubUrl(url) {
  return match(url) !== null;
}

/** The canonical browse URL, for printing and for comparing. */
function githubRepoUrl(url) {
  const m = match(url);
  return m ? `https://github.com/${m.owner}/${m.repo}` : null;
}

/**
 * Canonicalise the shapes npm and PyPI put in `repository.url` so two spellings
 * of the same repository compare equal.
 *
 * Kept separate from `githubSlug` because it also has to pass through hosts
 * that are not GitHub — GitLab, Codeberg and self-hosted instances appear in
 * this DB, and a comparison between two of *those* is still useful even though
 * nothing here can resolve a slug for them.
 */
function normalizeGitUrl(url) {
  if (!url || typeof url !== 'string') return null;
  return url
    .trim()
    .replace(/^git\+ssh:\/\/git@github\.com\//, 'https://github.com/')
    .replace(/^git\+https:\/\//, 'https://')
    .replace(/^git\+/, '')
    .replace(/^git@github\.com:/, 'https://github.com/')
    .replace(/\.git$/, '')
    .replace(/\/issues\/?$/, '');                       // Bug Tracker URLs
}

module.exports = { githubSlug, githubOwner, isGithubUrl, githubRepoUrl, normalizeGitUrl, GITHUB_URL };
