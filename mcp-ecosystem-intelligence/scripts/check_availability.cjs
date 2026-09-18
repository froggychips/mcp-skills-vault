#!/usr/bin/env node
/**
 * Is every entry still there, and is it still the same thing?
 *
 * The gate answers "do these bytes match the pin". It cannot answer "does this
 * package still exist", because a 404 arrives on the same code path as a
 * network failure and both read as "could not check". That is how
 * `@diskd-ai/email-mcp@0.3.8` sat in the DB with `trust: "verified"` after npm
 * had stopped serving it entirely — and an unpublished name is not merely
 * unavailable, it is *claimable by someone else*, which is a supply-chain
 * problem rather than a broken link.
 *
 * Four distinct states, kept apart because they need different responses:
 *
 *   gone          the package is no longer published at all. The name may be
 *                 re-registered by anyone. Blocks: trust drops to unverified.
 *   version-gone  the package exists, our pinned version does not. Whatever
 *                 `npx` resolves now is not what was verified. Also blocks.
 *   yanked        PyPI's soft delete: still installable if pinned, but the
 *                 maintainer is telling you not to. Blocks.
 *   deprecated    npm's `deprecated` field. Still works, still installs; the
 *                 maintainer has said stop using it, often naming a successor.
 *                 A warning, not a block.
 *
 * And one that is about identity rather than availability:
 *
 *   relocated     the registry (or GitHub) now points the package at a
 *                 different repository than the DB records. Not a block on its
 *                 own — monorepo moves and org renames are routine — but it is
 *                 the shape a hijack takes, so it is always reported.
 *
 * Results are written as evidence, in the same dated per-dimension form as
 * everything else (`availability`), so a stale answer ages out on its own
 * (7 days: a package can be unpublished today).
 *
 * `--write` records that dimension and, for an unavailable package, downgrades
 * `trust` to `unverified`. It deliberately does not re-derive `trust` from the
 * merged evidence: deriveTrust() answers "what do the recorded dimensions
 * establish", and most entries carry only the dimensions someone has got round
 * to recording — so calling it from a script that checked one thing took 91
 * entries from `verified` to `candidate`. One check does not get to discard
 * every other check's verdict.
 *
 * Usage:
 *   node scripts/check_availability.cjs [--json] [--write] [--repos]
 *                                       [--entry <name>] [--strict]
 *
 *   --write    record evidence in tools_database.json (re-derives `trust`)
 *   --repos    also ask GitHub whether the source repository moved. Off by
 *              default: 114 entries do not fit in 60 anonymous requests an
 *              hour, and this is the only check here that needs a token.
 *   --strict   deprecated / relocated also fail
 *
 * Exit codes:
 *   0  everything still published where we expect it
 *   1  at least one entry gone / version-gone / yanked (or, with --strict,
 *      deprecated / relocated)
 *   2  bad arguments, or no registry answered for any entry — an unanswered
 *      check must not exit 0
 */

'use strict';

const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb, writeDb } = require('./lib/db_io.cjs');
const { getJson, mapLimit } = require('./lib/http.cjs');
const { npmPkgName, pypiPkgName } = require('./lib/install_cmd.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { buildEvidence, mergeEvidence } = require('./lib/evidence.cjs');
// One definition of what a repository URL names, anchored: see lib/repo_url.cjs.
const { githubSlug: repoSlug } = require('./lib/repo_url.cjs');

const DB_PATH     = path.resolve(__dirname, '../assets/tools_database.json');
const CONCURRENCY = 8;
// Short enough that a weekly job sees today's registry, long enough that
// re-running it twice in an afternoon doesn't re-fetch everything.
const CACHE_TTL_MS = 30 * 60 * 1000;

const T  = process.stdout.isTTY;
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

// States that mean "do not install this", in report order.
const BLOCKING = new Set(['gone', 'version-gone', 'yanked']);
const NOTABLE  = new Set(['deprecated', 'relocated']);

function parseArgs(argv) {
  const opts = { json: false, write: false, repos: false, strict: false, entry: null, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--write') opts.write = true;
    else if (a === '--repos') opts.repos = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--entry') opts.entry = argv[++i] || null;
    else if (a === '-h' || a === '--help') opts.help = true;
    else return { ...opts, error: `unknown flag ${a}` };
  }
  return opts;
}

const HELP = `check_availability — is every entry still published, and still the same thing?

  node scripts/check_availability.cjs [--json] [--write] [--repos] [--entry <name>] [--strict]

  --write    record 'availability' evidence in the DB (re-derives trust)
  --repos    also ask GitHub whether the source repository moved (needs a token)
  --strict   deprecated / relocated also fail
  --entry    check one entry by name
`;

/**
 * The successor package named in a deprecation message, if there is one.
 *
 * Deprecation text is prose. A bare "the next word after 'use'" match read
 * "Use the remote MCP server" as a package called "the", and "use CircleCI's
 * hosted MCP server" as one called "CircleCI" — confident nonsense, printed as
 * advice. So: drop URLs first (they are documentation links, not package
 * names), then take only a token actually shaped like a package — scoped, or
 * containing a hyphen or a slash — and only when a handover word introduces it.
 */
function successorFrom(message) {
  const text = String(message || '').replace(/https?:\/\/\S+/g, ' ');
  const m = text.match(/\b(?:use|switch to|moved to|renamed to|replaced by|superseded by)\s+`?(@[A-Za-z0-9][\w.-]*\/[\w.-]+|[A-Za-z0-9][\w.]*[-/][\w.@/-]+)`?/i);
  if (!m) return null;
  const token = m[1].replace(/[.,;:)\]]+$/, '');
  // Two characters and a hyphen is not a package name; neither is a sentence
  // fragment that happened to contain one.
  if (token.length < 4 || !/[-/]/.test(token)) return null;
  return token;
}


/**
 * npm: does the package exist, does our pinned version exist, is it deprecated,
 * and does it still point at the repository we recorded?
 *
 * Two requests, both cacheable: the version document (which is small) and, only
 * if that 404s, the package document (to tell "package gone" from "version
 * gone" — a distinction that changes what a reader should do about it).
 */
async function checkNpm(tool, pkg, { get = getJson } = {}) {
  const version = tool.version || null;
  const base    = 'https://registry.npmjs.org';
  const encoded = pkg.replace(/\//g, '%2f');

  const verUrl = `${base}/${encoded}/${version || 'latest'}`;
  const ver    = await get(verUrl, { cacheTtlMs: CACHE_TTL_MS });

  if (ver.ok) {
    const meta = ver.data || {};
    const npmRepo = typeof meta.repository === 'string' ? meta.repository : (meta.repository?.url ?? null);
    const out = { state: 'present', detail: null, registry_repo: npmRepo || null };
    if (meta.deprecated) {
      // npm's deprecation message is free text and usually names a successor;
      // pass it through rather than paraphrasing it.
      out.state  = 'deprecated';
      out.detail = String(meta.deprecated).slice(0, 300);
      const hint = successorFrom(meta.deprecated);
      if (hint) out.replacement = hint;
    }
    return out;
  }

  if (ver.status !== 404) {
    // A transport failure is not an answer. Saying "gone" here would be the
    // same bug this script exists to fix, in the other direction.
    return { state: 'unknown', detail: `npm lookup failed: ${ver.error || `HTTP ${ver.status}`}` };
  }

  // 404 on the version: is the package itself still there?
  const pkgDoc = await get(`${base}/${encoded}`, { cacheTtlMs: CACHE_TTL_MS });
  if (pkgDoc.ok) {
    const versions = Object.keys((pkgDoc.data && pkgDoc.data.versions) || {});
    const latest   = pkgDoc.data?.['dist-tags']?.latest || null;
    return {
      state:  'version-gone',
      detail: `${pkg}@${version} is no longer published (${versions.length} version${versions.length === 1 ? '' : 's'} remain; latest ${latest || 'unknown'})`,
      latest,
    };
  }
  if (pkgDoc.status === 404) {
    return { state: 'gone', detail: `${pkg} returns 404 from the npm registry — unpublished, renamed or taken down; the name is claimable` };
  }
  return { state: 'unknown', detail: `npm lookup failed: ${pkgDoc.error || `HTTP ${pkgDoc.status}`}` };
}

/** PyPI: the same four questions, plus `yanked`, which npm has no equivalent of. */
async function checkPypi(tool, pkg, { get = getJson } = {}) {
  const version = tool.version || null;
  const verUrl  = version
    ? `https://pypi.org/pypi/${encodeURIComponent(pkg)}/${encodeURIComponent(version)}/json`
    : `https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`;
  const ver = await get(verUrl, { cacheTtlMs: CACHE_TTL_MS });

  if (ver.ok) {
    const info = ver.data?.info || {};
    const urls = ver.data?.urls || [];
    const registryRepo = info.project_urls
      ? (info.project_urls.Source || info.project_urls.Homepage || info.project_urls.Repository || null)
      : (info.home_page || null);
    // `info.yanked` is the release-level flag; a release can also have every
    // file yanked individually, which amounts to the same thing.
    const yanked = info.yanked === true || (urls.length > 0 && urls.every((u) => u.yanked === true));
    if (yanked) {
      return {
        state:  'yanked',
        detail: `${pkg}==${version} is yanked${info.yanked_reason ? `: ${info.yanked_reason}` : ''}`,
        registry_repo: registryRepo,
      };
    }
    return { state: 'present', detail: null, registry_repo: registryRepo };
  }

  if (ver.status !== 404) {
    return { state: 'unknown', detail: `PyPI lookup failed: ${ver.error || `HTTP ${ver.status}`}` };
  }

  const pkgDoc = await get(`https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`, { cacheTtlMs: CACHE_TTL_MS });
  if (pkgDoc.ok) {
    return {
      state:  'version-gone',
      detail: `${pkg}==${version} is no longer on PyPI (latest ${pkgDoc.data?.info?.version || 'unknown'})`,
      latest: pkgDoc.data?.info?.version || null,
    };
  }
  if (pkgDoc.status === 404) {
    return { state: 'gone', detail: `${pkg} returns 404 from PyPI — removed or renamed` };
  }
  return { state: 'unknown', detail: `PyPI lookup failed: ${pkgDoc.error || `HTTP ${pkgDoc.status}`}` };
}

/**
 * Did the source repository move?
 *
 * GitHub follows renames and transfers transparently, answering 200 with the
 * *current* full_name — which is exactly what makes it a usable relocation
 * detector: a mismatch between what we stored and what it answers is a move
 * that happened without anyone updating the entry.
 */
async function checkRepo(tool, { get = getJson } = {}) {
  const slug = repoSlug(tool.source_url);
  if (!slug) return null;
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;
  const res = await get(`https://api.github.com/repos/${slug}`, {
    headers: {
      'Accept':     'application/vnd.github+json',
      'User-Agent': 'mcp-vault-availability',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    cacheTtlMs: CACHE_TTL_MS,
  });
  if (res.status === 404) return { state: 'repo-gone', detail: `${tool.source_url} returns 404 from the GitHub API` };
  if (!res.ok) return { state: 'unknown', detail: `GitHub lookup failed: ${res.error || `HTTP ${res.status}`}` };
  const now = String(res.data?.full_name || '').toLowerCase();
  if (now && now !== slug) {
    return { state: 'relocated', detail: `source repository is now ${res.data.full_name} (was ${slug})`, moved_to: res.data.full_name };
  }
  if (res.data?.archived) return { state: 'archived', detail: `${res.data.full_name} is archived on GitHub` };
  return { state: 'present', detail: null };
}

async function checkEntry(tool, opts, { get = getJson } = {}) {
  const typed = toTypedEntry(tool);
  const eco   = typed ? typed.artifact.ecosystem : null;
  const row   = {
    name:       tool.name,
    ecosystem:  eco,
    version:    tool.version || null,
    artifact_id: typed ? artifactId(typed.artifact) : null,
    availability: { state: 'unknown', detail: 'no registry for this ecosystem' },
    identity:   null,
  };

  if (eco === 'npm') {
    const pkg = npmPkgName(tool.install_cmd);
    row.package = pkg;
    row.availability = pkg
      ? await checkNpm(tool, pkg, { get })
      : { state: 'unknown', detail: 'the launch command is not a shape we can resolve to a package' };
  } else if (eco === 'pypi') {
    const pkg = pypiPkgName(tool.install_cmd);
    row.package = pkg;
    row.availability = pkg
      ? await checkPypi(tool, pkg, { get })
      : { state: 'unknown', detail: 'the launch command is not a shape we can resolve to a package' };
  } else if (eco === 'oci') {
    // check_docker_drift.cjs already probes registries by digest; duplicating
    // it here would give two answers to one question.
    row.availability = { state: 'unknown', detail: 'container images are covered by `mcp-vault docker-drift`' };
  }

  // Identity: the registry's own idea of where this package comes from.
  const registryRepo = row.availability.registry_repo || null;
  if (registryRepo && tool.source_url) {
    const a = repoSlug(registryRepo);
    const b = repoSlug(tool.source_url);
    if (a && b && a !== b) {
      row.identity = {
        state:  'relocated',
        detail: `${eco === 'pypi' ? 'PyPI' : 'npm'} points at ${a}, the entry records ${b}`,
        registry_repo: registryRepo,
      };
    }
  }
  if (opts.repos) {
    const repo = await checkRepo(tool, { get });
    if (repo && repo.state !== 'present') {
      // A GitHub answer is about the repository, which is a stronger statement
      // than the registry's metadata field; it wins where both spoke.
      row.identity = { ...(row.identity || {}), ...repo };
    }
  }
  return row;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`check_availability: ${opts.error}\n\n${HELP}`); return Promise.resolve(2); }
  if (opts.help)  { process.stdout.write(HELP); return Promise.resolve(0); }

  const { db } = readDb(DB_PATH);
  const tools = (db.tools || []).filter((t) => !opts.entry || t.name === opts.entry);
  if (opts.entry && !tools.length) {
    process.stderr.write(`check_availability: no entry named "${opts.entry}"\n`);
    return Promise.resolve(2);
  }

  return mapLimit(tools, CONCURRENCY, (t) => checkEntry(t, opts)).then((rows) => {
    const blocking = rows.filter((r) => BLOCKING.has(r.availability.state));
    const notable  = rows.filter((r) => r.availability.state === 'deprecated' || (r.identity && NOTABLE.has(r.identity.state)));
    const unknown  = rows.filter((r) => r.availability.state === 'unknown');

    if (opts.write) {
      const byName = new Map(rows.map((r) => [r.name, r]));
      const downgraded = [];
      let recorded = 0;
      for (const tool of db.tools || []) {
        const row = byName.get(tool.name);
        // An inconclusive answer is not recorded. Writing `unknown` would
        // overwrite a dated 'present' with a non-answer and make a feed
        // outage look like a finding.
        if (!row || row.availability.state === 'unknown') continue;
        const fresh = buildEvidence({ availability: row.availability }, { artifactId: row.artifact_id });
        tool.trust_evidence = mergeEvidence(tool.trust_evidence, fresh);
        recorded++;

        // This script may *downgrade* trust and nothing else.
        //
        // Re-deriving the word from the merged evidence looks right and is
        // wrong: deriveTrust() answers "what do the dimensions establish", and
        // most entries have only the dimensions someone has got round to
        // recording. Running it here took 91 entries from `verified` to
        // `candidate` because this run had recorded availability and knew
        // nothing else — a script that checks one thing quietly discarding
        // every other check's verdict. The full word belongs to the run that
        // collects the full evidence (`verify --record-evidence`).
        //
        // An unavailable package is the one case where one dimension settles
        // it on its own: there is nothing to install, so nothing downstream
        // can make it installable.
        if (BLOCKING.has(row.availability.state) && tool.trust !== 'unverified') {
          downgraded.push({ name: tool.name, from: tool.trust, state: row.availability.state });
          tool.trust = 'unverified';
        }
      }
      if (recorded) writeDb(DB_PATH, db);
      process.stderr.write(`Recorded availability for ${recorded} entr${recorded === 1 ? 'y' : 'ies'} in ${DB_PATH}\n`);
      for (const d of downgraded) {
        process.stderr.write(`  trust ${d.from} → unverified: ${d.name} (${d.state})\n`);
      }
    }

    if (opts.json) {
      process.stdout.write(`${JSON.stringify({
        schema:       'mcp-vault/availability@1',
        generated_at: new Date().toISOString(),
        checked:      rows.length,
        summary: {
          present:        rows.filter((r) => r.availability.state === 'present').length,
          gone:           rows.filter((r) => r.availability.state === 'gone').length,
          version_gone:   rows.filter((r) => r.availability.state === 'version-gone').length,
          yanked:         rows.filter((r) => r.availability.state === 'yanked').length,
          deprecated:     rows.filter((r) => r.availability.state === 'deprecated').length,
          relocated:      rows.filter((r) => r.identity && r.identity.state === 'relocated').length,
          unknown:        unknown.length,
        },
        entries: rows,
      }, null, 2)}\n`);
    } else {
      for (const r of rows) {
        const s = r.availability.state;
        if (s === 'present' && !r.identity) continue;
        const colour = BLOCKING.has(s) ? RD : (s === 'deprecated' || r.identity ? YL : DM);
        const label  = BLOCKING.has(s) ? s.toUpperCase() : (s === 'present' ? (r.identity ? r.identity.state.toUpperCase() : 'OK') : s.toUpperCase());
        process.stdout.write(`${colour}${label.padEnd(13)}${RS} ${r.name}\n`);
        if (r.availability.detail) process.stdout.write(`              ${DM}${r.availability.detail}${RS}\n`);
        if (r.identity && r.identity.detail) process.stdout.write(`              ${DM}${r.identity.detail}${RS}\n`);
        if (r.availability.replacement) process.stdout.write(`              ${DM}successor named: ${r.availability.replacement}${RS}\n`);
      }
      const ok = rows.length - blocking.length - notable.length - unknown.length;
      process.stdout.write(
        `\n${rows.length} checked — ${GN}${ok} present${RS}, ` +
        `${blocking.length ? RD : ''}${blocking.length} unavailable${RS}, ` +
        `${notable.length} deprecated/relocated, ${unknown.length} not checkable\n`
      );
      if (blocking.length) {
        process.stdout.write(`\nAn unavailable entry is not just a broken link: an unpublished name can be\nre-registered by someone else. Re-pin or remove:\n`);
        for (const r of blocking) process.stdout.write(`  ${r.name} — ${r.availability.state}\n`);
      }
    }

    if (blocking.length) return 1;
    if (opts.strict && notable.length) return 1;
    // No registry answered for any entry. "Everything is still published" is
    // not what that means.
    if (rows.length && unknown.length === rows.length) {
      process.stderr.write('check_availability: no registry answered for any entry — nothing was established\n');
      return 2;
    }
    return 0;
  });
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => exitAfterFlush(code)).catch((e) => {
    process.stderr.write(`check_availability: ${e.stack || e.message}\n`);
    exitAfterFlush(2);
  });
}

module.exports = { parseArgs, repoSlug, successorFrom, checkNpm, checkPypi, checkRepo, checkEntry, BLOCKING, NOTABLE };
