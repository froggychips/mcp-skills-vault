#!/usr/bin/env node
/**
 * Detect upstream license drift between what tools_database.json records and
 * what the registry (npm / PyPI / GitHub) currently advertises.
 *
 * Why a separate script: `calculate_health.cjs` already penalises non-OSI
 * licenses with -10, but that signal is quiet — it surfaces only when someone
 * reads the recomputed score, and even then a "MIT → BSL-1.1" flip looks the
 * same as a "MIT → Unknown" hiccup in registry metadata. This script reports
 * the diff loudly per entry and, in `--strict` mode, fails CI on the specific
 * pattern that matters: an OSI license switching to a source-available one
 * (HashiCorp/Elastic/MongoDB/Redis-style relicensing).
 *
 * Drift classifications:
 *   match                       — same SPDX, or both unknown
 *   drift-osi-to-osi            — between two OSI licenses (warn only)
 *   drift-osi-to-restrictive    — OSI → BSL/SSPL/Elastic/FSL/Commons Clause/…
 *                                 → HARD FAIL in --strict
 *   drift-restrictive-to-osi    — going more permissive (rare, worth noting)
 *   drift-to-unknown            — license disappeared from registry
 *   drift-from-unknown          — DB had no license, registry now reports one
 *
 * Sources, by ecosystem (lowest-noise source first):
 *   npm     → `npm view <pkg>@<version> license`
 *   PyPI    → https://pypi.org/pypi/<pkg>/<version>/json → info.license
 *             (falls back to scanning info.classifiers for "License :: ...")
 *   docker  → skipped (no canonical license field in OCI manifests). DB
 *             entries that carry a `license` for docker images sourced it
 *             from the upstream repo — treat as "docker-license-from-source"
 *             and don't drift-check.
 *   github  → only as a fallback when npm/PyPI omit it; `gh api repos/<o>/<r>`
 *             returns `.license.spdx_id`. Same NOASSERTION/GitHub-SPDX
 *             normalisation as refresh_scores.cjs.
 *
 * Usage:
 *   node scripts/check_license_drift.cjs                  human-readable summary
 *   node scripts/check_license_drift.cjs --strict   (drifts AND fetch errors fail)         exit 1 on osi-to-restrictive
 *   node scripts/check_license_drift.cjs --json           machine-readable
 *   node scripts/check_license_drift.cjs --no-fetch       offline self-consistency only
 *   node scripts/check_license_drift.cjs --db <path>      override DB path
 *
 * Exit codes:
 *   0  no restrictive drift (or --strict not set)
 *   1  --strict + at least one drift-osi-to-restrictive, or a fetch error
 *   2  bad arguments / DB not readable
 *
 * An entry the DB already records as `availability: gone` is reported as GONE
 * and not fetched: there is no licence to read, and the 404 it would return is
 * a settled fact rather than a failed measurement. A package that disappears
 * before that is recorded still errors, and still fails --strict.
 *
 * To wire into CI: add a job that runs this script with --strict. Failure
 * (relicensing detected) is the signal — don't auto-open a PR.
 *
 * Zero external dependencies. Network calls happen only in the default
 * (online) run; --no-fetch and the test injection point keep tests offline.
 */

'use strict';

const { execFileSync } = require('child_process');
const { exitAfterFlush } = require('./lib/exit.cjs');
const fs           = require('fs');
const https        = require('https');
const path         = require('path');
const { githubSlug } = require('./lib/repo_url.cjs');

const { classifyLicense } = require('./calculate_health.cjs');

const DEFAULT_DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');

// Same GitHub→canonical SPDX map as refresh_scores.cjs. GitHub returns short
// IDs (e.g. "GPL-3.0") and the special value "NOASSERTION" when it couldn't
// auto-detect; treat both as "unknown" rather than risk a false drift.
const GITHUB_SPDX_MAP = {
  'GPL-2.0':  'GPL-2.0-or-later',
  'GPL-3.0':  'GPL-3.0-or-later',
  'LGPL-2.0': 'LGPL-2.0-or-later',
  'LGPL-2.1': 'LGPL-2.1-or-later',
  'LGPL-3.0': 'LGPL-3.0-or-later',
  'AGPL-3.0': 'AGPL-3.0-or-later',
};

// ── pure helpers (no I/O) ─────────────────────────────────────────────────

/**
 * Normalise a license string for comparison. Returns null when there's no
 * usable value (null, '', whitespace, "Unknown", "NOASSERTION", "UNKNOWN").
 * The output is the input trimmed, with GitHub-style short SPDX IDs upgraded
 * to canonical "-or-later" variants so npm/PyPI/GitHub agree.
 */
function normalizeLicense(raw) {
  if (raw === null || raw === undefined) return null;
  const s = String(raw).trim();
  if (s === '' || s === 'Unknown' || s === 'NOASSERTION' || s === 'UNKNOWN') return null;
  return GITHUB_SPDX_MAP[s] || s;
}

/**
 * Compare an old (DB) license to a new (registry) license and return one of:
 *   match | drift-osi-to-osi | drift-osi-to-restrictive |
 *   drift-restrictive-to-osi | drift-to-unknown | drift-from-unknown
 *
 * Both inputs may be null. `null` represents "no usable license known" —
 * registry returned blank, NOASSERTION, "Unknown", etc. Two nulls are a
 * match (no information has changed).
 */
function diffLicense(oldRaw, newRaw) {
  const a = normalizeLicense(oldRaw);
  const b = normalizeLicense(newRaw);
  if (a === b) return 'match';            // covers both-null and string-equal

  const ka = a === null ? 'unknown' : classifyLicense(a);
  const kb = b === null ? 'unknown' : classifyLicense(b);

  if (kb === 'unknown') return 'drift-to-unknown';
  if (ka === 'unknown') return 'drift-from-unknown';

  if (ka === 'osi' && kb === 'osi')                 return 'drift-osi-to-osi';
  if (ka === 'osi' && kb === 'restrictive')         return 'drift-osi-to-restrictive';
  if (ka === 'restrictive' && kb === 'osi')         return 'drift-restrictive-to-osi';
  // restrictive → restrictive (e.g. BSL-1.1 → SSPL-1.0). Treat as osi-to-restrictive-
  // grade severity because a swap between source-available terms can still
  // change what's allowed (Confluent's BSL vs MongoDB's SSPL aren't equivalent).
  return 'drift-osi-to-restrictive';
}

/** True if the classification is the kind that should fail --strict. */
function isHardFail(classification) {
  return classification === 'drift-osi-to-restrictive';
}

// ── install_cmd parsers (mirrors verify_integrity.cjs) ─────────────────────

function npmPkgName(cmd) {
  const m = cmd.match(/^npx\s+-y\s+((?:@[\w-]+\/)?[\w.-]+?)(?:@[^\s]+)?(?:\s|$)/);
  return m ? m[1] : null;
}

function pypiPkgName(cmd) {
  if (/^uvx\s+--from/.test(cmd)) return null;
  const m = cmd.match(/^uvx\s+([\w.-]+?)(?:==[\d.\w]+)?(?:\s|$)/);
  return m ? m[1] : null;
}

function githubOwnerRepo(url) {
  // Anchored via lib/repo_url.cjs: an unanchored match read
  // `https://evil.example/github.com/acme/server` as `acme/server`, and this
  // slug decides which repository gets asked about. The substring pre-check
  // that used to guard this line was the same bug in miniature — it accepted
  // exactly the hostile URL the anchored pattern then rejected — so the
  // anchored matcher is the only thing deciding.
  return githubSlug(url);
}

// ── PyPI license extraction ────────────────────────────────────────────────

/**
 * Map a PyPI "License :: OSI Approved :: MIT License" classifier string to
 * an SPDX-ish identifier. PyPI classifiers are free-form-ish — most are well
 * known but a tail of less-common ones (Eclipse, Boost, etc.) we leave as
 * the trailing token, which works for equality comparisons because the DB
 * is populated from the same source.
 */
function pypiClassifierToSpdx(classifier) {
  if (typeof classifier !== 'string') return null;
  // Examples:
  //   "License :: OSI Approved :: MIT License"
  //   "License :: OSI Approved :: Apache Software License"
  //   "License :: OSI Approved :: BSD License"
  //   "License :: Other/Proprietary License"
  const m = classifier.match(/^License\s*::\s*(?:OSI Approved\s*::\s*)?(.+?)\s*$/);
  if (!m) return null;
  const tail = m[1].trim();
  const map = {
    'MIT License':                                'MIT',
    'Apache Software License':                    'Apache-2.0',
    'BSD License':                                'BSD-3-Clause',
    'ISC License (ISCL)':                         'ISC',
    'Mozilla Public License 2.0 (MPL 2.0)':       'MPL-2.0',
    'GNU General Public License v2 (GPLv2)':      'GPL-2.0-or-later',
    'GNU General Public License v3 (GPLv3)':      'GPL-3.0-or-later',
    'GNU Lesser General Public License v3 (LGPLv3)': 'LGPL-3.0-or-later',
    'GNU Affero General Public License v3':       'AGPL-3.0-or-later',
    'GNU Affero General Public License v3 or later (AGPLv3+)': 'AGPL-3.0-or-later',
    // Not an SPDX id, but it is a definite statement: the package is no longer
    // open source. Mapping it to null made an MIT → proprietary relicensing
    // read as `drift-to-unknown`, which --strict does not fail on — the exact
    // event this gate exists to catch. 'Proprietary' classifies as restrictive.
    'Other/Proprietary License':                  'Proprietary',
    'Public Domain':                              'CC0-1.0',
    'The Unlicense (Unlicense)':                  'Unlicense',
  };
  return map.hasOwnProperty(tail) ? map[tail] : tail;
}

/**
 * Pull the most informative license string out of a PyPI metadata blob.
 * Prefers `info.license` (free-form), falls back to scanning `info.classifiers`.
 */
function pypiLicenseFromMeta(meta) {
  const lic = meta?.info?.license;
  if (lic && String(lic).trim() !== '' && String(lic).trim().toUpperCase() !== 'UNKNOWN') {
    return String(lic).trim();
  }
  const classifiers = meta?.info?.classifiers || [];
  for (const c of classifiers) {
    if (typeof c === 'string' && c.startsWith('License ::')) {
      const spdx = pypiClassifierToSpdx(c);
      if (spdx) return spdx;
    }
  }
  return null;
}

// ── network (only invoked in online mode) ─────────────────────────────────

function httpsGetJson(url, timeoutMs = 10000, headers = {}) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const req = https.get(
      { hostname: u.hostname, path: u.pathname + u.search, headers },
      (res) => {
        if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end',  ()  => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
      },
    );
    req.on('error', () => resolve(null));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve(null); });
  });
}

/**
 * Default fetcher — does the real network calls. Tests inject a stub by
 * passing a different `fetcher` to `runDriftCheck`.
 *
 * Returns `{ source, license }` (license may be null if the source couldn't
 * resolve one) or `{ source, error }` on hard failure.
 */
async function defaultFetcher(tool) {
  // npm
  const npmName = /^npx\s+-y/.test(tool.install_cmd) ? npmPkgName(tool.install_cmd) : null;
  if (npmName) {
    const spec = tool.version ? `${npmName}@${tool.version}` : `${npmName}@latest`;
    try {
      // --json prints the field as a JSON string when present; missing → "".
      // argv form, not a shell string: `spec` embeds DB-controlled `version`.
      const raw = execFileSync('npm', ['view', spec, 'license', '--json'],
                               { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      const parsed = raw.trim() ? JSON.parse(raw) : null;
      const lic = typeof parsed === 'string' ? parsed : null;
      return { source: 'npm', license: lic };
    } catch (e) {
      return { source: 'npm', error: e.message.split('\n')[0] };
    }
  }

  // PyPI
  const pypiName = /^uvx/.test(tool.install_cmd) ? pypiPkgName(tool.install_cmd) : null;
  if (pypiName) {
    const v = tool.version ? `/${encodeURIComponent(tool.version)}` : '';
    const meta = await httpsGetJson(`https://pypi.org/pypi/${encodeURIComponent(pypiName)}${v}/json`);
    if (!meta) return { source: 'pypi', error: 'PyPI lookup failed' };
    return { source: 'pypi', license: pypiLicenseFromMeta(meta) };
  }

  // Docker — no canonical license field. Mark as source-of-record = repo.
  if (/^docker\s+run/.test(tool.install_cmd)) {
    return { source: 'docker-license-from-source', skip: true };
  }

  // Fallback: gh api on the source repo.
  const repo = githubOwnerRepo(tool.source_url);
  if (repo) {
    try {
      const meta = JSON.parse(execFileSync('gh', ['api', `repos/${repo}`],
                                           { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }));
      const spdx = meta?.license?.spdx_id || null;
      const norm = spdx && spdx !== 'NOASSERTION' ? (GITHUB_SPDX_MAP[spdx] || spdx) : null;
      return { source: 'github', license: norm };
    } catch (e) {
      return { source: 'github', error: e.message.split('\n')[0] };
    }
  }

  return { source: 'none', skip: true };
}

// ── orchestrator ──────────────────────────────────────────────────────────

/**
 * Run the drift check over every entry in `db.tools`. Pure of process I/O —
 * the fetcher is the only side-effecting collaborator, and tests pass a stub.
 *
 * @param {object}   db        — parsed tools_database.json (`.tools` array)
 * @param {object}   opts
 * @param {Function} opts.fetcher — async (tool) → { source, license? , error? , skip? }
 * @param {boolean}  opts.noFetch — when true, only compare DB to itself (mostly
 *                                  a no-op; lets CI run an offline smoke step)
 * @returns {Promise<{ checked, drifts, errors, items }>}
 */
async function runDriftCheck(db, { fetcher, noFetch }) {
  const items   = [];
  const drifts  = [];
  const errors  = [];

  for (const tool of (db.tools || [])) {
    if (noFetch) {
      // Offline smoke: classify the DB's stored license against itself.
      // Always "match"; the value of this mode is exercising the data shape
      // and catching DB-level surprises (e.g. a tool entry missing entirely).
      const stored = normalizeLicense(tool.license);
      items.push({
        name: tool.name,
        old:  tool.license || null,
        new:  tool.license || null,
        classification: 'match',
        source: 'no-fetch',
        offline: true,
        stored_class: stored === null ? 'unknown' : classifyLicense(stored),
      });
      continue;
    }

    // A package that is no longer published has no licence to read, and the DB
    // already says so: check_availability recorded `availability: gone` with
    // the date it established that. Letting the 404 come back as a fetch error
    // made --strict red every week for a fact settled once and unable to
    // change — and a gate that is permanently red is a gate nobody reads.
    //
    // This keys off the *recorded* state, not off the 404. A package that
    // vanishes and has not been recorded yet still fails the run, which is the
    // week that finding matters.
    const recordedAvailability = tool?.trust_evidence?.dimensions?.availability?.status;
    if (recordedAvailability === 'gone') {
      items.push({
        name: tool.name,
        old: tool.license || null,
        new: tool.license || null,
        classification: 'match',
        source: 'availability:gone',
        skipped: true,
        gone: { recorded_at: tool.trust_evidence.dimensions.availability.checked_at || null },
      });
      continue;
    }

    let res;
    try {
      res = await fetcher(tool);
    } catch (e) {
      res = { source: 'fetcher', error: e.message || String(e) };
    }

    if (!res || res.error) {
      errors.push({ name: tool.name, error: res?.error || 'no fetcher result', source: res?.source || 'unknown' });
      continue;
    }
    if (res.skip) {
      items.push({
        name: tool.name,
        old: tool.license || null,
        new: tool.license || null,
        classification: 'match',
        source: res.source,
        skipped: true,
      });
      continue;
    }

    const newLic = res.license !== undefined ? res.license : null;
    const cls    = diffLicense(tool.license, newLic);
    const item   = {
      name: tool.name,
      old: tool.license || null,
      new: newLic,
      classification: cls,
      source: res.source,
    };
    items.push(item);
    if (cls !== 'match') drifts.push(item);
  }

  return { checked: items.length, drifts, errors, items };
}

// ── CLI ───────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const out = { strict: false, json: false, noFetch: false, dbPath: DEFAULT_DB_PATH };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if      (a === '--strict')                            out.strict = true;
    else if (a === '--json')                              out.json = true;
    else if (a === '--no-fetch' || a === '--offline')     out.noFetch = true;
    else if (a === '--db')                                out.dbPath = argv[++i];
    else if (a === '--help' || a === '-h')                out.help = true;
    else {
      console.error(`Unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return out;
}

function helpText() {
  return [
    'Usage: node check_license_drift.cjs [--strict] [--json] [--no-fetch] [--db <path>]',
    '',
    'Detects upstream license drift vs the recorded `license` field in',
    'tools_database.json. --strict exits 1 on any OSI → restrictive drift',
    '(the HashiCorp/Elastic relicensing pattern).',
  ].join('\n');
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { console.log(helpText()); process.exit(0); }

  let db;
  try {
    db = JSON.parse(fs.readFileSync(opts.dbPath, 'utf8'));
  } catch (e) {
    console.error(`Cannot read DB at ${opts.dbPath}: ${e.message}`);
    process.exit(2);
  }

  const report = await runDriftCheck(db, { fetcher: defaultFetcher, noFetch: opts.noFetch });

  if (opts.json) {
    // Match the documented output shape.
    process.stdout.write(JSON.stringify({
      schema: 'mcp-vault/license-drift@1',
      checked: report.checked,
      drifts:  report.drifts,
      errors:  report.errors,
      gone:    (report.items || []).filter((i) => i.gone).map((i) => ({ name: i.name, recorded_at: i.gone.recorded_at })),
    }, null, 2) + '\n');
  } else {
    for (const d of report.drifts) {
      console.log(`DRIFT  ${d.name.padEnd(30)} ${d.old || '(none)'} → ${d.new || '(none)'}  [${d.classification}, ${d.source}]`);
    }
    for (const e of report.errors) {
      console.log(`ERROR  ${e.name.padEnd(30)} (${e.source}) ${e.error}`);
    }
    // Not silence: a skipped entry is one nobody is watching any more, and the
    // count belongs in the summary so it cannot grow unnoticed.
    const gone = (report.items || []).filter((i) => i.gone);
    for (const g of gone) {
      console.log(`GONE   ${g.name.padEnd(30)} no longer published — licence not read (recorded ${g.gone.recorded_at || 'date unknown'})`);
    }
    const goneNote = gone.length ? `, ${gone.length} gone (not read)` : '';
    console.log(`\n${report.checked} entries checked — ${report.drifts.length} drift(s), ${report.errors.length} error(s)${goneNote}`);
  }

  exitAfterFlush(licenseExitCode(report, opts.strict));
}

if (require.main === module) {
  main().catch((e) => { console.error(e.stack || e.message); process.exit(1); });
}

/**
 * --strict exit code for a drift report.
 *
 * A run that couldn't read any license is not a run that found no drift: under
 * --strict, fetch errors fail alongside real drifts. Without that, a total
 * outage (npm + PyPI + GitHub all unreachable) exited 0 and the weekly gate
 * reported green having checked nothing.
 */
function licenseExitCode(report, strict) {
  if (!strict) return 0;
  const hardDrift = (report.drifts || []).some((d) => isHardFail(d.classification));
  return (hardDrift || (report.errors || []).length > 0) ? 1 : 0;
}

module.exports = {
  // Pure helpers — easy to unit-test.
  normalizeLicense,
  licenseExitCode,
  diffLicense,
  isHardFail,
  pypiClassifierToSpdx,
  pypiLicenseFromMeta,
  npmPkgName,
  pypiPkgName,
  githubOwnerRepo,
  // Orchestrator — accepts an injected fetcher so tests can stay offline.
  runDriftCheck,
};
