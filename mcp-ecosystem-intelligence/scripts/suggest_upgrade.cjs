#!/usr/bin/env node
/**
 * mcp-vault upgrade — the shortest version that clears what is known against
 * this one.
 *
 * The gate tells you an entry is affected by GHSA-2h44-8472-frjj and stops.
 * That is correct and not actionable: the next question is always "so what do
 * I install instead", and answering it by hand means reading four advisories
 * and taking the highest `fixed` version out of them.
 *
 * OSV already carries that. Each advisory's affected range has a `fixed` event,
 * so the target is the largest `fixed` across every advisory that applies —
 * computed, not searched. No probing of candidate versions, no resolving trees
 * for each one: two requests per entry, one to ask what applies now and one to
 * confirm the target is clean.
 *
 * What it reports, per entry:
 *
 *   clear        nothing known applies to the pinned version
 *   upgrade      a published version clears every advisory *and* was confirmed
 *                clean itself — named, with what each advisory was
 *   upgrade-unconfirmed
 *                a target that clears them on paper, which we could not check.
 *                Not counted as a safe upgrade: a recommendation resting on a
 *                check that failed is the bug this repo keeps finding.
 *   no-clean-target
 *                every candidate has advisories of its own
 *   no-fix       advisories apply and none of them has a fix. This is the case
 *                worth knowing about and the one a "just upgrade" tool hides.
 *   unknown      the feed did not answer, or a version string nobody can order
 *
 * The advisory feeds are asked about the *candidate* too, because "fixed in
 * 2.1.30" means fixed for that advisory, not free of every other one. A
 * recommendation that moves someone onto a version with a different CVE would
 * be worse than no recommendation.
 *
 * Usage:
 *   node scripts/suggest_upgrade.cjs [--entry <name>] [--json] [--strict]
 *                                    [--include-prereleases]
 *
 * Exit codes:
 *   0  nothing to do (or advisories exist and --strict was not given)
 *   1  --strict and at least one entry is affected
 *   2  bad arguments
 */

'use strict';

const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb } = require('./lib/db_io.cjs');
const { postJson, getJson, mapLimit } = require('./lib/http.cjs');
const { npmPkgName, pypiPkgName } = require('./lib/install_cmd.cjs');
const { toTypedEntry } = require('./lib/entry_model.cjs');
const { comparatorFor, maxVersion, isPrerelease } = require('./lib/versions.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
const OSV      = 'https://api.osv.dev/v1/query';
const CONCURRENCY = 6;
// Advisories are the perishable feed in this repo; ten minutes is enough to
// make a re-run cheap without serving yesterday's answer.
const CACHE_TTL_MS = 10 * 60 * 1000;

const T  = process.stdout.isTTY;
const B  = T ? '\x1b[1m'  : '';
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW', 'UNKNOWN'];

function parseArgs(argv) {
  const opts = { entry: null, json: false, strict: false, prereleases: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--include-prereleases') opts.prereleases = true;
    else if (a === '--entry') opts.entry = argv[++i] || null;
    else if (a === '-h' || a === '--help') opts.help = true;
    else return { ...opts, error: `unknown flag ${a}` };
  }
  return opts;
}

const HELP = `suggest_upgrade — the shortest version that clears what is known

  node scripts/suggest_upgrade.cjs [--entry <name>] [--json] [--strict]
                                   [--include-prereleases]

  --strict                exit 1 when any entry is affected
  --include-prereleases   allow a pre-release as an upgrade target
`;

/** OSV's severity for one vuln, normalised to a word. */
function severityOf(vuln) {
  const ds = vuln.database_specific && vuln.database_specific.severity;
  if (typeof ds === 'string') return ds.toUpperCase();
  const cvss = (vuln.severity || []).find((s) => String(s.type || '').startsWith('CVSS'));
  if (!cvss) return 'UNKNOWN';
  // A vector string without a score; rank by the qualitative band the spec
  // defines rather than inventing a number.
  const m = String(cvss.score || '').match(/^(\d+(?:\.\d+)?)$/);
  if (!m) return 'UNKNOWN';
  const n = Number(m[1]);
  if (n >= 9) return 'CRITICAL';
  if (n >= 7) return 'HIGH';
  if (n >= 4) return 'MODERATE';
  return 'LOW';
}

const worstSeverity = (vulns) => SEVERITY_ORDER.find((s) => vulns.some((v) => severityOf(v) === s)) || 'UNKNOWN';

/**
 * The version each advisory says fixes it, for the package we asked about.
 *
 * An advisory with no `fixed` event has no published fix — that is a distinct
 * and important answer, so it comes back as `null` in the list rather than
 * being dropped.
 */
function fixedVersions(vulns, pkgName) {
  const out = [];
  for (const vuln of vulns || []) {
    let fixed = null;
    for (const affected of vuln.affected || []) {
      // A single advisory can cover several packages; only ours orders our
      // upgrade.
      if (affected.package && affected.package.name && affected.package.name !== pkgName) continue;
      for (const range of affected.ranges || []) {
        for (const event of range.events || []) {
          if (event.fixed) fixed = fixed ? [fixed, event.fixed] : event.fixed;
        }
      }
    }
    // Several `fixed` events in one advisory (multiple affected branches): the
    // lowest that is ≥ current would be ideal, but the safe simplification is
    // the highest, which cannot land you back inside another range of the same
    // advisory.
    const flat = Array.isArray(fixed) ? fixed.flat(Infinity) : (fixed ? [fixed] : []);
    out.push({ id: vuln.id, severity: severityOf(vuln), summary: vuln.summary || null, fixed: flat });
  }
  return out;
}

/**
 * The plan for one package: the target version, what it clears, and what it
 * does not.
 */
function planUpgrade({ ecosystem, pkg, current, vulns, published = [], allowPrerelease = false }) {
  const compare = comparatorFor(ecosystem);
  if (!compare) return { state: 'unknown', reason: `no version ordering for ${ecosystem}` };
  if (!vulns || !vulns.length) return { state: 'clear', advisories: [] };

  const advisories = fixedVersions(vulns, pkg);
  const unfixed = advisories.filter((a) => !a.fixed.length);
  const targets = advisories.flatMap((a) => a.fixed);

  if (!targets.length) {
    return {
      state: 'no-fix',
      advisories,
      reason: `${advisories.length} advisor${advisories.length === 1 ? 'y' : 'ies'} apply and none names a fixed version`,
    };
  }

  // A single unorderable `fixed` value passes straight through maxVersion (a
  // one-element list is never compared), and then reads as a version in the
  // output: "a fix exists in sometime-soon, but no published version reaches
  // it". Check each target is orderable at all before trusting the maximum.
  const unorderable = targets.filter((t) => compare(t, t) === null);
  if (unorderable.length) {
    return {
      state: 'unknown',
      advisories,
      reason: `could not order the fixed versions (${unorderable.join(', ')})`,
    };
  }

  const needed = maxVersion(targets, compare);
  if (!needed) {
    return { state: 'unknown', advisories, reason: `could not order the fixed versions (${targets.join(', ')})` };
  }

  // The smallest published version that is at least `needed` — the *shortest*
  // safe move, not the newest release. Jumping to latest is a bigger change
  // than the advisory requires.
  const candidates = published
    .filter((v) => allowPrerelease || !isPrerelease(v, ecosystem))
    .filter((v) => {
      const c = compare(v, needed);
      return c !== null && c >= 0;
    })
    .sort((a, b) => compare(a, b) ?? 0);

  const target = candidates[0] || null;
  const latest = published.length ? maxVersion(published.filter((v) => allowPrerelease || !isPrerelease(v, ecosystem)), compare) : null;

  if (!target) {
    return {
      state: 'no-fix',
      advisories,
      needed,
      latest,
      reason: `a fix exists in ${needed}, but no published version reaches it`
        + `${latest ? ` (latest is ${latest})` : ''}`,
    };
  }

  return {
    state: 'upgrade',
    advisories,
    current,
    needed,
    target,
    latest,
    // Named because they change the reading: an advisory with no fix is not
    // cleared by any upgrade, and saying "upgrade to X" without that would be
    // a false all-clear.
    unresolved: unfixed.map((a) => a.id),
    steps_behind_latest: latest && target !== latest ? 'target is not the latest release' : null,
  };
}

/** Ask OSV what applies to one exact version. */
async function osvFor(ecosystem, name, version) {
  const payload = { package: { ecosystem: ecosystem === 'npm' ? 'npm' : 'PyPI', name }, version };
  const res = await postJson(OSV, payload, { timeoutMs: 15000, retries: 2 });
  if (!res.ok) return { ok: false, error: res.error || `HTTP ${res.status}`, vulns: [] };
  return { ok: true, vulns: (res.data && res.data.vulns) || [] };
}

/** Every version the registry has published, for picking the shortest hop. */
async function publishedVersions(ecosystem, name) {
  if (ecosystem === 'npm') {
    const res = await getJson(`https://registry.npmjs.org/${name.replace(/\//g, '%2f')}`, { cacheTtlMs: CACHE_TTL_MS, timeoutMs: 20000 });
    if (!res.ok) return { ok: false, versions: [], error: res.error || `HTTP ${res.status}` };
    return { ok: true, versions: Object.keys((res.data && res.data.versions) || {}) };
  }
  const res = await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { cacheTtlMs: CACHE_TTL_MS, timeoutMs: 20000 });
  if (!res.ok) return { ok: false, versions: [], error: res.error || `HTTP ${res.status}` };
  return { ok: true, versions: Object.keys((res.data && res.data.releases) || {}) };
}

async function checkEntry(tool, { osv = osvFor, published = publishedVersions } = {}) {
  const typed = toTypedEntry(tool);
  const eco = typed ? typed.artifact.ecosystem : null;
  const row = { name: tool.name, ecosystem: eco, package: null, current: tool.version || null, plan: { state: 'unknown' } };

  if (eco !== 'npm' && eco !== 'pypi') {
    row.plan = { state: 'unknown', reason: `${eco || 'unknown'} entries have no advisory feed keyed by version` };
    return row;
  }
  const pkg = eco === 'npm' ? npmPkgName(tool.install_cmd) : pypiPkgName(tool.install_cmd);
  row.package = pkg;
  if (!pkg || !tool.version) {
    row.plan = { state: 'unknown', reason: pkg ? 'no pinned version to compare against' : 'could not resolve a package name' };
    return row;
  }

  const now = await osv(eco, pkg, tool.version);
  if (!now.ok) {
    // An unreachable feed is not "clear".
    row.plan = { state: 'unknown', reason: `OSV did not answer: ${now.error}` };
    return row;
  }
  if (!now.vulns.length) {
    row.plan = { state: 'clear', advisories: [] };
    return row;
  }

  const pub = await published(eco, pkg);
  const plan = planUpgrade({
    ecosystem: eco, pkg, current: tool.version, vulns: now.vulns,
    published: pub.versions, allowPrerelease: false,
  });

  // "Fixed in 2.1.30" is per advisory. Ask about the target as well, because a
  // recommendation that moves someone onto a version with a *different* CVE is
  // worse than none.
  if (plan.state === 'upgrade') {
    const after = await osv(eco, pkg, plan.target);
    if (!after.ok) {
      // The check did not run. Saying "upgrade to X" on the strength of a
      // check that failed is the bug this whole repo is about, so the state
      // says the target is unconfirmed and every reader has to deal with it.
      plan.target_check = { ok: false, reason: after.error };
      plan.state = 'upgrade-unconfirmed';
    } else {
      const remaining = fixedVersions(after.vulns, pkg);
      plan.target_check = { ok: true, remaining: remaining.map((a) => ({ id: a.id, severity: a.severity })) };
      if (remaining.length) {
        // Try the newest release before giving up on a clean target.
        const latest = plan.latest;
        let cleanFound = false;
        if (latest && latest !== plan.target) {
          const atLatest = await osv(eco, pkg, latest);
          if (atLatest.ok && !atLatest.vulns.length) {
            plan.target = latest;
            plan.target_check = { ok: true, remaining: [], note: 'the shortest hop still had advisories; the latest release is clean' };
            cleanFound = true;
          } else if (!atLatest.ok) {
            plan.latest_check = { ok: false, reason: atLatest.error };
          } else {
            plan.latest_check = { ok: true, remaining: fixedVersions(atLatest.vulns, pkg).map((a) => ({ id: a.id, severity: a.severity })) };
          }
        }
        if (!cleanFound) {
          // No version we can name is clean. This is not an upgrade
          // recommendation and must not be counted as one — the previous
          // version of this code left `state: 'upgrade'` with a target whose
          // own advisories it had just read.
          plan.state = 'no-clean-target';
          // `current` is not in scope here — it is `planUpgrade`'s parameter,
          // not this function's. The only path that reached this line is the
          // one where a fix exists but is not clean, so the bug hid where it
          // did the most damage: a ReferenceError instead of an honest verdict.
          plan.reason = `${plan.target} clears the advisories against ${row.current} but has `
            + `${plan.target_check.remaining.length} of its own`
            + `${latest && latest !== plan.target ? `, and ${latest} is not clean either` : ''}`;
        }
      }
    }
  }

  row.plan = plan;
  return row;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`suggest_upgrade: ${opts.error}\n\n${HELP}`); return Promise.resolve(2); }
  if (opts.help)  { process.stdout.write(HELP); return Promise.resolve(0); }

  const { db } = readDb(DB_PATH);
  const tools = (db.tools || []).filter((t) => !opts.entry || t.name === opts.entry);
  if (opts.entry && !tools.length) {
    process.stderr.write(`suggest_upgrade: no entry named "${opts.entry}"\n`);
    return Promise.resolve(2);
  }

  return mapLimit(tools, CONCURRENCY, (t) => checkEntry(t)).then((rows) => {
    const STATES = ['upgrade', 'upgrade-unconfirmed', 'no-clean-target', 'no-fix'];
    const affected = rows.filter((r) => STATES.includes(r.plan.state));

    if (opts.json) {
      process.stdout.write(`${JSON.stringify({
        schema: 'mcp-vault/upgrade-plan@1',
        generated_at: new Date().toISOString(),
        source: 'OSV.dev',
        checked: rows.length,
        summary: {
          clear:               rows.filter((r) => r.plan.state === 'clear').length,
          upgrade:             rows.filter((r) => r.plan.state === 'upgrade').length,
          upgrade_unconfirmed: rows.filter((r) => r.plan.state === 'upgrade-unconfirmed').length,
          no_clean_target:     rows.filter((r) => r.plan.state === 'no-clean-target').length,
          no_fix:              rows.filter((r) => r.plan.state === 'no-fix').length,
          unknown:             rows.filter((r) => r.plan.state === 'unknown').length,
        },
        entries: rows,
      }, null, 2)}\n`);
    } else {
      for (const r of affected) {
        const p = r.plan;
        const worst = p.advisories ? worstSeverity((p.advisories || []).map((a) => ({ database_specific: { severity: a.severity } }))) : 'UNKNOWN';
        const colour = worst === 'CRITICAL' || worst === 'HIGH' ? RD : YL;
        const label = {
          'no-fix': 'NO FIX',
          'no-clean-target': 'NO CLEAN TARGET',
          'upgrade-unconfirmed': 'UNCONFIRMED',
          upgrade: 'UPGRADE',
        }[p.state] || p.state.toUpperCase();
        process.stdout.write(`\n${p.state === 'upgrade' ? colour : RD}${label}${RS}  ${B}${r.name}${RS} ${DM}${r.package}@${r.current}${RS}\n`);
        for (const a of p.advisories || []) {
          process.stdout.write(`  ${a.severity.padEnd(9)} ${a.id}${a.fixed.length ? ` — fixed in ${a.fixed.join(' / ')}` : ` — ${RD}no published fix${RS}`}\n`);
          if (a.summary) process.stdout.write(`            ${DM}${a.summary.slice(0, 96)}${RS}\n`);
        }
        if (p.state === 'upgrade' || p.state === 'upgrade-unconfirmed') {
          process.stdout.write(`  ${GN}→ ${r.package}@${p.target}${RS} clears ${(p.advisories || []).filter((a) => a.fixed.length).length} of ${(p.advisories || []).length}`);
          process.stdout.write(`${p.latest && p.latest !== p.target ? `  ${DM}(latest is ${p.latest})${RS}` : ''}\n`);
          if (p.unresolved && p.unresolved.length) {
            process.stdout.write(`  ${YL}still unresolved after the upgrade: ${p.unresolved.join(', ')}${RS}\n`);
          }
          if (p.target_check && p.target_check.ok && p.target_check.remaining.length) {
            process.stdout.write(`  ${YL}${p.target} itself has ${p.target_check.remaining.length} advisor${p.target_check.remaining.length === 1 ? 'y' : 'ies'}: `
              + `${p.target_check.remaining.map((x) => x.id).join(', ')}${RS}\n`);
          }
          if (p.target_check && p.target_check.note) process.stdout.write(`  ${DM}${p.target_check.note}${RS}\n`);
          if (p.target_check && !p.target_check.ok) {
            process.stdout.write(`  ${YL}could not confirm ${p.target} is clean: ${p.target_check.reason}${RS}\n`);
          }
          process.stdout.write(`  ${DM}verify_integrity.cjs --update will re-pin and re-hash it${RS}\n`);
        } else {
          process.stdout.write(`  ${RD}${p.reason}${RS}\n`);
        }
      }
      const unknown = rows.filter((r) => r.plan.state === 'unknown');
      const count = (state) => rows.filter((r) => r.plan.state === state).length;
      process.stdout.write(
        `\n${rows.length} checked — ${GN}${count('clear')} clear${RS}, `
        + `${count('upgrade')} with a confirmed safe upgrade, `
        + `${count('upgrade-unconfirmed')} with a target we could not confirm, `
        + `${count('no-clean-target')} where every candidate has advisories of its own, `
        + `${count('no-fix')} with no fix available, `
        + `${unknown.length} not checkable\n`
      );
    }

    return opts.strict && affected.length ? 1 : 0;
  });
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => exitAfterFlush(code)).catch((e) => {
    process.stderr.write(`suggest_upgrade: ${e.stack || e.message}\n`);
    exitAfterFlush(2);
  });
}

module.exports = { parseArgs, planUpgrade, fixedVersions, severityOf, checkEntry };
