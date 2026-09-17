#!/usr/bin/env node
/**
 * mcp-vault capabilities — what a package can do, and what it gained since the
 * version we last looked at.
 *
 * This is the gap the rest of the repo cannot see. The gate answers "are these
 * the bytes we expected"; the advisory feeds answer "does anyone know something
 * bad about this version". Neither notices a patch release that starts reading
 * `process.env` and shelling out, because that is not a hash mismatch and it
 * does not have a CVE yet. The window between "compromised release published"
 * and "advisory published" is exactly where an integrity scanner is blind, and
 * a capability delta is what sees into it.
 *
 * Two rules make this honest rather than theatrical, and both are enforced in
 * lib/capabilities.cjs:
 *
 *   1. **`found` is a fact; `absent` is never recorded.** A capability found
 *      with a file and a line is evidence. Not finding one says something about
 *      our detector, not about the package: minified bundles, dynamic requires
 *      and runtime-built strings all defeat a pattern scan. Every report
 *      carries a coverage block saying what was actually read.
 *   2. **Additions are findings; disappearances are not improvements.** A
 *      capability that stopped matching is as likely to mean a new bundler as a
 *      changed behaviour.
 *
 * Scope: the package's own files. A capability that arrives through a
 * dependency is not visible here — `verify --deps` walks that tree, and the two
 * checks are complementary rather than overlapping.
 *
 * History lives in `assets/capabilities.json`, keyed by `npm:pkg@version`, so a
 * version bump in a pull request shows its capability delta *in the diff*.
 *
 * Usage:
 *   node scripts/check_capabilities.cjs [--entry <name>] [--write] [--json]
 *                                       [--strict] [--all]
 *
 * Exit codes:
 *   0  nothing new appeared
 *   1  --strict and a high-risk capability appeared since the last scan
 *   2  bad arguments
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const https = require('https');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb } = require('./lib/db_io.cjs');
const { getJson, mapLimit } = require('./lib/http.cjs');
const { npmPkgName } = require('./lib/install_cmd.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { readTarGz } = require('./lib/tarball.cjs');
const { detect, diffCapabilities, HIGH_RISK, CAPABILITIES } = require('./lib/capabilities.cjs');
const { comparatorFor } = require('./lib/versions.cjs');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const CAPS_PATH = path.resolve(__dirname, '../assets/capabilities.json');
const CONCURRENCY = 4;
// Tarballs are the heavy fetch here. 16 MB covers every MCP server in the DB
// (the largest is under 3 MB) and refuses a package that is mostly fixtures.
const MAX_TARBALL_BYTES = 16 * 1024 * 1024;
const MAX_SCAN_BYTES    = 6 * 1024 * 1024;

const T  = process.stdout.isTTY;
const B  = T ? '\x1b[1m'  : '';
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

function parseArgs(argv) {
  const opts = { entry: null, write: false, json: false, strict: false, all: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--write') opts.write = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--all') opts.all = true;
    else if (a === '--entry') opts.entry = argv[++i] || null;
    else if (a === '-h' || a === '--help') opts.help = true;
    else return { ...opts, error: `unknown flag ${a}` };
  }
  return opts;
}

const HELP = `check_capabilities — what a package can do, and what it gained

  node scripts/check_capabilities.cjs [--entry <name>] [--write] [--json] [--strict] [--all]

  --write    record the scan in assets/capabilities.json (the delta baseline)
  --strict   exit 1 when a high-risk capability appeared since the last scan
  --all      scan every entry, not only those whose version changed since the
             last recorded scan
`;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

/**
 * Fetch a tarball into memory, with a hard ceiling.
 *
 * Streamed and aborted past the limit rather than buffered and checked: the
 * point of a limit is not to have the bytes.
 */
function fetchTarball(url, { maxBytes = MAX_TARBALL_BYTES, timeoutMs = 30000 } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { resolve({ ok: false, error: 'bad tarball url' }); return; }
    if (u.protocol !== 'https:') { resolve({ ok: false, error: 'refusing a non-https tarball' }); return; }

    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        const next = res.headers.location;
        if (!next) { resolve({ ok: false, error: `redirect with no location (${res.statusCode})` }); return; }
        resolve(fetchTarball(new URL(next, url).toString(), { maxBytes, timeoutMs }));
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        resolve({ ok: false, error: `HTTP ${res.statusCode}` });
        return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) {
          req.destroy();
          resolve({ ok: false, error: `tarball larger than ${Math.round(maxBytes / 1024 / 1024)} MB` });
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => resolve({ ok: true, buffer: Buffer.concat(chunks), bytes: size }));
      res.on('error', (e) => resolve({ ok: false, error: e.message }));
    });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: `timeout after ${timeoutMs}ms` }); });
  });
}

/**
 * The most recent recorded scan for this package at a *different* version.
 *
 * "Different" matters: comparing a version with itself produces an empty delta
 * and would hide the fact that nothing new has been looked at.
 */
function previousScan(history, ecosystem, pkg, currentVersion) {
  const compare = comparatorFor(ecosystem);
  const prefix = `${ecosystem}:${pkg}@`;
  const candidates = Object.entries(history.packages || {})
    .filter(([key]) => key.startsWith(prefix))
    .map(([key, value]) => ({ version: key.slice(prefix.length), ...value }))
    .filter((r) => r.version !== currentVersion);
  if (!candidates.length) return null;
  if (!compare) return candidates[candidates.length - 1];
  // The highest version below the current one; failing that, the highest recorded.
  const below = candidates.filter((r) => {
    const c = compare(r.version, currentVersion);
    return c !== null && c < 0;
  });
  const pool = below.length ? below : candidates;
  return pool.reduce((best, r) => {
    if (!best) return r;
    const c = compare(r.version, best.version);
    return c !== null && c > 0 ? r : best;
  }, null);
}

async function scanEntry(tool, history) {
  const typed = toTypedEntry(tool);
  const eco = typed ? typed.artifact.ecosystem : null;
  const row = { name: tool.name, ecosystem: eco, package: null, version: tool.version || null, artifact_id: typed ? artifactId(typed.artifact) : null };

  if (eco !== 'npm') {
    // PyPI sdists are zip/tar.gz with a different layout and wheels are zips;
    // supporting them means a zip reader, which is a separate piece of work.
    // Saying so beats reporting "no capabilities found" for nine entries.
    row.state = 'unsupported';
    row.reason = `${eco || 'unknown'} packages are not scanned yet (npm only)`;
    return row;
  }
  const pkg = npmPkgName(tool.install_cmd);
  row.package = pkg;
  if (!pkg || !tool.version) {
    row.state = 'unsupported';
    row.reason = pkg ? 'no pinned version to scan' : 'could not resolve a package name';
    return row;
  }

  const meta = await getJson(`https://registry.npmjs.org/${pkg.replace('/', '%2f')}/${tool.version}`, { cacheTtlMs: 60 * 60 * 1000 });
  const tarballUrl = meta.ok && meta.data && meta.data.dist && meta.data.dist.tarball;
  if (!tarballUrl) {
    row.state = 'unknown';
    row.reason = `no tarball url for ${pkg}@${tool.version}: ${meta.error || 'registry metadata incomplete'}`;
    return row;
  }

  const got = await fetchTarball(tarballUrl);
  if (!got.ok) {
    row.state = 'unknown';
    row.reason = `could not fetch the tarball: ${got.error}`;
    return row;
  }

  const read = readTarGz(got.buffer, {
    include: (p) => /\.(?:js|cjs|mjs|jsx|ts|tsx|mts|cts)$/i.test(p) || /\/package\.json$/.test(p),
    maxBytes: MAX_SCAN_BYTES,
  });
  if (!read.ok) {
    row.state = 'unknown';
    row.reason = read.error;
    return row;
  }

  const manifest = read.files.find((f) => /^[^/]+\/package\.json$/.test(f.path));
  let packageJson = null;
  try { packageJson = manifest ? JSON.parse(manifest.text) : null; } catch { /* a manifest we cannot parse is not a manifest */ }

  const scan = detect(read.files, packageJson);
  row.state = 'scanned';
  row.found = scan.found;
  row.coverage = { ...scan.coverage, tarball_bytes: got.bytes, truncated: Boolean(read.truncated) };
  row.notes = scan.notes;

  const prev = previousScan(history, 'npm', pkg, tool.version);
  if (prev) {
    row.compared_with = prev.version;
    row.delta = diffCapabilities(prev, { found: scan.found, coverage: scan.coverage });
  } else {
    row.delta = null;
    row.baseline = true;
  }
  return row;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`check_capabilities: ${opts.error}\n\n${HELP}`); return Promise.resolve(2); }
  if (opts.help)  { process.stdout.write(HELP); return Promise.resolve(0); }

  const { db } = readDb(DB_PATH);
  const history = readJson(CAPS_PATH, { $schema: 'mcp-vault/capabilities@1', packages: {} });

  let tools = (db.tools || []).filter((t) => !opts.entry || t.name === opts.entry);
  if (opts.entry && !tools.length) {
    process.stderr.write(`check_capabilities: no entry named "${opts.entry}"\n`);
    return Promise.resolve(2);
  }
  if (!opts.all && !opts.entry) {
    // Default to what has moved: re-scanning an unchanged version costs a
    // tarball download and can only produce the answer already on disk.
    tools = tools.filter((t) => {
      const pkg = npmPkgName(t.install_cmd);
      if (!pkg || !t.version) return true;
      return !history.packages[`npm:${pkg}@${t.version}`];
    });
  }

  if (!tools.length) {
    process.stdout.write('Every pinned version has already been scanned. `--all` re-scans them.\n');
    return Promise.resolve(0);
  }

  return mapLimit(tools, CONCURRENCY, (t) => scanEntry(t, history)).then((rows) => {
    const scanned = rows.filter((r) => r.state === 'scanned');
    const withAdditions = scanned.filter((r) => r.delta && r.delta.added.length);
    const highRisk = withAdditions.filter((r) => r.delta.added.some((a) => a.high_risk));

    if (opts.write) {
      for (const r of scanned) {
        history.packages[`npm:${r.package}@${r.version}`] = {
          checked_at: new Date().toISOString().slice(0, 10),
          // Evidence, not just the capability names: a reader of the diff
          // should be able to go and look at the line.
          found: r.found,
          coverage: r.coverage,
        };
      }
      history.generated_at = new Date().toISOString();
      history.note = 'Capability presence with evidence, per package version. `found` is a fact; absence is never recorded — see lib/capabilities.cjs.';
      const ordered = { $schema: history.$schema, generated_at: history.generated_at, note: history.note, packages: {} };
      for (const key of Object.keys(history.packages).sort()) ordered.packages[key] = history.packages[key];
      fs.writeFileSync(CAPS_PATH, `${JSON.stringify(ordered, null, 2)}\n`);
      process.stderr.write(`Recorded ${scanned.length} scan(s) in ${CAPS_PATH}\n`);
    }

    if (opts.json) {
      process.stdout.write(`${JSON.stringify({
        schema: 'mcp-vault/capability-scan@1',
        generated_at: new Date().toISOString(),
        scanned: scanned.length,
        summary: {
          with_additions: withAdditions.length,
          high_risk_additions: highRisk.length,
          baselines: scanned.filter((r) => r.baseline).length,
          unsupported: rows.filter((r) => r.state === 'unsupported').length,
          unknown: rows.filter((r) => r.state === 'unknown').length,
        },
        entries: rows,
      }, null, 2)}\n`);
    } else {
      for (const r of scanned) {
        const caps = Object.keys(r.found || {});
        const risky = caps.filter((c) => HIGH_RISK.has(c));
        process.stdout.write(`\n${B}${r.name}${RS} ${DM}${r.package}@${r.version}${RS}\n`);
        process.stdout.write(`  ${caps.length ? caps.map((c) => (HIGH_RISK.has(c) ? `${YL}${c}${RS}` : c)).join(', ') : `${DM}nothing matched${RS}`}\n`);
        process.stdout.write(`  ${DM}${r.coverage.code_files} code file(s), ${r.coverage.bytes} bytes`
          + `${r.coverage.minified ? ', minified' : ''}${r.coverage.truncated ? ', scan truncated' : ''} — ${r.coverage.caveat}${RS}\n`);
        if (r.baseline) {
          process.stdout.write(`  ${DM}first scan of this package — nothing to compare against yet${RS}\n`);
          continue;
        }
        if (r.delta && r.delta.added.length) {
          for (const a of r.delta.added) {
            const colour = a.high_risk ? RD : YL;
            process.stdout.write(`  ${colour}+ ${a.capability}${RS} since ${r.compared_with} — ${a.why || ''}\n`);
            for (const e of a.evidence) process.stdout.write(`      ${DM}${e.file}:${e.line || '?'}  ${e.match}${RS}\n`);
          }
        } else if (r.delta) {
          process.stdout.write(`  ${GN}no new capability since ${r.compared_with}${RS}\n`);
        }
        if (r.delta && r.delta.removed.length) {
          process.stdout.write(`  ${DM}stopped matching: ${r.delta.removed.map((x) => x.capability).join(', ')} `
            + `— may be a change in behaviour, or only in readability${RS}\n`);
        }
        if (r.delta && r.delta.coverage_note) process.stdout.write(`  ${YL}${r.delta.coverage_note}${RS}\n`);
        void risky;
      }
      process.stdout.write(
        `\n${rows.length} entr${rows.length === 1 ? 'y' : 'ies'} — ${scanned.length} scanned, `
        + `${withAdditions.length} gained a capability${highRisk.length ? `, ${RD}${highRisk.length} of them high-risk${RS}` : ''}, `
        + `${rows.filter((r) => r.state === 'unsupported').length} unsupported, ${rows.filter((r) => r.state === 'unknown').length} not readable\n`
      );
      process.stdout.write(`${DM}A capability found is a fact; nothing here says a package cannot do something.${RS}\n`);
    }

    return opts.strict && highRisk.length ? 1 : 0;
  });
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => exitAfterFlush(code)).catch((e) => {
    process.stderr.write(`check_capabilities: ${e.stack || e.message}\n`);
    exitAfterFlush(2);
  });
}

module.exports = { parseArgs, fetchTarball, previousScan, scanEntry, CAPABILITIES };
