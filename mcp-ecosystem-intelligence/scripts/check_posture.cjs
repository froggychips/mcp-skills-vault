#!/usr/bin/env node
/**
 * mcp-vault posture — what the upstream repository's own process looks like.
 *
 * Every other check in this repo is about the artifact. This one is about where
 * it came from: is the default branch protected, is code reviewed, can a fork
 * trigger the release workflow, are the CI actions pinned, are releases signed.
 * A perfectly verified artifact can come out of a repository anybody can push
 * to, and nothing here noticed that until now.
 *
 * The data is OpenSSF Scorecard's, read through deps.dev (no token needed). Two
 * things are done differently from how Scorecard is normally consumed, both for
 * the same reason this repo keeps three separate scores:
 *
 *   - the individual checks are recorded, not the 0–10 average. An average puts
 *     "there is a SECURITY.md" and "a fork can trigger the release workflow"
 *     into one number.
 *   - Scorecard's `-1` ("could not run this check") is recorded as `unknown`,
 *     never as a failure.
 *
 * Coverage, stated plainly: Scorecard only has reports for repositories someone
 * ran it on — about 4% of the repositories in this DB, the large vendor ones.
 * For the rest this prints `no report` and records nothing. It is still worth
 * running: those vendor repositories are where most installs come from.
 *
 * Usage:
 *   node scripts/check_posture.cjs [--json] [--write] [--entry <name>] [--strict]
 *
 * Exit codes:
 *   0  no repository with a report has a failing check
 *   1  at least one does (with --strict)
 *   2  bad arguments
 */

'use strict';

const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb, writeDb } = require('./lib/db_io.cjs');
const { mapLimit } = require('./lib/http.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { buildEvidence, mergeEvidence } = require('./lib/evidence.cjs');
const { fetchPosture, summarisePosture, repoSlug, POSTURE_CHECKS } = require('./lib/scorecard.cjs');

const DB_PATH     = path.resolve(__dirname, '../assets/tools_database.json');
const CONCURRENCY = 6;

const T  = process.stdout.isTTY;
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

function parseArgs(argv) {
  const opts = { json: false, write: false, entry: null, strict: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--write') opts.write = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--entry') opts.entry = argv[++i] || null;
    else if (a === '-h' || a === '--help') opts.help = true;
    else return { ...opts, error: `unknown flag ${a}` };
  }
  return opts;
}

const HELP = `check_posture — OpenSSF Scorecard checks for each entry's upstream repository

  node scripts/check_posture.cjs [--json] [--write] [--entry <name>] [--strict]

  --write    record 'repository_posture' evidence in the DB
  --strict   exit 1 when a repository with a report has a failing check
  --entry    check one entry by name

  Coverage is ~4% of this DB's repositories: Scorecard only has reports for
  projects somebody ran it on. Everything else reads "no report".
`;

async function checkEntry(tool) {
  const slug = repoSlug(tool.source_url);
  const typed = toTypedEntry(tool);
  const row = {
    name: tool.name,
    repository: slug,
    artifact_id: typed ? artifactId(typed.artifact) : null,
    posture: null,
    state: 'unknown',
    date: null,
    findings: [],
  };
  if (!slug) {
    row.findings.push(tool.source_url ? 'source is not a GitHub repository' : 'no source repository recorded');
    return row;
  }

  const res = await fetchPosture(slug);
  if (!res.ok) {
    // A feed that did not answer establishes nothing — not even "no report".
    row.findings.push(`could not reach the Scorecard feed: ${res.error}`);
    return row;
  }
  if (!res.posture) {
    row.no_report = true;
    return row;
  }

  const summary = summarisePosture(res.posture);
  row.posture  = res.posture;
  row.state    = summary.state;
  row.date     = res.date;
  row.overall  = res.overall;
  row.findings = summary.bad.map((b) => `${b.field}: ${b.why}`);
  row.passing  = summary.good;
  return row;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`check_posture: ${opts.error}\n\n${HELP}`); return Promise.resolve(2); }
  if (opts.help)  { process.stdout.write(HELP); return Promise.resolve(0); }

  const { db } = readDb(DB_PATH);
  const tools = (db.tools || []).filter((t) => !opts.entry || t.name === opts.entry);
  if (opts.entry && !tools.length) {
    process.stderr.write(`check_posture: no entry named "${opts.entry}"\n`);
    return Promise.resolve(2);
  }

  return mapLimit(tools, CONCURRENCY, (t) => checkEntry(t)).then((rows) => {
    const reported = rows.filter((r) => r.posture);
    const weak     = reported.filter((r) => r.state === 'weak');
    const clean    = reported.filter((r) => r.state === 'clean');

    if (opts.write) {
      const byName = new Map(rows.map((r) => [r.name, r]));
      let recorded = 0;
      for (const tool of db.tools || []) {
        const row = byName.get(tool.name);
        if (!row || !row.posture) continue;         // no report: nothing to record
        const fresh = buildEvidence({
          repository_posture: {
            state:  row.state,
            checks: row.posture,
            report_date: row.date,
          },
        }, { artifactId: row.artifact_id });
        tool.trust_evidence = mergeEvidence(tool.trust_evidence, fresh);
        recorded++;
      }
      if (recorded) writeDb(DB_PATH, db);
      process.stderr.write(`Recorded repository posture for ${recorded} entr${recorded === 1 ? 'y' : 'ies'} in ${DB_PATH}\n`);
    }

    if (opts.json) {
      process.stdout.write(`${JSON.stringify({
        schema: 'mcp-vault/posture@1',
        generated_at: new Date().toISOString(),
        source: 'OpenSSF Scorecard via deps.dev',
        checked: rows.length,
        summary: {
          with_report: reported.length,
          clean: clean.length,
          weak: weak.length,
          no_report: rows.filter((r) => r.no_report).length,
          unreachable: rows.filter((r) => !r.posture && !r.no_report).length,
        },
        checks_mapped: Object.fromEntries(Object.entries(POSTURE_CHECKS).map(([k, v]) => [k, v.field])),
        entries: rows,
      }, null, 2)}\n`);
    } else {
      for (const r of reported) {
        const colour = r.state === 'weak' ? YL : GN;
        process.stdout.write(`${colour}${r.state.padEnd(8)}${RS} ${r.name} ${DM}${r.repository}${r.date ? ` (report ${r.date})` : ''}${RS}\n`);
        for (const f of r.findings) process.stdout.write(`         ${YL}${f}${RS}\n`);
        if (r.passing && r.passing.length) process.stdout.write(`         ${DM}passing: ${r.passing.join(', ')}${RS}\n`);
      }
      const noReport = rows.filter((r) => r.no_report).length;
      process.stdout.write(
        `\n${rows.length} checked — ${reported.length} with a Scorecard report `
        + `(${GN}${clean.length} clean${RS}, ${YL}${weak.length} with a failing check${RS}), `
        + `${noReport} with no report, ${rows.length - reported.length - noReport} unreachable\n`
      );
      process.stdout.write(`${DM}"No report" is not a finding: Scorecard only covers repositories somebody ran it on.${RS}\n`);
    }

    return opts.strict && weak.length ? 1 : 0;
  });
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => exitAfterFlush(code)).catch((e) => {
    process.stderr.write(`check_posture: ${e.stack || e.message}\n`);
    exitAfterFlush(2);
  });
}

module.exports = { parseArgs, checkEntry };
