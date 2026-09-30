#!/usr/bin/env node
/**
 * Turn a `verify_integrity --json` report into the markdown a reviewer reads:
 * the job summary and the body of the weekly refresh PR.
 *
 * Why this exists. The weekly refresh ran
 * `verify_integrity --deep --record-evidence` as a plain step, so its exit code
 * was the step's verdict. The verifier exits 1 whenever any entry has a hard
 * finding — which is its job as an install gate — and seven pinned versions
 * with published advisories were enough to fail the step. Every step after it
 * was skipped: the availability check that would have refreshed seven-day
 * evidence, the scores, the PR. The evidence the step had just written for all
 * 114 entries was thrown away with the runner's checkout, the DB stayed dated
 * 17.09, and the next week's run met the same advisories and the same stale
 * dates. A writer step that cannot write while there is anything to report
 * never reports anything.
 *
 * In the refresh job an advisory is a *result*: it is recorded as
 * `advisories: vulnerable` (trust drops to `unverified`), and it belongs in the
 * PR a human reads. So the step captures the exit code, and this script decides
 * whether the run is usable:
 *
 *   exit 0  the report parsed and the verifier's exit code matches it
 *           (0 with no failures, 1 with failures) — findings are data
 *   exit 2  anything else: no report, unparseable JSON, a crash exit code, or
 *           an exit code the report does not explain. That is a broken tool,
 *           not a finding, and the job must stop before opening a PR.
 *
 * Nothing here relaxes the install gate: `orchestrate --install` and a user's
 * `verify_integrity --fail-unverified` still fail closed on the same findings.
 *
 * Usage:
 *   node scripts/verify_summary.cjs <report.json> [--rc <verifier exit code>]
 *                                   [--db <tools_database.json>] [--out <file>]
 *                                   [--as-of <date|instant>]
 *
 *   --rc   the verifier's exit code (default 0)
 *   --db   the DB after the run; adds how many entries now carry fresh evidence
 *   --out  write the markdown there as well as to stdout
 *   --as-of the instant freshness is judged at (lib/clock.cjs). Default: the
 *          report's own `as_of` — the instant the verifier judged and dated
 *          the evidence at — so "dated today" and "past its age limit" agree
 *          with the run being summarised; the wall clock (read once, in main)
 *          only when the report carries none.
 */

'use strict';

const fs = require('fs');
const { staleDimensions, DEFAULT_MAX_AGE_DAYS } = require('./lib/evidence.cjs');
const { asOfFromArgv, readWallClock, requireAsOf, isoDay, stripAsOf } = require('./lib/clock.cjs');

// GitHub rejects a PR body over 65536 characters; the summary shares the body
// with the checklist, so it gets well under that.
const MAX_CHARS = 40000;

const STALE_RE = /stored evidence has aged out/;

function cell(s, max = 160) {
  // Backslash first: escaping only `|` would let a value ending in `\` turn
  // the added `\|` into an escaped backslash followed by a live column break.
  const t = String(s == null ? '' : s).replace(/\s+/g, ' ').replace(/\\/g, '\\\\').replace(/\|/g, '\\|').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/**
 * Is this report usable, given the exit code the verifier returned?
 * Returns { ok, reason }.
 */
function judgeRun(report, rc) {
  if (!report || typeof report !== 'object' || !Array.isArray(report.entries)) {
    return { ok: false, reason: 'no verify report (the verifier crashed or printed no JSON)' };
  }
  if (report.schema !== 'mcp-vault/verify-report@1') {
    return { ok: false, reason: `unexpected report schema ${JSON.stringify(report.schema)}` };
  }
  if (!report.entries.length) return { ok: false, reason: 'the report checked no entries' };
  const failures = report.entries.reduce((n, e) => n + (e.failures || 0), 0);
  if (rc === 0 && failures === 0) return { ok: true, reason: null };
  if (rc === 1 && failures > 0)  return { ok: true, reason: null };
  return {
    ok: false,
    reason: `verifier exited ${rc} with ${failures} failure(s) in its report — an exit code the findings do not explain`,
  };
}

/** Group the report into what a reviewer acts on. */
function classify(report) {
  const failed = [];
  const unverified = { stale: [], other: [] };
  let ok = 0;
  for (const e of report.entries || []) {
    const findings = e.findings || [];
    if (e.status === 'FAIL') {
      const hard = findings.filter((f) => f.level === 'error');
      failed.push({
        name: e.name,
        version: e.version,
        findings: hard.length ? hard : findings,
      });
    } else if (e.status === 'UNVERIFIED') {
      const nonStale = findings.filter((f) => f.tag === 'UNVERIFIED' && !STALE_RE.test(f.message));
      const staleOnly = !nonStale.length && findings.some((f) => STALE_RE.test(f.message));
      (staleOnly ? unverified.stale : unverified.other).push({
        name: e.name,
        version: e.version,
        why: (nonStale[0] || findings.find((f) => STALE_RE.test(f.message)) || findings[0] || {}).message || '',
      });
    } else if (e.status === 'OK') {
      ok++;
    }
  }
  return { failed, unverified, ok };
}

/**
 * Freshness of what the DB now holds: how many entries carry evidence dated
 * today, and which dimensions are still past their age limit (dimensions this
 * run does not produce, and nothing earlier in the job refreshed).
 */
function freshness(db, asOf) {
  const now = requireAsOf(asOf, 'verify_summary.freshness');
  const today = isoDay(now);
  const tools = (db && db.tools) || [];
  const staleBy = {};
  const trust = {};
  let datedToday = 0;
  let fullyFresh = 0;
  for (const t of tools) {
    trust[t.trust || 'none'] = (trust[t.trust || 'none'] || 0) + 1;
    const dims = (t.trust_evidence && t.trust_evidence.dimensions) || {};
    if (Object.values(dims).some((d) => d && d.checked_at === today)) datedToday++;
    const stale = staleDimensions(t.trust_evidence, DEFAULT_MAX_AGE_DAYS, now);
    if (!stale.length) fullyFresh++;
    for (const s of stale) (staleBy[s.dimension] = staleBy[s.dimension] || []).push(t.name);
  }
  return { total: tools.length, datedToday, fullyFresh, staleBy, trust };
}

function renderMarkdown(report, { rc = 0, db = null, asOf } = {}) {
  const verdict = judgeRun(report, rc);
  const lines = ['## Re-verify and dated evidence', ''];
  if (!verdict.ok) {
    lines.push(`**The verifier run is not usable:** ${verdict.reason}.`, '',
      'No evidence from this run should be trusted; the job stops before opening a PR.');
    return { markdown: `${lines.join('\n')}\n`, verdict };
  }

  const { failed, unverified, ok } = classify(report);
  const nUnverified = unverified.stale.length + unverified.other.length;
  lines.push(`${report.entries.length} entries checked — ${ok} OK, **${failed.length} FAIL**, ${nUnverified} unverified (verifier exit ${rc}).`, '');

  if (db) {
    const f = freshness(db, asOf);
    const trust = Object.entries(f.trust).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${v} ${k}`).join(', ');
    lines.push(`Evidence written: ${f.datedToday} of ${f.total} entries carry evidence dated today; `
      + `${f.fullyFresh} have no dimension past its age limit. Trust now: ${trust}.`, '');
    const staleDims = Object.entries(f.staleBy);
    if (staleDims.length) {
      lines.push('Still past the age limit after this run:', '');
      for (const [dim, names] of staleDims) {
        lines.push(`- \`${dim}\` (max ${DEFAULT_MAX_AGE_DAYS[dim]}d): ${names.length} — ${cell(names.slice(0, 12).join(', '), 400)}${names.length > 12 ? ', …' : ''}`);
      }
      lines.push('');
    }
  }

  lines.push('Findings below are recorded in the DB (an advisory lands as `advisories: vulnerable`, '
    + 'which derives `trust: unverified`) instead of blocking the write. The install gate still refuses these entries.', '');

  if (failed.length) {
    lines.push('### FAIL — needs a re-pin, an upgrade or removal', '',
      '| entry | pinned | findings |', '| --- | --- | --- |');
    for (const f of failed) {
      const shown = f.findings.slice(0, 3).map((x) => `[${x.tag}] ${x.message}`).join('; ');
      const more = f.findings.length > 3 ? ` (+${f.findings.length - 3} more)` : '';
      lines.push(`| ${cell(f.name, 60)} | ${cell(f.version, 30)} | ${cell(shown, 400)}${more} |`);
    }
    lines.push('', 'The **Advisories and the shortest safe version** table in the job summary names the version that clears each one.', '');
  }

  if (unverified.other.length) {
    lines.push('### Unverified — could not be checked', '', '| entry | why |', '| --- | --- |');
    for (const u of unverified.other) lines.push(`| ${cell(u.name, 60)} | ${cell(u.why, 200)} |`);
    lines.push('');
  }
  if (unverified.stale.length) {
    lines.push(`### Unverified only because stored evidence aged out (${unverified.stale.length})`, '',
      'Checked this run, but a dimension the verifier does not itself produce is still past its limit '
      + '(see the list above); the next check that records it clears this.', '',
      cell(unverified.stale.map((u) => u.name).join(', '), 4000), '');
  }

  let markdown = `${lines.join('\n')}\n`;
  if (markdown.length > MAX_CHARS) {
    markdown = `${markdown.slice(0, MAX_CHARS)}\n\n… truncated; the full report is in the job log.\n`;
  }
  return { markdown, verdict };
}

function parseArgs(argv) {
  const out = { report: null, rc: 0, db: null, out: null, asOf: null };
  const clock = asOfFromArgv(argv);
  if (clock.error) return { error: clock.error };
  if (clock.source === 'as-of') out.asOf = clock.asOf;
  argv = stripAsOf(argv);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--rc') out.rc = Number(argv[++i]);
    else if (a === '--db') out.db = argv[++i];
    else if (a === '--out') out.out = argv[++i];
    else if (!a.startsWith('--') && !out.report) out.report = a;
    else return { error: `unknown argument: ${a}` };
  }
  if (!out.report) return { error: 'missing <report.json>' };
  if (!Number.isInteger(out.rc)) return { error: '--rc takes an integer' };
  return out;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) {
    process.stderr.write(`verify_summary: ${opts.error}\n`);
    return 2;
  }
  let report = null;
  try { report = JSON.parse(fs.readFileSync(opts.report, 'utf8')); } catch { report = null; }
  let db = null;
  if (opts.db) {
    try { db = JSON.parse(fs.readFileSync(opts.db, 'utf8')); } catch { db = null; }
  }
  // Time is an input (docs/adr/0001): --as-of, else the instant the verifier
  // judged at, else the wall clock — read once, here.
  let asOf = opts.asOf;
  if (asOf === null && report && typeof report.as_of === 'string' && Number.isFinite(Date.parse(report.as_of))) {
    asOf = Date.parse(report.as_of);
  }
  if (asOf === null) asOf = readWallClock();
  const { markdown, verdict } = renderMarkdown(report, { rc: opts.rc, db, asOf });
  process.stdout.write(markdown);
  if (opts.out) fs.writeFileSync(opts.out, markdown);
  if (!verdict.ok) process.stderr.write(`verify_summary: ${verdict.reason}\n`);
  return verdict.ok ? 0 : 2;
}

if (require.main === module) {
  const { exitAfterFlush } = require('./lib/exit.cjs');
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { judgeRun, classify, freshness, renderMarkdown, parseArgs, main };
