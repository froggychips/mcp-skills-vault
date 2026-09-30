'use strict';
/**
 * verify_summary: the weekly refresh records findings instead of dying on them.
 *
 * The failure these tests exist for: `verify_integrity --deep --record-evidence`
 * exited 1 on seven pinned versions with advisories, which failed the step,
 * skipped the rest of the refresh job and discarded the evidence it had just
 * written for the other 107 entries. The refresh step now captures the exit
 * code and asks this script whether the run is *usable*. The line that must
 * not move: a broken run (no report, crash code, exit code the report does not
 * explain) still stops the job.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const os     = require('node:os');
const path   = require('node:path');
const { spawnSync } = require('node:child_process');

const s = require('../mcp-ecosystem-intelligence/scripts/verify_summary.cjs');
const SCRIPT = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts/verify_summary.cjs');

const NOW = Date.parse('2026-09-30T12:00:00Z');

function report(entries) {
  return {
    schema: 'mcp-vault/verify-report@1',
    checked: entries.length,
    failures: entries.reduce((n, e) => n + (e.failures || 0), 0),
    unverified: entries.filter((e) => e.status === 'UNVERIFIED').length,
    entries,
  };
}
const ok   = (name) => ({ name, status: 'OK', version: '1.0.0', failures: 0, findings: [] });
const fail = (name) => ({
  name, status: 'FAIL', version: '3.5.1', failures: 1,
  findings: [
    { tag: 'SIG', level: 'note', message: 'registry signature verified' },
    { tag: 'CVE', level: 'error', message: '[HIGH] (npm) Tool Access Control Bypass' },
  ],
});
const staleOnly = (name) => ({
  name, status: 'UNVERIFIED', version: '1.0.0', failures: 0,
  findings: [{ tag: 'UNVERIFIED', level: 'warning', message: 'stored evidence has aged out: availability 13d old (max 7) (use --fail-unverified to fail closed)' }],
});
const unreachable = (name) => ({
  name, status: 'UNVERIFIED', version: '1.0.0', failures: 0,
  findings: [{ tag: 'UNVERIFIED', level: 'warning', message: 'no longer in the npm registry (404)' }],
});

test('findings are a usable result: exit 1 with failures in the report', () => {
  assert.deepEqual(s.judgeRun(report([ok('a'), fail('k8s')]), 1), { ok: true, reason: null });
  assert.deepEqual(s.judgeRun(report([ok('a')]), 0), { ok: true, reason: null });
});

test('a broken run is not: no report, wrong schema, crash code, unexplained code', () => {
  assert.equal(s.judgeRun(null, 1).ok, false);
  assert.equal(s.judgeRun({ entries: [] }, 0).ok, false);
  assert.equal(s.judgeRun({ ...report([ok('a')]), schema: 'other' }, 0).ok, false);
  assert.equal(s.judgeRun(report([]), 0).ok, false, 'a run that checked nothing is not a pass');
  // exit 1 with a clean report: the process died after printing, or something
  // other than findings produced the code.
  assert.equal(s.judgeRun(report([ok('a')]), 1).ok, false);
  // exit 0 with failures: the gate and its report disagree.
  assert.equal(s.judgeRun(report([fail('k8s')]), 0).ok, false);
  assert.equal(s.judgeRun(report([ok('a')]), 2).ok, false);
});

test('unverified is split into "could not check" and "only stale evidence"', () => {
  const c = s.classify(report([ok('a'), fail('k8s'), staleOnly('b'), unreachable('gone')]));
  assert.equal(c.ok, 1);
  assert.deepEqual(c.failed.map((f) => f.name), ['k8s']);
  // Only the hard findings are carried for a FAIL row; the SIG note is noise there.
  assert.deepEqual(c.failed[0].findings.map((f) => f.tag), ['CVE']);
  assert.deepEqual(c.unverified.stale.map((u) => u.name), ['b']);
  assert.deepEqual(c.unverified.other.map((u) => u.name), ['gone']);
});

test('freshness counts what the DB now holds, per dimension', () => {
  const db = { tools: [
    { name: 'fresh', trust: 'verified', trust_evidence: { dimensions: {
      availability: { status: 'present', checked_at: '2026-09-30' },
      advisories:   { status: 'clean',   checked_at: '2026-09-30' },
    } } },
    { name: 'stale', trust: 'candidate', trust_evidence: { dimensions: {
      availability: { status: 'present', checked_at: '2026-09-17' },
      advisories:   { status: 'clean',   checked_at: '2026-09-30' },
    } } },
    { name: 'none', trust: 'candidate' },
  ] };
  const f = s.freshness(db, NOW);
  assert.equal(f.total, 3);
  assert.equal(f.datedToday, 2);
  assert.equal(f.fullyFresh, 2, 'an entry without evidence has nothing stale — it is counted by trust instead');
  assert.deepEqual(f.staleBy, { availability: ['stale'] });
  assert.deepEqual(f.trust, { verified: 1, candidate: 2 });
});

test('the markdown names the FAIL entries and says the gate still refuses them', () => {
  const { markdown, verdict } = s.renderMarkdown(report([ok('a'), fail('mcp-server-kubernetes'), staleOnly('b')]), { rc: 1, now: NOW });
  assert.equal(verdict.ok, true);
  assert.match(markdown, /\*\*1 FAIL\*\*/);
  assert.match(markdown, /\| mcp-server-kubernetes \| 3\.5\.1 \| \[CVE\] \[HIGH\]/);
  assert.match(markdown, /install gate still refuses/);
  assert.match(markdown, /aged out \(1\)/);
});

test('a pipe in a finding cannot break the table', () => {
  const e = fail('x');
  e.findings[1].message = 'a | b';
  const { markdown } = s.renderMarkdown(report([e]), { rc: 1, now: NOW });
  assert.match(markdown, /a \\\| b/);
});

test('a trailing backslash cannot un-escape the pipe after it', () => {
  const e = fail('x');
  e.findings[1].message = 'a \\| b';
  const { markdown } = s.renderMarkdown(report([e]), { rc: 1, now: NOW });
  assert.ok(markdown.includes('a \\\\\\| b'), 'expected the backslash and the pipe each escaped');
});

test('an unusable run renders a warning, not a findings table', () => {
  const { markdown, verdict } = s.renderMarkdown(null, { rc: 1, now: NOW });
  assert.equal(verdict.ok, false);
  assert.match(markdown, /not usable/);
  assert.doesNotMatch(markdown, /### FAIL/);
});

test('CLI: exit 0 on findings, 2 on a missing or truncated report', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vsum-'));
  try {
    const good = path.join(dir, 'r.json');
    fs.writeFileSync(good, JSON.stringify(report([ok('a'), fail('k8s')])));
    const out = path.join(dir, 'summary.md');
    let r = spawnSync(process.execPath, [SCRIPT, good, '--rc', '1', '--out', out], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(fs.readFileSync(out, 'utf8'), /k8s/);

    const truncated = path.join(dir, 't.json');
    fs.writeFileSync(truncated, '{"schema":"mcp-vault/verify-report@1","entries":[');
    r = spawnSync(process.execPath, [SCRIPT, truncated, '--rc', '1'], { encoding: 'utf8' });
    assert.equal(r.status, 2);

    r = spawnSync(process.execPath, [SCRIPT, path.join(dir, 'missing.json'), '--rc', '0'], { encoding: 'utf8' });
    assert.equal(r.status, 2);

    r = spawnSync(process.execPath, [SCRIPT, good, '--rc', 'x'], { encoding: 'utf8' });
    assert.equal(r.status, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
