'use strict';
/**
 * finding_reports: drafts for someone else's tracker, so the bar is "only real
 * findings, only facts, nothing opened".
 *
 * Pinned down here: a clean entry produces nothing; the text never asks the
 * author to add a badge or anything else for us; the same inputs write the
 * same bytes; stale evidence is flagged in the index; and the script contains
 * no code that could open an issue anywhere.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

const SCRIPT = path.join(__dirname, '..', '.github', 'scripts', 'finding_reports.cjs');
const fr = require(SCRIPT);

const day = (d) => Date.parse(`${d}T00:00:00Z`);
const NOW = day('2026-09-20');

const tool = (name, dims = {}, over = {}) => ({
  name, install_cmd: `npx -y ${name}@1.0.0`, version: '1.0.0', trust: 'verified',
  source_url: `https://github.com/owner/${name}`,
  trust_evidence: {
    artifact_id: `npm:${name}@1.0.0`,
    dimensions: {
      availability: { status: 'present', checked_at: '2026-09-17' },
      artifact:     { status: 'verified', checked_at: '2026-09-17' },
      advisories:   { status: 'clean', checked_at: '2026-09-17' },
      source_binding: { status: 'verified', checked_at: '2026-09-17' },
      ...dims,
    },
  },
  ...over,
});

const clean      = tool('clean-server');
const vulnerable = tool('vuln-server', { advisories: { status: 'vulnerable', checked_at: '2026-09-17' } });
const mismatch   = tool('moved-server', { source_binding: { status: 'mismatch', checked_at: '2026-09-17' } });
const yanked     = tool('yanked-server', { availability: { status: 'yanked', checked_at: '2026-09-01', detail: 'yanked: broken build' } });
const hooks      = tool('hooky-server', { dependencies: { status: 'hooks', checked_at: '2026-09-17', count: 212 } });

const upgrades = new Map([['vuln-server', {
  name: 'vuln-server', current: '1.0.0',
  plan: { state: 'upgrade', target: '1.2.0', advisories: [
    { id: 'GHSA-bbbb-2222-bbbb', severity: 'MODERATE', fixed: ['1.2.0'] },
    { id: 'GHSA-aaaa-1111-aaaa', severity: 'HIGH', fixed: ['1.1.0'] },
  ] },
}]]);

test('an entry with no finding is not in the report at all', () => {
  assert.deepEqual(fr.findingsFor(clean, null, null, { asOf: NOW }), []);
  const { files, index } = fr.buildReports([clean, vulnerable], new Map(), upgrades, { asOf: NOW });
  assert.equal(index.count, 1);
  assert.deepEqual(index.entries.map((e) => e.name), ['vuln-server']);
  assert.equal(files.has('clean-server.md'), false);
  // Positive statuses of every dimension are not findings either.
  const allGood = tool('ok', { dependencies: { status: 'clean', checked_at: '2026-09-17' }, registry: { status: 'listed', checked_at: '2026-09-17' } });
  assert.deepEqual(fr.findingsFor(allGood, { surface_drift: null }, null, { asOf: NOW }), []);
});

test('each finding type is recognised from stored evidence', () => {
  const t = (x, ev) => fr.findingsFor(x, ev || null, null, { asOf: NOW }).map((f) => f.type);
  assert.deepEqual(t(vulnerable), ['advisory']);
  assert.deepEqual(t(mismatch), ['identity']);
  assert.deepEqual(t(yanked), ['availability']);
  assert.deepEqual(t(hooks), ['dependency-hooks']);
  assert.deepEqual(t(clean, { checked_at: '2026-09-18', surface_drift: { artifact_changed: false, since: '2026-09-01', lines: ['tool x: description changed'] } }), ['surface-unexplained']);
  // A drift explained by a new artifact, or one that could not be compared, is not a finding.
  assert.deepEqual(t(clean, { checked_at: '2026-09-18', surface_drift: { artifact_changed: true } }), []);
  assert.deepEqual(t(clean, { checked_at: '2026-09-18', surface_drift: { artifact_changed: null } }), []);
});

test('the text reports facts, never asks for a badge, and says how to dispute', () => {
  const { files } = fr.buildReports([vulnerable, mismatch, yanked, hooks], new Map(), upgrades, { asOf: NOW });
  for (const [name, body] of files) {
    if (!name.endsWith('.md')) continue;
    assert.doesNotMatch(body, /badge|shields|star (us|this)|sponsor/i, `${name} asks for something`);
    assert.match(body, /## If this is wrong/);
    assert.match(body, /mcp-vault explain /);
    // At most one line naming the tool.
    assert.equal(body.split('\n').filter((l) => /^Found with \[mcp-vault\]/.test(l)).length, 1);
  }
  const v = files.get('vuln-server.md');
  assert.match(v, /\[GHSA-aaaa-1111-aaaa\]\(https:\/\/osv\.dev\/vulnerability\/GHSA-aaaa-1111-aaaa\) \(HIGH\) — fixed in 1\.1\.0/);
  assert.match(v, /`1\.2\.0` clears every advisory/);
  assert.match(v, /checked 2026-09-17/);
  // Worst first.
  assert.ok(v.indexOf('GHSA-aaaa') < v.indexOf('GHSA-bbbb'));
});

test('an upgrade plan for a different version is not applied to this pin', () => {
  const other = new Map([['vuln-server', { ...upgrades.get('vuln-server'), current: '0.9.0' }]]);
  const [f] = fr.findingsFor(vulnerable, null, other.get('vuln-server'), { asOf: NOW });
  assert.equal(f.advisories, null);
  const { index } = fr.buildReports([vulnerable], new Map(), other, { asOf: NOW });
  assert.ok(index.entries[0].needs.some((n) => /advisory IDs missing/.test(n)));
  assert.equal(index.entries[0].ready, false);
});

test('evidence past its shelf life is marked stale in the index', () => {
  // availability keeps 7 days: checked 09-01, judged 09-20.
  const { index } = fr.buildReports([yanked, mismatch], new Map(), new Map(), { asOf: NOW });
  const y = index.entries.find((e) => e.name === 'yanked-server');
  assert.equal(y.stale, true);
  assert.ok(y.needs.includes(fr.STALE_NOTE));
  assert.equal(y.evidence_date, '2026-09-01');
  assert.equal(y.repo, 'owner/yanked-server');
  // source_binding keeps 60 days: still current.
  const m = index.entries.find((e) => e.name === 'moved-server');
  assert.equal(m.stale, false);
  assert.equal(m.ready, true);
});

test('the output is deterministic: same inputs, same bytes, whatever the input order', () => {
  const a = fr.buildReports([vulnerable, mismatch, yanked, hooks, clean], new Map(), upgrades, { asOf: NOW });
  const b = fr.buildReports([clean, hooks, yanked, mismatch, vulnerable], new Map(), upgrades, { asOf: NOW + 3600e3 });
  assert.deepEqual([...a.files.entries()], [...b.files.entries()]);
  assert.deepEqual(a.index.by_type, { advisory: 1, identity: 1, 'dependency-hooks': 1, availability: 1, 'surface-unexplained': 0 });
});

test('writing refuses a directory holding files it did not write', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fr-'));
  try {
    fs.writeFileSync(path.join(dir, 'mine.txt'), 'keep me');
    const { files } = fr.buildReports([vulnerable], new Map(), upgrades, { asOf: NOW });
    assert.throws(() => fr.writeReports(dir, files), /not empty/);
    assert.equal(fs.readFileSync(path.join(dir, 'mine.txt'), 'utf8'), 'keep me');

    const out = path.join(dir, 'out');
    fr.writeReports(out, files);
    // A second run replaces its own files, including ones no longer produced.
    fs.writeFileSync(path.join(out, 'vuln-server.md'), 'old');
    const next = fr.buildReports([mismatch], new Map(), new Map(), { asOf: NOW });
    fr.writeReports(out, next.files);
    assert.deepEqual(fs.readdirSync(out).sort(), ['index.json', 'moved-server.md']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('there is no code path that opens anything', () => {
  const src = fs.readFileSync(SCRIPT, 'utf8');
  // No network, no subprocess (so no `gh`), no GitHub API.
  assert.doesNotMatch(src, /require\(['"](https?|net|child_process)['"]\)/);
  assert.doesNotMatch(src, /api\.github\.com|execFile|spawn|fetch\(/);
});

test('against the shipped DB, only entries with a finding are drafted', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const { index } = fr.buildReports(db.tools, new Map(), new Map(), { asOf: NOW });
  assert.ok(index.count > 0 && index.count < db.tools.length);
  for (const e of index.entries) {
    const t = db.tools.find((x) => x.name === e.name);
    assert.ok(fr.findingsFor(t, null, null, { asOf: NOW }).length > 0);
  }
});

// ── the drafts are renderings of model Findings ─────────────────────────────

const F = require('../mcp-ecosystem-intelligence/scripts/lib/finding.cjs');

test('each draft finding is a lib/finding.cjs Finding on the artifact, with no effect', () => {
  const [f] = fr.findingsFor(vulnerable, null, null, { asOf: NOW });
  assert.equal(f.finding.rule, 'advisories/known-vulnerability');
  assert.equal(f.finding.subject.type, 'artifact');
  assert.equal(f.finding.state, 'observed');
  assert.equal(f.finding.refs.length, 1);
  for (const k of ['effect', 'outcome', 'decision', 'level']) assert.equal(k in f.finding, false);
  // Past its shelf life: the Finding says stale, and so does the draft.
  const [y] = fr.findingsFor(yanked, null, null, { asOf: NOW });
  assert.equal(y.finding.state, 'stale');
  assert.equal(y.stale, true);
});

test('index.json carries the findings as findings@1, and each entry points into it', () => {
  const { index } = fr.buildReports([vulnerable, mismatch, yanked], new Map(), upgrades, { asOf: NOW });
  assert.equal(index.findings.schema, 'mcp-vault/findings@1');
  assert.equal(index.findings.as_of, '2026-09-20T00:00:00.000Z');
  const ids = new Set(index.findings.findings.map((f) => f.id));
  for (const e of index.entries) for (const id of e.finding_ids) assert.ok(ids.has(id), `${e.name}: ${id}`);
  const obs = new Set(index.findings.observations.map((o) => o.id));
  for (const f of index.findings.findings) for (const r of f.refs) assert.ok(obs.has(r), `${f.id} refs ${r}`);
  assert.deepEqual(index.findings.decisions, []);
});

test('evidence recorded for another version is not drafted against this one (Codex review)', () => {
  const moved = tool('moved-on', { advisories: { status: 'vulnerable', checked_at: '2026-09-17' }, dependencies: { status: 'hooks', checked_at: '2026-09-17' } },
    { install_cmd: 'npx -y moved-on@2.0.0', version: '2.0.0' });
  assert.deepEqual(fr.findingsFor(moved, null, null, { asOf: NOW }), []);
  // A name that is gone is gone for every version, and is still news.
  const gone = tool('gone-name', { availability: { status: 'gone', checked_at: '2026-09-17' } },
    { install_cmd: 'npx -y gone-name@2.0.0', version: '2.0.0' });
  assert.deepEqual(fr.findingsFor(gone, null, null, { asOf: NOW }).map((f) => f.finding.rule), ['availability/gone']);
});

test('--as-of replaces --now, and is taken to its UTC day', () => {
  assert.equal(fr.parseArgs(['--as-of', '2026-09-20T15:00:00Z']).asOf, NOW);
  assert.match(fr.parseArgs(['--as-of', 'yesterday']).error, /--as-of/);
  assert.match(fr.parseArgs(['--now', '2026-09-20']).error, /unknown argument --now/);
  assert.throws(() => fr.findingsFor(vulnerable, null, null, {}), /asOf is required/);
  assert.equal(typeof F.finding, 'function');
});
