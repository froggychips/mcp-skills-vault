'use strict';
/**
 * `--as-of`: the same inputs at the same instant print the same bytes, and
 * moving the instant past a shelf life is what — and all that — changes.
 *
 * These run the real commands over the shipped DB. They do not assert what
 * the DB says (that moves weekly, and docs/COMPATIBILITY.md says not to pin
 * behaviour to it); they assert how the answer depends on the date.
 */
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('fs');
const os       = require('os');
const path     = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const S    = path.join(ROOT, 'mcp-ecosystem-intelligence', 'scripts');
const DB   = require(path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json')).tools;

// An empty project and an empty HOME, so no real host config leaks in.
const TMP  = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-asof-'));
const ENV  = { ...process.env, HOME: TMP, USERPROFILE: TMP, NO_COLOR: '1' };
const run = (script, args) => spawnSync(process.execPath, [path.join(S, script), ...args], { encoding: 'utf8', env: ENV, cwd: TMP, maxBuffer: 64 * 1024 * 1024 });

// The newest date any stored claim carries: "as of the snapshot".
const SNAPSHOT = DB.flatMap((t) => Object.values((t.trust_evidence && t.trust_evidence.dimensions) || {}))
  .map((d) => d.checked_at).filter(Boolean).sort().pop();
const FRESH = `${SNAPSHOT}T12:00:00.000Z`;
const LATER = '2031-01-01T00:00:00.000Z';
// An entry with an artifact-bound, affirmative advisories record (7-day life).
const ENTRY = DB.find((t) => t.trust_evidence && t.trust_evidence.dimensions
  && t.trust_evidence.dimensions.advisories && t.trust_evidence.dimensions.advisories.status === 'clean'
  && t.trust_evidence.dimensions.advisories.checked_at === SNAPSHOT);

test('the fixture exists: a snapshot date and an entry with fresh advisories', () => {
  assert.match(SNAPSHOT, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(ENTRY, 'no entry carries advisories: clean as of the snapshot date');
});

const COMMANDS = [
  ['verify_integrity.cjs', ['--offline', '--json']],
  ['verify_integrity.cjs', ['--offline', '--sarif']],
  ['verify_integrity.cjs', ['--offline', '--strict', '--json']],
  ['status.cjs', ['--json', '--cwd', TMP]],
  ['list_entries.cjs', ['--json']],
  ['audit_setup.cjs', ['--json', '--cwd', TMP]],
  ['orchestrate.cjs', ['--json', '--cwd', TMP, '--offline']],
  ['sbom.cjs', []],
];

test('same inputs, same --as-of: byte-for-byte the same document, twice', () => {
  const cmds = [...COMMANDS, ['explain.cjs', [ENTRY.name, '--json', '--cwd', TMP]]];
  for (const [script, args] of cmds) {
    const a = run(script, [...args, '--as-of', FRESH]);
    const b = run(script, [...args, '--as-of', FRESH]);
    assert.ok(a.stdout.length > 0, `${script} ${args.join(' ')} printed nothing (${a.stderr})`);
    assert.equal(a.status, b.status, `${script}: exit code moved between two identical runs`);
    assert.equal(a.stdout, b.stdout, `${script} ${args.join(' ')}: two runs at one instant differ`);
    if (!args.includes('--sarif') && script !== 'sbom.cjs') {
      assert.equal(JSON.parse(a.stdout).as_of, FRESH, `${script} does not print the instant it judged at`);
    }
  }
});

test('the SARIF does not depend on the instant unless the evidence does', () => {
  // SARIF carries no timestamp; what it reports may change with staleness,
  // and nothing else about it may.
  const a = run('verify_integrity.cjs', ['--offline', '--sarif', '--as-of', FRESH]).stdout;
  const b = run('verify_integrity.cjs', ['--offline', '--sarif', '--as-of', `${SNAPSHOT}T13:00:00.000Z`]).stdout;
  assert.equal(a, b);
});

test('past the shelf life, the same evidence reads as stale — in every view', () => {
  // explain: the dimension record and the findings model agree.
  const fresh = JSON.parse(run('explain.cjs', [ENTRY.name, '--json', '--cwd', TMP, '--as-of', FRESH]).stdout);
  const later = JSON.parse(run('explain.cjs', [ENTRY.name, '--json', '--cwd', TMP, '--as-of', LATER]).stdout);
  const adv = (r) => r.evidence.dimensions.find((d) => d.dimension === 'advisories');
  assert.equal(adv(fresh).stale, false);
  assert.equal(adv(later).stale, true);
  const staleFindings = (doc) => doc.findings.findings.filter((f) => f.state === 'stale');
  assert.equal(staleFindings(fresh).length, 0);
  assert.ok(staleFindings(later).length > 0, 'nothing in the model went stale');
  const obs = (doc) => doc.findings.observations.find((o) => o.dimension === 'advisories');
  assert.equal(obs(fresh).expires_at, obs(later).expires_at, 'an observation\'s expiry is a fact, not a function of when you ask');
  assert.equal(later.findings.decisions[0].effect === 'allow', false, 'stale evidence decided allow');

  // verify: the legacy UNVERIFIED line and the model's stale finding appear together.
  const v1 = JSON.parse(run('verify_integrity.cjs', ['--offline', '--entry', ENTRY.name, '--json', '--as-of', FRESH]).stdout);
  const v2 = JSON.parse(run('verify_integrity.cjs', ['--offline', '--entry', ENTRY.name, '--json', '--as-of', LATER]).stdout);
  const aged = (r) => r.entries[0].findings.some((f) => /aged out/.test(f.message));
  assert.equal(aged(v1), false);
  assert.equal(aged(v2), true);
  assert.equal(v1.findings.findings.some((f) => f.state === 'stale'), false);
  assert.ok(v2.findings.findings.some((f) => f.rule === 'evidence/stale' && f.state === 'stale'));
  // …and --fail-unverified turns exactly that into a failure.
  assert.equal(run('verify_integrity.cjs', ['--offline', '--entry', ENTRY.name, '--fail-unverified', '--as-of', LATER]).status, 1);
});

test('a malformed --as-of is a usage error (2) everywhere, never a silent "now"', () => {
  const cmds = [
    ['verify_integrity.cjs', ['--offline']], ['status.cjs', ['--cwd', TMP]], ['explain.cjs', [ENTRY.name, '--cwd', TMP]],
    ['list_entries.cjs', []], ['audit_setup.cjs', ['--cwd', TMP]], ['orchestrate.cjs', ['--cwd', TMP]], ['sbom.cjs', []],
    ['check_license_drift.cjs', ['--no-fetch']],
  ];
  for (const [script, args] of cmds) {
    const r = run(script, [...args, '--as-of', '2026-13-45']);
    assert.equal(r.status, 2, `${script} accepted a date that does not exist`);
  }
});

test('a replayed instant never dates an observation or approves an install', () => {
  const rec = run('verify_integrity.cjs', ['--offline', '--entry', ENTRY.name, '--record-evidence', '--as-of', FRESH]);
  assert.equal(rec.status, 2);
  assert.match(rec.stderr, /evidence is dated when it is observed/);
  const inst = run('orchestrate.cjs', ['--install', ENTRY.name, '--cwd', TMP, '--offline', '--as-of', FRESH]);
  assert.equal(inst.status, 2);
  assert.match(inst.stderr, /an install is decided against the current time/);
  assert.equal(fs.existsSync(path.join(TMP, '.mcp.json')), false, 'the install went ahead');
});
