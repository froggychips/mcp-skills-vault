'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const cp       = require('node:child_process');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

const s = require('../mcp-ecosystem-intelligence/scripts/smoke_compare.cjs');

const pass = (name, n) => ({ name, status: 'pass', failure_class: n === 0 ? 'NO_TOOLS' : null, error_code: null, tool_count: n, sandboxed: true });
const fail = (name, cls, extra = {}) => ({ name, status: 'fail', failure_class: cls, error_code: cls === 'TIMEOUT' ? 'timeout' : 'exit 1', tool_count: null, sandboxed: true, ...extra });

// Base line as recorded in eval_results.json on master (run of 2026-09-17),
// and the smoke PR #133 produced for the same entries.
const BASE_17_09 = [
  { name: 'mcp-atlassian', status: 'pass', failure_class: 'NO_TOOLS', error_code: null, tool_count: 0, sandboxed: true },
  fail('mcp-server-kubernetes', 'TIMEOUT'),
  fail('gitlab-mcp', 'CRASH'),
  fail('actors-mcp-server', 'CRASH'),
  fail('@dynatrace-oss/dynatrace-mcp-server', 'CRASH'),
  fail('@contentful/mcp-server', 'TIMEOUT'),
];
const PR_133 = [
  { name: 'mcp-atlassian', status: 'fail', failure_class: 'NO_TOOLS', error_code: null, tool_count: 0, sandboxed: true },
  fail('mcp-server-kubernetes', 'CRASH', { stderr_tail: 'Error: Invalid kube config: no configuration has been provided' }),
  fail('gitlab-mcp', 'CRASH', { stderr_tail: 'GITLAB_PERSONAL_ACCESS_TOKEN environment variable is required' }),
  fail('actors-mcp-server', 'CRASH'),
  fail('@dynatrace-oss/dynatrace-mcp-server', 'CRASH'),
  fail('@contentful/mcp-server', 'CRASH'),
];

test('PR #133: already-failing entries are not breaking', () => {
  const rows = s.compare(BASE_17_09, PR_133);
  assert.deepEqual(rows.filter((r) => r.verdict === 'breaking'), []);
  assert.ok(rows.every((r) => r.verdict === 'unchanged-failing'), JSON.stringify(rows));
});

test('NO_TOOLS: `pass, tools=0` and failure_class NO_TOOLS are one state', () => {
  const a = s.normalizeState({ status: 'pass', failure_class: null, tool_count: 0 });
  const b = s.normalizeState({ status: 'pass', failure_class: 'NO_TOOLS', tool_count: 0 });
  const c = s.normalizeState({ status: 'fail', failure_class: 'NO_TOOLS', tool_count: null });
  assert.deepEqual(a, b);
  assert.deepEqual(b, c);
  assert.equal(s.verdictFor(BASE_17_09[0], PR_133[0]), 'unchanged-failing');
});

test('was PASS, now CRASH / NO_TOOLS / FAIL → breaking', () => {
  for (const now of [fail('x', 'CRASH'), pass('x', 0), fail('x', 'TIMEOUT'), fail('x', null)]) {
    assert.equal(s.verdictFor(pass('x', 5), now), 'breaking', JSON.stringify(now));
  }
});

test('fewer tools at the same version → breaking; with a version bump → shrunk', () => {
  assert.equal(s.verdictFor(pass('x', 5), pass('x', 3)), 'breaking');
  assert.equal(s.verdictFor(pass('x', 5), pass('x', 3), { versionChanged: true }), 'shrunk');
  const rows = s.compare([pass('x', 5)], [pass('x', 3)], {
    baseTools: [{ name: 'x', version: '1.0.0' }], headTools: [{ name: 'x', version: '2.0.0' }],
  });
  assert.equal(rows[0].verdict, 'shrunk');
  const same = s.compare([pass('x', 5)], [pass('x', 3)], {
    baseTools: [{ name: 'x', version: '1.0.0' }], headTools: [{ name: 'x', version: '1.0.0' }],
  });
  assert.equal(same[0].verdict, 'breaking');
});

test('same or more tools → ok; failing → pass → improved', () => {
  assert.equal(s.verdictFor(pass('x', 5), pass('x', 5)), 'ok');
  assert.equal(s.verdictFor(pass('x', 5), pass('x', 7)), 'ok');
  assert.equal(s.verdictFor(fail('x', 'CRASH'), pass('x', 2)), 'improved');
  assert.equal(s.verdictFor(pass('x', 0), pass('x', 2)), 'improved');
});

test('no base line → new-pass / new-failing (warning, not breaking)', () => {
  assert.equal(s.verdictFor(null, pass('x', 1)), 'new-pass');
  assert.equal(s.verdictFor(null, fail('x', 'CRASH')), 'new-failing');
  assert.equal(s.verdictFor(null, pass('x', 0)), 'new-failing');
});

test('runner could not check it → unchecked, never breaking', () => {
  const skip = { name: 'x', status: 'skip', failure_class: null, error_code: 'launcher unavailable: uvx', tool_count: null };
  assert.equal(s.verdictFor(pass('x', 5), skip), 'unchecked');
  assert.equal(s.verdictFor(pass('x', 5), fail('x', 'SANDBOX_UNAVAILABLE')), 'unchecked');
});

test('needs-credentials from stderr; NEEDS_ENV counts; passes never tagged', () => {
  const rows = s.compare(BASE_17_09, PR_133);
  const tagged = rows.filter((r) => r.tags.includes('needs-credentials')).map((r) => r.name);
  assert.deepEqual(tagged, ['mcp-server-kubernetes', 'gitlab-mcp']);
  assert.ok(s.needsCredentials(fail('x', 'NEEDS_ENV')));
  assert.ok(s.needsCredentials(fail('x', 'CRASH', { stderr_tail: 'Missing API token' })));
  assert.ok(s.needsCredentials(fail('x', 'CRASH', { stderr_tail: 'Error: DT_ENVIRONMENT environment variable not set' })));
  assert.ok(!s.needsCredentials(fail('x', 'CRASH', { stderr_tail: 'TypeError: cannot read properties of undefined' })));
  assert.ok(!s.needsCredentials(pass('x', 3)));
});

test('toMarkdown: was/now/verdict table, breaking called out', () => {
  const rows = s.compare([pass('a', 4), fail('b', 'CRASH')], [fail('a', 'CRASH'), fail('b', 'CRASH')]);
  const md = s.toMarkdown(rows, { title: 'T', baseRef: 'abc' });
  assert.match(md, /^## T\n/);
  assert.match(md, /\*\*1 breaking\*\*/);
  assert.match(md, /\| entry \| was \| now \| verdict \|/);
  assert.match(md, /\| a \| PASS \(4\) \| CRASH \| \*\*breaking\*\* \|/);
  assert.match(md, /\| b \| CRASH \| CRASH \| unchanged-failing \|/);
  const clean = s.toMarkdown(s.compare(BASE_17_09, PR_133));
  assert.match(clean, /No regressions/);
  assert.match(clean, /needs-credentials/);
});

test('parseRuns: concatenated pretty-printed mcp_eval documents', () => {
  const text = [JSON.stringify({ results: [pass('a', 1)] }, null, 2), JSON.stringify({ results: [fail('b', 'CRASH')] }, null, 2)].join('\n');
  assert.deepEqual(s.parseRuns(text).map((r) => r.name), ['a', 'b']);
});

test('CLI: gate fails only on breaking, against eval_results.json at the base ref', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'smoke-compare-'));
  const git = (...a) => cp.execFileSync('git', a, { cwd: dir, stdio: 'pipe' });
  git('init', '-q');
  git('config', 'user.email', 't@t'); git('config', 'user.name', 't');
  fs.mkdirSync(path.join(dir, 'mcp-ecosystem-intelligence/assets'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'mcp-ecosystem-intelligence/assets/eval_results.json'),
    JSON.stringify({ results: [...BASE_17_09, pass('good', 3)] }));
  git('add', '.'); git('commit', '-qm', 'base');

  const script = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts/smoke_compare.cjs');
  const run = (results) => {
    const runs = path.join(dir, 'runs.json');
    fs.writeFileSync(runs, JSON.stringify({ results }, null, 2));
    const summary = path.join(dir, 'summary.md');
    fs.writeFileSync(summary, '');
    const r = cp.spawnSync(process.execPath, [script, '--runs', runs, '--base', 'HEAD', '--gate', '--summary', summary,
      '--db', path.join(dir, 'missing.json')], { cwd: dir, encoding: 'utf8' });
    return { status: r.status, stderr: r.stderr, md: fs.readFileSync(summary, 'utf8') };
  };

  const ok = run(PR_133);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stderr, /unchanged-failing: /);
  assert.doesNotMatch(ok.stderr, /^breaking:/m);

  const bad = run([...PR_133, fail('good', 'CRASH')]);
  assert.equal(bad.status, 1, bad.stderr);
  assert.match(bad.stderr, /^breaking: good\(PASS \(3\) → CRASH\)/m);
  assert.match(bad.md, /\| good \| PASS \(3\) \| CRASH \| \*\*breaking\*\* \|/);
  fs.rmSync(dir, { recursive: true, force: true });
});
