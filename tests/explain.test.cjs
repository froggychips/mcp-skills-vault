'use strict';
/**
 * explain: the decision, and the rule that made it.
 *
 * What these tests pin down is the *shape* of a decision, because that is what
 * an audit trail depends on: which rule denied, in what order the rules were
 * evaluated, and the difference between a refusal and a warning. A denial whose
 * reason cannot be named is the failure mode — "computer says no" is what a
 * policy engine is supposed to replace.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const e = require('../mcp-ecosystem-intelligence/scripts/explain.cjs');
const { DEFAULTS } = require('../mcp-ecosystem-intelligence/scripts/lib/policy.cjs');

const tool = (over = {}) => ({
  name: 'x', install_cmd: 'npx -y pkg@1.0.0', version: '1.0.0',
  license: 'MIT', health_score: 80, trust: 'verified', ...over,
});
const ok    = { score: 80, gate: 'ok', reasons: ['artifact: verified'] };
const thin  = { score: 20, gate: 'thin', reasons: ['artifact was never verified'] };
const block = {
  score: 0, gate: 'block',
  blocking: [{ dimension: 'artifact', status: 'mismatch', checked_at: '2026-09-17' }],
  reasons: ['artifact: mismatch (as of 2026-09-17)'],
};
const starts = { state: 'starts', reason: 'starts and lists 12 tools', tools: 12 };

test('a blocked trust gate is a denial, and names the dimension that blocked', () => {
  const d = e.decide({ tool: tool(), policy: DEFAULTS, gateEntry: null, trust: block, behav: starts, budget: null });
  assert.equal(d.decision, 'deny');
  // Named, not generic. `reasons[0]` used to supply this text, and for an entry
  // with a known CVE and a good hash it printed "artifact: verified" as the
  // reason for the denial.
  assert.deepEqual(d.blocking, ['trust/artifact']);
  assert.match(d.rules[0].detail, /artifact is mismatch/);
});

test('every blocking dimension gets its own rule', () => {
  const twoBlockers = {
    score: 0, gate: 'block',
    blocking: [
      { dimension: 'advisories', status: 'vulnerable', checked_at: '2026-09-17' },
      { dimension: 'availability', status: 'yanked', checked_at: '2026-09-17' },
    ],
    reasons: [],
  };
  const d = e.decide({ tool: tool(), policy: DEFAULTS, gateEntry: null, trust: twoBlockers, behav: starts, budget: null });
  assert.deepEqual(d.blocking, ['trust/advisories', 'trust/availability']);
});

test('thin trust warns rather than denies — unknown is not the same as wrong', () => {
  const d = e.decide({ tool: tool(), policy: DEFAULTS, gateEntry: null, trust: thin, behav: starts, budget: null });
  assert.equal(d.decision, 'allow');
  assert.equal(d.rules[0].outcome, 'warn');
});

test('a policy that fails closed on unverified turns the same evidence into a denial', () => {
  const policy = { ...DEFAULTS, unverified: 'fail' };
  const gateEntry = { name: 'x', status: 'UNVERIFIED', findings: [], install_cmd: 'npx -y pkg@1.0.0' };
  const d = e.decide({ tool: tool(), policy, gateEntry, trust: thin, behav: starts, budget: null });
  assert.equal(d.decision, 'deny');
  assert.ok(d.blocking.includes('policy/unverified') || d.blocking.includes('gate/unverified'),
    `expected an unverified rule to block, got ${d.blocking.join(', ')}`);
});

test('a failing gate denies on its own, whatever the stored evidence says', () => {
  const gateEntry = { name: 'x', status: 'FAIL', findings: [{ tag: 'FAIL' }], install_cmd: 'npx -y pkg@1.0.0' };
  const d = e.decide({ tool: tool(), policy: DEFAULTS, gateEntry, trust: ok, behav: starts, budget: null });
  assert.equal(d.decision, 'deny');
  assert.ok(d.blocking.includes('gate/fail'));
});

test('behaviour warns and never denies: not starting is not a security refusal', () => {
  for (const state of ['never-started', 'needs-credentials', 'needs-arguments']) {
    const d = e.decide({
      tool: tool(), policy: DEFAULTS, gateEntry: null, trust: ok,
      behav: { state, reason: `${state} reason` }, budget: null,
    });
    assert.equal(d.decision, 'allow', `${state} must not deny`);
    const rule = d.rules.find((r) => r.rule.startsWith('behaviour/'));
    assert.equal(rule.outcome, 'warn');
    assert.equal(rule.detail, `${state} reason`);
  }
});

test('the context ceiling denies only when the policy says fail', () => {
  const budget = { over: true, after: 120000, limit: 100000, limit_source: 'maxContextTokens' };
  const warn = e.decide({ tool: tool(), policy: { ...DEFAULTS, contextBudget: 'warn' }, gateEntry: null, trust: ok, behav: starts, budget });
  assert.equal(warn.decision, 'allow');
  assert.equal(warn.rules.find((r) => r.rule === 'budget/over').outcome, 'warn');

  const fail = e.decide({ tool: tool(), policy: { ...DEFAULTS, contextBudget: 'fail' }, gateEntry: null, trust: ok, behav: starts, budget });
  assert.equal(fail.decision, 'deny');
  assert.ok(fail.blocking.includes('budget/over'));
});

test('a licence deny list denies, and says which licence', () => {
  const policy = { ...DEFAULTS, licenses: { allow: null, deny: ['BUSL-1.1'] } };
  const d = e.decide({ tool: tool({ license: 'BUSL-1.1' }), policy, gateEntry: null, trust: ok, behav: starts, budget: null });
  assert.equal(d.decision, 'deny');
  const rule = d.rules.find((r) => r.rule === 'policy/license');
  assert.match(rule.detail, /BUSL-1\.1/);
});

test('every rule carries an outcome from a closed set, so a record stays machine-readable', () => {
  const d = e.decide({
    tool: tool({ license: 'Unknown' }),
    policy: { ...DEFAULTS, licenses: { allow: ['MIT'], deny: null }, contextBudget: 'fail' },
    gateEntry: { name: 'x', status: 'WARN', findings: [{ tag: 'HOOK' }], install_cmd: 'npx -y pkg@1.0.0' },
    trust: thin,
    behav: { state: 'never-started', reason: 'crashed' },
    budget: { over: true, after: 1, limit: 0, limit_source: 'maxContextTokens' },
  });
  for (const r of d.rules) {
    assert.ok(['allow', 'warn', 'deny'].includes(r.outcome), `${r.rule} has outcome "${r.outcome}"`);
    assert.equal(typeof r.rule, 'string');
    assert.ok(r.detail && r.detail.length > 0, `${r.rule} has no detail — a denial nobody can act on`);
  }
  assert.equal(d.decision, 'deny');
});

test('parseArgs: one name, known flags only', () => {
  assert.equal(parse(['playwright-mcp']).name, 'playwright-mcp');
  assert.equal(parse(['x', '--json']).json, true);
  assert.equal(parse(['x', '--verify']).verify, true);
  assert.equal(parse(['x', '--record', 'log.jsonl']).record, 'log.jsonl');
  assert.match(parse([]).error, /which entry/);
  assert.match(parse(['a', 'b']).error, /one entry name/);
  assert.match(parse(['x', '--nope']).error, /unknown flag/);
  function parse(argv) { return e.parseArgs(argv); }
});
