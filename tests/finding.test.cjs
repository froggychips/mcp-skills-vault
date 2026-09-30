'use strict';
/**
 * The findings model (lib/finding.cjs) and the rule table it decides with
 * (lib/policy_rules.cjs). docs/adr/0001-findings-and-time.md is the why; these
 * pin the shape a consumer — and each of the open feature PRs — will build on.
 */
const { test } = require('node:test');
const assert   = require('node:assert/strict');

const S  = '../mcp-ecosystem-intelligence/scripts';
const F  = require(`${S}/lib/finding.cjs`);
const PR = require(`${S}/lib/policy_rules.cjs`);
const ev = require(`${S}/lib/evidence.cjs`);
const { DEFAULTS } = require(`${S}/lib/policy.cjs`);

const NOW = Date.parse('2026-09-24T12:00:00Z');
const policy = (base = null, flags = {}) => PR.effectivePolicy(base, flags, { defaults: DEFAULTS });
const art = F.subject.artifact({ entry: 'pkg', version: '1.0.0', integrity: 'sha512-abc' });

test('subjects are typed, and their ids are derived rather than supplied', () => {
  assert.equal(art.id, 'pkg@1.0.0+sha512-abc');
  assert.equal(F.subject.artifact({ entry: 'pkg' }).id, 'pkg');
  assert.equal(F.subject.tool({ server: 'github', tool: 'create_issue' }).id, 'github/create_issue');
  assert.equal(F.subject.tool({ server: 'g', tool: 't', location: 'inputSchema.x' }).id, 'g/t#inputSchema.x');
  assert.equal(F.subject.hostConfig({ path: '.mcp.json', line: 12 }).id, '.mcp.json:12');
  assert.equal(F.subject.hostConfig({ path: '.mcp.json' }).id, '.mcp.json');
  assert.equal(F.subject.setup({ host: 'claude-code' }).id, 'claude-code');
  assert.equal(F.subject.name({ name: 'githbu-mcp', ecosystem: 'npm' }).id, 'npm:githbu-mcp');
  assert.throws(() => F.subject.tool({ server: 'x' }), /required/);
  assert.throws(() => F.validateSubject({ type: 'server', id: 'x' }), /unknown subject type/);
});

test('a finding validates its vocabulary, and cannot carry a policy effect', () => {
  const ok = { rule: 'secrets/aws-access-key', subject: art, severity: 'high', message: 'AKIA… in env' };
  const f = F.finding(ok);
  assert.equal(f.state, 'observed');
  assert.equal(f.confidence, 'high');
  assert.match(f.id, /^f:[0-9a-f]{16}$/);
  for (const [bad, re] of [
    [{ rule: 'NoFamily' }, /family/], [{ rule: 'Secrets/x' }, /lower case/], [{ severity: 'severe' }, /severity/],
    [{ state: 'clean' }, /state/], [{ confidence: 'format' }, /confidence/], [{ message: '  ' }, /message/],
    [{ subject: { id: 'x' } }, /subject/],
  ]) assert.throws(() => F.finding({ ...ok, ...bad }), re);
  // "Finding НЕ содержит policy effect": the decision is decide()'s alone.
  for (const k of ['effect', 'outcome', 'decision', 'level']) {
    assert.throws(() => F.finding({ ...ok, [k]: 'deny' }), /is a decision/);
  }
});

test('a finding id is stable across refs and runs; sorting does not depend on input order', () => {
  const a = F.finding({ rule: 'x/y', subject: art, severity: 'low', message: 'm', refs: ['o2', 'o1'] });
  const b = F.finding({ rule: 'x/y', subject: art, severity: 'low', message: 'm', refs: [] });
  assert.equal(a.id, b.id, 'what was concluded about what — not which dated facts it rests on');
  assert.deepEqual(a.refs, ['o1', 'o2']);
  const list = ['c/c', 'a/b', 'a/a', 'b/z'].map((rule) => F.finding({ rule, subject: art, severity: 'info', message: rule }));
  const sorted = F.sortFindings(list).map((f) => f.rule);
  assert.deepEqual(F.sortFindings([...list].reverse()).map((f) => f.rule), sorted);
  assert.deepEqual(sorted, ['a/a', 'a/b', 'b/z', 'c/c']);
  assert.equal(F.canonicalJson({ b: 1, a: { d: 2, c: [3, { z: 1, y: 2 }] } }), '{"a":{"c":[3,{"y":2,"z":1}],"d":2},"b":1}');
});

test('an observation expires exactly where staleDimensions says it is stale', () => {
  for (const [dimension, ttl] of Object.entries(ev.DEFAULT_MAX_AGE_DAYS)) {
    const evidence = { artifact_id: 'npm:pkg@1.0.0', dimensions: { [dimension]: { status: 'x', checked_at: '2026-09-10', verified_at: '2026-09-08' } } };
    const [obs] = F.observationsFromEvidence(evidence, { subject: art, maxAgeDays: ev.DEFAULT_MAX_AGE_DAYS });
    assert.equal(obs.ttl_days, ttl);
    const edge = Date.parse(obs.expires_at);
    for (const at of [edge - 1, edge, edge + 1, edge - 86400000]) {
      const stale = ev.staleDimensions(evidence, ev.DEFAULT_MAX_AGE_DAYS, at).length > 0;
      assert.equal(F.observationState(obs, at) === 'stale', stale, `${dimension} at ${new Date(at).toISOString()}`);
    }
  }
});

test('effectivePolicy: frozen, flags only tighten, and --strict is a threshold', () => {
  const p = policy({ ...DEFAULTS, signatures: 'require' });
  assert.ok(Object.isFrozen(p) && Object.isFrozen(p.gate));
  assert.throws(() => { 'use strict'; p.signatures = 'prefer'; }, TypeError);
  assert.equal(p.gate.require_signatures, true, 'a file bar survives no flag');
  assert.equal(p.fail_on, 'deny');
  assert.equal(policy(null, { failUnverified: true }).fail_on, 'unknown');
  assert.equal(policy(null, { strict: true }).fail_on, 'warn');
  assert.equal(policy(null, { strict: true }).gate.fail_unverified, true, '--strict implies --fail-unverified');
  assert.equal(policy({ ...DEFAULTS, unverified: 'fail' }).fail_on, 'unknown');
  const bound = policy(null, { requireProvenanceBinding: true });
  assert.equal(bound.gate.require_provenance, true, 'asking for a bound attestation is asking for one');
  // The file's own keys are the file's: a flag raises the gate, not a POLICY line.
  assert.equal(bound.provenance, 'prefer');
});

test('decide: the worst effect wins, decided_by names the rule, the threshold decides failure', () => {
  const high = F.finding({ rule: 'verify/check-failed', subject: art, severity: 'high', message: 'integrity mismatch' });
  const med  = F.finding({ rule: 'install/hook', subject: art, severity: 'medium', message: 'postinstall' });
  const gap  = F.finding({ rule: 'verify/unverified', subject: art, severity: 'medium', state: 'not-run', message: 'feed down' });
  const other = F.subject.artifact({ entry: 'clean' });

  const [d] = F.decide([med, high, gap], policy(), NOW, { subjects: [art] });
  assert.equal(d.effect, 'deny');
  assert.equal(d.decided_by, 'finding/severity');
  assert.deepEqual(d.findings, [high.id]);
  assert.equal(d.fails, true);
  assert.equal(d.as_of, '2026-09-24T12:00:00.000Z');

  const [u] = F.decide([med, gap], policy(), NOW);
  assert.equal(u.effect, 'unknown', 'nobody looked outranks somebody looked and disliked it');
  assert.equal(u.fails, false, 'unknown fails only when the policy fails closed');
  assert.equal(F.decide([med, gap], policy(null, { failUnverified: true }), NOW)[0].fails, true);
  assert.equal(F.decide([med], policy(), NOW)[0].fails, false);
  assert.equal(F.decide([med], policy(null, { strict: true }), NOW)[0].fails, true);

  // A subject with nothing to say is an explicit allow, not an absence.
  const clean = F.decide([], policy(), NOW, { subjects: [other] });
  assert.deepEqual(clean.map((x) => [x.effect, x.decided_by]), [['allow', 'finding/none']]);
  // No policy assembled on the way: only the frozen, effective one.
  assert.throws(() => F.decide([], { ...DEFAULTS }, NOW), /frozen effective policy/);
});

test('decide: an unanswerable question is exit 2, a failure outranks it', () => {
  const cfg = F.subject.hostConfig({ path: '/home/u/.cursor/mcp.json' });
  const unread = F.finding({ rule: 'scope/unreadable', subject: cfg, severity: 'medium', state: 'no-data', message: 'parse error' });
  const ds = F.decide([unread], policy(), NOW);
  assert.equal(ds[0].unanswered, true);
  assert.equal(F.exitCode(ds), 2);
  const bad = F.finding({ rule: 'verify/check-failed', subject: art, severity: 'high', message: 'x' });
  assert.equal(F.exitCode(F.decide([unread, bad], policy(), NOW)), 1);
  assert.equal(F.exitCode(F.decide([], policy(), NOW, { subjects: [art] })), 0);
});

test('policy rows read findings in gate mode and evidence in evidence mode', () => {
  const hook = F.finding({ rule: 'install/hook', subject: art, severity: 'medium', message: 'postinstall' });
  const p = policy({ ...DEFAULTS, installHooks: 'fail' });
  const facts = { [art.id]: { entry: { install_cmd: 'npx -y pkg@1.0.0' } } };
  const [gate] = F.decide([hook], p, NOW, { subjects: [art], facts });
  assert.equal(gate.decided_by, 'policy/install-hooks');
  assert.equal(gate.effect, 'deny');
  // Without a gate run, "no HOOK finding" is not "no hooks".
  const [evd] = F.decide([], p, NOW, { subjects: [art], facts: { [art.id]: { ...facts[art.id], mode: 'evidence' } } });
  assert.equal(evd.effect, 'unknown');
  assert.equal(evd.decided_by, 'policy/install-hooks');
  // --no-policy keeps the gate's own rules and drops the file's.
  const off = PR.effectivePolicy({ ...DEFAULTS, installHooks: 'fail' }, {}, { defaults: DEFAULTS, policyRules: false });
  assert.equal(F.decide([hook], off, NOW, { subjects: [art], facts })[0].decided_by, 'finding/severity');
});

test('the rule table: stable ids, one row each, every ordered id exists, the open PRs reserved', () => {
  const ids = PR.RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, 'a rule id is one row');
  for (const r of PR.RULES) {
    assert.match(r.id, /^[a-z0-9-]+(\/([a-z0-9.-]+|\*))+$/, r.id);
    assert.ok(['active', 'reserved'].includes(r.status), r.id);
    assert.equal(typeof r.evaluate, 'function', r.id);
  }
  const active = PR.RULES.filter((r) => r.status === 'active').map((r) => r.id).sort();
  for (const mode of Object.keys(PR.ORDER)) {
    for (const id of PR.ORDER[mode]) assert.ok(PR.RULE_BY_ID.has(id), `${mode}: ${id}`);
    for (const id of PR.ORDER[mode]) assert.equal(PR.RULE_BY_ID.get(id).status, 'active', `${mode}: ${id} is reserved`);
    assert.equal(new Set(PR.ORDER[mode]).size, PR.ORDER[mode].length, `${mode} lists a row twice`);
  }
  // The two full modes run every rule; a narrower mode (`approval`: approve,
  // lock --check, #127; `setup`: a host's session, #123) runs only the rows
  // that answer its question.
  for (const mode of ['gate', 'evidence']) {
    assert.deepEqual([...PR.ORDER[mode]].sort(), active, `${mode} lists every active row exactly once`);
  }
  // org/* landed with #127, secrets/* with #122, flows/* and shadowing/* with
  // #123; the rest are still claimed for their PRs.
  for (const family of ['org/', 'flows/', 'shadowing/']) {
    const rows = PR.RULES.filter((r) => r.id.startsWith(family));
    assert.ok(rows.length && rows.every((r) => r.status === 'active'), `${family} rows are active`);
  }
  for (const family of ['tool-scan/', 'lookalike/']) {
    assert.ok(PR.RULES.some((r) => r.status === 'reserved' && r.id.startsWith(family)), family);
  }
  assert.equal(PR.RULE_BY_ID.get('secrets/*').status, 'active', '#122 landed as its row');
  assert.equal(PR.rowFor('trust/artifact').id, 'trust/*');
  assert.equal(PR.rowFor('policy/license').id, 'policy/license');
});

test('toSarif: one location per subject type, notes left out, fingerprints from the finding id', () => {
  const tool = F.subject.tool({ server: 'gh', tool: 'run' });
  const cfg  = F.subject.hostConfig({ path: '.mcp.json', line: 7 });
  const setup = F.subject.setup({ host: 'cursor' });
  const list = [
    F.finding({ rule: 'verify/check-failed', subject: art, severity: 'high', message: 'mismatch' }),
    F.finding({ rule: 'tool-scan/unicode-tags', subject: tool, severity: 'medium', message: 'hidden text' }),
    F.finding({ rule: 'secrets/github-token', subject: cfg, severity: 'high', message: 'ghp_… in env' }),
    F.finding({ rule: 'flows/lethal-trifecta', subject: setup, severity: 'medium', message: 'three legs' }),
    F.finding({ rule: 'verify/note', subject: art, severity: 'info', message: 'fyi' }),
  ];
  const sarif = F.toSarif(list, { lineOf: (n) => (n === 'pkg' ? 42 : 1) });
  const results = sarif.runs[0].results;
  assert.equal(results.length, 4, 'a note is not an alert');
  const by = Object.fromEntries(results.map((r) => [r.ruleId, r]));
  assert.equal(by['verify/check-failed'].locations[0].physicalLocation.region.startLine, 42);
  assert.equal(by['secrets/github-token'].locations[0].physicalLocation.artifactLocation.uri, '.mcp.json');
  assert.equal(by['secrets/github-token'].locations[0].physicalLocation.region.startLine, 7);
  assert.equal(by['tool-scan/unicode-tags'].locations[0].logicalLocations[0].fullyQualifiedName, 'gh/run');
  assert.equal(by['flows/lethal-trifecta'].locations[0].logicalLocations[0].name, 'cursor');
  assert.equal(by['secrets/github-token'].level, 'error');
  assert.equal(by['tool-scan/unicode-tags'].partialFingerprints.findingId, list[1].id);
  assert.deepEqual(sarif.runs[0].tool.driver.rules.map((r) => r.id), [...Object.keys(by)].sort());
});

test('explainTrace: decision ← rule ← finding ← dated observation', () => {
  const evidence = { artifact_id: 'npm:pkg@1.0.0', dimensions: { advisories: { status: 'clean', checked_at: '2026-09-10', verified_at: '2026-09-10' } } };
  const obs = F.observationsFromEvidence(evidence, { subject: art, maxAgeDays: ev.DEFAULT_MAX_AGE_DAYS });
  const stale = F.finding({ rule: 'evidence/stale', subject: art, severity: 'medium', state: 'stale', refs: [obs[0].id], message: 'advisories aged out' });
  const decisions = F.decide([stale], policy(), NOW, { subjects: [art] });
  const doc = F.toJson(F.findingsDocument({ asOf: NOW, observations: obs, findings: [stale], decisions, policy: policy() }));
  assert.equal(doc.schema, 'mcp-vault/findings@1');
  const [t] = F.explainTrace(doc, art.id);
  assert.equal(t.decided_by, 'finding/incomplete');
  assert.equal(t.rules[0].findings[0].observations[0].state, 'stale');
  assert.match(F.renderTrace([t]).join('\n'), /UNKNOWN .* decided by finding\/incomplete[\s\S]*← evidence\/stale[\s\S]*← advisories: clean \(stored, observed 2026-09-10, stale since 2026-09-18\)/);
});
