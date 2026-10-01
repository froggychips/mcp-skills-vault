'use strict';
/**
 * One place decides (docs/adr/0001-findings-and-time.md §3), checked.
 *
 * Three ways a command can end up deciding on its own, and one test each:
 *
 *   1. Its decision is not what `decide()` makes of its own inputs. Every
 *      findings@1 document carries the policy and facts it was decided on, so
 *      the decisions are recomputed from the document and must come out equal
 *      — over fixture policies, flag sets and entries.
 *   2. Its legacy view (verify's FAIL status and POLICY lines, explain's
 *      decision and blocking list, both exit codes) says something the
 *      Decision does not.
 *   3. It is a new command nobody classified, or new code that writes a
 *      decision word outside lib/finding.cjs and lib/policy_rules.cjs.
 *
 * The legacy deciders — commands that still map their own findings to an
 * exit code — are listed by name with the step that moves them. Moving one
 * is deleting its line; adding a command without a line fails.
 */
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('fs');
const os       = require('os');
const path     = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const S    = path.join(ROOT, 'mcp-ecosystem-intelligence', 'scripts');
const F    = require(path.join(S, 'lib', 'finding.cjs'));
const PR   = require(path.join(S, 'lib', 'policy_rules.cjs'));
const ORG  = require(path.join(S, 'lib', 'org_policy.cjs'));
const DB   = require(path.join(ROOT, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json')).tools;

const AS_OF = '2026-09-24T12:00:00.000Z';
const TMP   = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-decide-'));
const ENV   = { ...process.env, HOME: TMP, USERPROFILE: TMP, NO_COLOR: '1' };

// Fixture policies: none, a strict one that exercises every policy@1 rule,
// and a licence-list one.
const POLICIES = {
  none: null,
  strict: { unverified: 'fail', installHooks: 'fail', dependencyHooks: 'fail', dependencyAdvisories: 'fail',
    signatures: 'require', provenance: 'require', docker: 'digest', trust: ['verified'], minHealthScore: 70, maxEvidenceAgeDays: 5 },
  licences: { licenses: { allow: ['MIT', 'Apache-2.0'], deny: ['BUSL-1.1'] }, signatures: 'require', docker: 'tag' },
  unverified: { unverified: 'fail' },
  // Every org/* row (#127): allow and deny lists, a tier floor, required
  // evidence, a capability ban and tool approval.
  org: {
    allow: [{ npmScope: '@modelcontextprotocol' }, { githubOwner: 'github' }, { entry: DB[1].name }, { entry: DB[2].name }],
    deny: [{ entry: DB[2].name, reason: 'fixture' }],
    minTier: 'Recommended', requireEvidence: { artifact: 30, advisories: null },
    denyCapabilities: ['shell'], toolApproval: 'require',
  },
};
const DIRS = {};
for (const [name, body] of Object.entries(POLICIES)) {
  DIRS[name] = fs.mkdtempSync(path.join(TMP, `${name}-`));
  if (body) fs.writeFileSync(path.join(DIRS[name], '.mcp-vault.policy.json'), JSON.stringify(body));
}

const run = (script, args) => spawnSync(process.execPath, [path.join(S, script), ...args], {
  encoding: 'utf8', env: ENV, cwd: TMP, maxBuffer: 64 * 1024 * 1024,
});

/** decide() over a document's own inputs, as it would be called by any command. */
function recompute(doc) {
  const policy = PR.deepFreeze(JSON.parse(JSON.stringify(doc.policy)));
  const failOn = doc.decisions.length ? doc.decisions[0].fail_on : null;
  return F.toJson(F.decide(doc.findings, policy, Date.parse(doc.as_of), {
    subjects: F.documentSubjects(doc), facts: doc.facts, failOn,
  }));
}

// A spread of entries: npm, PyPI, docker, a blocked one, an unroutable one.
const SAMPLE = (() => {
  const pick = (pred) => DB.find(pred);
  const out = new Set([
    pick((t) => /^npx/.test(t.install_cmd)),
    pick((t) => /^uvx/.test(t.install_cmd)),
    pick((t) => /^docker/.test(t.install_cmd)),
    pick((t) => t.trust_evidence && Object.values(t.trust_evidence.dimensions || {}).some((d) => d.status === 'vulnerable')),
    pick((t) => /^uvx --from/.test(t.install_cmd)),
    ...DB.slice(0, 6),
  ].filter(Boolean).map((t) => t.name));
  return [...out];
})();

const FLAGS = [[], ['--strict'], ['--fail-unverified'], ['--require-signatures', '--require-provenance-binding', '--fail-dep-advisories'], ['--no-policy']];

test('verify: every decision is decide() of the document\'s own inputs, and its legacy view agrees', () => {
  for (const [pname, dir] of Object.entries(DIRS)) {
    for (const flags of FLAGS) {
      const r = run('verify_integrity.cjs', ['--offline', '--json', '--cwd', dir, '--as-of', AS_OF, ...flags]);
      const label = `${pname} ${flags.join(' ') || '(no flags)'}`;
      assert.ok(r.stdout, `${label}: no output (${r.stderr})`);
      assert.doesNotMatch(r.stderr, /internal:/, `${label}: the decision and the gate's counters disagree`);
      const report = JSON.parse(r.stdout);
      const doc = report.findings;
      assert.equal(doc.schema, 'mcp-vault/findings@1');
      assert.deepEqual(recompute(doc), doc.decisions, `${label}: the printed decisions are not decide()'s`);

      const bySubject = new Map(doc.decisions.map((d) => [d.subject.id, d]));
      for (const e of report.entries) {
        const id = F.subject.artifact({ entry: e.name, version: e.version, integrity: e.integrity }).id;
        const d = bySubject.get(id);
        assert.ok(d, `${label}: ${e.name} has no decision`);
        // `failures`, not `status`: an unroutable entry under --fail-unverified
        // has always been counted as a failure while its status still read
        // UNVERIFIED, and the exit code follows the count.
        assert.equal(e.failures > 0, d.fails, `${label}: ${e.name} failures ${e.failures} vs decision fails=${d.fails}`);
        const lines = e.findings.filter((f) => f.tag === 'POLICY-FAIL' || f.tag === 'POLICY-WARN').map((f) => f.message);
        const rendered = d.rules.filter((o) => {
          const row = PR.rowFor(o.rule);
          return row && row.views.includes('policy-line') && (o.effect === 'deny' || o.effect === 'warn');
        }).map((o) => `${o.rule}: ${o.detail}`);
        assert.deepEqual(lines, rendered, `${label}: ${e.name} POLICY lines are not the decision's rules`);
      }
      assert.equal(r.status, F.exitCode(doc.decisions), `${label}: the exit code is not the decisions'`);
    }
  }
});

test('explain: its decision, blocking list and exit code are views of decide()', () => {
  for (const [pname, dir] of Object.entries(DIRS)) {
    for (const name of SAMPLE) {
      const r = run('explain.cjs', [name, '--json', '--cwd', dir, '--as-of', AS_OF]);
      const rec = JSON.parse(r.stdout);
      const doc = rec.findings;
      const label = `${pname} ${name}`;
      assert.deepEqual(recompute(doc), doc.decisions, `${label}: the printed decision is not decide()'s`);
      const [d] = doc.decisions;
      assert.equal(rec.decision, d.effect === 'deny' ? 'deny' : 'allow', label);
      const view = d.rules.filter((o) => { const row = PR.rowFor(o.rule); return row && row.views.includes('explain'); });
      assert.deepEqual(rec.rules.map((x) => [x.rule, x.outcome, x.detail]), view.map((o) => [o.rule, o.effect, o.detail]), label);
      assert.deepEqual(rec.blocking, view.filter((o) => o.effect === 'deny').map((o) => o.rule), label);
      assert.equal(r.status, d.fails ? 1 : 0, `${label}: exit ${r.status} vs fails=${d.fails}`);
    }
  }
});

test('one subject, one answer: the same inputs decide the same way whichever command asks', () => {
  // verify's findings for an entry, handed to explain's model as a live gate
  // result: the gate-derived part of explain's decision is exactly verify's.
  const e = require(path.join(S, 'explain.cjs'));
  const { loadPolicy } = require(path.join(S, 'lib', 'policy.cjs'));
  for (const [pname, dir] of Object.entries(DIRS)) {
    const report = JSON.parse(run('verify_integrity.cjs', ['--offline', '--json', '--cwd', dir, '--as-of', AS_OF]).stdout);
    for (const name of SAMPLE) {
      const tool = DB.find((t) => t.name === name);
      const gateEntry = report.entries.find((x) => x.name === name);
      const m = e.explainModel({
        tool, policy: loadPolicy(dir).policy, gateEntry, gateDoc: report.findings,
        trust: null, behav: null, budget: null, evidence: null, asOf: Date.parse(AS_OF),
        org: ORG.loadOrgContext({ cwd: dir, dbTools: DB, asOf: Date.parse(AS_OF) }),
      });
      const v = report.findings.decisions.find((d) => d.subject.id === m.subject.id);
      assert.ok(v, `${pname} ${name}: verify made no decision for ${m.subject.id}`);
      const gatePart = (d) => d.rules.filter((o) => o.rule.startsWith('finding/') || o.rule.startsWith('gate/require') || o.rule.startsWith('gate/fail-dep'));
      assert.deepEqual(gatePart(m.decision), gatePart(v), `${pname} ${name}: explain and verify read the same findings differently`);
    }
  }
});

test('explain exits as verify does: same policy, flags and --as-of, same exit and decided_by', () => {
  // Far enough ahead that every stored claim is past its shelf life: the case
  // where explain used to answer 0 ("not denied") while verify, holding the
  // same decision to `fail_on: unknown`, answered 1.
  const STALE = '2027-06-01T00:00:00.000Z';
  const cases = [[DIRS.unverified, []], [DIRS.none, ['--fail-unverified']], [DIRS.none, ['--strict']]];
  let stale = 0;
  for (const [dir, flags] of cases) {
    const v = JSON.parse(run('verify_integrity.cjs', ['--offline', '--json', '--cwd', dir, '--as-of', STALE, ...flags]).stdout);
    const byId = new Map(v.findings.decisions.map((d) => [d.subject.id, d]));
    for (const name of SAMPLE) {
      const label = `${path.basename(dir)} ${flags.join(' ') || '(no flags)'} ${name}`;
      const vr = run('verify_integrity.cjs', ['--offline', '--json', '--entry', name, '--cwd', dir, '--as-of', STALE, ...flags]);
      const er = run('explain.cjs', [name, '--json', '--cwd', dir, '--as-of', STALE, ...flags]);
      const [ed] = JSON.parse(er.stdout).findings.decisions;
      const vd = byId.get(ed.subject.id);
      assert.ok(vd, `${label}: verify made no decision for ${ed.subject.id}`);
      assert.equal(ed.fail_on, vd.fail_on, `${label}: explain and verify hold the entry to different thresholds`);
      assert.equal(er.status, vr.status, `${label}: explain exits ${er.status}, verify ${vr.status}`);
      // The case this test is about: nothing denies, and the threshold decides.
      if (vd.fails && vd.effect === 'unknown' && ed.effect !== 'deny') {
        stale++;
        assert.equal(ed.decided_by, vd.decided_by, `${label}: decided by ${ed.decided_by} here, ${vd.decided_by} in verify`);
        assert.equal(er.status, 1, `${label}: unknown under fail_on=${vd.fail_on} must fail`);
      }
    }
  }
  assert.ok(stale >= 3, `the fixtures must exercise stale evidence failing at fail_on (got ${stale})`);
});

// ── stored evidence: verify --offline and explain are one decision ─────────
//
// `verify --offline` used to check pins only, while `explain` applied the
// stored evidence: on the shipped DB nine entries were denied by one and
// passed by the other. Both now read the record through one producer
// (lib/findings_from.cjs fromStoredEvidence). And time is applied the same
// way (docs/adr/0001, "Positive findings do not age"): a found problem
// stays a finding at any age; only a claim of absence — "clean", "present"
// — goes stale, and stale is `unknown`, which fails only at fail_on unknown.

const FIX_AS_OF = '2026-09-30T12:00:00.000Z';
const FRESH = '2026-09-28';   // inside every shelf life at FIX_AS_OF
const OLD   = '2026-08-01';   // past the 7-day advisories/availability shelf life
const dim = (status, at) => ({ status, checked_at: at, ...(['present', 'verified', 'clean'].includes(status) ? { verified_at: at } : {}) });
const fixtureEntry = (name, dims) => ({
  name, category: 'utility', install_cmd: `npx -y ${name}`, source_url: `https://github.com/example/${name}`,
  version: '1.0.0', pkg_integrity: 'sha512-' + Buffer.from(name.padEnd(64, '.')).toString('base64'),
  trust: 'candidate', license: 'MIT', health_score: 80,
  trust_evidence: { artifact_id: `npm:${name}@1.0.0`, dimensions: {
    availability: dim('present', FRESH), artifact: dim('verified', FRESH), advisories: dim('clean', FRESH), ...dims,
  } },
});
// name -> [fixture, expected effect, expected decided_by, exit (no flags), exit (--fail-unverified)]
const FIXTURES = {
  'fx-advisory-fresh': [{ advisories: dim('vulnerable', FRESH) }, 'deny', 'trust/advisories', 1, 1],
  // Older than the advisories shelf life, and still a deny: a known advisory
  // against the pinned version does not stop being true by ageing.
  'fx-advisory-old':   [{ advisories: dim('vulnerable', OLD) }, 'deny', 'trust/advisories', 1, 1],
  // "No advisories" older than its shelf life: nobody knows any more.
  'fx-clean-old':      [{ advisories: dim('clean', OLD) }, 'unknown', 'finding/incomplete', 0, 1],
  'fx-yanked':         [{ availability: dim('yanked', OLD) }, 'deny', 'trust/availability', 1, 1],
};

function fixtureTree(t) {
  // DB_PATH is resolved next to the scripts, so the CLIs run on a copy.
  const root = fs.mkdtempSync(path.join(TMP, 'stored-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.cpSync(path.join(ROOT, 'mcp-ecosystem-intelligence'), path.join(root, 'mcp-ecosystem-intelligence'), { recursive: true });
  const dbFile = path.join(root, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json');
  const db = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
  db.tools = Object.entries(FIXTURES).map(([name, [dims]]) => fixtureEntry(name, dims));
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
  const scripts = path.join(root, 'mcp-ecosystem-intelligence', 'scripts');
  return (script, args) => spawnSync(process.execPath, [path.join(scripts, script), ...args], {
    encoding: 'utf8', env: ENV, cwd: TMP, maxBuffer: 64 * 1024 * 1024,
  });
}

test('verify --offline applies stored evidence as explain does: same effect, decided_by and exit', (t) => {
  const runIn = fixtureTree(t);
  const dir = DIRS.none;
  for (const [flags, col] of [[[], 3], [['--fail-unverified'], 4]]) {
    for (const [name, spec] of Object.entries(FIXTURES)) {
      const label = `${name} ${flags.join(' ') || '(no flags)'}`;
      const vr = runIn('verify_integrity.cjs', ['--offline', '--json', '--entry', name, '--cwd', dir, '--as-of', FIX_AS_OF, ...flags]);
      const er = runIn('explain.cjs', [name, '--json', '--cwd', dir, '--as-of', FIX_AS_OF, ...flags]);
      assert.doesNotMatch(vr.stderr, /internal:/, `${label}: the decision and the gate's counters disagree`);
      const vd = JSON.parse(vr.stdout).findings.decisions[0];
      assert.equal(vd.effect, spec[1], `${label}: verify effect`);
      assert.equal(vd.decided_by, spec[2], `${label}: verify decided_by`);
      assert.equal(vr.status, spec[col], `${label}: verify exit`);
      const ed = JSON.parse(er.stdout).findings.decisions[0];
      assert.equal(ed.subject.id, vd.subject.id, label);
      assert.equal(ed.effect, vd.effect, `${label}: explain says ${ed.effect}, verify ${vd.effect}`);
      assert.equal(ed.decided_by, vd.decided_by, `${label}: decided by ${ed.decided_by} here, ${vd.decided_by} in verify`);
      assert.equal(er.status, vr.status, `${label}: explain exits ${er.status}, verify ${vr.status}`);
    }
  }
  // The deny on an old advisory is a finding about the artifact, observed
  // then — not a stale claim — and it says when it was observed.
  const doc = JSON.parse(runIn('verify_integrity.cjs', ['--offline', '--json', '--entry', 'fx-advisory-old', '--cwd', dir, '--as-of', FIX_AS_OF]).stdout);
  const adv = doc.findings.findings.find((f) => f.rule === 'evidence/advisories');
  assert.ok(adv, 'the stored advisory is a finding');
  assert.equal(adv.state, 'observed');
  assert.equal(adv.severity, 'high');
  assert.match(adv.message, new RegExp(`observed ${OLD}`));
  assert.ok(!doc.findings.findings.some((f) => f.state === 'stale' && /advisories: vulnerable/.test(f.message)), 'a found advisory never reads as stale');
  const entry = doc.entries.find((e) => e.name === 'fx-advisory-old');
  assert.ok(entry.findings.some((f) => f.tag === 'CVE' && /stored evidence: advisories: vulnerable/.test(f.message)), 'rendered as a CVE line');
  assert.ok(!entry.findings.some((f) => /aged out: advisories/.test(f.message)), 'and not as evidence that aged out');
});

test('--fail-families narrows what fails the run, not what is decided', (t) => {
  const runIn = fixtureTree(t);
  const smoke = ['--fail-families', 'integrity,pin,oci,verify,policy'];
  const all = runIn('verify_integrity.cjs', ['--offline', '--json', '--cwd', DIRS.none, '--as-of', FIX_AS_OF, ...smoke]);
  assert.equal(all.status, 0, all.stderr);
  const doc = JSON.parse(all.stdout);
  assert.deepEqual(doc.findings.policy.fail_families, ['integrity', 'oci', 'pin', 'policy', 'verify']);
  // Still denied and still reported; only the exit code's question changed.
  assert.equal(doc.findings.decisions.filter((d) => d.effect === 'deny').length, 3);
  assert.ok(doc.findings.decisions.every((d) => !d.fails));
  assert.deepEqual(recompute(doc.findings), doc.findings.decisions, 'decide() of the document reproduces it');
  assert.ok(doc.entries.every((e) => e.failures === 0));
  // A family that is in scope still fails it.
  const adv = runIn('verify_integrity.cjs', ['--offline', '--json', '--cwd', DIRS.none, '--as-of', FIX_AS_OF, '--fail-families=evidence']);
  assert.equal(adv.status, 1);
  assert.doesNotMatch(adv.stderr, /internal:/);
});

test('outcomeFails: the family filter, by the outcome\'s rule or a finding it rests on', () => {
  const ruleOf = new Map([['f:1', 'integrity/docker-pin-mismatch'], ['f:2', 'evidence/advisories']]);
  const deny = (rule, findings) => ({ rule, effect: 'deny', findings, thresholded: true });
  assert.equal(F.outcomeFails(deny('finding/severity', ['f:2']), { families: ['integrity'], ruleOf }), false);
  assert.equal(F.outcomeFails(deny('finding/severity', ['f:1']), { families: ['integrity'], ruleOf }), true);
  assert.equal(F.outcomeFails(deny('policy/docker-digest', []), { families: ['policy'], ruleOf }), true);
  assert.equal(F.outcomeFails(deny('trust/advisories', []), { families: ['integrity'], ruleOf }), false);
  assert.equal(F.outcomeFails(deny('trust/advisories', []), { families: null, ruleOf }), true);
  const unknown = { rule: 'finding/incomplete', effect: 'unknown', findings: ['f:1'], thresholded: true };
  assert.equal(F.outcomeFails(unknown, { threshold: 'deny', ruleOf }), false);
  assert.equal(F.outcomeFails(unknown, { threshold: 'unknown', families: ['integrity'], ruleOf }), true);
  assert.deepEqual(PR.flagsFromArgv(['--fail-families', 'integrity/*, pin']).failFamilies, ['integrity', 'pin']);
  assert.equal(PR.flagsFromArgv([]).failFamilies, null);
});

// #127: `lock --check` and `approve` exit via decide(); their documents
// carry the policy and facts, and the legacy `servers` view renders the
// org/tool-approval outcome.
test('lock --check and approve: the decision is decide() of the document, and the exit code is its', () => {
  const dir = fs.mkdtempSync(path.join(TMP, 'approval-'));
  fs.writeFileSync(path.join(dir, '.mcp-vault.policy.json'), JSON.stringify({ toolApproval: 'require' }));
  const tools = path.join(dir, 'tools.json');
  fs.writeFileSync(tools, JSON.stringify({ tools: [{ name: 'q', description: 'Query.', inputSchema: { type: 'object', properties: { sql: { type: 'string' } } } }] }));
  const check = () => {
    const r = run('lock.cjs', ['--entry', 'mcp-clickhouse', '--check', '--json', '--cwd', dir]);
    const out = JSON.parse(r.stdout);
    const doc = out.findings;
    assert.equal(doc.schema, 'mcp-vault/findings@1');
    assert.deepEqual(recompute(doc), doc.decisions, 'lock --check: the printed decisions are not decide()\'s');
    assert.equal(r.status, F.exitCode(doc.decisions) === 1 ? 1 : 0, 'lock --check: the exit code is not the decisions\'');
    const unapproved = out.servers.filter((x) => x.changes.some((c) => c.kind === 'tool-unapproved')).map((x) => x.name);
    const denied = doc.decisions.filter((d) => d.rules.some((o) => o.rule === 'org/tool-approval' && o.effect === 'deny')).map((d) => d.subject.entry);
    assert.deepEqual(unapproved, denied, 'lock --check: tool-unapproved is not the org/tool-approval outcome');
    return { r, doc };
  };
  assert.equal(run('lock.cjs', ['--entry', 'mcp-clickhouse', '--cwd', dir]).status, 0);
  let c = check();
  assert.equal(c.r.status, 1);
  assert.equal(c.doc.decisions[0].decided_by, 'org/tool-approval');

  for (const extra of [[], ['--tools', tools]]) {
    const r = run('approve.cjs', ['mcp-clickhouse', '--dry-run', '--json', '--cwd', dir, ...extra]);
    const doc = JSON.parse(r.stdout).findings;
    assert.deepEqual(recompute(doc), doc.decisions, 'approve: the printed decisions are not decide()\'s');
    assert.equal(r.status, F.exitCode(doc.decisions) === 1 ? 1 : 0, 'approve: the exit code is not the decisions\'');
  }
  assert.equal(run('approve.cjs', ['mcp-clickhouse', '--cwd', dir]).status, 0);
  c = check();
  assert.equal(c.r.status, 0);
  assert.equal(c.doc.decisions[0].effect, 'allow');
});

// ── #121: signature and audit imports ─────────────────────────────────────

test('signature: the decision is decide() of its document, the exit code is the decisions\', across contexts and flags', () => {
  const s = require(path.join(S, 'lib', 'signing.cjs'));
  const ds = require(path.join(S, 'lib', 'db_signature.cjs'));
  const dir = fs.mkdtempSync(path.join(TMP, 'sig-'));
  const db = (name) => { const f = path.join(dir, name); fs.writeFileSync(f, JSON.stringify({ tools: [{ name }] })); return f; };
  const stranger = s.generateKeyPair();
  const byStranger = db('stranger.json');
  ds.signFile(byStranger, { privateKeyPem: stranger.privateKeyPem, now: Date.parse(AS_OF) });
  const malformed = db('malformed.json');
  fs.writeFileSync(`${malformed}.sig`, '{"format":"nope"}');
  const unsigned = db('unsigned.json');
  // The bundled DB (no .sig in a checkout), a DB without one, one signed by a
  // key the keyring does not list, one with a broken envelope.
  const FILES = [[], [unsigned], [byStranger], [malformed], [unsigned, byStranger]];
  const CONTEXTS = { checkout: {}, package: { MCP_VAULT_REQUIRE_SIGNED_DB: '1' } };
  const SFLAGS = [[], ['--strict'], ['--fail-unverified'], ['--allow-unsigned-db'], ['--allow-unsigned-db', '--strict']];
  const seen = new Set();
  for (const [cname, cenv] of Object.entries(CONTEXTS)) {
    for (const files of FILES) {
      for (const flags of SFLAGS) {
        const label = `${cname} ${files.map((f) => path.basename(f)).join(',') || '(bundled)'} ${flags.join(' ')}`;
        const r = spawnSync(process.execPath, [path.join(S, 'check_signature.cjs'), ...files, '--json', '--as-of', AS_OF, ...flags], {
          encoding: 'utf8', env: { ...ENV, MCP_VAULT_ALLOW_UNSIGNED_DB: '', MCP_VAULT_REQUIRE_SIGNED_DB: '', ...cenv }, cwd: TMP,
        });
        const doc = JSON.parse(r.stdout);
        assert.equal(doc.schema, 'mcp-vault/findings@1', label);
        assert.equal(doc.as_of, AS_OF, label);
        assert.deepEqual(recompute(doc), doc.decisions, `${label}: the printed decisions are not decide()'s`);
        assert.equal(r.status, F.exitCode(doc.decisions), `${label}: exit ${r.status}`);
        for (const d of doc.decisions) { assert.equal(d.decided_by, 'db/signature', label); seen.add(d.effect); }
      }
    }
  }
  // The fixtures reach every effect the row can give.
  assert.deepEqual([...seen].sort(), ['allow', 'deny', 'warn']);
});

test('audits check / fetch: the decision is decide() of its document, the exit code is the decisions\'', () => {
  const s = require(path.join(S, 'lib', 'signing.cjs'));
  const A = require(path.join(S, 'lib', 'audits.cjs'));
  const dir = fs.mkdtempSync(path.join(TMP, 'audits-'));
  const alice = s.generateKeyPair();
  const tool = DB.find((t) => A.subjectOf(t));
  const bundle = A.exportBundle([{ who: 'Alice', ...A.subjectOf(tool), criteria: 'safe-to-run', date: '2026-09-24' }],
    { privateKeyPem: alice.privateKeyPem, now: Date.parse(AS_OF) });
  fs.writeFileSync(path.join(dir, 'alice.json'), JSON.stringify(bundle));
  fs.writeFileSync(path.join(dir, A.IMPORTS_FILE), JSON.stringify({ sources: {
    alice: { path: 'alice.json', public_key: alice.publicKey, criteria: ['safe-to-run'] },
    bob:   { path: 'bob.json', public_key: s.generateKeyPair().publicKey, criteria: ['safe-to-run'] },
  } }));
  const audits = (...args) => {
    const r = spawnSync(process.execPath, [path.join(S, 'audits.cjs'), ...args, '--cwd', dir, '--json'], { encoding: 'utf8', env: ENV, cwd: TMP });
    const doc = JSON.parse(r.stdout);
    assert.equal(doc.schema, 'mcp-vault/findings@1', args.join(' '));
    assert.deepEqual(recompute(doc), doc.decisions, `${args.join(' ')}: the printed decisions are not decide()'s`);
    assert.equal(r.status, F.exitCode(doc.decisions), `${args.join(' ')}: exit ${r.status}`);
    return Object.fromEntries(doc.decisions.map((d) => [d.subject.id, [d.effect, d.decided_by]]));
  };
  // Nothing fetched yet; then bob's file is missing, so fetch fails for him
  // and writes nothing; with bob gone, fetch and check both pass.
  assert.deepEqual(audits('check'), { 'audit-source:alice': ['deny', 'audits/import'], 'audit-source:bob': ['deny', 'audits/import'] });
  assert.deepEqual(audits('fetch'), { 'audit-source:alice': ['allow', 'audits/import'], 'audit-source:bob': ['deny', 'audits/import'] });
  const cfg = JSON.parse(fs.readFileSync(path.join(dir, A.IMPORTS_FILE), 'utf8'));
  delete cfg.sources.bob;
  fs.writeFileSync(path.join(dir, A.IMPORTS_FILE), JSON.stringify(cfg));
  assert.deepEqual(audits('fetch'), { 'audit-source:alice': ['allow', 'audits/import'] });
  assert.deepEqual(audits('check'), { 'audit-source:alice': ['allow', 'audits/import'] });
  // A hand-edited lock is refused on the next check.
  const lockFile = path.join(dir, A.LOCK_FILE);
  const lock = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
  lock.sources.alice.bundle.payload.audits[0].who = 'Mallory';
  fs.writeFileSync(lockFile, JSON.stringify(lock));
  assert.deepEqual(audits('check'), { 'audit-source:alice': ['deny', 'audits/import'] });
});

// ── who decides ────────────────────────────────────────────────────────────

// Commands whose verdict is a Decision from decide() (and prints findings@1).
const DECIDES_VIA_MODEL = {
  verify:  'verify_integrity.cjs',
  explain: 'explain.cjs',
  // `install` is decided by verify's exit code, and refuses --as-of.
  install: 'orchestrate.cjs',
  // #127: tool approval is findings `org/tool-approval`, and both exit via
  // decide() (the `approval` rows); --check's differences are findings too.
  approve: 'approve.cjs',
  lock:    'lock.cjs',
  // #121: the DB signature (row db/signature) and the audit import check
  // (row audits/import, `audits fetch|check`); `audits list|add|export` are data.
  signature: 'check_signature.cjs',
  audits:    'audits.cjs',
};
// Commands that still map their own findings to an exit code. Each moves by
// emitting findings@1 and exiting via decide() — then its line goes.
const LEGACY_DECIDERS = {
  status:          'step 3: installed rows + audit findings → findings; verdict() → decide()',
  audit:           'step 3: categories → findings audit/<category>; --strict is fail_on',
  budget:          'step 4: the ceiling is the budget/over row explain already uses',
  doctor:          'step 5: environment checks → findings on a setup subject',
  eval:            'step 5: behaviour → findings; the ceiling rows already exist',
  availability:    'step 5: gone/yanked → findings; exit via decide()',
  identity:        'step 5: registry contradictions → findings',
  posture:         'step 5: scorecard → observations; weak → finding',
  capabilities:    'step 5: delta → findings; denyCapabilities is an org row (#127)',
  'docker-drift':  'step 5: drift → finding on the artifact',
  'license-drift': 'step 5: drift → finding; --strict is fail_on',
  upgrade:         'step 5: an upgrade plan is advice; its exit reports whether one exists',
  health:          'step 5: a score with a threshold → finding',
};
// Commands that answer a question without a verdict.
const NON_DECIDING = {
  scan: 'recommends; `install` is the decision', list: 'lists', ls: 'alias of list', discover: 'harvests candidates',
  refresh: 'writes pins', wrap: 'generates code', 'site-registry': 'renders the registry page', sbom: 'describes',
};

test('every command is classified: decides via the model, legacy decider (with its step), or no verdict', () => {
  const bin = fs.readFileSync(path.join(ROOT, 'bin', 'mcp-vault.cjs'), 'utf8');
  const block = bin.slice(bin.indexOf('const COMMANDS = {'), bin.indexOf('};', bin.indexOf('const COMMANDS = {')));
  const commands = [...block.matchAll(/^\s*"?([a-z-]+)"?:\s*"/gm)].map((m) => m[1]).sort();
  const classified = [...Object.keys(DECIDES_VIA_MODEL), ...Object.keys(LEGACY_DECIDERS), ...Object.keys(NON_DECIDING)].sort();
  assert.deepEqual(commands, classified,
    'a command was added or removed without saying whether it decides. New commands decide via decide() '
    + '(lib/finding.cjs) and print mcp-vault/findings@1 — see docs/adr/0001-findings-and-time.md');
  for (const [k, v] of Object.entries(LEGACY_DECIDERS)) assert.match(v, /^step \d/, `${k}: say which migration step moves it`);
});

// ── nobody else writes a decision word ─────────────────────────────────────

/** String-literal tokens with the code just before each, comments skipped. */
function stringTokens(src) {
  const out = [];
  let i = 0;
  const n = src.length;
  let line = 1;
  while (i < n) {
    const c = src[i];
    if (c === '\n') { line++; i++; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') line++; i++; }
      i += 2; continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const start = i;
      i++;
      let value = '';
      while (i < n && src[i] !== c) {
        if (src[i] === '\\') { value += src[i + 1] || ''; i += 2; continue; }
        if (src[i] === '\n') line++;
        value += src[i]; i++;
      }
      i++;
      out.push({ value, line, before: src.slice(Math.max(0, start - 12), start) });
      continue;
    }
    i++;
  }
  return out;
}

// Rendering a decision needs the word; making one is decide()'s. Each line
// here is a place that *prints* an effect, with why.
const DECISION_WORD_ALLOWLIST = [
  { file: 'explain.cjs', line: /decision: m\.decision\.effect === 'deny' \? 'deny' : 'allow'/, reason: 'the decision@1 view: its two-word vocabulary, read off the Decision' },
  // `deny` is also the name of a policy@1 key and a value of its `default`
  // key (#127): policy vocabulary that lib/org_policy.cjs parses, not an effect.
  { file: 'lib/org_policy.cjs', line: /^\s*default:\s+\['allow', 'deny'\],$/, reason: 'the values the `default` key accepts' },
  { file: 'lib/org_policy.cjs', line: /^\s*case 'deny': \{$/, reason: 'parsing the `deny` key' },
  { file: 'lib/org_policy.cjs', line: /^\s*if \(hasAllow\) policy\.default = 'deny';$/, reason: 'an allow list implies `default: deny` in the normalised file' },
  { file: 'lib/org_policy.cjs', line: /^const LAYERED\s+= new Set\(\['allow', 'deny',/, reason: 'the policy keys merged per layer' },
];

test('no code outside lib/finding.cjs and lib/policy_rules.cjs writes an effect', () => {
  const files = [];
  for (const dir of [S, path.join(S, 'lib')]) for (const f of fs.readdirSync(dir)) if (f.endsWith('.cjs')) files.push(path.join(dir, f));
  const offenders = [];
  for (const file of files) {
    const rel = path.relative(S, file).split(path.sep).join('/');
    if (rel === 'lib/finding.cjs' || rel === 'lib/policy_rules.cjs') continue;
    const src = fs.readFileSync(file, 'utf8');
    const lines = src.split('\n');
    for (const t of stringTokens(src)) {
      if (t.value !== 'deny') continue;
      if (/[!=]==\s*$/.test(t.before)) continue;   // reading an effect is fine
      const text = lines[t.line - 1] || '';
      if (DECISION_WORD_ALLOWLIST.some((a) => a.file === rel && a.line.test(text))) continue;
      offenders.push(`${rel}:${t.line}  ${text.trim()}`);
    }
  }
  assert.deepEqual(offenders, [],
    'an effect is being produced outside decide(). Add a row to lib/policy_rules.cjs and render the Decision instead.');
  assert.ok(stringTokens("a === 'deny'; b = 'deny' // 'deny'\n/* 'deny' */").filter((t) => t.value === 'deny').length === 2, 'the lexer skips comments');
});
