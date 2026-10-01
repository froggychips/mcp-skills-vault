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
      // Stored evidence can also *deny* (a recorded advisory, a vanished
      // package), which an offline verify does not re-read: there explain
      // is stricter, and both still exit 1. The case this test is about is
      // the other one — nothing denies, and the threshold decides.
      if (vd.fails && vd.effect === 'unknown' && ed.effect !== 'deny') {
        stale++;
        assert.equal(ed.decided_by, vd.decided_by, `${label}: decided by ${ed.decided_by} here, ${vd.decided_by} in verify`);
        assert.equal(er.status, 1, `${label}: unknown under fail_on=${vd.fail_on} must fail`);
      }
    }
  }
  assert.ok(stale >= 3, `the fixtures must exercise stale evidence failing at fail_on (got ${stale})`);
});

// ── who decides ────────────────────────────────────────────────────────────

// Commands whose verdict is a Decision from decide() (and prints findings@1).
const DECIDES_VIA_MODEL = {
  verify:  'verify_integrity.cjs',
  explain: 'explain.cjs',
  // `install` is decided by verify's exit code, and refuses --as-of.
  install: 'orchestrate.cjs',
};
// Commands that still map their own findings to an exit code. Each moves by
// emitting findings@1 and exiting via decide() — then its line goes.
const LEGACY_DECIDERS = {
  status:          'step 3: installed rows + audit findings → findings; verdict() → decide()',
  audit:           'step 3: categories → findings audit/<category>; --strict is fail_on',
  lock:            'step 4 (with #127): --check differences → findings on the server; tool approval a row',
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
