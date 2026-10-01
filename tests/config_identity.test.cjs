'use strict';
/**
 * One configured server, one vault entry, one answer — whichever command asks.
 *
 * A config key is a label: `"pw": npx -y @playwright/mcp@0.0.75` is the
 * vault's playwright-mcp. `status` knew that; `check` and `verify --config`
 * matched by the key and called it "not in the vault DB". And for a server
 * they did know, they checked pins only: a yanked release or a known advisory
 * on record passed `check` while `status` and `verify --offline` failed it.
 *
 * Both are one matcher now (lib/entry_match.cjs) and one producer of the
 * stored part of the decision (lib/findings_from.cjs fromStoredEvidence). This
 * file holds the three commands to the same subject and the same decision on
 * one fixture whose keys are nobody's vault names.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

const match = require('../mcp-ecosystem-intelligence/scripts/lib/entry_match.cjs');
const budget = require('../mcp-ecosystem-intelligence/scripts/lib/budget.cjs');
const flows = require('../mcp-ecosystem-intelligence/scripts/lib/flows.cjs');
const auditSetup = require('../mcp-ecosystem-intelligence/scripts/audit_setup.cjs');
const { serverLine } = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-identity-'));
const HOME = fs.mkdtempSync(path.join(TMP, 'home-'));
const ENV = { ...process.env, HOME, NO_COLOR: '1', CI: '', MCP_VAULT_ALLOW_UNSIGNED_DB: '', MCP_VAULT_REQUIRE_SIGNED_DB: '' };

// The DB is a staged copy whose evidence this file controls
// (tests/lib/fixture_skill.cjs: playwright-mcp clean, mcp-atlassian with an
// advisory, mcp-server-aws yanked, all observed on OBSERVED), and every run has
// an explicit --as-of — so what is compared is how the commands read a record,
// never what the shipped DB says today.
const { fixtureSkill, AS_OF, LATE } = require('./lib/fixture_skill.cjs');
const trees = [];
process.on('exit', () => { for (const t of trees) t.cleanup(); });

function skillTree(opts = {}) {
  const f = fixtureSkill({ ...opts, env: ENV });
  trees.push(f);
  const versions = Object.fromEntries(Object.entries(f.launches).map(([n, l]) => [n, [l.command, ...l.args].join(' ')]));
  return { versions, run: (script, args, cwd) => f.run(script, args, { cwd, env: ENV }) };
}

/** `npx -y pkg@v` / `uvx pkg==v` as a config entry. */
function launch(installCmd) {
  const [command, ...args] = installCmd.split(/\s+/);
  return { command, args };
}

function project(servers) {
  const dir = fs.mkdtempSync(path.join(TMP, 'project-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }, null, 2));
  return dir;
}

const lineDecisions = (doc) => new Map(doc.decisions
  .filter((d) => d.subject.type === 'host-config' && d.subject.line)
  .map((d) => [d.subject.id, d]));

test('check, verify --config and status: same subject, same entry, same decision — keys are labels, stored evidence applies', (t) => {
  const tree = skillTree();
  const dir = project({
    pw:    launch(tree.versions['playwright-mcp']),     // clean
    jira:  launch(tree.versions['mcp-atlassian']),      // advisory on record
    cloud: launch(tree.versions['mcp-server-aws']),     // yanked
  });
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const c = tree.run('check_configs.cjs', ['--json', '--as-of', AS_OF], dir);
  const v = tree.run('verify_integrity.cjs', ['--offline', '--json', '--as-of', AS_OF, '--config', '.mcp.json'], dir);
  const s = tree.run('status.cjs', ['--json', '--as-of', AS_OF, '--cwd', dir], dir);
  for (const [name, r] of [['check', c], ['verify --config', v], ['status', s]]) {
    assert.doesNotMatch(r.stderr, /internal:/, `${name}: ${r.stderr}`);
    assert.ok(r.stdout, `${name} printed nothing: ${r.stderr}`);
  }
  const cd = JSON.parse(c.stdout);
  const vd = JSON.parse(v.stdout).findings;
  const sj = JSON.parse(s.stdout);
  const sd = sj.findings;

  // Every key is matched to its vault entry, by what it launches.
  const rows = new Map(sj.installed.map((r) => [r.name, r]));
  assert.equal(rows.get('pw').db_entry, 'playwright-mcp');
  assert.equal(rows.get('jira').db_entry, 'mcp-atlassian');
  assert.equal(rows.get('cloud').db_entry, 'mcp-server-aws');
  assert.ok(!vd.findings.some((f) => /not in the vault/.test(f.message)), 'verify --config called a vault server "not in the vault DB"');
  assert.ok(!cd.findings.some((f) => /not in the vault/.test(f.message)), 'check called a vault server "not in the vault DB"');

  // The same subjects, on the lines that launch them.
  const C = lineDecisions(cd); const V = lineDecisions(vd); const S = lineDecisions(sd);
  const text = fs.readFileSync(path.join(dir, '.mcp.json'), 'utf8');
  const ids = ['pw', 'jira', 'cloud'].map((k) => `.mcp.json:${serverLine(text, k)}`);
  const byServer = { pw: null, jira: null, cloud: null };
  for (const id of ids) {
    for (const [name, m] of [['check', C], ['verify --config', V], ['status', S]]) assert.ok(m.has(id), `${name} has no decision on ${id}`);
    byServer[C.get(id).subject.server] = id;
    assert.equal(V.get(id).subject.server, C.get(id).subject.server, id);
    assert.equal(S.get(id).subject.server, C.get(id).subject.server, id);
  }

  // The same decision: check is verify --config's, line for line; status
  // blocks exactly the lines they block.
  for (const id of ids) {
    assert.equal(C.get(id).effect, V.get(id).effect, `${id}: check ${C.get(id).effect}, verify --config ${V.get(id).effect}`);
    assert.equal(C.get(id).fails, V.get(id).fails, id);
    assert.equal(S.get(id).effect === 'deny', C.get(id).effect === 'deny', `${id}: status ${S.get(id).effect}, check ${C.get(id).effect}`);
  }
  assert.equal(C.get(byServer.pw).effect, 'allow');
  assert.equal(C.get(byServer.jira).effect, 'deny');
  assert.equal(C.get(byServer.cloud).effect, 'deny');
  assert.ok(cd.findings.some((f) => f.rule === 'evidence/advisories' && f.subject.id === byServer.jira));
  assert.ok(cd.findings.some((f) => f.rule === 'evidence/availability' && f.subject.id === byServer.cloud));

  // And one exit code.
  assert.equal(c.status, 1, c.stderr);
  assert.equal(v.status, 1, v.stderr);
  assert.equal(s.status, 1, s.stderr);

  // verify --offline on the vault entries themselves says the same.
  for (const [entry, want] of [['playwright-mcp', 0], ['mcp-atlassian', 1], ['mcp-server-aws', 1]]) {
    const e = tree.run('verify_integrity.cjs', ['--offline', '--json', '--as-of', AS_OF, '--entry', entry], dir);
    assert.equal(e.status, want, `verify --offline --entry ${entry}: ${e.stderr}`);
  }
});

test('check: a yanked release and one with an advisory on record fail it alone, as verify --offline and status fail them', (t) => {
  const tree = skillTree();
  for (const [key, entry] of [['a', 'mcp-server-aws'], ['b', 'mcp-atlassian']]) {
    const dir = project({ [key]: launch(tree.versions[entry]) });
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const c = tree.run('check_configs.cjs', ['--as-of', AS_OF], dir);
    const v = tree.run('verify_integrity.cjs', ['--offline', '--as-of', AS_OF, '--entry', entry], dir);
    const s = tree.run('status.cjs', ['--as-of', AS_OF, '--cwd', dir], dir);
    assert.equal(c.status, 1, `check on ${entry}:\n${c.stdout}${c.stderr}`);
    assert.equal(v.status, 1, `verify --offline on ${entry}:\n${v.stdout}${v.stderr}`);
    assert.equal(s.status, 1, `status on ${entry}:\n${s.stdout}${s.stderr}`);
    assert.match(c.stdout, /stored|yanked|vulnerable/);
  }
});

test('check: another version of a vault server is that server, but its record is not about these bytes', (t) => {
  const tree = skillTree();
  // The yanked entry's package at a version the vault never pinned.
  const dir = project({ cloud: { command: 'uvx', args: ['awslabs.core-mcp-server==1.0.26'] } });
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const c = JSON.parse(tree.run('check_configs.cjs', ['--json', '--as-of', AS_OF], dir).stdout);
  assert.ok(!c.findings.some((f) => f.rule === 'evidence/availability'), 'a yanked 1.0.27 is not a finding about 1.0.26');
  assert.ok(c.findings.some((f) => /not the one the vault pinned/.test(f.message)), c.findings.map((f) => f.message).join('\n'));
});

test('entry_match: one matcher — status, flows, budget, audit and org rules all see the package, never the key', () => {
  const db = [
    { name: 'playwright-mcp', install_cmd: 'npx -y @playwright/mcp@0.0.75', version: '0.0.75' },
    { name: 'mcp-server-aws', install_cmd: 'uvx awslabs.core-mcp-server==1.0.27', version: '1.0.27' },
  ];
  const pw = 'npx -y @playwright/mcp@0.0.75';
  assert.equal(match.matchLaunch(db, pw).entry.name, 'playwright-mcp');
  assert.equal(match.matchLaunch(db, pw).version_match, 'same');
  assert.equal(match.matchLaunch(db, 'npx -y @playwright/mcp@0.0.80').version_match, 'different');
  assert.equal(match.matchLaunch(db, 'npx -y @playwright/mcp').version_match, 'different');
  assert.equal(match.sameArtifactEntry(db, 'npx -y @playwright/mcp@0.0.80'), null);
  // PyPI names compare normalised.
  assert.equal(match.matchLaunch(db, 'uvx awslabs-core-mcp-server==1.0.27').entry.name, 'mcp-server-aws');
  assert.equal(match.matchLaunch(db, 'node ./innocent.js').entry, null);
  assert.equal(match.matchLaunch(db, null).entry, null);

  // The vault's name as a key on another package is not that entry — anywhere.
  const server = { name: 'mcp-server-aws', command: 'npx', args: ['-y', '@playwright/mcp@0.0.75'], install_cmd: pw };
  assert.equal(budget.matchDbEntry(server, db).name, 'playwright-mcp');
  assert.equal(flows.dbEntryForLaunch(db, pw).name, 'playwright-mcp');
  assert.equal(auditSetup.matchDbEntry({ tools: db }, 'mcp-server-aws', { command: 'npx', args: ['-y', '@playwright/mcp@0.0.75'] }).name, 'playwright-mcp');
  assert.equal(budget.matchDbEntry({ name: 'mcp-server-aws', command: 'node', args: ['./innocent.js'] }, db), null);
});

test('one version equality: PEP 440 / PEP 503 spellings of a release are that release — in status, check and audit alike', () => {
  const { sameVersion } = require('../mcp-ecosystem-intelligence/scripts/lib/versions.cjs');
  for (const [a, b] of [['1.0', '1.0.0'], ['1.0.27.0', '1.0.27'], ['V1.0RC1', '1.0rc1'], ['1.0-post1', '1.0.post1'],
    ['1.0.dev0', '1.0.dev'], ['1.0alpha1', '1.0a1'], ['1.0.r2', '1.0.post2'], ['01.002', '1.2']]) {
    assert.equal(sameVersion(a, b, 'pypi'), true, `${a} == ${b}`);
  }
  for (const [a, b] of [['1.0', '1.0.1'], ['1.0+abc', '1.0'], ['1.0a1', '1.0b1'], ['1.0.post1', '1.0']]) {
    assert.equal(sameVersion(a, b, 'pypi'), false, `${a} != ${b}`);
  }
  assert.equal(sameVersion('v1.2.3', '1.2.3', 'npm'), true);
  assert.equal(sameVersion('1.2.3', '1.2.4', 'npm'), false);
  assert.equal(sameVersion('latest', '1.2.3', 'npm'), null, 'a tag is not a version: cannot tell, never "same"');

  const db = { tools: [{
    name: 'mcp-server-aws', category: 'cloud', trust: 'verified', est_tools_count: 4,
    install_cmd: 'uvx awslabs.core-mcp-server==1.0.27', version: '1.0.27',
  }] };
  for (const args of [['awslabs-core-mcp-server==1.0.27.0'], ['Awslabs_Core_MCP_Server==1.0.27'], ['awslabs.core-mcp-server==1.0.27']]) {
    const cmd = `uvx ${args[0]}`;
    assert.equal(match.matchLaunch(db.tools, cmd).version_match, 'same', cmd);
    const findings = auditSetup.audit({
      project: { cloud: { command: 'uvx', args } }, global: {}, settings: { enabled: null, allowedTools: [] }, db,
    });
    assert.ok(!findings.some((f) => f.category === 'drift'), `${cmd}: audit reported drift for the same release`);
  }
  const moved = auditSetup.audit({
    project: { cloud: { command: 'uvx', args: ['awslabs.core-mcp-server==1.0.28'] } }, global: {}, settings: { enabled: null, allowedTools: [] }, db,
  });
  assert.ok(moved.some((f) => f.category === 'drift'), 'another release is still drift');
});

test('check: an aged-out vault record is one context line per server — said, in text, JSON and SARIF, and never the answer', (t) => {
  const tree = skillTree();
  // LATE: every claim of absence past its shelf life.
  const dir = project({ pw: launch(tree.versions['playwright-mcp']), jira: launch(tree.versions['mcp-atlassian']) });
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  for (const failOn of ['deny', 'unknown', 'warn']) {
    // pw: only its age is new, so the exit is what it was without it; jira:
    // an advisory on record still fails at every threshold.
    const solo = project({ pw: launch(tree.versions['playwright-mcp']) });
    t.after(() => fs.rmSync(solo, { recursive: true, force: true }));
    const fresh = tree.run('check_configs.cjs', ['--json', '--as-of', AS_OF, '--fail-on', failOn], solo);
    const late = tree.run('check_configs.cjs', ['--json', '--as-of', LATE, '--fail-on', failOn], solo);
    assert.equal(late.status, fresh.status, `fail-on ${failOn}: an aged record changed the exit (${fresh.status} → ${late.status})`);
    assert.equal(tree.run('check_configs.cjs', ['--as-of', LATE, '--fail-on', failOn], dir).status, 1, `fail-on ${failOn}`);
  }

  const text = tree.run('check_configs.cjs', ['--as-of', LATE], dir).stdout;
  const lines = text.split('\n').filter((l) => /^\s+i vault evidence for /.test(l));
  assert.equal(lines.length, 2, `one context line per server:\n${text}`);
  assert.match(lines.join('\n'), /@playwright\/mcp@[\d.]+ is \d+ days old \([a-z_, ]+\) — the result above uses what was last seen/);

  const doc = JSON.parse(tree.run('check_configs.cjs', ['--json', '--as-of', LATE], dir).stdout);
  const age = doc.findings.filter((f) => f.rule === 'evidence/vault-age');
  assert.equal(age.length, 2);
  for (const f of age) {
    assert.equal(f.state, 'stale');
    const d = doc.decisions.find((x) => x.subject.id === f.subject.id);
    const o = d.rules.find((x) => x.findings.includes(f.id));
    assert.equal(o.role, 'context', 'the age is context, not part of the answer');
    assert.equal(o.rule, 'evidence/vault-age');
  }
  const pwLine = age.find((f) => /playwright/.test(f.message)).subject.id;
  assert.equal(doc.decisions.find((x) => x.subject.id === pwLine).effect, 'allow');
  assert.ok(doc.findings.some((f) => f.rule === 'evidence/advisories' && f.state === 'observed'), 'the advisory is still decided');

  const sarif = JSON.parse(tree.run('check_configs.cjs', ['--sarif', '--as-of', LATE], dir).stdout);
  const notes = sarif.runs[0].results.filter((r) => r.ruleId === 'evidence/vault-age');
  assert.equal(notes.length, 2);
  assert.ok(notes.every((r) => r.level === 'note'));

  // One stale entry beside a fresh one, at the same instant: only the stale
  // one gets the line, and the run is clean at every threshold.
  const mixed = skillTree({ stale: ['playwright-mcp'] });
  const both = project({ pw: launch(mixed.versions['playwright-mcp']), db: launch(mixed.versions['mongodb-mcp-server']) });
  t.after(() => fs.rmSync(both, { recursive: true, force: true }));
  const m = mixed.run('check_configs.cjs', ['--as-of', AS_OF, '--fail-on', 'unknown'], both);
  assert.equal(m.status, 0, m.stdout + m.stderr);
  const ctx = m.stdout.split('\n').filter((l) => /^\s+i vault evidence for /.test(l));
  assert.equal(ctx.length, 1, m.stdout);
  assert.match(ctx[0], /@playwright\/mcp@0\.0\.75 is \d+ days old/);
});
