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
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const match = require('../mcp-ecosystem-intelligence/scripts/lib/entry_match.cjs');
const budget = require('../mcp-ecosystem-intelligence/scripts/lib/budget.cjs');
const flows = require('../mcp-ecosystem-intelligence/scripts/lib/flows.cjs');
const auditSetup = require('../mcp-ecosystem-intelligence/scripts/audit_setup.cjs');
const { serverLine } = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-identity-'));
const HOME = fs.mkdtempSync(path.join(TMP, 'home-'));
const ENV = { ...process.env, HOME, NO_COLOR: '1', CI: '', MCP_VAULT_ALLOW_UNSIGNED_DB: '', MCP_VAULT_REQUIRE_SIGNED_DB: '' };

// A day after the stored evidence below was observed: every claim is fresh,
// so what differs between the commands can only be how they read it.
const OBSERVED = '2026-09-17';
const AS_OF = '2026-09-18T12:00:00Z';

/**
 * A copy of the skill (DB_PATH resolves next to the scripts) in which one
 * entry carries an advisory against its pinned version, and one is yanked —
 * as stored evidence bound to exactly that artifact.
 */
function skillTree() {
  const root = fs.mkdtempSync(path.join(TMP, 'skill-'));
  fs.cpSync(path.join(ROOT, 'mcp-ecosystem-intelligence'), path.join(root, 'mcp-ecosystem-intelligence'), { recursive: true });
  const dbFile = path.join(root, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json');
  const db = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
  const entry = (name) => {
    const t = db.tools.find((x) => x.name === name);
    assert.ok(t && t.trust_evidence, `${name} is no longer in the DB with evidence; pick another entry`);
    return t;
  };
  entry('mcp-atlassian').trust_evidence.dimensions.advisories = { status: 'vulnerable', checked_at: OBSERVED };
  assert.equal(entry('mcp-server-aws').trust_evidence.dimensions.availability.status, 'yanked');
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
  const scripts = path.join(root, 'mcp-ecosystem-intelligence', 'scripts');
  const versions = Object.fromEntries(['playwright-mcp', 'mcp-atlassian', 'mcp-server-aws'].map((n) => [n, entry(n).install_cmd]));
  return {
    versions,
    run: (script, args, cwd) => spawnSync(process.execPath, [path.join(scripts, script), ...args], {
      cwd, encoding: 'utf8', env: ENV, maxBuffer: 64 * 1024 * 1024,
    }),
  };
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
