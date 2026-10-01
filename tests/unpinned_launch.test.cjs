'use strict';
// config/unpinned-launch: a host config that launches a registry package with
// no exact version. A finding about the *config line*, decided by its own
// policy row — not the vault's DB "missing a pin", and not "unverified".
const { test }      = require('node:test');
const assert        = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs            = require('node:fs');
const os            = require('node:os');
const path          = require('node:path');

const inst = require('../mcp-ecosystem-intelligence/scripts/lib/installed.cjs');
const F    = require('../mcp-ecosystem-intelligence/scripts/lib/finding.cjs');
const PR   = require('../mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs');
const policy = require('../mcp-ecosystem-intelligence/scripts/lib/policy.cjs');

const REPO = path.resolve(__dirname, '..');
const DB   = JSON.parse(fs.readFileSync(path.join(REPO, 'mcp-ecosystem-intelligence/assets/tools_database.json'), 'utf8'));
const AS_OF = '2026-10-01T00:00:00Z';

const srv = (command, ...args) => ({ name: 's', command, args });

// ── the observation ────────────────────────────────────────────────────────

test('unpinnedLaunch: no version, a tag and a range are all unpinned; an exact version is not', () => {
  assert.match(inst.unpinnedLaunch(srv('npx', '-y', 'some-pkg')).message, /^this config launches some-pkg without a version: whatever is latest at each start runs$/);
  assert.match(inst.unpinnedLaunch(srv('npx', '-y', 'some-pkg@latest')).message, /some-pkg@latest, a tag rather than a version: whatever is latest at each start runs/);
  assert.match(inst.unpinnedLaunch(srv('npx', '-y', 'some-pkg@^1.2.0')).message, /some-pkg@\^1\.2\.0, a range rather than a version/);
  assert.match(inst.unpinnedLaunch(srv('uvx', 'some-pkg')).message, /without a version/);
  assert.equal(inst.unpinnedLaunch(srv('npx', '-y', 'some-pkg@1.2.3')), null);
  assert.equal(inst.unpinnedLaunch(srv('uvx', 'some-pkg==1.2')), null);
  // Not a registry launch, or not readable: the gate says so itself.
  assert.equal(inst.unpinnedLaunch(srv('node', './server.js')), null);
  assert.equal(inst.unpinnedLaunch(srv('npx', '-y', '--registry=https://x', 'p')), null);
  assert.equal(inst.unpinnedLaunch(srv('uvx', '--from', 'git+https://x/y', 'z')), null);
});

test('unpinnedLaunch: the advice is the config\'s own line, pinned to the version the vault verified', () => {
  const u = inst.unpinnedLaunch(srv('npx', '-y', '@playwright/mcp@latest', '--headless'), { dbTools: DB.tools });
  const pw = DB.tools.find((t) => t.name === 'playwright-mcp');
  assert.deepEqual(u.pinned_args, ['-y', `@playwright/mcp@${pw.version}`, '--headless']);
  assert.equal(u.advice, `pin it to the version the vault verified (playwright-mcp): "args": ${JSON.stringify(['-y', `@playwright/mcp@${pw.version}`, '--headless'])}`);
  // -p / --package=: the spec is rewritten where it stands.
  assert.deepEqual(inst.unpinnedLaunch(srv('npx', '--package=@playwright/mcp', 'mcp-server-playwright'), { dbTools: DB.tools }).pinned_args,
    [`--package=@playwright/mcp@${pw.version}`, 'mcp-server-playwright']);
  // A runner other than npx: the same line, its own runner.
  assert.deepEqual(inst.unpinnedLaunch(srv('pnpx', '@playwright/mcp@latest'), { dbTools: DB.tools }).pinned_args, [`@playwright/mcp@${pw.version}`]);
  // PyPI
  const fetch = DB.tools.find((t) => t.name === 'mcp-server-fetch');
  assert.deepEqual(inst.unpinnedLaunch(srv('uvx', 'mcp-server-fetch'), { dbTools: DB.tools }).pinned_args, [`mcp-server-fetch==${fetch.version}`]);
  // Not in the vault: say how, not what.
  assert.equal(inst.unpinnedLaunch(srv('npx', '-y', 'zz-not-in-vault'), { dbTools: DB.tools }).advice, 'pin to an exact version (zz-not-in-vault@<x.y.z>)');
});

test('unpinnedLaunch: matched by package, never by the config key', () => {
  // A key that is a vault name launching some other package gets no vault version.
  const u = inst.unpinnedLaunch({ name: 'playwright-mcp', command: 'npx', args: ['-y', 'zz-other'] }, { dbTools: DB.tools });
  assert.equal(u.db_entry, null);
  assert.match(u.advice, /^pin to an exact version/);
});

// ── the decision ───────────────────────────────────────────────────────────

const subj = F.subject.hostConfig({ path: '.mcp.json', line: 3, host: 'claude-code', scope: 'project', server: 's' });
const fnd = F.finding({ rule: 'config/unpinned-launch', subject: subj, scope: 'installed', severity: 'medium', message: 'this config launches x without a version: whatever is latest at each start runs. Pin to an exact version (x@<x.y.z>).' });
const decideWith = (file, flags = {}) => {
  const p = PR.effectivePolicy(file ? policy.normalizePolicy(file).policy : null, flags, { defaults: policy.DEFAULTS });
  return F.decide([fnd], p, new Date(AS_OF), { subjects: [subj], facts: {} })[0];
};

test('config/unpinned-launch: warn by default (fails only under --strict), fail and allow by policy', () => {
  const d = decideWith(null);
  assert.equal(d.effect, 'warn');
  assert.equal(d.decided_by, 'config/unpinned-launch');
  assert.equal(d.fails, false, 'a default does not get stricter in a minor');
  assert.equal(decideWith(null, { strict: true }).fails, true);
  const fail = decideWith({ unpinnedLaunch: 'fail' });
  assert.equal(fail.effect, 'deny');
  assert.equal(fail.fails, true);
  const allow = decideWith({ unpinnedLaunch: 'allow' }, { strict: true });
  assert.equal(allow.effect, 'allow');
  assert.equal(allow.fails, false);
  // The generic severity rows do not judge it a second time.
  assert.deepEqual(d.rules.map((o) => o.rule), ['config/unpinned-launch']);
});

test('policy: unpinnedLaunch is a known key with its own enum, stricter-wins ranked', () => {
  assert.equal(policy.DEFAULTS.unpinnedLaunch, 'warn');
  assert.equal(policy.normalizePolicy({ unpinnedLaunch: 'fail' }).ok, true);
  assert.equal(policy.normalizePolicy({ unpinnedLaunch: 'sometimes' }).ok, false);
  assert.deepEqual(PR.RANK.unpinnedLaunch, ['allow', 'warn', 'fail']);
  assert.ok(PR.FINDING_FAMILIES.includes('config'));
  assert.equal(PR.rowFor('config/unpinned-launch').id, 'config/unpinned-launch');
});

// ── end to end ─────────────────────────────────────────────────────────────

function project(servers, pol = null) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unpinned-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }, null, 2));
  if (pol) fs.writeFileSync(path.join(dir, '.mcp-vault.policy.json'), JSON.stringify(pol));
  return dir;
}
function verify(dir, ...flags) {
  const r = spawnSync(process.execPath, [path.join(REPO, 'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs'),
    '--installed', '--offline', '--json', '--cwd', dir, '--as-of', AS_OF, ...flags], {
    cwd: dir, encoding: 'utf8', env: { ...process.env, HOME: dir, APPDATA: dir },
  });
  return { status: r.status, stderr: r.stderr, doc: JSON.parse(r.stdout) };
}

test('CLI verify --installed: an UNPINNED line on the config line, the finding on its host-config subject', () => {
  const dir = project({
    pinned:   { command: 'npx', args: ['-y', '@playwright/mcp@0.0.75'] },
    floating: { command: 'npx', args: ['--yes', '@playwright/mcp@latest'] },
  });
  const { status, doc, stderr } = verify(dir);
  assert.equal(status, 0, stderr);
  assert.doesNotMatch(stderr, /internal:/);
  const floating = doc.entries.find((e) => e.name === 'floating');
  const line = floating.findings.find((f) => f.tag === 'UNPINNED');
  assert.match(line.message, /this config launches @playwright\/mcp@latest, a tag rather than a version: whatever is latest at each start runs/);
  assert.match(line.message, /"args": \["--yes","@playwright\/mcp@0\.0\.75"\]/);
  // The config's problem is not phrased as the DB's.
  assert.ok(!floating.findings.some((f) => /in DB/.test(f.message)), JSON.stringify(floating.findings));
  assert.ok(!doc.entries.find((e) => e.name === 'pinned').findings.some((f) => f.tag === 'UNPINNED'));

  const f = doc.findings.findings.find((x) => x.rule === 'config/unpinned-launch');
  assert.equal(f.subject.type, 'host-config');
  assert.equal(f.subject.server, 'floating');
  assert.match(f.subject.id, /\.mcp\.json:\d+$/);
  const d = doc.findings.decisions.find((x) => x.subject.id === f.subject.id);
  assert.ok(d.rules.some((o) => o.rule === 'config/unpinned-launch' && o.effect === 'warn'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI verify --installed: unpinnedLaunch "fail" fails the run on its own; "allow" turns the line into a NOTE', () => {
  const servers = { floating: { command: 'npx', args: ['-y', '@playwright/mcp'] } };
  const failDir = project(servers, { unpinnedLaunch: 'fail' });
  const failed = verify(failDir);
  assert.equal(failed.status, 1);
  assert.doesNotMatch(failed.stderr, /internal:/);
  const fe = failed.doc.entries.find((e) => e.name === 'floating');
  assert.equal(fe.status, 'FAIL');
  assert.ok(fe.findings.some((x) => x.tag === 'UNPINNED'));

  const allowDir = project(servers, { unpinnedLaunch: 'allow' });
  const allowed = verify(allowDir);
  const ae = allowed.doc.entries.find((e) => e.name === 'floating');
  assert.ok(!ae.findings.some((x) => x.tag === 'UNPINNED'));
  assert.ok(ae.findings.some((x) => x.tag === 'NOTE' && /unpinnedLaunch: allow/.test(x.message)));
  for (const d of [failDir, allowDir]) fs.rmSync(d, { recursive: true, force: true });
});

test('CLI verify --installed --sarif: the finding is anchored on the config line', () => {
  const dir = project({ floating: { command: 'npx', args: ['-y', '@playwright/mcp@latest'] } });
  const r = spawnSync(process.execPath, [path.join(REPO, 'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs'),
    '--installed', '--offline', '--sarif', '--cwd', dir, '--as-of', AS_OF], { cwd: dir, encoding: 'utf8', env: { ...process.env, HOME: dir, APPDATA: dir } });
  const sarif = JSON.parse(r.stdout);
  const res = sarif.runs[0].results.find((x) => /config\/unpinned-launch/.test(x.ruleId));
  assert.ok(res, JSON.stringify(sarif.runs[0].results.map((x) => x.ruleId)));
  const loc = res.locations[0].physicalLocation;
  assert.match(loc.artifactLocation.uri, /\.mcp\.json$/);
  assert.equal(loc.region.startLine, 3);
  fs.rmSync(dir, { recursive: true, force: true });
});
