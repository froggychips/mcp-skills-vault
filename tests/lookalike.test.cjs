'use strict';
const { test }      = require('node:test');
const assert        = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs            = require('node:fs');
const os            = require('node:os');
const path          = require('node:path');

const L = require('../mcp-ecosystem-intelligence/scripts/lib/lookalike.cjs');

const REPO = path.resolve(__dirname, '..');
const DB   = JSON.parse(fs.readFileSync(path.join(REPO, 'mcp-ecosystem-intelligence/assets/tools_database.json'), 'utf8'));
const INDEX = L.buildIndex(DB.tools);

// ── primitives ─────────────────────────────────────────────────────────────

test('damerauLevenshtein: insert, delete, substitute, and an adjacent swap as one edit', () => {
  assert.equal(L.damerauLevenshtein('memory', 'memory'), 0);
  assert.equal(L.damerauLevenshtein('memmory', 'memory'), 1);
  assert.equal(L.damerauLevenshtein('memry', 'memory'), 1);
  assert.equal(L.damerauLevenshtein('memeory', 'memory'), 1);
  assert.equal(L.damerauLevenshtein('servre', 'server'), 1);   // Levenshtein would say 2
  assert.equal(L.damerauLevenshtein('', 'abc'), 3);
});

test('skeleton: Cyrillic, digits, uppercase I and rn all fold to what they imitate', () => {
  assert.equal(L.skeleton('mcp-сlickhouse'), L.skeleton('mcp-clickhouse'));   // Cyrillic с
  assert.equal(L.skeleton('@modelcontextprotoco1'), L.skeleton('@modelcontextprotocol'));
  assert.equal(L.skeleton('fiIesystem'), L.skeleton('filesystem'));
  assert.equal(L.skeleton('rnemory'), L.skeleton('memory'));
  assert.equal(L.skeleton('ｍｃｐ'), L.skeleton('mcp'));                        // fullwidth, via NFKC
  assert.notEqual(L.skeleton('memory'), L.skeleton('mercury'));
});

test('threshold: short names get no fuzzy room at all', () => {
  assert.equal(L.threshold(3), 0);
  assert.equal(L.threshold(6), 1);
  assert.equal(L.threshold(12), 2);
});

test('core: affixes come off, generic leftovers are empty', () => {
  assert.equal(L.core('mcp-server-memory'), 'memory');
  assert.equal(L.core('tavily-mcp-server'), 'tavily');
  assert.equal(L.core('context7-mcp-official'), 'context7');
  assert.equal(L.core('mcp-server'), '');
});

// ── the DB against itself ──────────────────────────────────────────────────

test('every identity of every DB entry is known, and none is flagged', () => {
  const flagged = [];
  for (const tool of DB.tools) {
    for (const id of L.identitiesOf(tool)) {
      const r = L.checkName(id.value, id.kind, INDEX);
      if (r.lookalike || r.known === null) flagged.push(`${id.kind} ${id.value}`);
    }
  }
  assert.deepEqual(flagged, [], `DB entries must not flag each other:\n  ${flagged.join('\n  ')}`);
});

test('leave-one-out: a legitimate entry would almost never be flagged as a lookalike of the rest', () => {
  // Stronger than the test above, which the exact-identity short-circuit makes
  // pass by construction: take each entry out of the DB and ask whether the
  // rest would call it a lookalike. That is what a newly added legitimate
  // server would face. A few real pairs do resemble each other
  // (mcp-server-kubernetes / kubernetes-mcp-server); the rate is what matters.
  const flagged = [];
  let total = 0;
  for (const tool of DB.tools) {
    const rest = L.buildIndex(DB.tools.filter((t) => t !== tool));
    for (const id of L.identitiesOf(tool)) {
      total++;
      const r = L.checkName(id.value, id.kind, rest);
      if (r.lookalike) flagged.push(`${id.kind} ${id.value} → ${r.matches[0].db_name} (${r.matches[0].technique})`);
    }
  }
  assert.ok(flagged.length / total <= 0.03,
    `${flagged.length}/${total} DB identities would be flagged against the rest:\n  ${flagged.join('\n  ')}`);
  // and nothing on the strongest evidence: a one-letter edit or a homoglyph
  // between two real entries would make every such flag untrustworthy.
  assert.ok(!flagged.some((f) => /homoglyph|letter|transposition|substitution/.test(f)), flagged.join('\n'));
});

// ── real shapes ────────────────────────────────────────────────────────────

const CASES = [
  // candidate                                   kind    resembles                   technique
  ['mcp-server-memmory',                         'npm',  'mcp-server-memory',        'doubled-letter'],
  ['@modelcontextprotocol/server-memmory',       'npm',  'mcp-server-memory',        'doubled-letter'],
  ['@modelcontextprotocol/server-filesytem',     'npm',  'mcp-server-filesystem',    'missing-letter'],
  ['mongodb-mcp-servre',                         'npm',  'mongodb-mcp-server',       'transposition'],
  ['chrome-devtools-mpc',                        'npm',  'chrome-devtools-mcp',      'transposition'],
  ['@modelcontextprotoco1/server-filesystem',    'npm',  'mcp-server-filesystem',    'homoglyph'],
  ['@modeIcontextprotocol/server-memory',        'npm',  'mcp-server-memory',        'homoglyph'],
  ['mcp-сlickhouse',                             'pypi', 'mcp-clickhouse',           'homoglyph'],
  ['mongodb_mcp_server',                         'npm',  'mongodb-mcp-server',       'separator'],
  ['@modelcontextprotocl/server-memory',         'npm',  'mcp-server-memory',        'scope-typo'],
  ['mcp-server-supabase',                        'npm',  '@supabase/mcp-server-supabase', 'scope-dropped'],
  ['context7-mcp',                               'npm',  'context7',                 'scope-dropped'],
  ['@evil/mcp-server-supabase',                  'npm',  '@supabase/mcp-server-supabase', 'foreign-scope'],
  ['@evil/mongodb-mcp-server',                   'npm',  'mongodb-mcp-server',       'scope-added'],
  ['mcp-server-memory',                          'npm',  'mcp-server-memory',        'vault-name-reused'],
  ['tavily-mcp-server',                          'npm',  'tavily-mcp',               'affix'],
  ['@upstash/context7-mcp-official',             'npm',  'context7',                 'affix'],
  ['ghcr.io/githuh/github-mcp-server',           'oci',  'github-mcp-server',        'scope-typo'],
  ['github/github-mcp-server',                   'oci',  'github-mcp-server',        'registry-swap'],
  ['playwrigth-mcp',                             'name', 'playwright-mcp',           'transposition'],
];

for (const [cand, kind, dbName, technique] of CASES) {
  test(`lookalike: ${kind} ${cand} → ${dbName} (${technique})`, () => {
    const r = L.checkName(cand, kind, INDEX);
    assert.equal(r.known, null);
    assert.equal(r.lookalike, true, `${cand} should be flagged`);
    assert.equal(r.matches[0].db_name, dbName, JSON.stringify(r.matches));
    assert.equal(r.matches[0].technique, technique, JSON.stringify(r.matches));
    assert.ok(L.describe(r).includes(`Likely an impersonation of ${dbName}`), L.describe(r));
  });
}

test('not lookalikes: unrelated names, generic bases in another scope, nicknames as keys', () => {
  for (const [cand, kind] of [
    ['my-own-thing', 'npm'],
    ['@acme/internal-tools', 'npm'],
    ['@evil/mcp-server', 'npm'],   // `mcp-server` alone is no identity; the scope is the name
    ['@evil/mcp', 'npm'],
    ['gh', 'npm'],
    ['github', 'name'],            // how people name the github server in a config
    ['filesystem', 'name'],
    ['memory', 'name'],
    ['postgres', 'name'],
  ]) {
    const r = L.checkName(cand, kind, INDEX);
    assert.equal(r.lookalike, false, `${kind} ${cand} flagged: ${JSON.stringify(r.matches)}`);
  }
});

test('the same package spelled differently is known, not a lookalike (PEP 503, case, tag)', () => {
  assert.equal(L.checkName('mcp_clickhouse', 'pypi', INDEX).known, 'mcp-clickhouse');
  assert.equal(L.checkName('MCP.Clickhouse', 'pypi', INDEX).known, 'mcp-clickhouse');
  assert.equal(L.checkName('ghcr.io/github/github-mcp-server:latest', 'oci', INDEX).known, 'github-mcp-server');
  assert.equal(L.checkName('docker.io/hashicorp/terraform-mcp-server', 'oci', INDEX).known, 'terraform-mcp-server');
  assert.equal(L.checkName('@modelcontextprotocol/server-memory', 'name', INDEX).known, 'mcp-server-memory');
});

test('deterministic: the same input gives the same, ordered answer', () => {
  const a = L.checkName('mcp-server-supabase', 'npm', INDEX);
  const b = L.checkName('mcp-server-supabase', 'npm', L.buildIndex(DB.tools));
  assert.deepEqual(a, b);
  assert.ok(a.matches.length >= 2, 'resembles more than one entry');
  assert.equal(a.matches[0].confidence, 'high');
});

// ── configured servers ─────────────────────────────────────────────────────

test('checkServer: a vault package under any key is fine; a lookalike package is not', () => {
  assert.equal(L.checkServer({ name: 'ctx', install_cmd: 'npx -y @upstash/context7-mcp@2.2.4' }, INDEX), null);
  const r = L.checkServer({ name: 'memory', install_cmd: 'npx -y mcp-server-memmory@1.0.0' }, INDEX);
  assert.equal(r.matches[0].db_name, 'mcp-server-memory');
  assert.equal(r.server, 'memory');
  assert.equal('allowed' in r, false, 'excusing a match is decide()\'s, not the matcher\'s');
});

test('checkServer: a vault name launching some other package is flagged even when that package resembles nothing', () => {
  const r = L.checkServer({ name: 'mcp-server-filesystem', install_cmd: 'npx -y totally-other-pkg@1.0.0' },
    INDEX, { dbName: 'mcp-server-filesystem' });
  assert.equal(r.matches[0].technique, 'vault-name-on-other-package');
  assert.match(L.describe(r), /launches totally-other-pkg/);
  // …and the entry's own package, at any version, is not.
  assert.equal(L.checkServer({ name: 'mcp-server-filesystem', install_cmd: 'npx -y @modelcontextprotocol/server-filesystem@1.0.0' },
    INDEX, { dbName: 'mcp-server-filesystem' }), null);
});

test('checkServer: `npx --yes` is read like `npx -y` (a vault key launching another package is still flagged)', () => {
  const r = L.checkServer({ name: 'mcp-server-memory', install_cmd: 'npx --yes totally-other@2026.1.26' }, INDEX, { dbName: 'mcp-server-memory' });
  assert.equal(r.matches[0].technique, 'vault-name-on-other-package');
  assert.match(L.describe(r), /launches totally-other/);
  assert.equal(L.checkServer({ name: 'mcp-server-memory', install_cmd: 'npx --yes @modelcontextprotocol/server-memory@1.0.0' }, INDEX, { dbName: 'mcp-server-memory' }), null);
});

test('checkServer: a vault-named key whose package cannot be read is not trusted', () => {
  const r = L.checkServer({ name: 'mcp-server-memory', install_cmd: 'npx -y --registry=https://evil.example @modelcontextprotocol/server-memory' }, INDEX, { dbName: 'mcp-server-memory' });
  assert.equal(r.matches[0].technique, 'vault-name-on-other-package');
  assert.match(r.matches[0].detail, /cannot be read/);
});

test('checkServer: a key that is a vault name up to case and separators is held to that entry\'s package', () => {
  const r = L.checkServer({ name: 'MCP_Server_Memory', install_cmd: 'npx -y totally-other@1.0.0' }, INDEX);
  assert.equal(r.matches[0].technique, 'vault-name-on-other-package');
  assert.equal(r.matches[0].db_name, 'mcp-server-memory');
  assert.equal(L.checkServer({ name: 'MCP_Server_Memory', install_cmd: 'npx -y @modelcontextprotocol/server-memory@1.0.0' }, INDEX), null);
});

test('findings: a lookalike is a lookalike/<technique> finding on a name subject, with no effect', () => {
  const r = L.checkServer({ name: 'memory', install_cmd: 'npx -y mcp-server-memmory@1.0.0' }, INDEX);
  const f = L.toFinding(r, { scope: 'installed' });
  assert.equal(f.rule, 'lookalike/doubled-letter');
  assert.deepEqual(f.subject, { type: 'name', id: 'npm:mcp-server-memmory', name: 'mcp-server-memmory', ecosystem: 'npm' });
  assert.equal(f.state, 'observed');
  assert.equal(f.confidence, 'high');
  for (const k of ['effect', 'outcome', 'decision', 'level']) assert.equal(k in f, false, k);
  assert.equal(L.ruleFor('scope-typo+substitution'), 'lookalike/scope-typo');
  assert.equal(L.toFinding(L.checkName('zzqx-nothing-like-it', 'npm', INDEX)), null);
});

test('decide: requested → deny, configured → warn (fails only at fail_on warn), --allow-lookalike → allow', () => {
  const F = require(path.join(REPO, 'mcp-ecosystem-intelligence/scripts/lib/finding.cjs'));
  const PR = require(path.join(REPO, 'mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs'));
  const allow = L.allowFromArgv(['--installed', '--allow-lookalike', 'memory,other', '--allow-lookalike=x']);
  assert.deepEqual([...allow], ['memory', 'other', 'x']);
  const r = L.checkServer({ name: 'memory', install_cmd: 'npx -y mcp-server-memmory@1.0.0' }, INDEX);
  const f = L.toFinding(r);
  const at = Date.parse('2026-09-30T00:00:00Z');
  const one = (facts, flags = {}) => F.decide([f], PR.effectivePolicy(null, flags), at, { subjects: [f.subject], facts: { [f.subject.id]: facts } })[0];
  const asked = one(L.factsFor(r, { intent: 'requested' }));
  assert.equal(asked.effect, 'deny');
  assert.equal(asked.decided_by, 'lookalike/doubled-letter');
  assert.equal(asked.fails, true);
  const configured = one(L.factsFor(r, { intent: 'configured' }));
  assert.equal(configured.effect, 'warn');
  assert.equal(configured.fails, false, 'a default does not become stricter');
  assert.equal(one(L.factsFor(r, { intent: 'configured' }), { strict: true }).fails, true);
  const vouched = one(L.factsFor(r, { intent: 'configured', allow: [...allow] }), { strict: true });
  assert.equal(vouched.effect, 'allow');
  assert.equal(vouched.fails, false);
  assert.match(vouched.rules[0].detail, /allowed by --allow-lookalike memory/);
  // A name has no entry, so a policy's licence/health/trust rules have nothing to judge.
  const strictPolicy = PR.effectivePolicy({ licenses: { allow: ['MIT'] }, minHealthScore: 70, trust: ['verified'] }, {});
  const d = F.decide([f], strictPolicy, at, { subjects: [f.subject], facts: { [f.subject.id]: L.factsFor(r, { intent: 'configured' }) } })[0];
  assert.deepEqual(d.rules.map((o) => o.rule), ['lookalike/doubled-letter']);
});

// ── CLIs ───────────────────────────────────────────────────────────────────

function tmpProject(servers) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lookalike-'));
  fs.writeFileSync(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }));
  fs.writeFileSync(path.join(dir, 'global.json'), '{}');
  return dir;
}

// The user's own host configs are not part of any of these tests.
function run(script, args, home) {
  return spawnSync(process.execPath, [path.join(REPO, script), ...args], {
    cwd: REPO, encoding: 'utf8', env: { ...process.env, HOME: home, APPDATA: home },
  });
}

const SQUAT = {
  memory:  { command: 'npx', args: ['-y', 'mcp-server-memmory@1.0.0'] },
  mine:    { command: 'npx', args: ['-y', 'my-own-thing@1.0.0'] },
};

test('CLI install: a lookalike name is refused with the entry it resembles, exit 2 as for any unknown name', () => {
  const dir = tmpProject({});
  const r = run('bin/mcp-vault.cjs', ['install', 'mcp-server-memmory', '--cwd', dir], dir);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /REFUSED: npm package mcp-server-memmory is not in the vault but looks like mcp-server-memory/);
  assert.match(r.stderr, /mcp-vault install mcp-server-memory/);
  assert.ok(!fs.existsSync(path.join(dir, '.mcp.json.bak')));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, '.mcp.json'), 'utf8')), { mcpServers: {} }, 'config untouched');

  const j = run('bin/mcp-vault.cjs', ['install', 'mcp-server-memmory', '--cwd', dir, '--json'], dir);
  assert.equal(j.status, 2);
  const doc = JSON.parse(j.stdout);
  assert.equal(doc.schema, 'mcp-vault/findings@1');
  assert.equal(doc.decisions[0].effect, 'deny');
  assert.equal(doc.decisions[0].decided_by, 'lookalike/doubled-letter');
  assert.equal(doc.facts[doc.decisions[0].subject.id].lookalike.matches[0].db_name, 'mcp-server-memory');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI install: a vault package typed instead of the vault name points at the name', () => {
  const dir = tmpProject({});
  const r = run('bin/mcp-vault.cjs', ['install', '@modelcontextprotocol/server-memory', '--cwd', dir], dir);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /mcp-vault install mcp-server-memory/);
  assert.doesNotMatch(r.stderr, /REFUSED/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI audit: lookalike is its own finding, fails --strict, and --allow-lookalike demotes it', () => {
  const dir = tmpProject(SQUAT);
  const args = ['--cwd', dir, '--global-config', path.join(dir, 'global.json'), '--json'];
  const plain = run('mcp-ecosystem-intelligence/scripts/audit_setup.cjs', args, dir);
  assert.equal(plain.status, 0, 'a default does not become stricter (docs/COMPATIBILITY.md)');
  const doc = JSON.parse(plain.stdout);
  // audit@1 `findings` is the findings@1 document; a row's own fields are
  // `details` by finding id.
  const rows = (d) => d.findings.findings.map((x) => ({ ...d.details[x.id], finding: x }));
  const f = rows(doc).find((x) => x.server === 'memory');
  assert.equal(f.category, 'lookalike');
  assert.equal(f.db_name, 'mcp-server-memory');
  assert.equal(f.technique, 'doubled-letter');
  assert.equal(f.finding.rule, 'lookalike/doubled-letter');
  assert.equal(rows(doc).find((x) => x.server === 'mine').category, 'unknown');

  assert.equal(run('mcp-ecosystem-intelligence/scripts/audit_setup.cjs', [...args, '--strict'], dir).status, 1);
  const allowed = run('mcp-ecosystem-intelligence/scripts/audit_setup.cjs', [...args, '--strict', '--allow-lookalike', 'memory'], dir);
  const ad = JSON.parse(allowed.stdout);
  const name = ad.findings.decisions.find((x) => x.subject.type === 'name');
  assert.deepEqual([name.effect, name.fails], ['allow', false], 'the vouched-for name no longer fails --strict');
  // (The server `mine` is still not in the DB — unknown — which --strict
  // fails on its own, as verify --installed and status do.)
  assert.equal(allowed.status, 1, allowed.stdout);
  assert.deepEqual(ad.findings.decisions.filter((x) => x.fails).map((x) => x.decided_by), ['finding/incomplete']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI audit: a scoped copy is not mistaken for the vetted entry by the substring match', () => {
  const dir = tmpProject({ mongo: { command: 'npx', args: ['-y', '@evil/mongodb-mcp-server@1.10.0'] } });
  const r = run('mcp-ecosystem-intelligence/scripts/audit_setup.cjs',
    ['--cwd', dir, '--global-config', path.join(dir, 'global.json'), '--json'], dir);
  const out = JSON.parse(r.stdout);
  const findings = out.findings.findings.map((x) => out.details[x.id]).filter((x) => x && x.server === 'mongo');
  assert.deepEqual(findings.map((x) => x.category), ['lookalike']);
  assert.equal(findings[0].technique, 'scope-added');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI verify --installed: LOOKALIKE finding with structured matches; a failure under --strict', () => {
  const dir = tmpProject(SQUAT);
  const script = 'mcp-ecosystem-intelligence/scripts/verify_integrity.cjs';
  const base = ['--installed', '--offline', '--cwd', dir, '--json', '--no-policy'];
  const r = run(script, base, dir);
  const doc = JSON.parse(r.stdout);
  const e = doc.entries.find((x) => x.name === 'memory');
  const finding = e.findings.find((x) => x.tag === 'LOOKALIKE');
  assert.ok(finding, JSON.stringify(e.findings));
  assert.equal(finding.rule, 'lookalike-name');
  assert.equal(e.lookalike.matches[0].db_name, 'mcp-server-memory');
  assert.equal(doc.entries.find((x) => x.name === 'mine').lookalike, undefined);
  assert.equal(e.failures, 0, 'not a failure by default');

  const strict = JSON.parse(run(script, [...base, '--strict'], dir).stdout);
  const se = strict.entries.find((x) => x.name === 'memory');
  assert.equal(se.status, 'FAIL');
  assert.ok(se.findings.some((x) => x.tag === 'LOOKALIKE'));

  const allowed = JSON.parse(run(script, [...base, '--strict', '--allow-lookalike', 'memory'], dir).stdout);
  const ae = allowed.entries.find((x) => x.name === 'memory');
  assert.ok(!ae.findings.some((x) => x.tag === 'LOOKALIKE'));
  assert.ok(ae.findings.some((x) => x.tag === 'NOTE' && /allowed by --allow-lookalike memory/.test(x.message)));
  // (The server itself is still unverified, which --strict fails on its own.)
  const d = allowed.findings.decisions.find((x) => x.subject.type === 'name');
  assert.equal(d.effect, 'allow');
  assert.equal(d.fails, false);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI explain: a lookalike gets a deny decision naming the entry it resembles', () => {
  const dir = tmpProject({});
  const r = run('mcp-ecosystem-intelligence/scripts/explain.cjs', ['mcp-server-memmory', '--json', '--cwd', dir], dir);
  assert.equal(r.status, 1);
  const rec = JSON.parse(r.stdout);
  assert.equal(rec.schema, 'mcp-vault/decision@1');
  assert.equal(rec.decision, 'deny');
  assert.deepEqual(rec.blocking, ['lookalike/doubled-letter']);
  assert.equal(rec.findings.decisions[0].decided_by, 'lookalike/doubled-letter');
  assert.equal(rec.lookalike.matches[0].db_name, 'mcp-server-memory');
  // Something that resembles nothing is still "not found".
  assert.equal(run('mcp-ecosystem-intelligence/scripts/explain.cjs', ['zzqx-nothing-like-it', '--cwd', dir], dir).status, 2);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ── a publisher's own unscoped package is not a scope-dropped copy ──────────

test('playwright: Microsoft\'s own unscoped package is not an impersonation of @playwright/mcp', () => {
  // Seen in a public config: `npx -y playwright run-test-mcp-server`.
  for (const name of ['playwright', 'playwright-core', 'Playwright']) {
    const r = L.checkName(name, 'npm', INDEX);
    assert.equal(r.lookalike, false, `${name}: ${JSON.stringify(r.matches)}`);
  }
  assert.equal(L.checkServer({ name: 'playwright', install_cmd: 'npx -y playwright run-test-mcp-server' }, INDEX), null);
  assert.ok(L.publisherScopesOf('playwright').has('playwright'));
});

test('playwright: real fakes are still flagged — the table is not a free pass for the name', () => {
  const evil = L.checkName('@evil/playwright-mcp', 'npm', INDEX);
  assert.equal(evil.lookalike, true);
  assert.equal(evil.matches[0].db_name, 'playwright-mcp');
  const typo = L.checkName('@playwrigth/mcp', 'npm', INDEX);
  assert.equal(typo.lookalike, true);
  assert.equal(typo.matches[0].technique, 'scope-typo');
  // Not on the table: an unscoped near-copy of the vault's package name.
  assert.equal(L.checkName('playwright-mcp-server', 'npm', INDEX).lookalike, true);
  // A scoped spelling of a table name is not covered by it.
  assert.deepEqual([...L.publisherScopesOf('@evil/playwright')], []);
});

test('the publisher table covers exact unscoped npm names only', () => {
  // `supabase` (the CLI, published by Supabase) is not a copy of anything.
  assert.equal(L.checkName('supabase', 'npm', INDEX).lookalike, false);
  // One letter off a table name is not on the table.
  assert.deepEqual([...L.publisherScopesOf('playwrigth')], []);
  assert.deepEqual([...L.publisherScopesOf('supabasse')], []);
  // The table is about npm names; a server key is still a key.
  assert.deepEqual([...L.publisherScopesOf('supabase-mcp')], []);
  // Every row names the scope it belongs to as a vault scope or a known one.
  for (const [scope, names] of Object.entries(L.PUBLISHER_UNSCOPED)) {
    assert.ok(names.length && names.every((n) => n === n.toLowerCase() && !n.startsWith('@')), scope);
  }
});
