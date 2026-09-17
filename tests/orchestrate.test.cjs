'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const o = require('../mcp-ecosystem-intelligence/scripts/orchestrate.cjs');

// unmappedSignals(db, stack) returns one record per stack signal that
// either has no mapping in SIGNAL_TO_TOOLS or whose mapping references
// a tool absent from the DB.

const dbWith = (...names) => ({ tools: names.map(name => ({ name })) });
const stackWith = ({ dbs = [], infra = [] }) => ({ dbs: new Set(dbs), infra: new Set(infra) });

test('unmappedSignals: returns [] when every signal maps to a present tool', () => {
  // postgres maps to mcp-server-neon per SIGNAL_TO_TOOLS.
  const db    = dbWith('mcp-server-neon');
  const stack = stackWith({ dbs: ['postgres'] });
  assert.deepEqual(o.unmappedSignals(db, stack), []);
});

test('unmappedSignals: flags signals without any mapping or fallback (ansible in empty DB)', () => {
  // ansible is detected by detectStack but absent from SIGNAL_TO_TOOLS
  // AND no tool name/notes contains "ansible" — true gap.
  const db    = dbWith('mcp-server-neon');
  const stack = stackWith({ infra: ['ansible'] });
  const out   = o.unmappedSignals(db, stack);
  assert.equal(out.length, 1);
  assert.equal(out[0].signal, 'ansible');
  assert.equal(out[0].reason, 'no mapping');
  assert.equal(out[0].fallback, undefined);
});

test('unmappedSignals: signal resolved via fallback is marked fallback, not gap', () => {
  // Use a signal NOT in SIGNAL_TO_TOOLS (loki isn't curated today)
  // but with a matching tool name in the synthetic DB. Substring scan
  // should classify this as a fallback hit, not a gap.
  const db = {
    tools: [
      { name: 'loki-mcp', notes: 'Grafana Loki MCP server.', classification: 'Core' },
      { name: 'noise',    notes: 'unrelated',                 classification: 'Core' },
    ],
  };
  const stack = stackWith({ infra: ['loki'] });
  const out = o.unmappedSignals(db, stack);
  assert.equal(out.length, 1);
  assert.equal(out[0].signal, 'loki');
  assert.deepEqual(out[0].fallback, ['loki-mcp']);
  assert.match(out[0].reason, /^fallback →/);
});

test('fallbackBySignal: substring match against name+notes, skips Deprecated', () => {
  const db = {
    tools: [
      { name: '@salesforce/mcp', notes: 'CRM server', classification: 'Core' },
      { name: 'salesforce-legacy', notes: '', classification: 'Deprecated' },
      { name: 'irrelevant', notes: 'no match', classification: 'Core' },
    ],
  };
  const hits = o.fallbackBySignal(db, 'salesforce');
  assert.deepEqual(hits, ['@salesforce/mcp']); // Deprecated filtered out
});

test('matchDB: uses fallback when SIGNAL_TO_TOOLS has no mapping for the signal', () => {
  // loki is not in SIGNAL_TO_TOOLS today; loki-mcp would be picked up
  // via substring fallback. Synthetic DB to keep the test deterministic.
  const db = {
    tools: [
      { name: 'loki-mcp',              notes: 'Grafana Loki MCP', classification: 'Core', est_tools_count: 5 },
      { name: 'mcp-server-filesystem', notes: '', classification: 'Core', est_tools_count: 10 },
      { name: 'mcp-server-memory',     notes: '', classification: 'Core', est_tools_count: 9 },
      { name: 'context7',              notes: '', classification: 'Core', est_tools_count: 4 },
    ],
  };
  const stack = stackWith({ infra: ['loki'] });
  const matched = o.matchDB(db, stack, null);
  const names = matched.map(t => t.name);
  assert.ok(names.includes('loki-mcp'), `Expected loki match via fallback, got ${names}`);
});

test('unmappedSignals: flags mappings whose referenced tool is missing in DB', () => {
  // postgres maps to mcp-server-neon, but DB doesn't contain it → drift.
  const db    = dbWith('something-else');
  const stack = stackWith({ dbs: ['postgres'] });
  const out   = o.unmappedSignals(db, stack);
  assert.equal(out.length, 1);
  assert.equal(out[0].signal, 'postgres');
  assert.match(out[0].reason, /not in DB/);
});

test('unmappedSignals: handles both dbs and infra signals', () => {
  // kubernetes is infra; mapped to mcp-server-kubernetes per SIGNAL_TO_TOOLS.
  const db    = dbWith();        // empty DB
  const stack = stackWith({ dbs: ['postgres'], infra: ['kubernetes'] });
  const out   = o.unmappedSignals(db, stack);
  assert.equal(out.length, 2);
  const signals = out.map(u => u.signal).sort();
  assert.deepEqual(signals, ['kubernetes', 'postgres']);
});

test('unmappedSignals: empty stack returns empty array', () => {
  assert.deepEqual(o.unmappedSignals(dbWith(), stackWith({})), []);
});

test('SIGNAL_TO_TOOLS keys reference tools that exist in the seeded DB', () => {
  // This is a structural lint: if a mapping points at a deleted entry,
  // unmappedSignals will flag it for users — but we should catch it in
  // CI too. Load the real DB and check each mapped tool name is present.
  const path = require('path');
  const fs   = require('fs');
  const dbPath = path.resolve(__dirname, '../mcp-ecosystem-intelligence/assets/tools_database.json');
  const realDb = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  const dbNames = new Set(realDb.tools.map(t => t.name));
  const missing = [];
  for (const [signal, tools] of Object.entries(o.SIGNAL_TO_TOOLS)) {
    for (const name of tools) {
      if (!dbNames.has(name)) missing.push({ signal, name });
    }
  }
  assert.deepEqual(missing, [], `SIGNAL_TO_TOOLS references tools missing from DB: ${JSON.stringify(missing)}`);
});

test('UNIVERSAL_TOOLS members all exist in the seeded DB', () => {
  const path = require('path');
  const fs   = require('fs');
  const dbPath = path.resolve(__dirname, '../mcp-ecosystem-intelligence/assets/tools_database.json');
  const realDb = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  const dbNames = new Set(realDb.tools.map(t => t.name));
  const missing = [...o.UNIVERSAL_TOOLS].filter(n => !dbNames.has(n));
  assert.deepEqual(missing, [], `UNIVERSAL_TOOLS members missing from DB: ${missing}`);
});

// ── detectStack regression: new signals from the WO/infra expansion ─────────

const fs   = require('node:fs');
const os   = require('node:os');

function envProject(envContent, files = {}) {
  const dir = fs.mkdtempSync(`${os.tmpdir()}/orch-stack-`);
  fs.writeFileSync(`${dir}/.env.example`, envContent);
  for (const [name, body] of Object.entries(files)) {
    const full = `${dir}/${name}`;
    fs.mkdirSync(require('node:path').dirname(full), { recursive: true });
    fs.writeFileSync(full, body);
  }
  return dir;
}

test('detectStack: TEAMCITY_URL env-key adds teamcity signal', () => {
  const dir = envProject('TEAMCITY_URL=https://tc.example.com\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('teamcity'), `infra=${[...stack.infra]}`);
  assert.ok(stack.cats.has('ci-cd'));
});

test('detectStack: .teamcity/ directory adds teamcity signal', () => {
  const dir = envProject('', { '.teamcity/.keep': '' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('teamcity'));
});

test('detectStack: SALESFORCE_TOKEN adds salesforce → @salesforce/mcp via SIGNAL_TO_TOOLS', () => {
  const dir = envProject('SALESFORCE_TOKEN=x\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('salesforce'));
  assert.deepEqual(o.SIGNAL_TO_TOOLS['salesforce'], ['@salesforce/mcp']);
});

test('detectStack: helm/Chart.yaml adds helm signal', () => {
  const dir = envProject('', { 'helm/Chart.yaml': 'apiVersion: v2\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('helm'));
});

test('detectStack: argocd directory adds argocd signal', () => {
  const dir = envProject('', { 'argocd/.keep': '' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('argocd'));
});

test('detectStack: top-level .tf file adds terraform signal', () => {
  const dir = envProject('', { 'main.tf': 'terraform {}\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('terraform'));
});

test('detectStack: docker-compose with kafka image adds kafka signal', () => {
  const dir = envProject('', { 'docker-compose.yml': 'services:\n  kafka:\n    image: confluentinc/cp-kafka:7\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('kafka'));
});

test('detectStack: PROMETHEUS_* env-key adds prometheus signal', () => {
  const dir = envProject('PROMETHEUS_URL=http://p:9090\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('prometheus'));
  assert.ok(stack.cats.has('observability'));
});

test('detectStack: ATLASSIAN_* env-key adds atlassian → mcp-atlassian via SIGNAL_TO_TOOLS', () => {
  const dir = envProject('ATLASSIAN_URL=https://x.atlassian.net\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('atlassian'));
  assert.deepEqual(o.SIGNAL_TO_TOOLS['atlassian'], ['mcp-atlassian']);
});

test('detectStack: PG_* env-key adds postgres signal', () => {
  const dir = envProject('PG_HOST=db.example.com\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.dbs.has('postgres'));
});

// ── detectStack: Swift/JVM/Ruby/PHP/.NET/Elixir manifests ───────────────────

test('detectStack: Package.swift adds swift lang', () => {
  const dir = envProject('', { 'Package.swift': '// swift-tools-version:5.9\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('swift'), `langs=${[...stack.langs]}`);
});

test('detectStack: Project.swift (Tuist) adds swift lang', () => {
  const dir = envProject('', { 'Project.swift': 'import ProjectDescription\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('swift'));
});

test('detectStack: Gemfile with pg gem adds ruby + postgres', () => {
  const dir = envProject('', { 'Gemfile': 'source "https://rubygems.org"\ngem "rails"\ngem "pg"\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('ruby'), `langs=${[...stack.langs]}`);
  assert.ok(stack.dbs.has('postgres'), `dbs=${[...stack.dbs]}`);
  assert.ok(stack.cats.has('database'));
});

test('detectStack: Gemfile.lock fallback when no Gemfile present', () => {
  const dir = envProject('', { 'Gemfile.lock': '  specs:\n    pg (1.5.4)\n    redis (5.0.0)\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('ruby'));
  assert.ok(stack.dbs.has('postgres'));
  assert.ok(stack.dbs.has('redis'));
});

test('detectStack: composer.json with mongodb/mongodb adds php + mongodb', () => {
  const body = JSON.stringify({
    name: 'acme/x',
    require: { 'php': '^8.2', 'mongodb/mongodb': '^1.17' },
  });
  const dir = envProject('', { 'composer.json': body });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('php'), `langs=${[...stack.langs]}`);
  assert.ok(stack.dbs.has('mongodb'), `dbs=${[...stack.dbs]}`);
});

test('detectStack: composer.json with predis/predis adds redis', () => {
  const body = JSON.stringify({ require: { 'predis/predis': '^2.2' } });
  const dir = envProject('', { 'composer.json': body });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('php'));
  assert.ok(stack.dbs.has('redis'));
});

test('detectStack: pom.xml present adds jvm lang', () => {
  const dir = envProject('', { 'pom.xml': '<?xml version="1.0"?><project/>' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('jvm'), `langs=${[...stack.langs]}`);
});

test('detectStack: build.gradle adds jvm lang', () => {
  const dir = envProject('', { 'build.gradle': 'plugins { id "java" }\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('jvm'));
});

test('detectStack: build.gradle.kts adds jvm lang', () => {
  const dir = envProject('', { 'build.gradle.kts': 'plugins { kotlin("jvm") }\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('jvm'));
});

test('detectStack: .csproj file adds dotnet lang', () => {
  const dir = envProject('', { 'App.csproj': '<Project Sdk="Microsoft.NET.Sdk"/>' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('dotnet'), `langs=${[...stack.langs]}`);
});

test('detectStack: .sln file adds dotnet lang', () => {
  const dir = envProject('', { 'App.sln': 'Microsoft Visual Studio Solution File\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('dotnet'));
});

test('detectStack: mix.exs adds elixir lang', () => {
  const dir = envProject('', { 'mix.exs': 'defmodule App.MixProject do\nend\n' });
  const stack = o.detectStack(dir);
  assert.ok(stack.langs.has('elixir'));
});

// ── detectStack: jira / atlassian / seq env signals ─────────────────────────

test('detectStack: JIRA_URL env-key adds jira signal + docs category', () => {
  const dir = envProject('JIRA_URL=https://x.atlassian.net\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('jira'), `infra=${[...stack.infra]}`);
  assert.ok(stack.cats.has('docs'));
});

test('detectStack: ATLASSIAN_TOKEN adds jira signal', () => {
  const dir = envProject('ATLASSIAN_TOKEN=secret\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('jira'));
  assert.ok(stack.cats.has('docs'));
});

test('SIGNAL_TO_TOOLS: jira maps to mcp-atlassian (Jira/Confluence share the server)', () => {
  assert.deepEqual(o.SIGNAL_TO_TOOLS['jira'], ['mcp-atlassian']);
});

test('detectStack: SEQ_API_KEY env-key adds seq signal + observability category', () => {
  const dir = envProject('SEQ_API_KEY=x\n');
  const stack = o.detectStack(dir);
  assert.ok(stack.infra.has('seq'), `infra=${[...stack.infra]}`);
  assert.ok(stack.cats.has('observability'));
});

// ── pinInstallCmd ───────────────────────────────────────────────────────────
// The gate hashes `pkg@version` from the DB; .mcp.json must launch that exact
// artifact. Most DB entries store the command unpinned, so `npx -y pkg` in a
// config resolved `latest` at every server start — a different tarball than the
// one whose sha512 was compared.

test('pinInstallCmd: npm entry gets the DB version pinned in', () => {
  const r = o.pinInstallCmd('npx -y @mapbox/mcp-server', '0.11.0');
  assert.equal(r.pinned, true);
  assert.deepEqual(r.parts, ['npx', '-y', '@mapbox/mcp-server@0.11.0']);
});

test('pinInstallCmd: a matching pin is left alone', () => {
  const r = o.pinInstallCmd('npx -y @scope/pkg@1.2.3', '1.2.3');
  assert.equal(r.pinned, true);
  assert.deepEqual(r.parts, ['npx', '-y', '@scope/pkg@1.2.3']);
});

test('pinInstallCmd: a pin the gate did not verify is rewritten, not trusted', () => {
  // `@latest`, a range, or a stale pin all launch something other than the
  // artifact whose hash was compared. Carrying *a* specifier is not enough.
  for (const spec of ['@latest', '@^1.2', '@~1', '@1.0.0', '']) {
    const r = o.pinInstallCmd(`npx -y pkg${spec}`, '1.2.3');
    assert.equal(r.pinned, true, spec);
    assert.deepEqual(r.parts, ['npx', '-y', 'pkg@1.2.3'], spec);
  }
  assert.deepEqual(o.pinInstallCmd('uvx pkg==2.0.0', '1.2.3').parts, ['uvx', 'pkg==1.2.3']);
});

test('pinInstallCmd: a range is not a pin, whatever it looks like', () => {
  // `1`, `1.2` and `1.x` all used to pass as "exact", so the pinner produced
  // `pkg@1.x` and called the entry pinned.
  for (const version of ['^1.2.0', '~1.2', '1.x', '1', '1.2', 'latest', '*']) {
    const r = o.pinInstallCmd('npx -y pkg', version);
    assert.equal(r.pinned, false, version);
    assert.match(r.reason, /not an exact semver version/, version);
  }
  for (const version of ['1.2.3', '1.0.0-rc.1', '1.0.0+build.5']) {
    assert.equal(o.pinInstallCmd('npx -y pkg', version).pinned, true, version);
  }
});

test('pinInstallCmd: PyPI versions follow PEP 440, not semver', () => {
  // The DB legitimately carries dates-as-versions for PyPI entries.
  for (const version of ['2026.1.14', '1.0', '1.0.0', '1.0+local', '2.0rc1', '1.0.post1']) {
    assert.equal(o.pinInstallCmd('uvx pkg', version).pinned, true, version);
  }
  for (const version of ['1.*', '>=1.0', 'latest']) {
    assert.equal(o.pinInstallCmd('uvx pkg', version).pinned, false, version);
  }
});

test('isExactVersion: the two ecosystems have different rules', () => {
  assert.equal(o.isExactVersion('npx', '1.2'), false);      // npm wants three components
  assert.equal(o.isExactVersion('uvx', '1.2'), true);       // PyPI does not
  assert.equal(o.isExactVersion('npx', null), false);
  assert.equal(o.isExactVersion('uvx', ''), false);
});

test('pinInstallCmd: refuses commands the gate itself cannot parse', () => {
  // Flags before the package name: the old parser pinned "--cache" and the
  // gate checked a package that does not exist.
  for (const cmd of ['npx -y --cache /tmp/c pkg', 'npx -y --package pkg server']) {
    const r = o.pinInstallCmd(cmd, '1.2.3');
    assert.equal(r.pinned, false, cmd);
    assert.match(r.reason, /not a plain `npx -y <pkg>` command/);
  }
  for (const cmd of ['uvx --with extra server', 'uvx --from git+https://x/y z']) {
    const r = o.pinInstallCmd(cmd, '1.2.3');
    assert.equal(r.pinned, false, cmd);
    assert.match(r.reason, /not a plain `uvx <pkg>` command/);
  }
});

test('pinInstallCmd: a digest in some other argument is not a pin on the image', () => {
  const digest = 'a'.repeat(64);
  const r = o.pinInstallCmd(`docker run -e REF=img@sha256:${digest} img:latest`, null);
  assert.equal(r.pinned, false);
  assert.match(r.reason, /img:latest is not pinned/);
  // …while a value-taking flag before the image is handled.
  const ok = o.pinInstallCmd(`docker run --pull always ghcr.io/x/y@sha256:${digest}`, null);
  assert.equal(ok.pinned, true);
});

test('pinInstallCmd: pins the package token, not trailing args', () => {
  const r = o.pinInstallCmd('npx -y mcp-server-foo --toolsets repos,issues', '1.0.0');
  assert.deepEqual(r.parts, ['npx', '-y', 'mcp-server-foo@1.0.0', '--toolsets', 'repos,issues']);
});

test('pinInstallCmd: uvx uses == for the PyPI pin', () => {
  assert.deepEqual(
    o.pinInstallCmd('uvx mcp-server-git', '2026.1.14').parts,
    ['uvx', 'mcp-server-git==2026.1.14'],
  );
  assert.equal(o.pinInstallCmd('uvx mcp-server-git==2026.1.14', '9.9').pinned, true);
});

test('pinInstallCmd: docker is pinned by its digest, or not at all', () => {
  const digest = 'a'.repeat(64);
  assert.equal(o.pinInstallCmd(`docker run -i --rm ghcr.io/x/y@sha256:${digest}`, null).pinned, true);
  const loose = o.pinInstallCmd('docker run -i --rm ghcr.io/x/y:latest', '1.0');
  assert.equal(loose.pinned, false);
  assert.match(loose.reason, /not pinned by @sha256/);
});

test('pinInstallCmd: unpinnable cases report why', () => {
  assert.match(o.pinInstallCmd('npx -y @scope/pkg', null).reason, /no `version` in the DB entry/);
  assert.match(o.pinInstallCmd('npx -y pkg@1.0.0', null).reason, /asks for "1.0.0".*no verified/s);
  assert.match(o.pinInstallCmd('pipx run something', '1.0').reason, /unknown runner/);
});

test('pinInstallCmd: every npm/uvx entry in the shipped DB can be pinned', () => {
  const db = require('../mcp-ecosystem-intelligence/assets/tools_database.json');
  const unpinnable = db.tools
    .filter(t => /^(npx|uvx)\s/.test(t.install_cmd || ''))
    .map(t => ({ name: t.name, ...o.pinInstallCmd(t.install_cmd, t.version) }))
    .filter(r => !r.pinned)
    .map(r => `${r.name}: ${r.reason}`);
  // Entries that can't be pinned are exactly the ones verify_integrity reports
  // as UNVERIFIED (no version, or a --from source install). Keep the list small
  // and visible rather than asserting zero.
  assert.ok(unpinnable.length <= 2, `unpinnable entries grew:\n${unpinnable.join('\n')}`);
});

// ── signal provenance ──────────────────────────────────────────────────────

test('detectStack: every signal says where it came from and how much it implies', () => {
  const fs = require('node:fs'), os = require('node:os'), pathMod = require('node:path');
  const dir = fs.mkdtempSync(pathMod.join(os.tmpdir(), 'mcp-signals-'));
  // A declared dependency and a bare credential name are not the same claim.
  fs.writeFileSync(pathMod.join(dir, 'package.json'), JSON.stringify({ dependencies: { pg: '^8' } }));
  fs.writeFileSync(pathMod.join(dir, '.env.example'), 'AWS_ACCESS_KEY_ID=\nDATABASE_URL=\n');

  const stack = o.detectStack(dir);
  const byValue = Object.fromEntries(stack.signals.map(s => [s.value, s]));

  assert.equal(byValue.postgres.kind, 'detected');
  assert.equal(byValue.postgres.confidence, 0.95);
  assert.deepEqual(byValue.postgres.sources, ['package.json dependency']);

  // The env-derived one is weaker and marked as an inference.
  const inferred = stack.signals.filter(s => s.kind === 'inferred');
  assert.ok(inferred.length > 0, 'an .env key should produce an inferred signal');
  assert.ok(inferred.every(s => s.confidence < byValue.postgres.confidence));

  // The old shape still works for existing callers.
  assert.ok(stack.dbs.has('postgres'));
  assert.ok(stack.langs.has('Node'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('detectStack: two sources agreeing are recorded as both', () => {
  const fs = require('node:fs'), os = require('node:os'), pathMod = require('node:path');
  const dir = fs.mkdtempSync(pathMod.join(os.tmpdir(), 'mcp-signals-two-'));
  fs.writeFileSync(pathMod.join(dir, 'package.json'), JSON.stringify({ dependencies: { redis: '^4' } }));
  fs.writeFileSync(pathMod.join(dir, 'docker-compose.yml'), 'services:\n  cache:\n    image: redis:7\n');
  const stack = o.detectStack(dir);
  const redis = stack.signals.find(s => s.value === 'redis');
  assert.equal(redis.sources.length, 2);
  assert.equal(redis.confidence, 0.95);   // the stronger source wins
  fs.rmSync(dir, { recursive: true, force: true });
});

test('scan: evidence from a different version does not score the current one', () => {
  // Bumping `version` while leaving trust_evidence in place otherwise carries
  // the old release's verdict onto a version nothing has checked.
  const stale = {
    name: 'pkg', category: 'database', install_cmd: 'npx -y pkg@2.0.0', version: '2.0.0',
    pkg_integrity: 'sha512-new', health_score: 80, est_tools_count: 5,
    trust_evidence: {
      artifact_id: 'npm:pkg@1.0.0',
      dimensions: {
        artifact:   { status: 'verified', checked_at: new Date().toISOString().slice(0, 10) },
        advisories: { status: 'clean',    checked_at: new Date().toISOString().slice(0, 10) },
        signature:  { status: 'verified', checked_at: new Date().toISOString().slice(0, 10) },
      },
    },
  };
  const out = o.slim(stale, { cats: new Set(['database']), dbs: new Set(), infra: new Set(), signals: [] });
  assert.equal(out.scores.trust.gate, 'thin');
  assert.match(out.scores.trust.reasons.join(' '), /describes npm:pkg@1\.0\.0, not npm:pkg@2\.0\.0/);
  assert.notEqual(out.scores.recommendation.verdict, 'recommended');
});

test('scan: evidence for the current version is used', () => {
  const today = new Date().toISOString().slice(0, 10);
  const current = {
    name: 'pkg', category: 'database', install_cmd: 'npx -y pkg@2.0.0', version: '2.0.0',
    pkg_integrity: 'sha512-new', health_score: 80, est_tools_count: 5,
    trust_evidence: {
      artifact_id: 'npm:pkg@2.0.0',
      dimensions: {
        artifact:       { status: 'verified', checked_at: today },
        advisories:     { status: 'clean',    checked_at: today },
        signature:      { status: 'verified', checked_at: today },
        source_binding: { status: 'verified', checked_at: today },
      },
    },
  };
  const out = o.slim(current, { cats: new Set(['database']), dbs: new Set(), infra: new Set(), signals: [] });
  assert.equal(out.scores.trust.gate, 'ok');
});
