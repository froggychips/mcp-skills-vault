'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs   = require('fs');
const os   = require('os');
const path = require('path');

const sub = require('../mcp-ecosystem-intelligence/scripts/lib/subregistry.cjs');
const cli = require('../mcp-ecosystem-intelligence/scripts/export_subregistry.cjs');
const { validate } = require('./fixtures/json_schema_lite.cjs');

const ROOT   = path.resolve(__dirname, '..');
// Vendored verbatim from https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json
const SCHEMA = require('./fixtures/server.schema.2025-12-11.json');
const DB     = JSON.parse(fs.readFileSync(path.join(ROOT, 'mcp-ecosystem-intelligence/assets/tools_database.json'), 'utf8'));
const EVALS  = JSON.parse(fs.readFileSync(path.join(ROOT, 'mcp-ecosystem-intelligence/assets/eval_results.json'), 'utf8'));

const dims = (extra = {}) => ({
  artifact:     { status: 'verified', checked_at: '2026-09-17', verified_at: '2026-09-17' },
  availability: { status: 'present',  checked_at: '2026-09-17', verified_at: '2026-09-17' },
  advisories:   { status: 'clean',    checked_at: '2026-09-17', verified_at: '2026-09-17' },
  ...extra,
});
const npmEntry = (name, pkg, version, extra = {}) => ({
  name,
  category: 'utility',
  install_cmd: `npx -y ${pkg}@${version}`,
  source_url: 'https://github.com/o/r',
  version,
  pkg_integrity: 'sha512-AAAA',
  trust: 'verified',
  license: 'MIT',
  health_score: 70,
  est_tools_count: 3,
  trust_evidence: { artifact_id: `npm:${pkg}@${version}`, dimensions: dims(extra) },
});

test('the vendored schema is the one the export names', () => {
  assert.equal(SCHEMA.$id, sub.SCHEMA_URL);
});

test('the validator fails closed: a bad document fails, an unknown keyword throws', () => {
  assert.ok(validate(SCHEMA, { name: 'nope', version: '1', description: '' }).length >= 2);
  assert.throws(() => validate({ uniqueItems: true }, []), /unsupported keyword/);
});

test('every server exported from the real DB validates against server.schema.json', () => {
  const { servers, files } = sub.buildExport(DB, EVALS);
  assert.ok(servers.length > 50, `only ${servers.length} exported — the export broke`);
  for (const s of servers) {
    assert.deepEqual(validate(SCHEMA, s), [], `${s.name} does not validate`);
  }
  // The ToolHive file carries the same server.json objects.
  const th = JSON.parse(files.get(`v0.1/x/${sub.NAMESPACE}/toolhive.json`));
  assert.equal(th.data.servers.length, servers.length);
  assert.match(th.meta.last_updated, /^\d{4}-\d{2}-\d{2}T00:00:00Z$/);
  for (const s of th.data.servers) assert.deepEqual(validate(SCHEMA, s), []);
});

test('deterministic: the same data gives the same bytes, and no clock is read', () => {
  const a = sub.buildExport(DB, EVALS);
  const realNow = Date.now;
  Date.now = () => Date.parse('2031-01-01T00:00:00Z');   // a clock read would change tiers
  let b;
  try { b = sub.buildExport(DB, EVALS); } finally { Date.now = realNow; }
  assert.deepEqual([...a.files.keys()], [...b.files.keys()]);
  for (const [k, v] of a.files) assert.equal(b.files.get(k), v, `${k} differs between runs`);
  assert.equal(a.manifest.as_of, sub.asOfDate(DB, EVALS));
});

test('an official name is kept only when identity recorded it; otherwise our namespace', () => {
  const listed = npmEntry('x', 'x', '1.0.0', { registry: { status: 'listed', checked_at: '2026-09-17', server_id: 'io.github.o/x' } });
  assert.deepEqual(sub.serverName(listed), { name: 'io.github.o/x', source: 'official-registry' });

  const unlisted = npmEntry('@scope/pkg', '@scope/pkg', '1.0.0', { registry: { status: 'unlisted', checked_at: '2026-09-17' } });
  assert.deepEqual(sub.serverName(unlisted), { name: `${sub.NAMESPACE}/scope.pkg`, source: 'vault' });

  // Not derived from the source URL: that would print a namespace nobody proved.
  const junk = npmEntry('y', 'y', '1.0.0', { registry: { status: 'listed', checked_at: '2026-09-17', server_id: 'no slash here' } });
  assert.equal(sub.serverName(junk).source, 'vault');
});

test('fail closed: nothing pinned, or a Deprecated tier, is not exported', () => {
  const asOf = '2026-09-17';
  const git = { ...npmEntry('g', 'g', '1.0.0'), install_cmd: 'uvx --from git+https://github.com/o/r r', version: null };
  assert.match(sub.toServerJson(git, { asOf }).skip, /tier Deprecated|no released artifact/);

  const unpinned = { ...npmEntry('u', 'u', '1.0.0'), install_cmd: 'npx -y u', version: null };
  assert.ok(sub.toServerJson(unpinned, { asOf }).skip);

  const vulnerable = npmEntry('v', 'v', '1.0.0', { advisories: { status: 'vulnerable', checked_at: asOf } });
  assert.match(sub.toServerJson(vulnerable, { asOf }).skip, /Deprecated/);

  const tag = npmEntry('d', 'd', '1.0.0');
  tag.install_cmd = 'docker run -i --rm ghcr.io/o/d:latest';
  assert.match(sub.packageOf(tag).skip, /digest/);

  assert.throws(() => sub.toServerJson(npmEntry('n', 'n', '1.0.0'), {}), /asOf/);
});

test('a good npm entry: package, pin and dated evidence in our _meta, nothing under the official key', () => {
  const t = npmEntry('good', '@o/good', '1.2.3');
  t.source_url = 'https://github.com/o/mono/tree/main/packages/good';
  const { server } = sub.toServerJson(t, { asOf: '2026-09-17' });
  assert.deepEqual(validate(SCHEMA, server), []);
  assert.deepEqual(server.packages[0], {
    registryType: 'npm', registryBaseUrl: 'https://registry.npmjs.org', identifier: '@o/good',
    version: '1.2.3', runtimeHint: 'npx', transport: { type: 'stdio' },
  });
  assert.deepEqual(server.repository, { url: 'https://github.com/o/mono', source: 'github', subfolder: 'packages/good' });
  const m = server._meta[sub.META_KEY];
  assert.match(sub.META_KEY, /^[a-z0-9-]+(\.[a-z0-9-]+)+\/[a-z0-9-]+$/);
  assert.equal(m.as_of, '2026-09-17');
  assert.deepEqual(m.pinned, { ecosystem: 'npm', identifier: '@o/good', version: '1.2.3', integrity: 'sha512-AAAA', artifact_id: 'npm:@o/good@1.2.3' });
  assert.equal(m.evidence.artifact.checked_at, '2026-09-17');
  assert.match(m.explain.command, /mcp-vault explain good$/);
  assert.ok(m.tier && m.tier_reason);
  assert.equal(server._meta['io.modelcontextprotocol.registry/official'], undefined);
});

test('docker: digest identifier with the implied host, flags as runtime arguments, env as variables', () => {
  const t = npmEntry('dock', 'x', '1.0.0');
  t.install_cmd = `docker run -i --rm --cap-drop ALL --security-opt no-new-privileges -e API_TOKEN owner/img@sha256:${'a'.repeat(64)}`;
  t.version = 'latest';
  const p = sub.packageOf(t);
  assert.equal(p.package.registryType, 'oci');
  assert.equal(p.package.identifier, `docker.io/owner/img@sha256:${'a'.repeat(64)}`);
  assert.equal(p.package.version, undefined);
  assert.deepEqual(p.package.runtimeArguments, [
    { type: 'named', name: '--cap-drop', value: 'ALL' },
    { type: 'named', name: '--security-opt', value: 'no-new-privileges' },
  ]);
  assert.deepEqual(p.package.environmentVariables, [{ name: 'API_TOKEN', isRequired: true, isSecret: true }]);
  // `latest` is the API's alias for newest, so it is never a server version.
  assert.equal(sub.serverVersion(t, p.package), 'sha256-aaaaaaaaaaaa');

  // A value baked into the command would be published; refused instead.
  t.install_cmd = `docker run -i --rm -e API_TOKEN=secret owner/img@sha256:${'a'.repeat(64)}`;
  assert.ok(sub.packageOf(t).skip);
});

test('static layout: one list page without a cursor, both spellings of a name, latest = pinned', () => {
  const db = { tools: [
    npmEntry('a', 'a', '1.0.0', { registry: { status: 'listed', checked_at: '2026-09-17', server_id: 'io.github.o/a' } }),
    npmEntry('b', 'b', '2.0.0'),
  ] };
  const { files, manifest } = sub.buildExport(db, { results: [] });
  const list = JSON.parse(files.get('v0.1/servers/index.html'));
  assert.equal(list.metadata.count, 2);
  assert.equal(list.metadata.nextCursor, undefined);
  assert.deepEqual(list.servers.map((r) => r.server.name), ['io.github.o/a', `${sub.NAMESPACE}/b`]);

  for (const dir of ['v0.1/servers/io.github.o%2Fa', 'v0.1/servers/io.github.o/a']) {
    assert.equal(files.get(`${dir}/versions/latest`), files.get(`${dir}/versions/1.0.0`), dir);
    assert.equal(JSON.parse(files.get(`${dir}/versions/index.html`)).servers.length, 1);
    assert.equal(JSON.parse(files.get(`${dir}/versions/latest`)).server.version, '1.0.0');
  }
  // Every endpoint has a .json twin with the same bytes (application/json on Pages).
  assert.equal(files.get('v0.1/servers.json'), files.get('v0.1/servers/index.html'));
  assert.equal(files.get('v0.1/servers/io.github.o%2Fa/versions.json'), files.get('v0.1/servers/io.github.o%2Fa/versions/index.html'));
  assert.equal(files.get('v0.1/servers/io.github.o/a/versions/latest.json'), files.get('v0.1/servers/io.github.o/a/versions/latest'));
  assert.equal(files.get('v0.1/servers/io.github.o/a/versions/1.0.0.json'), files.get('v0.1/servers/io.github.o/a/versions/1.0.0'));
  // The manifest hashes every other file it describes.
  for (const k of files.keys()) {
    if (k.endsWith('/export.json')) continue;
    assert.match(manifest.files[k], /^sha256-[a-f0-9]{64}$/, k);
  }
});

test('two entries that would publish one name are refused, not silently shadowed', () => {
  const db = { tools: [npmEntry('@o/x', '@o/x', '1.0.0'), npmEntry('o.x', 'o.x', '1.0.0')] };
  assert.throws(() => sub.buildExport(db, { results: [] }), new RegExp(`two entries export as ${sub.NAMESPACE.replace(/\./g, '\\.')}/o\\.x`));
});

test('--min-tier narrows the export and the skip says why', () => {
  const db = { tools: [npmEntry('a', 'a', '1.0.0')] };
  const { manifest } = sub.buildExport(db, { results: [] }, { minTier: 'Core' });
  assert.equal(manifest.exported, 0);
  assert.match(manifest.skipped[0].reason, /below --min-tier Core/);
});

test('CLI: writes the tree, --check is 0 when current and 1 when stale or littered, 2 on bad args', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-subreg-'));
  const quiet = (fn) => {
    const w = process.stdout.write;
    process.stdout.write = () => true;
    try { return fn(); } finally { process.stdout.write = w; }
  };
  // Another generator's file beside ours is left alone.
  fs.writeFileSync(path.join(out, 'registry.html'), 'page');

  assert.equal(quiet(() => cli.run(['--out', out])), 0);
  assert.ok(fs.existsSync(path.join(out, 'v0.1/servers/index.html')));
  assert.equal(fs.readFileSync(path.join(out, 'registry.html'), 'utf8'), 'page');
  assert.equal(quiet(() => cli.run(['--out', out, '--check'])), 0);

  fs.writeFileSync(path.join(out, 'v0.1/servers/index.html'), '{}');
  assert.equal(quiet(() => cli.run(['--out', out, '--check'])), 1);
  assert.equal(quiet(() => cli.run(['--out', out])), 0);

  fs.writeFileSync(path.join(out, 'v0.1/servers/stray'), '{}');
  assert.equal(quiet(() => cli.run(['--out', out, '--check'])), 1);
  // A rewrite clears what the export owns, so the stray file is gone.
  assert.equal(quiet(() => cli.run(['--out', out])), 0);
  assert.ok(!fs.existsSync(path.join(out, 'v0.1/servers/stray')));

  const err = process.stderr.write;
  process.stderr.write = () => true;
  try {
    assert.equal(cli.run(['--as-of', 'yesterday']), 2);
    assert.equal(cli.run(['--min-tier', 'Deprecated']), 2);
    assert.equal(cli.run(['--bogus']), 2);
    assert.equal(cli.run(['--base-url', 'ftp://x']), 2);
    assert.equal(cli.run(['--out', out], { dbPath: path.join(out, 'missing.json') }), 2);
  } finally { process.stderr.write = err; }
});

test('CLI --json prints the manifest under its schema id', () => {
  const { spawnSync } = require('child_process');
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-subreg-json-'));
  const r = spawnSync(process.execPath, [path.join(ROOT, 'mcp-ecosystem-intelligence/scripts/export_subregistry.cjs'), '--out', out, '--json'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const doc = JSON.parse(r.stdout);
  assert.equal(doc.schema, 'mcp-vault/subregistry-export@1');
  assert.equal(doc.meta_key, sub.META_KEY);
});

test('--base-url: every absolute site URL is built from it, default is the production site', () => {
  const db = { tools: [npmEntry('b', 'b', '2.0.0')] };
  const def = sub.buildExport(db, { results: [] });
  assert.equal(def.manifest.base_url, sub.DEFAULT_BASE_URL);
  const { files, manifest } = sub.buildExport(db, { results: [] }, { baseUrl: 'https://staging.example.org/site/' });
  assert.equal(manifest.base_url, 'https://staging.example.org/site');
  const one = JSON.parse(files.get(`v0.1/servers/${encodeURIComponent(`${sub.NAMESPACE}/b`)}/versions/latest`));
  assert.equal(one.server._meta[sub.META_KEY].explain.page, 'https://staging.example.org/site/registry.html');
  const th = JSON.parse(files.get(`v0.1/x/${sub.NAMESPACE}/toolhive.json`));
  assert.equal(th.meta.source, 'https://staging.example.org/site/v0.1/servers.json');
  assert.equal(th.data.servers[0]._meta[sub.META_KEY].explain.page, 'https://staging.example.org/site/registry.html');
  // Nothing written under the export still names the production site.
  for (const [k, body] of files) assert.ok(!body.includes(sub.DEFAULT_BASE_URL), k);
  assert.throws(() => sub.normalizeBaseUrl('ftp://x'), /http\(s\)/);
  assert.throws(() => sub.normalizeBaseUrl('https://x/?q=1'), /plain/);
  assert.throws(() => sub.normalizeBaseUrl('not a url'), /not a URL/);
});

test('site-registry --out --base-url writes the page and the export under one root', () => {
  const { spawnSync } = require('child_process');
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-site-'));
  const r = spawnSync(process.execPath, [path.join(ROOT, 'mcp-ecosystem-intelligence/scripts/generate_registry_page.cjs'),
    '--out', out, '--base-url', 'https://mirror.example.org'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  for (const f of ['registry.html', 'registry.json', 'v0.1/servers/index.html', 'v0.1/servers.json', `v0.1/x/${sub.NAMESPACE}/toolhive.json`]) {
    assert.ok(fs.existsSync(path.join(out, f)), f);
  }
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, `v0.1/x/${sub.NAMESPACE}/export.json`), 'utf8')).base_url, 'https://mirror.example.org');
  const bad = spawnSync(process.execPath, [path.join(ROOT, 'mcp-ecosystem-intelligence/scripts/generate_registry_page.cjs'), '--bogus'], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
});
