'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const snap = require('../mcp-ecosystem-intelligence/scripts/lib/registry_snapshot.cjs');
const cli  = require('../mcp-ecosystem-intelligence/scripts/registry_ingest.cjs');
const discover = require('../mcp-ecosystem-intelligence/scripts/discover.cjs');

const ROOT    = path.resolve(__dirname, '..');
const SCRIPTS = path.join(ROOT, 'mcp-ecosystem-intelligence/scripts');
const PAGES   = require('./fixtures/registry_v0.1_pages.json').pages;

/** A `get` that serves the fixture pages by cursor, and records what was asked. */
function fakeGet(pages = PAGES, { failAt = -1 } = {}) {
  const seen = [];
  const get = async (url) => {
    seen.push(url);
    const u = new URL(url);
    const cursor = u.searchParams.get('cursor');
    const i = cursor ? pages.findIndex((p, k) => k > 0 && pages[k - 1].metadata.nextCursor === cursor) : 0;
    if (i === failAt || i === -1) return { ok: false, status: 503 };
    return { ok: true, status: 200, data: pages[i] };
  };
  return { get, seen };
}

const fixedNow = () => '2026-09-30T00:00:00.000Z';

async function fixtureSnapshot() {
  const r = await snap.fetchSnapshot({ get: fakeGet().get, now: fixedNow });
  assert.equal(r.ok, true, r.error);
  return r.snapshot;
}

const DB = { tools: [
  {
    name: 'playwright-mcp', install_cmd: 'npx -y @playwright/mcp@0.0.75', version: '0.0.75',
    source_url: 'https://github.com/microsoft/playwright-mcp',
    trust_evidence: { dimensions: { registry: { status: 'unlisted', checked_at: '2026-09-17' } } },
  },
  {
    name: 'mcp-clickhouse', install_cmd: 'uvx mcp-clickhouse==0.3.0', version: '0.3.0',
    source_url: 'https://github.com/ClickHouse/mcp-clickhouse',
    trust_evidence: { dimensions: { registry: { status: 'listed', checked_at: '2026-09-17', server_id: 'io.github.ClickHouse/mcp-clickhouse' } } },
  },
  {
    name: 'tavily-mcp', install_cmd: 'npx -y tavily-mcp@0.2.9', version: '0.2.9',
    source_url: 'https://github.com/tavily-ai/tavily-mcp',
    trust_evidence: { dimensions: { registry: { status: 'listed', checked_at: '2026-09-17', server_id: 'io.github.tavily-ai/tavily-mcp' } } },
  },
] };

test('fetch pages through the cursor, asks for deleted servers too, and sorts the result', async () => {
  const { get, seen } = fakeGet();
  const r = await snap.fetchSnapshot({ get, now: fixedNow });
  assert.equal(r.ok, true);
  assert.equal(seen.length, 2);
  for (const u of seen) {
    assert.match(u, /^https:\/\/registry\.modelcontextprotocol\.io\/v0\.1\/servers\?/);
    assert.match(u, /include_deleted=true/);
  }
  assert.match(seen[1], /cursor=com\.microsoft%2Fplaywright%3A0\.0\.80/);
  assert.equal(r.snapshot.schema, 'mcp-vault/registry-snapshot@1');
  assert.equal(r.snapshot.count, 7);
  const keys = r.snapshot.servers.map((s) => `${s.name}@${s.version}`);
  assert.deepEqual(keys, [...keys].sort());
  // The 2025-09 spelling of the package registry is normalised.
  const shiny = r.snapshot.servers.find((s) => s.name === 'io.github.newbie/shiny-mcp');
  assert.equal(shiny.packages[0].registryType, 'npm');
});

test('--latest-only asks the registry for latest versions and says so in the snapshot', async () => {
  const { get, seen } = fakeGet();
  const r = await snap.fetchSnapshot({ get, latestOnly: true, now: fixedNow });
  assert.match(seen[0], /version=latest/);
  assert.equal(r.snapshot.scope, 'latest');
  assert.equal(snap.ingestReport(DB, r.snapshot).snapshot.scope, 'latest');
  assert.equal((await fixtureSnapshot()).scope, 'all-versions');
});

test('fetch is all or nothing: a failed page, a repeated cursor or the page cap is not a snapshot', async () => {
  assert.equal((await snap.fetchSnapshot({ get: fakeGet(PAGES, { failAt: 1 }).get })).ok, false);
  const loop = [{ servers: [], metadata: { nextCursor: 'same' } }];
  const r = await snap.fetchSnapshot({ get: async () => ({ ok: true, data: loop[0] }) });
  assert.equal(r.ok, false);
  assert.match(r.error, /same cursor/);
  assert.equal((await snap.fetchSnapshot({ get: fakeGet().get, maxPages: 1 })).ok, false);
});

test('report: withdrawn by the latest version, and by the exact pinned version', async () => {
  const r = snap.ingestReport(DB, await fixtureSnapshot());
  assert.equal(r.schema, 'mcp-vault/registry-ingest@1');
  assert.equal(r.matched, 3);
  const by = Object.fromEntries(r.withdrawn.map((w) => [w.name, w]));
  assert.deepEqual(Object.keys(by).sort(), ['mcp-clickhouse', 'playwright-mcp']);

  // Proved link: the id identity recorded.
  assert.equal(by['mcp-clickhouse'].matched_by, 'server_id');
  assert.equal(by['mcp-clickhouse'].latest.status, 'deprecated');

  // The latest version is fine; the one this DB pins was deleted. That is the
  // case a "latest only" check misses.
  assert.equal(by['playwright-mcp'].matched_by, 'package');
  assert.equal(by['playwright-mcp'].latest.status, 'active');
  assert.equal(by['playwright-mcp'].pinned.version, '0.0.75');
  assert.equal(by['playwright-mcp'].pinned.status, 'deleted');
  assert.match(by['playwright-mcp'].pinned.statusMessage, /malicious/);
});

test('new servers: active, installable, and not already in the DB', async () => {
  const r = snap.ingestReport(DB, await fixtureSnapshot());
  // Not the remote-only one (nothing to pin), not the deleted spam, not the
  // three the DB already has.
  assert.deepEqual(r.new_servers.map((s) => s.name), ['io.github.newbie/shiny-mcp']);
  assert.equal(r.new_servers_count, 1);
});

test('the report is a pure function of its inputs and does not touch the DB object', async () => {
  const s = await fixtureSnapshot();
  const before = JSON.stringify(DB);
  const a = JSON.stringify(snap.ingestReport(DB, s));
  const b = JSON.stringify(snap.ingestReport(DB, s));
  assert.equal(a, b);
  assert.equal(JSON.stringify(DB), before);
  assert.throws(() => snap.ingestReport(DB, { servers: [] }), /registry-snapshot@1/);
});

test('discover --source registry-snapshot: latest active versions, tagged as a registry source', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-snap-'));
  const file = path.join(dir, 'snap.json');
  fs.writeFileSync(file, JSON.stringify(await fixtureSnapshot()));
  const got = discover.fromRegistrySnapshot(file);
  const ids = got.map((c) => c.registry_id).sort();
  // Deleted/deprecated latest versions are not candidates; playwright's
  // latest (0.0.80) is active and so still appears — the DB dedupe is
  // discover's job, done downstream the same way for every source.
  assert.deepEqual(ids, ['com.example/remote-only', 'com.microsoft/playwright', 'io.github.newbie/shiny-mcp', 'io.github.tavily-ai/tavily-mcp']);
  const pw = got.find((c) => c.registry_id === 'com.microsoft/playwright');
  assert.equal(pw.install_cmd, 'npx -y @playwright/mcp@0.0.80');
  assert.equal(pw.source, 'mcp-registry-snapshot');
  assert.equal(discover.looksLikeMcpServer(pw), true);
});

test('discover: registry-snapshot without --snapshot is a usage error, before any network', () => {
  const r = spawnSync(process.execPath, [path.join(SCRIPTS, 'discover.cjs'), '--source', 'registry-snapshot'], { encoding: 'utf8' });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /--snapshot/);
});

test('CLI: exit 1 on a withdrawn entry, 0 when clean, 2 on bad input; --fetch writes nothing on failure', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-ingest-'));
  const snapFile = path.join(dir, 'snap.json');
  const dbFile   = path.join(dir, 'db.json');
  const cleanDb  = path.join(dir, 'clean.json');
  fs.writeFileSync(dbFile, JSON.stringify(DB));
  fs.writeFileSync(cleanDb, JSON.stringify({ tools: [DB.tools[2]] }));

  const quiet = async (fn) => {
    const [o, e] = [process.stdout.write, process.stderr.write];
    let text = '';
    process.stdout.write = (s) => { text += s; return true; };
    process.stderr.write = () => true;
    try { return { code: await fn(), text }; } finally { process.stdout.write = o; process.stderr.write = e; }
  };

  let r = await quiet(() => cli.run(['--fetch', '--out', snapFile], { get: fakeGet().get }));
  assert.equal(r.code, 0);
  assert.equal(JSON.parse(fs.readFileSync(snapFile, 'utf8')).count, 7);

  const failed = path.join(dir, 'failed.json');
  r = await quiet(() => cli.run(['--fetch', '--out', failed], { get: fakeGet(PAGES, { failAt: 1 }).get }));
  assert.equal(r.code, 2);
  assert.equal(fs.existsSync(failed), false);

  r = await quiet(() => cli.run(['--snapshot', snapFile, '--json'], { dbPath: dbFile }));
  assert.equal(r.code, 1);
  assert.equal(JSON.parse(r.text).withdrawn.length, 2);

  r = await quiet(() => cli.run(['--snapshot', snapFile], { dbPath: cleanDb }));
  assert.equal(r.code, 0);
  assert.match(r.text, /No matched entry is deprecated or deleted/);

  for (const argv of [[], ['--fetch'], ['--snapshot', path.join(dir, 'nope.json')], ['--fetch', '--out', 'x', '--registry', 'http://insecure'], ['--what']]) {
    r = await quiet(() => cli.run(argv, { dbPath: dbFile }));
    assert.equal(r.code, 2, argv.join(' '));
  }
  // The DB file is read, never written.
  assert.equal(fs.readFileSync(dbFile, 'utf8'), JSON.stringify(DB));
});
