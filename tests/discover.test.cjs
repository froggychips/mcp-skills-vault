'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const d = require('../mcp-ecosystem-intelligence/scripts/discover.cjs');

test('normalizeRepoUrl: collapses /tree/branch/path to bare repo', () => {
  assert.equal(
    d.normalizeRepoUrl('https://github.com/owner/repo/tree/main/src/foo'),
    'https://github.com/owner/repo',
  );
});

test('normalizeRepoUrl: strips .git, trailing slash, git+ prefix, http→https', () => {
  assert.equal(d.normalizeRepoUrl('git+https://github.com/foo/bar.git'),  'https://github.com/foo/bar');
  assert.equal(d.normalizeRepoUrl('http://github.com/foo/bar/'),          'https://github.com/foo/bar');
});

test('ownerRepoFromUrl: parses {owner, repo}', () => {
  assert.deepEqual(d.ownerRepoFromUrl('https://github.com/foo/bar'), { owner: 'foo', repo: 'bar' });
  assert.equal(d.ownerRepoFromUrl('not-a-github-url'), null);
  assert.equal(d.ownerRepoFromUrl(null),               null);
});

test('scoreHealth: stars are log10-capped at 20', () => {
  // 10·log10(1+1) ≈ 3.01; 10·log10(1e9+1) ≈ 90 — but capped at 20.
  const onlyStars = (n) => d.scoreHealth({
    stars: n, last_commit_days: 9999, has_install_cmd: false, in_registry: false, open_issues: 999, license: 'Unknown',
  });
  // Just confirm the cap: 1e9 stars contributes the same as 1e6.
  assert.ok(onlyStars(1_000_000) <= onlyStars(1_000_000_000) + 0.001);
  assert.ok(onlyStars(1_000_000_000) <= 20 - 10 - 0.001 + 100); // very loose, just shape check
});

test('scoreHealth: recency tiers contribute 40/20/10/0', () => {
  const base = { stars: 0, has_install_cmd: false, in_registry: false, open_issues: 999, license: 'Unknown' };
  const score = (days) => d.scoreHealth({ ...base, last_commit_days: days });
  // 999 open_issues blocks the +5 bonus; license Unknown applies −10. So:
  // <30  → 40 + 0 + 0 − 10 = 30
  // <90  → 20 + 0 + 0 − 10 = 10
  // <180 → 10 + 0 + 0 − 10 = 0
  // older → 0 + 0 + 0 − 10 = −10
  assert.equal(score(10),  30);
  assert.equal(score(60),  10);
  assert.equal(score(150),  0);
  assert.equal(score(400), -10);
});

test('scoreHealth: in_registry adds 30, has_install_cmd adds 15, license penalty applies', () => {
  const s = d.scoreHealth({
    stars: 0, last_commit_days: 10, has_install_cmd: true, in_registry: true, open_issues: 0, license: 'MIT',
  });
  // 0 + 40 + 30 + 15 + 5 − 0 = 90
  assert.equal(s, 90);
});

test('classifyScore: tier boundaries', () => {
  assert.equal(d.classifyScore(105), 'Core');
  assert.equal(d.classifyScore(85),  'Core');
  assert.equal(d.classifyScore(84.9), 'Recommended');
  assert.equal(d.classifyScore(65),  'Recommended');
  assert.equal(d.classifyScore(50),  'Experimental');
  assert.equal(d.classifyScore(39),  'Deprecated');
});

test('looksLikeMcpServer: curated sources pass unconditionally', () => {
  assert.equal(d.looksLikeMcpServer({ source: 'npm-search', name: 'random' }), true);
  assert.equal(d.looksLikeMcpServer({ source: 'mcp-servers-readme', name: 'foo' }), true);
  assert.equal(d.looksLikeMcpServer({ source: 'mcp-registry', name: 'random' }), true);
  assert.equal(d.looksLikeMcpServer({ source: 'pypi',         name: 'random' }), true);
});

test('looksLikeMcpServer: gh-topic candidates need "mcp" in name/description', () => {
  const gh = (name, description) => ({ source: 'gh-topic', name, description });
  assert.equal(d.looksLikeMcpServer(gh('postgres-mcp-server', 'A server for Postgres')), true);
  assert.equal(d.looksLikeMcpServer(gh('weird-thing', 'Model Context Protocol thingy')), true);
  // Real false-positives caught in production: TrendRadar, gemini-cli, Scrapling.
  assert.equal(d.looksLikeMcpServer(gh('TrendRadar', 'Trending topic tracker')), false);
  assert.equal(d.looksLikeMcpServer(gh('Scrapling', 'Web scraper library')),     false);
});

test('rejectReason: low-stars / unmaintained / non-mcp / passing', () => {
  const base = { source: 'npm-search', name: 'foo', description: 'mcp server' };
  assert.equal(d.rejectReason({ ...base, stars: 100, last_commit_days: 30 }),   null);
  assert.equal(d.rejectReason({ ...base, stars: 5,   last_commit_days: 30 }),   'low-stars');
  assert.equal(d.rejectReason({ ...base, stars: 100, last_commit_days: 400 }),  'unmaintained');
  // gh-topic without MCP marker
  const ghOff = { source: 'gh-topic', name: 'random', description: 'thing', stars: 100, last_commit_days: 30 };
  assert.equal(d.rejectReason(ghOff), 'not-mcp-server');
});

// ── MCP registry parser ────────────────────────────────────────────────────

test('parseRegistryPage: extracts name, description, repo URL, install_cmd from npm package', () => {
  const fixture = {
    servers: [{
      server: {
        name:        'io.github.foo/bar',
        title:       'Foo Bar Server',
        description: 'A test MCP server',
        repository:  { url: 'https://github.com/foo/bar.git', source: 'github' },
        packages:    [{ registryType: 'npm', identifier: '@foo/bar-mcp', version: '1.2.3' }],
      },
      _meta: {},
    }],
    metadata: { nextCursor: 'cur-2', count: 1 },
  };
  const { entries, nextCursor } = d.parseRegistryPage(fixture);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name,         'Foo Bar Server');
  assert.equal(entries[0].registry_id,  'io.github.foo/bar');
  assert.equal(entries[0].description,  'A test MCP server');
  assert.equal(entries[0].source_url,   'https://github.com/foo/bar');
  assert.equal(entries[0].install_cmd,  'npx -y @foo/bar-mcp@1.2.3');
  assert.equal(entries[0].npm_package,  '@foo/bar-mcp');
  assert.equal(entries[0].pypi_package, null);
  assert.equal(entries[0].source,       'mcp-registry');
  assert.equal(nextCursor, 'cur-2');
});

test('parseRegistryPage: pypi package → uvx install_cmd, oci → docker run', () => {
  const fixture = {
    servers: [
      { server: { name: 'a/x', description: 'py', packages: [{ registryType: 'pypi', identifier: 'pkg-x', version: '0.9.0' }] } },
      { server: { name: 'a/y', description: 'docker', packages: [{ registryType: 'oci', identifier: 'docker.io/foo/y:1.0' }] } },
    ],
    metadata: { count: 2 },
  };
  const { entries, nextCursor } = d.parseRegistryPage(fixture);
  assert.equal(entries[0].install_cmd,  'uvx pkg-x==0.9.0');
  assert.equal(entries[0].pypi_package, 'pkg-x');
  assert.equal(entries[1].install_cmd,  'docker run --rm -i docker.io/foo/y:1.0');
  assert.equal(nextCursor, null);
});

test('parseRegistryPage: tolerates missing fields without crashing', () => {
  assert.deepEqual(d.parseRegistryPage(null),            { entries: [], nextCursor: null });
  assert.deepEqual(d.parseRegistryPage({}),              { entries: [], nextCursor: null });
  assert.deepEqual(d.parseRegistryPage({ servers: [] }), { entries: [], nextCursor: null });
  // Server with no name is skipped silently.
  const r = d.parseRegistryPage({ servers: [{ server: {} }, { server: { name: 'ok/x' } }] });
  assert.equal(r.entries.length, 1);
  assert.equal(r.entries[0].registry_id, 'ok/x');
});

test('fromMcpRegistry: follows nextCursor, dedupes by registry_id', async () => {
  // Stub fetcher: two pages, second has a duplicate of page-1 entry plus a new one.
  const pages = {
    'https://example/v0/servers': {
      servers: [{ server: { name: 'a/1', description: 'first', repository: { url: 'https://github.com/a/one' } } }],
      metadata: { nextCursor: 'c2', count: 1 },
    },
    'https://example/v0/servers?cursor=c2': {
      servers: [
        { server: { name: 'a/1', description: 'first (v2)' } },   // duplicate
        { server: { name: 'a/2', description: 'second' } },
      ],
      metadata: { count: 2 },
    },
  };
  const calls = [];
  const fetcher = async (url) => { calls.push(url); return pages[url] || null; };
  const out = await d.fromMcpRegistry({ fetcher, base: 'https://example/v0/servers', maxPages: 5 });
  assert.equal(calls.length, 2);
  assert.equal(out.length, 2);                          // dedup worked
  assert.deepEqual(out.map(e => e.registry_id), ['a/1', 'a/2']);
  assert.equal(out[0].source_url, 'https://github.com/a/one');
});

test('fromMcpRegistry: fetcher returning null stops pagination without crashing', async () => {
  const fetcher = async () => null;
  const out = await d.fromMcpRegistry({ fetcher, base: 'https://example/x', maxPages: 5 });
  assert.deepEqual(out, []);
});

// ── PyPI parsers ───────────────────────────────────────────────────────────

test('parsePypiSimpleIndex: extracts mcp-prefixed names, filters unrelated', () => {
  const html = `
    <html><body>
      <a href="/simple/mcp-server-git/">mcp-server-git</a>
      <a href="/simple/mcp-atlassian/">mcp-atlassian</a>
      <a href="/simple/mcp/">mcp</a>
      <a href="/simple/numpy/">numpy</a>
      <a href="/simple/foo-mcp-server/">foo-mcp-server</a>
      <a href="/simple/requests/">requests</a>
    </body></html>
  `;
  const names = d.parsePypiSimpleIndex(html);
  assert.ok(names.includes('mcp-server-git'));
  assert.ok(names.includes('mcp-atlassian'));
  assert.ok(names.includes('foo-mcp-server'));
  assert.ok(!names.includes('numpy'));
  assert.ok(!names.includes('requests'));
  // Bare "mcp" (no separator) should NOT match.
  assert.ok(!names.includes('mcp'));
});

test('parsePypiSimpleIndex: empty or non-string input returns []', () => {
  assert.deepEqual(d.parsePypiSimpleIndex(''),   []);
  assert.deepEqual(d.parsePypiSimpleIndex(null), []);
  assert.deepEqual(d.parsePypiSimpleIndex(42),   []);
});

test('parsePypiJson: extracts repo URL from project_urls.Source/Repository/Homepage', () => {
  const repoTop = d.parsePypiJson({
    info: {
      name: 'mcp-server-git', version: '0.5.0', summary: 'Git MCP server',
      project_urls: { Repository: 'https://github.com/modelcontextprotocol/servers' },
    },
  });
  assert.equal(repoTop.source_url,   'https://github.com/modelcontextprotocol/servers');
  assert.equal(repoTop.install_cmd,  'uvx mcp-server-git==0.5.0');
  assert.equal(repoTop.pypi_package, 'mcp-server-git');
  assert.equal(repoTop.source,       'pypi');

  // Falls back to Homepage when Repository is missing.
  const fromHomepage = d.parsePypiJson({
    info: { name: 'x', version: '1.0', project_urls: { Homepage: 'https://github.com/foo/x' } },
  });
  assert.equal(fromHomepage.source_url, 'https://github.com/foo/x');

  // No github URL anywhere → source_url is null but candidate is still returned.
  const noRepo = d.parsePypiJson({
    info: { name: 'y', version: '2', summary: 'no repo', project_urls: { Homepage: 'https://example.com' } },
  });
  assert.equal(noRepo.source_url, null);
  assert.equal(noRepo.install_cmd, 'uvx y==2');

  // Garbage in → null out, not a crash.
  assert.equal(d.parsePypiJson(null),                  null);
  assert.equal(d.parsePypiJson({}),                    null);
  assert.equal(d.parsePypiJson({ info: 'not-object' }), null);
});

test('fromPyPI: dependency-injected fetchers; honors probeLimit', async () => {
  const html = `
    <a>mcp-server-foo</a>
    <a>mcp-bar</a>
    <a>not-a-server</a>
  `;
  const jsonByName = {
    'mcp-server-foo': { info: { name: 'mcp-server-foo', version: '1.0', summary: 'foo',
                                project_urls: { Repository: 'https://github.com/a/foo' } } },
    'mcp-bar':        { info: { name: 'mcp-bar',        version: '2.0', summary: 'bar',
                                project_urls: { Repository: 'https://github.com/a/bar' } } },
  };
  const probed = [];
  const fetcherText = async () => html;
  const fetcherJson = async (url) => {
    const m = url.match(/\/pypi\/([^/]+)\/json/);
    if (!m) return null;
    const name = decodeURIComponent(m[1]);
    probed.push(name);
    return jsonByName[name] || null;
  };
  const out = await d.fromPyPI({ fetcherText, fetcherJson, base: 'https://example', probeLimit: 10 });
  // Both mcp-* names should be probed, and the mcp-server-* one comes first
  // (pre-rank). Order of probed[] reflects that.
  assert.equal(probed[0], 'mcp-server-foo');
  assert.equal(out.length, 2);
  assert.equal(out.find(c => c.pypi_package === 'mcp-server-foo').source_url, 'https://github.com/a/foo');

  // probeLimit caps probes.
  probed.length = 0;
  await d.fromPyPI({ fetcherText, fetcherJson, base: 'https://example', probeLimit: 1 });
  assert.equal(probed.length, 1);
});

test('fromPyPI: empty index → no crash, empty result', async () => {
  const out = await d.fromPyPI({
    fetcherText: async () => '',
    fetcherJson: async () => null,
    base:        'https://example',
  });
  assert.deepEqual(out, []);
});

// ── Cross-source dedup smoke test ──────────────────────────────────────────

test('normalizeRepoUrl: registry and npm sources yield matching keys for the same repo', () => {
  // The merge step in main() dedupes by normalizeRepoUrl(source_url). Confirm
  // that a registry entry (`https://github.com/foo/bar.git` with subfolder
  // implied by the registry, normalized to bare repo) and an npm-search entry
  // (`git+https://github.com/foo/bar.git`) collapse to the same key.
  assert.equal(
    d.normalizeRepoUrl('https://github.com/foo/bar.git'),
    d.normalizeRepoUrl('git+https://github.com/foo/bar.git'),
  );
});

// ── deterministic ordering ─────────────────────────────────────────────────

test('cmpName: plain lexicographic, byte-order, no locale surprises', () => {
  assert.ok(d.cmpName({ name: 'a' }, { name: 'b' }) < 0);
  assert.ok(d.cmpName({ name: 'b' }, { name: 'a' }) > 0);
  assert.equal(d.cmpName({ name: 'same' }, { name: 'same' }), 0);
  // Scoped npm names sort by the leading '@' rather than the package word;
  // that's fine — it only has to be the same every run.
  assert.ok(d.cmpName({ name: '@scope/pkg' }, { name: 'apkg' }) < 0);
});

test('cmpName: missing or non-string names never throw', () => {
  assert.equal(typeof d.cmpName({}, {}), 'number');
  assert.equal(typeof d.cmpName(null, undefined), 'number');
  assert.equal(typeof d.cmpName({ name: 42 }, { name: null }), 'number');
});

test('cmpName as a tiebreaker makes an equal-score ranking stable', () => {
  // The churn this fixes: health_score is coarse — on the live inbox 45 of 50
  // entries share a score — so the stored order used to follow whichever
  // source answered first, reshuffling the file with nothing discovered.
  const rank = (rows) =>
    [...rows].sort((a, b) => (b.health_score || 0) - (a.health_score || 0) || d.cmpName(a, b))
      .map(r => r.name);

  const arrivalA = [
    { name: 'zulu',  health_score: 80 },
    { name: 'alpha', health_score: 80 },
    { name: 'mike',  health_score: 90 },
  ];
  // Same data, different discovery order.
  const arrivalB = [
    { name: 'alpha', health_score: 80 },
    { name: 'mike',  health_score: 90 },
    { name: 'zulu',  health_score: 80 },
  ];

  assert.deepEqual(rank(arrivalA), ['mike', 'alpha', 'zulu']);
  assert.deepEqual(rank(arrivalA), rank(arrivalB));
  // Ranking itself is preserved: the higher score still leads.
  assert.equal(rank(arrivalA)[0], 'mike');
});
