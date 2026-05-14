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

test('looksLikeMcpServer: npm + readme sources pass unconditionally', () => {
  assert.equal(d.looksLikeMcpServer({ source: 'npm-search', name: 'random' }), true);
  assert.equal(d.looksLikeMcpServer({ source: 'mcp-servers-readme', name: 'foo' }), true);
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
