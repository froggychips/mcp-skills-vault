'use strict';
/**
 * badge: a claim on somebody else's README has to age honestly.
 *
 * What these pin down: the same input renders the same bytes (the badge is
 * committed and diffed), a required check past its shelf life turns the badge
 * grey and says `stale` rather than keeping the tier's colour, a failed check
 * outranks staleness, and an entry name — pull-request text — cannot break out
 * of the XML it is written into.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const b = require('../mcp-ecosystem-intelligence/scripts/lib/badge.cjs');
const cli = require('../mcp-ecosystem-intelligence/scripts/badge.cjs');

const day = (d) => Date.parse(`${d}T00:00:00Z`);

const tool = (over = {}, dims = {}) => ({
  name: 'pkg', install_cmd: 'npx -y pkg@1.0.0', version: '1.0.0', trust: 'verified',
  source_url: 'https://github.com/o/r',
  trust_evidence: {
    artifact_id: 'npm:pkg@1.0.0',
    dimensions: {
      artifact:   { status: 'verified', checked_at: '2026-09-17', verified_at: '2026-09-17' },
      advisories: { status: 'clean',    checked_at: '2026-09-17', verified_at: '2026-09-17' },
      ...dims,
    },
  },
  ...over,
});

test('fresh evidence: the tier, in its colour, with the newest date', () => {
  const s = b.badgeState(tool(), null, { now: day('2026-09-20') });
  assert.equal(s.state, 'Recommended');
  assert.equal(s.stale, false);
  assert.equal(s.message, 'recommended · 2026-09-17');
  assert.equal(s.color, '#97ca00');
  assert.equal(s.latest_evidence, '2026-09-17');
});

test('a required check past its shelf life turns the badge grey and says stale', () => {
  // advisories keeps 7 days; 13 days later the tier is not a current claim.
  const s = b.badgeState(tool(), null, { now: day('2026-09-30') });
  assert.equal(s.state, 'stale');
  assert.equal(s.stale, true);
  assert.deepEqual(s.stale_dimensions, ['advisories']);
  assert.match(s.message, /^stale · 2026-09-17$/);
  assert.equal(s.color, '#9f9f9f');
  assert.equal(b.endpointJson(s).color, 'lightgrey');
  assert.notEqual(s.color, b.COLORS.Recommended.hex);
});

test('staleness is judged on the dimensions the tier requires, not on every one', () => {
  // A 60-day-old Scorecard read does not make an npm tier untrue.
  const s = b.badgeState(tool({}, {
    repository_posture: { status: 'clean', checked_at: '2026-06-01' },
  }), null, { now: day('2026-09-20') });
  assert.equal(s.stale, false);
  assert.equal(s.state, 'Recommended');
});

test('the newest date is shown, but one stale required check is enough to grey it', () => {
  const s = b.badgeState(tool({}, {
    artifact:   { status: 'verified', checked_at: '2026-09-29', verified_at: '2026-09-29' },
    advisories: { status: 'clean',    checked_at: '2026-09-01', verified_at: '2026-09-01' },
  }), null, { now: day('2026-09-30') });
  assert.equal(s.latest_evidence, '2026-09-29');
  assert.equal(s.state, 'stale');
});

test('a failed check outranks staleness: blocked, red, however old', () => {
  const s = b.badgeState(tool({}, {
    advisories: { status: 'vulnerable', checked_at: '2026-08-01' },
  }), null, { now: day('2026-09-30') });
  assert.equal(s.tier, 'Deprecated');
  assert.equal(s.state, 'Deprecated');
  assert.equal(s.message, 'blocked · 2026-09-17');
  assert.equal(b.endpointJson(s).color, 'red');
});

test('no evidence at all: unverified, grey, no date', () => {
  const s = b.badgeState({ name: 'x', install_cmd: 'npx -y x@1.0.0', version: '1.0.0' }, null, { now: day('2026-09-20') });
  assert.equal(s.state, 'unverified');
  assert.equal(s.message, 'unverified');
  assert.equal(s.latest_evidence, null);
});

test('the SVG is deterministic: same input, same bytes', () => {
  const s1 = b.badgeState(tool(), null, { now: day('2026-09-20') });
  const s2 = b.badgeState(tool(), null, { now: day('2026-09-20') });
  const a = b.renderSvg({ message: s1.message, color: s1.color });
  const c = b.renderSvg({ message: s2.message, color: s2.color });
  assert.equal(a, c);
  assert.match(a, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" width="\d+" height="20"/);
  // Wider message, wider badge — widths come from a fixed table, not a font.
  const wide = b.renderSvg({ message: 'recommended · 2026-09-17 and more', color: '#4c1' });
  const w = (svg) => Number(/width="(\d+)"/.exec(svg)[1]);
  assert.ok(w(wide) > w(a));
});

test('the whole site build is deterministic, and sorted independently of locale', () => {
  const tools = [tool({ name: 'zeta' }), tool({ name: '@scope/alpha' }), tool({ name: 'Beta' })];
  const one = cli.buildAll(tools, new Map(), { now: day('2026-09-20') });
  const two = cli.buildAll([...tools].reverse(), new Map(), { now: day('2026-09-20') });
  assert.deepEqual([...one.files.entries()], [...two.files.entries()]);
  assert.deepEqual(one.index.map((e) => e.name), ['@scope/alpha', 'Beta', 'zeta']);
  assert.ok(one.files.has('badges/scope__alpha.svg'));
  assert.ok(one.files.has('badges/scope__alpha.json'));
  assert.ok(one.files.has('entry/scope__alpha.html'));
  const idx = JSON.parse(one.files.get('badges/index.json'));
  assert.equal(idx.as_of, '2026-09-20');
  assert.equal(idx.count, 3);
});

test('two entries that would share a badge file are refused, not overwritten', () => {
  assert.throws(() => cli.buildAll([tool({ name: '@a/b' }), tool({ name: 'a__b' })], new Map(), { now: day('2026-09-20') }),
    /would share the badge file/);
});

test('XML is escaped in names: a hostile name cannot inject markup', () => {
  const name = '<script>alert("x")</script>&\'\u0001';
  assert.equal(b.escXml(name), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&apos;');
  const svg = b.renderSvg({ label: name, message: `${name} · 2026-09-17`, color: '#4c1', title: name });
  assert.equal(svg.includes('<script>'), false);
  assert.equal(svg.includes('\u0001'), false);
  // Every tag in the output is one the renderer wrote.
  const tags = new Set([...svg.matchAll(/<\/?([a-zA-Z]+)/g)].map((m) => m[1]));
  assert.deepEqual([...tags].sort(), ['clipPath', 'g', 'linearGradient', 'rect', 'stop', 'svg', 'text', 'title']);
  // A colour that is not a hex colour is not written into an attribute.
  assert.equal(b.renderSvg({ message: 'm', color: '"/><script>' }).includes('<script>'), false);

  const built = cli.buildAll([tool({ name, source_url: 'javascript:alert(1)"' })], new Map(), { now: day('2026-09-20') });
  const page = [...built.files.entries()].find(([k]) => k.startsWith('entry/'))[1];
  assert.equal(page.includes('<script>'), false);
  assert.equal(page.includes('alert(1)"'), false);
  // Escaping is not enough for an href: a javascript: URL is not linked at all.
  assert.equal(page.includes('href="javascript:'), false);
});

test('slugs are file-safe', () => {
  assert.equal(b.slugFor('@modelcontextprotocol/server-github'), 'modelcontextprotocol__server-github');
  assert.equal(b.slugFor('../../etc/passwd'), '__..__etc__passwd'.replace(/^[.-]+/, ''));
  assert.doesNotMatch(b.slugFor('a b/c<d>'), /[^a-z0-9._-]/);
  assert.doesNotMatch(b.slugFor('../x'), /^\./);
});

test('the snippet links the badge to the entry\'s evidence page', () => {
  const s = b.snippet('@scope/pkg');
  assert.equal(s.markdown, '[![vetted by mcp-vault](https://mcp.froggychips.xyz/badges/scope__pkg.svg)](https://mcp.froggychips.xyz/entry/scope__pkg.html)');
  assert.match(s.html, /^<a href="https:\/\/mcp\.froggychips\.xyz\/entry\/scope__pkg\.html"><img /);
  assert.match(s.shields_markdown, /img\.shields\.io\/endpoint\?url=https%3A%2F%2Fmcp\.froggychips\.xyz%2Fbadges%2Fscope__pkg\.json/);
});

test('endpoint JSON is shields schemaVersion 1', () => {
  const j = b.endpointJson(b.badgeState(tool(), null, { now: day('2026-09-20') }));
  assert.deepEqual(Object.keys(j).sort(), ['cacheSeconds', 'color', 'label', 'message', 'schemaVersion']);
  assert.equal(j.schemaVersion, 1);
  assert.equal(j.label, 'mcp-vault');
});

test('CLI arguments: a name or --write, never both', () => {
  assert.match(cli.parseArgs([]).error, /which entry/);
  assert.match(cli.parseArgs(['x', '--write']).error, /drop the name/);
  assert.match(cli.parseArgs(['--now', '2026-13-45']).error, /YYYY-MM-DD/);
  assert.equal(cli.parseArgs(['x', '--json']).json, true);
});

test('--out and --base-url: the site root and the URL it is served at', () => {
  const o = cli.parseArgs(['--write', '--out', 'site', '--base-url', 'https://example.test/']);
  assert.equal(o.out, require('path').resolve('site'));
  assert.equal(o.base, 'https://example.test');
  assert.equal(cli.parseArgs(['x']).base, 'https://mcp.froggychips.xyz');
  assert.match(cli.parseArgs(['x', '--base-url', 'not a url']).error, /http\(s\) URL/);
  assert.match(cli.parseArgs(['--write', '--out']).error, /needs a directory/);
});

test('site-registry writes the page and the badges under --out, linked from --base-url', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const reg = require('../mcp-ecosystem-intelligence/scripts/generate_registry_page.cjs');
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-site-'));
  const log = console.log; const write = process.stdout.write;
  try {
    console.log = () => {}; process.stdout.write = () => true;
    reg.main(['--out', out, '--base-url', 'https://example.test']);
  } finally { console.log = log; process.stdout.write = write; }
  try {
    assert.ok(fs.existsSync(path.join(out, 'registry.html')));
    assert.ok(fs.existsSync(path.join(out, 'registry.json')));
    const idx = JSON.parse(fs.readFileSync(path.join(out, 'badges', 'index.json'), 'utf8'));
    assert.ok(idx.count > 0);
    const e = idx.entries[0];
    assert.ok(fs.existsSync(path.join(out, 'badges', `${e.slug}.svg`)));
    assert.ok(fs.existsSync(path.join(out, 'badges', `${e.slug}.json`)));
    assert.equal(e.page, `https://example.test/entry/${e.slug}.html`);
    const page = fs.readFileSync(path.join(out, 'entry', `${e.slug}.html`), 'utf8');
    assert.match(page, new RegExp(`https://example\\.test/badges/${e.slug.replace(/[.]/g, '\\.')}\\.svg`));
    assert.equal(page.includes('docs/site'), false);
  } finally { fs.rmSync(out, { recursive: true, force: true }); }
});
