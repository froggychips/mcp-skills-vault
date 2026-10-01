'use strict';
/**
 * What a repository URL names.
 *
 * There were six copies of this, four of them matching `github.com/o/r`
 * *unanchored*, so `https://evil.example/github.com/acme/server` produced the
 * slug `acme/server`. Every consumer then talked about the wrong project: the
 * health scorer fetched its stars, the licence-drift check read its licence,
 * the availability check asked whether it had moved, and the registry
 * cross-reference compared identities. `source_url` is a field a pull request
 * writes, so this function is a trust boundary.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const r = require('../mcp-ecosystem-intelligence/scripts/lib/repo_url.cjs');

test('every spelling of the same repository gives one slug', () => {
  for (const url of [
    'https://github.com/acme/server',
    'https://www.github.com/Acme/Server',
    'https://github.com/acme/server.git',
    'git+https://github.com/acme/server.git',
    'git+ssh://git@github.com/acme/server.git',
    'git@github.com:acme/server.git',
    'ssh://git@github.com/acme/server',
    'https://github.com/acme/server/tree/main/packages/x',
    'https://github.com/acme/server#readme',
    'https://github.com/acme/server?tab=readme-ov-file',
    '  https://github.com/acme/server  ',
  ]) {
    assert.equal(r.githubSlug(url), 'acme/server', url);
  }
});

test('a host that merely contains github.com is not github.com', () => {
  for (const url of [
    'https://evil.example/github.com/acme/server',
    'https://github.com.evil.example/acme/server',
    'https://notgithub.com/acme/server',
    'https://gitlab.com/acme/server',
    'https://raw.githubusercontent.com/acme/server/main/x',
    'http://example.com/?q=github.com/acme/server',
  ]) {
    assert.equal(r.githubSlug(url), null, url);
    assert.equal(r.isGithubUrl(url), false, url);
  }
});

test('an incomplete or nonsensical URL is refused', () => {
  for (const url of ['https://github.com/acme', 'https://github.com/', 'https://github.com', '', null, undefined, 42, {}]) {
    assert.equal(r.githubSlug(url), null, String(url));
  }
  // `.` and `..` cannot be repository names, and letting them through would
  // put path traversal into an API request.
  assert.equal(r.githubSlug('https://github.com/acme/.'), null);
  assert.equal(r.githubSlug('https://github.com/acme/..'), null);
});

test('owner and canonical URL come from the same parse', () => {
  assert.equal(r.githubOwner('git@github.com:Acme/Server.git'), 'acme');
  assert.equal(r.githubRepoUrl('git@github.com:Acme/Server.git'), 'https://github.com/Acme/Server');
  assert.equal(r.githubOwner('https://evil.example/github.com/acme/server'), null);
  assert.equal(r.githubRepoUrl('https://gitlab.com/acme/server'), null);
});

test('normalizeGitUrl canonicalises without deciding the host', () => {
  // It has to pass through hosts nothing here can resolve a slug for: GitLab,
  // Codeberg and self-hosted instances appear in this DB, and comparing two of
  // *those* is still useful.
  assert.equal(r.normalizeGitUrl('git+https://gitlab.com/acme/server.git'), 'https://gitlab.com/acme/server');
  assert.equal(r.normalizeGitUrl('git@github.com:acme/server.git'), 'https://github.com/acme/server');
  assert.equal(r.normalizeGitUrl('https://github.com/acme/server/issues'), 'https://github.com/acme/server');
  assert.equal(r.normalizeGitUrl(null), null);
});

test('no script matches github.com in an unanchored pattern', () => {
  // Not a style point: the reason there were six copies of this parse is that
  // each consumer wrote its own, and four of them were unanchored in the same
  // way. Checked per line, because extracting regex literals properly needs a
  // tokeniser and a crude one flagged anchored patterns by splitting them in
  // the middle.
  const fs = require('fs');
  const path = require('path');
  const dir = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts');
  const files = [
    ...fs.readdirSync(dir).filter((f) => f.endsWith('.cjs')),
    ...fs.readdirSync(path.join(dir, 'lib')).filter((f) => f.endsWith('.cjs')).map((f) => `lib/${f}`),
  ];

  const offenders = [];
  for (const file of files) {
    if (file === 'lib/repo_url.cjs') continue;
    const src = fs.readFileSync(path.join(dir, file), 'utf8');
    src.split('\n').forEach((line, i) => {
      // Only lines that actually build a pattern over a host.
      if (!/github\\\.com/.test(line)) return;
      if (!/(?:match|test|exec|replace)\s*\(/.test(line)) return;
      // An anchor makes it safe; a markdown-link pattern is parsing prose, not
      // deciding what a URL names.
      if (line.includes('^')) return;
      if (/\\\[|\\\]|\\\(/.test(line)) return;
      offenders.push(`${file}:${i + 1}  ${line.trim().slice(0, 90)}`);
    });
  }
  assert.deepEqual(offenders, [], `unanchored github.com patterns outside lib/repo_url.cjs:\n${offenders.join('\n')}`);
});

// ── source_binding: does a registry's repository field name our repository? ──
//
// verify_integrity.cjs used to compare whole normalised URLs with its own copy
// of the normaliser, which kept `/tree/<branch>/<path>` and `#fragment` on the
// npm side. Every monorepo package whose npm metadata points into a
// subdirectory read as "repo mismatch" — and that word makes trust unverified.

test('repoKey / githubSlug: the npm spellings seen in the DB name one repository', () => {
  assert.equal(r.githubSlug('https://github.com/mondaycom/monday-ai/tree/master/packages/monday-api-mcp'), 'mondaycom/monday-ai');
  assert.equal(r.githubSlug('git+https://github.com/mondaycom/mcp.git#master'), 'mondaycom/mcp');
  assert.equal(r.githubSlug('git@github.com:o/r.git'), 'o/r');
  assert.equal(r.githubSlug('github:o/r'), 'o/r');
  assert.equal(r.githubSlug('github:O/R.git#main'), 'o/r');
  assert.equal(r.githubSlug('git://github.com/o/r.git'), 'o/r');
  // The shorthand is anchored like everything else.
  assert.equal(r.githubSlug('xgithub:o/r'), null);
  assert.equal(r.githubSlug('github:o'), null);
  assert.equal(r.repoKey('https://GitHub.com/O/R/tree/main/x'), 'github.com/o/r');
  // Not GitHub: still compared, by normalised spelling.
  assert.equal(r.repoKey('git+https://gitlab.com/Acme/Server.git#v1'), 'gitlab.com/acme/server');
  assert.equal(r.repoKey('https://gitlab.com/acme/server/-/tree/main/pkg'), 'gitlab.com/acme/server');
  assert.equal(r.repoKey(null), null);
});

test('sourceBinding: subdirectory, fragment, ssh, shorthand and case are the same repository', () => {
  const stored = 'https://github.com/mondaycom/mcp';
  for (const declared of [
    'git+https://github.com/mondaycom/mcp.git#master',
    'https://github.com/mondaycom/mcp/tree/master/packages/monday-api-mcp',
    'git@github.com:mondaycom/mcp.git',
    'github:mondaycom/mcp',
    'https://github.com/MondayCom/MCP',
    'https://github.com/mondaycom/mcp?tab=readme-ov-file',
  ]) {
    assert.deepEqual(r.sourceBinding(stored, declared), { state: 'verified' }, declared);
  }
  assert.deepEqual(r.sourceBinding('https://github.com/o/r/tree/main/pkg', 'git+https://github.com/o/r.git'), { state: 'verified' });
  assert.equal(r.sourceBinding(stored, 'https://github.com/someone-else/mcp').state, 'mismatch');
  assert.equal(r.sourceBinding(stored, 'https://evil.example/github.com/mondaycom/mcp').state, 'mismatch');
  assert.equal(r.sourceBinding(stored, null).state, 'unverified');
  assert.equal(r.sourceBinding(null, stored).state, 'unverified');
});

test('sourceBinding: a renamed repository matches only through a recorded alias that resolves to it', () => {
  const stored = 'https://github.com/mondaycom/mcp';
  const old = 'https://github.com/mondaycom/monday-ai/tree/master/packages/monday-api-mcp';
  // No network here: without a recorded alias a rename is a mismatch.
  assert.equal(r.sourceBinding(stored, old).state, 'mismatch');
  const aliases = [{ slug: 'mondaycom/monday-ai', resolved_to: 'mondaycom/mcp', resolved_at: '2026-10-01', via: 'github-api' }];
  assert.deepEqual(r.sourceBinding(stored, old, { aliases }), { state: 'verified', alias: 'mondaycom/monday-ai' });
  assert.deepEqual(r.sourceBinding('https://github.com/MondayCom/MCP', 'git+https://github.com/MONDAYCOM/monday-ai.git', { aliases }),
    { state: 'verified', alias: 'mondaycom/monday-ai' });
  // An alias recorded for a different repository is not inherited when
  // source_url changes: it named an earlier name of *that* repository.
  assert.equal(r.sourceBinding('https://github.com/fork/mcp', old, { aliases }).state, 'mismatch');
  // Malformed alias lists are ignored, not trusted.
  assert.equal(r.sourceBinding(stored, old, { aliases: 'mondaycom/monday-ai' }).state, 'mismatch');
  assert.equal(r.sourceBinding(stored, old, { aliases: [null, { slug: 'mondaycom/monday-ai' }] }).state, 'mismatch');
});

test('one URL normaliser: no script outside lib/repo_url.cjs defines its own', () => {
  const fs = require('fs');
  const path = require('path');
  const roots = [
    path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts'),
    path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts/lib'),
    path.resolve(__dirname, '../.github/scripts'),
    path.resolve(__dirname, '../bin'),
  ];
  const offenders = [];
  for (const dir of roots) {
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.cjs'))) {
      if (f === 'repo_url.cjs') continue;
      const src = fs.readFileSync(path.join(dir, f), 'utf8');
      // A normaliser is a chain that strips `.git` from a URL.
      if (/\.replace\(\/\\\.git\$\//.test(src)) offenders.push(path.relative(path.resolve(__dirname, '..'), path.join(dir, f)));
    }
  }
  assert.deepEqual(offenders, []);
});

// ── renames: GitHub answers the old /repos path with a 301 ──

const http = require('../mcp-ecosystem-intelligence/scripts/lib/http.cjs');

/** A stand-in transport: GitHub's actual answers for a renamed repository. */
function githubTransport(routes) {
  const seen = [];
  const transport = async (url) => {
    seen.push(url);
    const hit = routes[url];
    if (!hit) return { status: 404, headers: {}, text: '{"message":"Not Found"}' };
    return { status: hit.status, headers: hit.headers || {}, text: JSON.stringify(hit.body || {}) };
  };
  return { transport, seen };
}
const RENAMED = {
  'https://api.github.com/repos/mondaycom/monday-ai': {
    status: 301,
    headers: { location: 'https://api.github.com/repositories/962148723' },
    body: { message: 'Moved Permanently', url: 'https://api.github.com/repositories/962148723' },
  },
  'https://api.github.com/repositories/962148723': { status: 200, body: { full_name: 'mondaycom/mcp' } },
};
const getVia = (transport) => (url, opts) => http.getJson(url, { ...opts, retries: 0, transport });
const NOW = Date.parse('2026-10-01T12:00:00Z');

test('http.getJson: a 301 is not an answer unless the caller asks to follow it', async () => {
  const { transport } = githubTransport(RENAMED);
  const plain = await http.getJson('https://api.github.com/repos/mondaycom/monday-ai', { retries: 0, transport });
  assert.equal(plain.ok, false);
  assert.equal(plain.status, 301);
  const followed = await http.getJson('https://api.github.com/repos/mondaycom/monday-ai', { retries: 0, transport, maxRedirects: 2 });
  assert.equal(followed.ok, true);
  assert.equal(followed.data.full_name, 'mondaycom/mcp');
  assert.equal(followed.url, 'https://api.github.com/repositories/962148723');
  // Bounded: a loop ends as a failure, not a hang.
  const loop = { 'https://x.example/a': { status: 302, headers: { location: '/a' } } };
  const looped = await http.getJson('https://x.example/a', { retries: 0, transport: githubTransport(loop).transport, maxRedirects: 3 });
  assert.equal(looped.ok, false);
});

test('resolveRepoAlias follows GitHub\'s redirect and records a dated alias', async () => {
  const { transport, seen } = githubTransport(RENAMED);
  const tool = { name: 'm', source_url: 'https://github.com/mondaycom/mcp' };
  const alias = await r.resolveRepoAlias(tool,
    'https://github.com/mondaycom/monday-ai/tree/master/packages/monday-api-mcp', { get: getVia(transport), now: NOW });
  assert.deepEqual(alias, { slug: 'mondaycom/monday-ai', resolved_to: 'mondaycom/mcp', resolved_at: '2026-10-01', via: 'github-api' });
  assert.deepEqual(tool.source_aliases, [alias]);
  assert.deepEqual(seen, ['https://api.github.com/repos/mondaycom/monday-ai', 'https://api.github.com/repositories/962148723']);
  // Once known, not asked again.
  assert.equal(await r.resolveRepoAlias(tool, 'git+https://github.com/mondaycom/monday-ai.git', { get: getVia(transport), now: NOW }), null);
  assert.equal(seen.length, 2);
  // And the offline comparison now accepts the old name.
  assert.equal(r.sourceBinding(tool.source_url, 'https://github.com/mondaycom/monday-ai', { aliases: tool.source_aliases }).state, 'verified');
});

test('resolveRepoAlias records nothing when GitHub names another repository, 404s, or redirects off the API', async () => {
  const tool = () => ({ name: 'm', source_url: 'https://github.com/mondaycom/mcp' });
  const other = githubTransport({
    'https://api.github.com/repos/someone/fork': { status: 301, headers: { location: 'https://api.github.com/repositories/1' } },
    'https://api.github.com/repositories/1': { status: 200, body: { full_name: 'someone/elsewhere' } },
  });
  let t = tool();
  assert.equal(await r.resolveRepoAlias(t, 'https://github.com/someone/fork', { get: getVia(other.transport), now: NOW }), null);
  assert.equal(t.source_aliases, undefined);
  t = tool();
  assert.equal(await r.resolveRepoAlias(t, 'https://github.com/gone/repo', { get: getVia(githubTransport({}).transport), now: NOW }), null);
  const offApi = githubTransport({
    'https://api.github.com/repos/mondaycom/monday-ai': { status: 301, headers: { location: 'https://evil.example/repositories/1' } },
    'https://evil.example/repositories/1': { status: 200, body: { full_name: 'mondaycom/mcp' } },
  });
  t = tool();
  assert.equal(await r.resolveRepoAlias(t, 'https://github.com/mondaycom/monday-ai', { get: getVia(offApi.transport), now: NOW }), null);
  // Same repository: nothing to resolve, no request.
  const none = githubTransport({});
  assert.equal(await r.resolveRepoAlias(tool(), 'git+https://github.com/MondayCom/mcp.git', { get: getVia(none.transport), now: NOW }), null);
  assert.deepEqual(none.seen, []);
});

test('provenance: a release attested before the rename binds through a recorded alias', () => {
  const { checkProvenance } = require('../mcp-ecosystem-intelligence/scripts/lib/npm_signatures.cjs');
  const stored = 'https://github.com/mondaycom/mcp';
  const claim = { repository: 'https://github.com/mondaycom/monday-ai' };
  const aliases = [{ slug: 'mondaycom/monday-ai', resolved_to: 'mondaycom/mcp', resolved_at: '2026-10-01', via: 'github-api' }];
  const without = checkProvenance({ claim, sourceUrl: stored, normalizeRepo: r.aliasAwareRepoKey(stored, []) });
  assert.equal(without.state, 'mismatch');
  assert.ok(without.findings.some((f) => /provenance names/.test(f)));
  const withAlias = checkProvenance({ claim, sourceUrl: stored, normalizeRepo: r.aliasAwareRepoKey(stored, aliases) });
  assert.notEqual(withAlias.state, 'mismatch');
  assert.ok(!withAlias.findings.some((f) => /provenance names/.test(f)), withAlias.findings.join('; '));
  // An alias for another repository does not stretch to this one.
  const fork = 'https://github.com/fork/mcp';
  assert.equal(checkProvenance({ claim, sourceUrl: fork, normalizeRepo: r.aliasAwareRepoKey(fork, aliases) }).state, 'mismatch');
  assert.equal(r.aliasAwareRepoKey(stored, aliases)('https://github.com/MondayCom/Monday-AI/tree/x'), 'github.com/mondaycom/mcp');
});
