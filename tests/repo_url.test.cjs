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
