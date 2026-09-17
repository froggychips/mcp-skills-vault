'use strict';
/**
 * check_availability: the four states, and the two ways to get them wrong.
 *
 * The failure modes these tests exist for:
 *   - a transport failure reported as "gone" (the bug this script fixes, in
 *     reverse: a feed outage would unpublish the whole DB)
 *   - "version gone" reported as "package gone", which changes what a reader
 *     is supposed to do about it
 *   - a deprecation message mined for a successor that isn't one ("Use the
 *     remote MCP server" → a package called "the")
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const a = require('../mcp-ecosystem-intelligence/scripts/check_availability.cjs');

// A fake transport: a map of url-substring → response, so a test says what the
// registry answered rather than what it wishes it had asked.
function fakeGet(routes) {
  return async (url) => {
    for (const [needle, response] of Object.entries(routes)) {
      if (url.includes(needle)) return response;
    }
    return { ok: false, status: 404 };
  };
}
const ok       = (data) => ({ ok: true, status: 200, data });
const notFound = { ok: false, status: 404 };
const down     = { ok: false, status: null, error: 'timeout after 10000ms' };

test('npm: published and pointing at the same repo is "present"', async () => {
  const res = await a.checkNpm({ version: '1.2.3' }, 'pkg', {
    get: fakeGet({ '/pkg/1.2.3': ok({ version: '1.2.3', repository: { url: 'git+https://github.com/o/r.git' } }) }),
  });
  assert.equal(res.state, 'present');
  assert.equal(res.registry_repo, 'git+https://github.com/o/r.git');
});

test('npm: the pinned version gone is not the package gone', async () => {
  const res = await a.checkNpm({ version: '1.2.3' }, 'pkg', {
    get: fakeGet({
      '/pkg/1.2.3': notFound,
      '/pkg':       ok({ versions: { '1.2.4': {}, '1.3.0': {} }, 'dist-tags': { latest: '1.3.0' } }),
    }),
  });
  assert.equal(res.state, 'version-gone');
  assert.match(res.detail, /2 versions remain/);
  assert.match(res.detail, /latest 1\.3\.0/);
});

test('npm: package gone says the name is claimable', async () => {
  const res = await a.checkNpm({ version: '1.2.3' }, 'pkg', { get: fakeGet({}) });   // everything 404s
  assert.equal(res.state, 'gone');
  assert.match(res.detail, /claimable/);
});

test('npm: a feed that did not answer is "unknown", never "gone"', async () => {
  // The whole point. Reporting an outage as an unpublished package would
  // downgrade the entire DB the first time npm had a bad minute.
  const res = await a.checkNpm({ version: '1.2.3' }, 'pkg', { get: fakeGet({ '/pkg': down }) });
  assert.equal(res.state, 'unknown');
  assert.match(res.detail, /lookup failed/);
});

test('npm: a 404 on the version with an unreachable package doc stays unknown', async () => {
  const res = await a.checkNpm({ version: '1.2.3' }, 'pkg', {
    get: async (url) => (url.endsWith('/1.2.3') ? notFound : down),
  });
  assert.equal(res.state, 'unknown');
});

test('npm: deprecated is a warning, and carries the maintainer\'s own words', async () => {
  const res = await a.checkNpm({ version: '1.0.0' }, 'pkg', {
    get: fakeGet({ '/pkg/1.0.0': ok({ version: '1.0.0', deprecated: 'Renamed to @new/pkg. See https://x.dev/migrate.' }) }),
  });
  assert.equal(res.state, 'deprecated');
  assert.equal(res.replacement, '@new/pkg');
  assert.ok(!a.BLOCKING.has(res.state), 'a deprecated package still installs and still works');
});

test('pypi: yanked, including when every file is yanked individually', async () => {
  const byRelease = await a.checkPypi({ version: '1.0.0' }, 'pkg', {
    get: fakeGet({ '/pkg/1.0.0/json': ok({ info: { yanked: true, yanked_reason: 'broken wheel' }, urls: [] }) }),
  });
  assert.equal(byRelease.state, 'yanked');
  assert.match(byRelease.detail, /broken wheel/);

  const byFiles = await a.checkPypi({ version: '2.0.0' }, 'pkg', {
    get: fakeGet({ '/pkg/2.0.0/json': ok({ info: {}, urls: [{ yanked: true }, { yanked: true }] }) }),
  });
  assert.equal(byFiles.state, 'yanked');
});

test('pypi: a release with some files live is not yanked', async () => {
  const res = await a.checkPypi({ version: '2.0.0' }, 'pkg', {
    get: fakeGet({ '/pkg/2.0.0/json': ok({ info: {}, urls: [{ yanked: true }, { yanked: false }] }) }),
  });
  assert.equal(res.state, 'present');
});

test('successorFrom: only a package-shaped token, only after a handover word', () => {
  assert.equal(a.successorFrom('Renamed to @donmai/mcp-server. See https://donmai.dev/docs/migration.'), '@donmai/mcp-server');
  assert.equal(a.successorFrom('replaced by server-fetch'), 'server-fetch');
  // Confident nonsense this used to print as advice:
  assert.equal(a.successorFrom('This package is deprecated. Use the remote MCP server at mcp.neon.tech instead.'), null);
  assert.equal(a.successorFrom("Deprecated: use CircleCI's hosted MCP server or CircleCI CLI MCP instead."), null);
  assert.equal(a.successorFrom('Package no longer supported. Contact Support at https://www.npmjs.com/support for more info.'), null);
  assert.equal(a.successorFrom(''), null);
  assert.equal(a.successorFrom(null), null);
});

test('repoSlug: the same repository written five ways is one identity', () => {
  const want = 'owner/repo';
  assert.equal(a.repoSlug('https://github.com/owner/repo'), want);
  assert.equal(a.repoSlug('https://github.com/Owner/Repo.git'), want);
  assert.equal(a.repoSlug('git+ssh://git@github.com/owner/repo.git'), want);
  assert.equal(a.repoSlug('https://github.com/owner/repo/tree/main/packages/x'), want);
  assert.equal(a.repoSlug('https://github.com/owner/repo#readme'), want);
  assert.equal(a.repoSlug('https://gitlab.com/owner/repo'), null);
  assert.equal(a.repoSlug(null), null);
});

test('checkRepo: GitHub follows renames, so a different full_name is a move', async () => {
  const moved = await a.checkRepo({ source_url: 'https://github.com/old/name' }, {
    get: fakeGet({ '/repos/old/name': ok({ full_name: 'new/name' }) }),
  });
  assert.equal(moved.state, 'relocated');
  assert.equal(moved.moved_to, 'new/name');

  const same = await a.checkRepo({ source_url: 'https://github.com/o/r' }, {
    get: fakeGet({ '/repos/o/r': ok({ full_name: 'o/r' }) }),
  });
  assert.equal(same.state, 'present');

  const archived = await a.checkRepo({ source_url: 'https://github.com/o/r' }, {
    get: fakeGet({ '/repos/o/r': ok({ full_name: 'o/r', archived: true }) }),
  });
  assert.equal(archived.state, 'archived');

  const gone = await a.checkRepo({ source_url: 'https://github.com/o/r' }, { get: fakeGet({}) });
  assert.equal(gone.state, 'repo-gone');

  const outage = await a.checkRepo({ source_url: 'https://github.com/o/r' }, { get: fakeGet({ '/repos/o/r': down }) });
  assert.equal(outage.state, 'unknown');
});

test('checkEntry: a registry pointing somewhere else is an identity finding', async () => {
  const row = await a.checkEntry({
    name: 'x', install_cmd: 'npx -y pkg@1.0.0', version: '1.0.0',
    source_url: 'https://github.com/author/pkg',
  }, { repos: false }, {
    get: fakeGet({ '/pkg/1.0.0': ok({ version: '1.0.0', repository: { url: 'https://github.com/someone-else/pkg' } }) }),
  });
  assert.equal(row.availability.state, 'present');
  assert.equal(row.identity.state, 'relocated');
  assert.match(row.identity.detail, /someone-else\/pkg/);
});

test('checkEntry: docker entries defer to docker-drift rather than answering twice', async () => {
  const row = await a.checkEntry({
    name: 'img', install_cmd: 'docker run -i --rm ghcr.io/o/r@sha256:' + 'a'.repeat(64),
  }, { repos: false }, { get: fakeGet({}) });
  assert.equal(row.availability.state, 'unknown');
  assert.match(row.availability.detail, /docker-drift/);
});

test('BLOCKING is exactly the set that means "there is nothing to install"', () => {
  assert.deepEqual([...a.BLOCKING].sort(), ['gone', 'version-gone', 'yanked']);
  assert.ok(!a.BLOCKING.has('deprecated'));
  assert.ok(!a.BLOCKING.has('unknown'));
});

test('repoSlug is anchored: github.com inside someone else\'s URL is not a match', () => {
  // An unanchored `github\.com[:/]+…` matched anywhere in a string, so
  // `https://evil.example/github.com/acme/server` produced the slug
  // `acme/server`. A URL in a DB entry could then borrow another project's
  // identity in every check that compares repositories.
  assert.equal(a.repoSlug('https://evil.example/github.com/acme/server'), null);
  assert.equal(a.repoSlug('https://github.com.evil.example/acme/server'), null);
  assert.equal(a.repoSlug('https://github.com/acme/server'), 'acme/server');
  assert.equal(a.repoSlug('git+ssh://git@github.com/acme/server.git'), 'acme/server');
  assert.equal(a.repoSlug('git@github.com:acme/server.git'), 'acme/server');
});
