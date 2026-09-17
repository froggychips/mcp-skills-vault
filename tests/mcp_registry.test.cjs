'use strict';
/**
 * The official registry as an identity feed.
 *
 * The property that matters most here is that **absence is not a finding**.
 * Most of this DB is not listed in the official registry, and a check that
 * treated "unlisted" as suspicious would flag 90% of the database and then be
 * ignored — which is how a real finding gets buried.
 *
 * The second property: what the registry *proves* is the namespace. Everything
 * else in a listing is self-reported, so `io.github.<owner>` disagreeing with
 * the entry's repository owner is worth more than the listing's repository
 * field disagreeing.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const r = require('../mcp-ecosystem-intelligence/scripts/lib/mcp_registry.cjs');

const record = ({ name, repo, packages = [], status = 'active', isLatest = true } = {}) => ({
  server: {
    name,
    version: '1.0.0',
    ...(repo ? { repository: { url: repo, source: 'github' } } : {}),
    packages,
  },
  _meta: { [r.META_KEY]: { status, isLatest, publishedAt: '2026-09-01T00:00:00Z' } },
});

test('namespaceOwner: github namespaces name an account, domains reverse', () => {
  assert.deepEqual(r.namespaceOwner('io.github.microsoft/playwright-mcp'), { kind: 'github', owner: 'microsoft' });
  assert.deepEqual(r.namespaceOwner('io.github.Digital-Defiance/x'), { kind: 'github', owner: 'digital-defiance' });
  assert.deepEqual(r.namespaceOwner('com.pulsemcp/remote-filesystem'), { kind: 'domain', owner: 'pulsemcp.com' });
  assert.deepEqual(r.namespaceOwner('ac.inference.sh/mcp'), { kind: 'domain', owner: 'sh.inference.ac' });
  assert.equal(r.namespaceOwner('nodots'), null);
  assert.equal(r.namespaceOwner(''), null);
  assert.equal(r.namespaceOwner(null), null);
});

test('packagesOf reads both schema generations', () => {
  // 2025-12 uses registryType, 2025-09 used registry_name; both are live.
  const now = r.packagesOf(record({ packages: [{ registryType: 'npm', identifier: 'pkg', version: '1.0.0' }] }));
  const then = r.packagesOf(record({ packages: [{ registry_name: 'NPM', name: 'pkg', version: '1.0.0' }] }));
  assert.deepEqual(now.map((p) => [p.ecosystem, p.identifier]), [['npm', 'pkg']]);
  assert.deepEqual(then.map((p) => [p.ecosystem, p.identifier]), [['npm', 'pkg']]);
  // A package entry with no identifier is dropped rather than carried as null.
  assert.deepEqual(r.packagesOf(record({ packages: [{ registryType: 'npm' }] })), []);
});

test('unlisted is a state, not a finding', () => {
  const out = r.identityFindings({ record: null, tool: { source_url: 'https://github.com/o/r' } });
  assert.equal(out.state, 'unlisted');
  assert.deepEqual(out.findings, []);
});

test('a listing that agrees is "listed", with the server id carried through', () => {
  const out = r.identityFindings({
    record: record({ name: 'io.github.microsoft/playwright-mcp', repo: 'https://github.com/microsoft/playwright-mcp' }),
    tool:   { source_url: 'https://github.com/microsoft/playwright-mcp' },
  });
  assert.equal(out.state, 'listed');
  assert.deepEqual(out.findings, []);
  assert.equal(out.server_id, 'io.github.microsoft/playwright-mcp');
  assert.equal(out.namespace.owner, 'microsoft');
});

test('a verified namespace under a different owner is the finding worth having', () => {
  const out = r.identityFindings({
    record: record({ name: 'io.github.someone-else/pkg', repo: 'https://github.com/someone-else/pkg' }),
    tool:   { source_url: 'https://github.com/original-author/pkg' },
  });
  assert.equal(out.state, 'contradicted');
  assert.equal(out.findings.length, 2, 'both the repository and the verified namespace disagree');
  assert.match(out.findings.join(' '), /verified namespace/);
  assert.match(out.findings.join(' '), /someone-else/);
});

test('a repository disagreement alone is reported without overstating it', () => {
  // Same owner, different repo — a monorepo move looks like this, and so does
  // a hijack. It is reported, and it is not called a mismatch.
  const out = r.identityFindings({
    record: record({ name: 'io.github.acme/server', repo: 'https://github.com/acme/monorepo' }),
    tool:   { source_url: 'https://github.com/acme/server' },
  });
  assert.equal(out.state, 'contradicted');
  assert.equal(out.findings.length, 1);
  assert.match(out.findings[0], /acme\/monorepo/);
});

test('a withdrawn listing says so instead of being read as agreement', () => {
  const out = r.identityFindings({
    record: record({ name: 'io.github.o/r', repo: 'https://github.com/o/r', status: 'deleted' }),
    tool:   { source_url: 'https://github.com/o/r' },
  });
  assert.equal(out.state, 'withdrawn');
  assert.match(out.findings[0], /deleted/);
});

test('a case difference in a repository URL is not a disagreement', () => {
  const out = r.identityFindings({
    record: record({ name: 'io.github.Acme/Server', repo: 'https://github.com/Acme/Server.git' }),
    tool:   { source_url: 'https://github.com/acme/server' },
  });
  assert.equal(out.state, 'listed');
});

test('findByPackage: a feed that did not answer is not "not listed"', async () => {
  const down = async () => ({ ok: false, status: null, error: 'timeout after 30000ms' });
  const res = await r.findByPackage('npm', 'pkg', { get: down });
  assert.equal(res.ok, false, 'the caller must be able to tell an outage from an absence');
  assert.equal(res.record, null);
});

test('findByPackage: prefers the latest record and reports every claimant', async () => {
  const servers = [
    record({ name: 'io.github.a/pkg', packages: [{ registryType: 'npm', identifier: 'pkg', version: '1.0.0' }], isLatest: false }),
    record({ name: 'io.github.a/pkg', packages: [{ registryType: 'npm', identifier: 'pkg', version: '2.0.0' }], isLatest: true }),
    record({ name: 'io.github.b/pkg', packages: [{ registryType: 'npm', identifier: 'pkg', version: '9.9.9' }], isLatest: false }),
  ];
  const get = async () => ({ ok: true, status: 200, data: { servers } });
  const res = await r.findByPackage('npm', 'pkg', { get });
  assert.equal(res.ok, true);
  assert.equal(res.record.server.name, 'io.github.a/pkg');
  assert.equal(res.record.server.packages[0].version, '2.0.0');
  // Two different verified namespaces shipping the same package identifier is
  // exactly the thing a reader needs to see.
  assert.deepEqual(res.candidates.sort(), ['io.github.a/pkg', 'io.github.b/pkg']);
});

test('findByPackage: a search hit that ships a different package is not a match', async () => {
  const get = async () => ({ ok: true, status: 200, data: { servers: [
    record({ name: 'io.github.x/other', packages: [{ registryType: 'npm', identifier: 'something-else' }] }),
  ] } });
  const res = await r.findByPackage('npm', 'pkg', { get });
  assert.equal(res.record, null);
  assert.deepEqual(res.candidates, []);
});

test('findByPackage: the ecosystem has to agree too', async () => {
  const get = async () => ({ ok: true, status: 200, data: { servers: [
    record({ name: 'io.github.x/y', packages: [{ registryType: 'pypi', identifier: 'pkg' }] }),
  ] } });
  assert.equal((await r.findByPackage('npm', 'pkg', { get })).record, null);
  assert.ok((await r.findByPackage('pypi', 'pkg', { get })).record);
});
