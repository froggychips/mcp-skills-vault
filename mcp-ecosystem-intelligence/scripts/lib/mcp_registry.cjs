'use strict';
/**
 * The official MCP Registry, as an identity feed.
 *
 * This repo is not a competing registry and should not try to be one. The
 * official registry (registry.modelcontextprotocol.io) answers a question this
 * DB cannot: **who published this, and were they entitled to that name.** Its
 * namespaces are ownership-verified — `io.github.<owner>/<name>` can only be
 * published by someone who authenticated as that GitHub account, and a
 * reverse-DNS namespace (`com.example/name`) requires control of the domain.
 *
 * That makes the right relationship a layering, not a rivalry:
 *
 *     official registry  →  who published it, under a name they proved they own
 *     mcp-vault          →  supply-chain evidence, policy, behaviour
 *
 * The check that earns its keep is the cross-reference. This DB has an entry
 * whose `source_url` is `jerhadf/linear-mcp-server` while npm's metadata for
 * the same package says `modelcontextprotocol/linear-server`; a third opinion
 * from an ownership-verified namespace is exactly what resolves that, and the
 * same comparison catches the case that matters — a package whose registry
 * listing belongs to somebody else entirely.
 *
 * Statuses are deliberately shaped so that *absence is not a finding*. Most
 * entries in this DB are not in the official registry, and "unlisted" says
 * nothing bad about a package: the registry is young and listing is opt-in.
 * Only a contradiction is a finding.
 *
 * API:
 *   searchServers(query, opts)        -> { ok, servers }
 *   findByPackage(eco, pkg, opts)     -> { ok, record, candidates }
 *   namespaceOwner(name)              -> { kind, owner } | null
 *   packagesOf(record)                -> [{ ecosystem, identifier, version }]
 *   identityFindings({ record, tool }) -> { state, findings, … }
 */

const { getJson } = require('./http.cjs');
const { githubSlug } = require('./repo_url.cjs');

const REGISTRY = 'https://registry.modelcontextprotocol.io';
const META_KEY = 'io.modelcontextprotocol.registry/official';
// The registry is a public index of published metadata; an hour-old answer is
// fine and keeps a 114-entry sweep to one round of requests.
const CACHE_TTL_MS = 60 * 60 * 1000;

// The registry's full-text search is slow for some queries — a scoped package
// name regularly takes longer than the 10s default, and with the default three
// retries that became 40 seconds of waiting to conclude "not listed". One
// generous attempt and one retry is the right shape for a feed whose answer is
// informational.
const SEARCH_TIMEOUT_MS = 30000;
const SEARCH_RETRIES    = 1;

/** `?search=` matches name and description, so the package name is a good query. */
async function searchServers(query, { get = getJson, limit = 20 } = {}) {
  const url = `${REGISTRY}/v0/servers?search=${encodeURIComponent(query)}&limit=${limit}`;
  const res = await get(url, {
    cacheTtlMs: CACHE_TTL_MS,
    timeoutMs:  SEARCH_TIMEOUT_MS,
    retries:    SEARCH_RETRIES,
    headers:    { Accept: 'application/json' },
  });
  if (!res.ok) return { ok: false, error: res.error || `HTTP ${res.status}`, servers: [] };
  const servers = Array.isArray(res.data && res.data.servers) ? res.data.servers : [];
  return { ok: true, servers, fromCache: Boolean(res.fromCache) };
}

/** The packages a registry record says it ships, normalised to our vocabulary. */
function packagesOf(record) {
  const list = (record && record.server && record.server.packages) || [];
  return list.map((p) => ({
    // The field was `registry_name` in the 2025-09 schema and `registryType`
    // in 2025-12. Both appear in live data today.
    ecosystem:  String(p.registryType || p.registry_name || '').toLowerCase() || null,
    identifier: p.identifier || p.name || null,
    version:    p.version || null,
    transport:  (p.transport && p.transport.type) || null,
  })).filter((p) => p.identifier);
}

function metaOf(record) {
  return (record && record._meta && record._meta[META_KEY]) || {};
}

/**
 * Find the registry record that ships a given package.
 *
 * Several versions of the same server are separate records, so the latest is
 * preferred (`isLatest`), falling back to the newest `publishedAt`. All the
 * matches are returned as well: two *different* servers claiming the same
 * package identifier is itself worth seeing.
 */
async function findByPackage(ecosystem, pkg, { get = getJson } = {}) {
  if (!pkg) return { ok: true, record: null, candidates: [] };
  const res = await searchServers(pkg, { get });
  if (!res.ok) return { ok: false, error: res.error, record: null, candidates: [] };

  const matches = res.servers.filter((row) =>
    packagesOf(row).some((p) => p.identifier === pkg && (!ecosystem || !p.ecosystem || p.ecosystem === ecosystem)));
  if (!matches.length) return { ok: true, record: null, candidates: [] };

  const latest = matches.find((row) => metaOf(row).isLatest)
    || matches.slice().sort((a, b) => String(metaOf(b).publishedAt || '').localeCompare(String(metaOf(a).publishedAt || '')))[0];

  // Distinct server names claiming the same package identifier.
  const names = new Set(matches.map((row) => row.server && row.server.name).filter(Boolean));
  return { ok: true, record: latest, candidates: [...names] };
}

/**
 * Who the namespace belongs to.
 *
 * `io.github.owner/name`  → that GitHub account (OAuth-verified at publish)
 * `com.example/name`      → that domain (DNS/HTTP-verified at publish)
 *
 * This is the only part of a registry listing that is *proved* rather than
 * self-reported, which is why it is the part worth comparing against.
 */
function namespaceOwner(name) {
  const ns = String(name || '').split('/')[0];
  if (!ns) return null;
  const gh = ns.match(/^io\.github\.(.+)$/i);
  if (gh) return { kind: 'github', owner: gh[1].toLowerCase() };
  const parts = ns.split('.');
  if (parts.length < 2) return null;
  // Reverse-DNS: com.example.sub → sub.example.com
  return { kind: 'domain', owner: parts.slice().reverse().join('.').toLowerCase() };
}

function repoSlug(url) {
  // One definition of what a repository URL names, anchored: lib/repo_url.cjs.
  const slug = githubSlug(url);
  if (!slug) return null;
  const [owner] = slug.split('/');
  return { owner, repo: slug };
}

/**
 * Compare a registry record with a DB entry.
 *
 * States:
 *   listed       found, and everything that can be compared agrees
 *   unlisted     no record ships this package. Not a finding: listing is
 *                opt-in and the registry is young.
 *   contradicted something disagrees — the repository, or the verified
 *                namespace owner. Deliberately not called "mismatch": that
 *                word blocks trust elsewhere, and a fork or a monorepo move
 *                produces this legitimately. It is a finding to read, not a
 *                verdict.
 *   withdrawn    the registry says this server was deleted or deprecated
 *
 * `findings` is always specific enough to act on, and never says "mismatch"
 * without naming both sides.
 */
function identityFindings({ record, tool }) {
  if (!record) {
    return { state: 'unlisted', findings: [], server_id: null };
  }
  const server = record.server || {};
  const meta   = metaOf(record);
  const findings = [];

  const serverId = server.name || null;
  const ns       = namespaceOwner(serverId);
  const ours     = repoSlug(tool && tool.source_url);
  const theirs   = repoSlug(server.repository && server.repository.url);

  // The registry's own record of where the code lives.
  if (ours && theirs && ours.repo !== theirs.repo) {
    findings.push(`the registry lists this server's repository as ${server.repository.url}, the entry records ${tool.source_url}`);
  }
  // The proved part: a `io.github.<owner>` namespace and a repo under a
  // different owner means the publisher is not who the entry points at.
  if (ns && ns.kind === 'github' && ours && ns.owner !== ours.owner) {
    findings.push(`published under the verified namespace ${serverId} (GitHub account "${ns.owner}"), while the entry's source is owned by "${ours.owner}"`);
  }

  const pkgs = packagesOf(record);
  const status = String(meta.status || '').toLowerCase();

  if (status && status !== 'active') {
    findings.push(`the registry marks this server "${status}"${meta.statusChangedAt ? ` since ${String(meta.statusChangedAt).slice(0, 10)}` : ''}`);
    return { state: 'withdrawn', findings, server_id: serverId, packages: pkgs, namespace: ns };
  }

  return {
    state:     findings.length ? 'contradicted' : 'listed',
    findings,
    server_id: serverId,
    namespace: ns,
    packages:  pkgs,
    repository: (server.repository && server.repository.url) || null,
    registry_version: server.version || null,
    is_latest: meta.isLatest === true,
  };
}

module.exports = {
  REGISTRY, META_KEY,
  searchServers, findByPackage, packagesOf, namespaceOwner, identityFindings, repoSlug, metaOf,
};
