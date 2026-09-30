'use strict';
/**
 * A saved copy of the official MCP Registry, and what it says about this DB.
 *
 * The registry's aggregator guidance is to scrape it "on a regular but
 * infrequent basis" and persist the result, and to keep each server's
 * `status` current — metadata is immutable except for that field, which moves
 * to `deprecated` or `deleted` (the latter usually a moderation action: spam,
 * malware). Both are worth knowing about an entry this DB recommends.
 *
 * The network part is one function, `fetchSnapshot`, run only by an explicit
 * `registry-ingest --fetch`. Everything else reads the saved file, so the
 * report is offline and repeatable: the same snapshot and the same DB give
 * the same answer, and the snapshot is a file a reviewer can open.
 *
 * Nothing here changes the DB. Two outputs, both for a human:
 *   - DB entries whose server the registry now marks deprecated or deleted —
 *     the latest version, or the exact version this DB pins;
 *   - servers the registry lists that the DB does not have — discovery
 *     candidates, fed to `discover --source registry-snapshot`.
 *
 * API:
 *   fetchSnapshot({ get, base, maxPages, now })  -> { ok, snapshot } | { ok:false, error }
 *   slimRecord(row)                              -> snapshot record | null
 *   latestByServer(snapshot)                     -> Map<name, record>
 *   ingestReport(db, snapshot)                   -> report (mcp-vault/registry-ingest@1)
 *   snapshotAsRegistryPage(snapshot)             -> { servers: [{ server }] } — discover's input shape
 */

const { getJson } = require('./http.cjs');
const { githubSlug } = require('./repo_url.cjs');
const { toTypedEntry } = require('./entry_model.cjs');
const { META_KEY: OFFICIAL } = require('./mcp_registry.cjs');

const REGISTRY  = 'https://registry.modelcontextprotocol.io';
// The registry caps `limit` at 100; a larger value is refused, not clamped.
const PAGE_SIZE = 100;
// Every version is a record, so a full listing runs to hundreds of pages and
// grows; the cap exists to stop a cursor that never ends, not to trim.
const DEFAULT_MAX_PAGES = 5000;
const WITHDRAWN = new Set(['deprecated', 'deleted']);

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** One registry row, reduced to what the report and discovery read. */
function slimRecord(row) {
  const s = row && row.server;
  if (!s || typeof s.name !== 'string' || typeof s.version !== 'string') return null;
  const m = (row._meta && row._meta[OFFICIAL]) || {};
  const packages = (Array.isArray(s.packages) ? s.packages : []).map((p) => ({
    // `registry_name` was the 2025-09 spelling; both appear in live data.
    registryType: String(p.registryType || p.registry_name || '').toLowerCase() || null,
    identifier:   p.identifier || p.name || null,
    version:      p.version || null,
  })).filter((p) => p.identifier);
  return {
    name:        s.name,
    version:     s.version,
    title:       s.title || null,
    description: s.description || null,
    repository:  (s.repository && s.repository.url) || null,
    packages,
    remotes:     Array.isArray(s.remotes) ? s.remotes.length : 0,
    status:      m.status || 'active',
    statusMessage:   m.statusMessage || null,
    statusChangedAt: m.statusChangedAt || null,
    publishedAt: m.publishedAt || null,
    updatedAt:   m.updatedAt || null,
    isLatest:    m.isLatest === true,
  };
}

/**
 * Page through `/v0.1/servers` with `include_deleted=true` — the default
 * listing hides deleted servers, and a deleted server is the finding that
 * matters most.
 *
 * All or nothing: a page that fails, or a cap reached before the last page,
 * returns `ok: false`. A partial snapshot would under-report candidates and
 * could miss a withdrawal, while looking complete.
 */
async function fetchSnapshot({
  get = getJson, base = REGISTRY, maxPages = DEFAULT_MAX_PAGES, latestOnly = false,
  now = () => new Date().toISOString(), onPage = null,
} = {}) {
  const records = [];
  let cursor = null;
  let pages = 0;
  for (;;) {
    if (pages >= maxPages) return { ok: false, error: `stopped at the page cap (${maxPages}) before the last page` };
    const url = `${base}/v0.1/servers?limit=${PAGE_SIZE}&include_deleted=true${latestOnly ? '&version=latest' : ''}`
      + `${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
    const res = await get(url, { headers: { Accept: 'application/json' }, timeoutMs: 30000, retries: 2 });
    pages++;
    if (!res || !res.ok || !res.data || !Array.isArray(res.data.servers)) {
      return { ok: false, error: `page ${pages} failed: ${(res && (res.error || res.status)) || 'no response'}` };
    }
    for (const row of res.data.servers) {
      const r = slimRecord(row);
      if (r) records.push(r);
    }
    if (onPage) onPage(pages, records.length);
    const next = res.data.metadata && res.data.metadata.nextCursor;
    if (!next) break;
    if (next === cursor) return { ok: false, error: `the registry returned the same cursor twice (${next})` };
    cursor = next;
  }
  // Keyed on (name, version): a record seen twice across pages is one record.
  const byKey = new Map(records.map((r) => [`${r.name}\u0000${r.version}`, r]));
  const servers = [...byKey.values()].sort((a, b) => cmp(a.name, b.name) || cmp(a.version, b.version));
  return {
    ok: true,
    snapshot: {
      schema:     'mcp-vault/registry-snapshot@1',
      source:     base,
      api:        'v0.1',
      // `latest`: one record per server, so a deleted *pinned* version that is
      // not the latest cannot be seen. The report says so.
      scope:      latestOnly ? 'latest' : 'all-versions',
      fetched_at: now(),
      pages,
      count:      servers.length,
      servers,
    },
  };
}

/** Validate the shape of a snapshot read from disk. Throws with a reason. */
function checkSnapshot(snap) {
  if (!snap || snap.schema !== 'mcp-vault/registry-snapshot@1') throw new Error('not an mcp-vault/registry-snapshot@1 file');
  if (!Array.isArray(snap.servers)) throw new Error('snapshot has no servers array');
  return snap;
}

/**
 * The record that stands for each server: the one flagged `isLatest`, else
 * the newest `publishedAt`, else the highest version string. `isLatest` is
 * per version, so a server whose latest version was deleted is represented by
 * that deleted version — which is the point.
 */
function latestByServer(snapshot) {
  const groups = new Map();
  for (const r of snapshot.servers) {
    if (!groups.has(r.name)) groups.set(r.name, []);
    groups.get(r.name).push(r);
  }
  const out = new Map();
  for (const [name, rows] of groups) {
    const flagged = rows.filter((r) => r.isLatest);
    const pool = flagged.length ? flagged : rows;
    const pick = [...pool].sort((a, b) =>
      cmp(String(b.publishedAt || ''), String(a.publishedAt || '')) || cmp(b.version, a.version))[0];
    out.set(name, pick);
  }
  return out;
}

/** What an entry installs, in the registry's vocabulary: [{ registryType, identifier, version }]. */
function entryPackage(tool) {
  const typed = toTypedEntry(tool);
  const a = (typed && typed.artifact) || {};
  if ((a.ecosystem === 'npm' || a.ecosystem === 'pypi') && a.package) {
    return { registryType: a.ecosystem, identifier: a.package, version: a.version || null };
  }
  if (a.ecosystem === 'oci' && a.image) return { registryType: 'oci', identifier: a.image, version: null };
  return null;
}

/** `ghcr.io/o/r:1.0` and `docker.io/o/r@sha256:…` → `ghcr.io/o/r`, `o/r`. */
function ociRepo(id) {
  return String(id || '').replace(/@sha256:[a-f0-9]+$/, '').replace(/:[^:/]+$/, '')
    .replace(/^(?:docker\.io|index\.docker\.io)\//, '').replace(/^library\//, '').toLowerCase();
}

function samePackage(ours, theirs) {
  if (!ours || !theirs || !theirs.identifier) return false;
  if (theirs.registryType && theirs.registryType !== ours.registryType) return false;
  if (ours.registryType === 'oci') return ociRepo(ours.identifier) === ociRepo(theirs.identifier);
  if (ours.registryType === 'pypi') return ours.identifier.toLowerCase().replace(/[-_.]+/g, '-') === theirs.identifier.toLowerCase().replace(/[-_.]+/g, '-');
  return ours.identifier === theirs.identifier;
}

const statusOf = (r) => (r ? {
  version: r.version, status: r.status, statusMessage: r.statusMessage, statusChangedAt: r.statusChangedAt,
} : null);

/**
 * Compare a DB with a snapshot.
 *
 * An entry is matched to a server by the registry id `mcp-vault identity`
 * recorded (`trust_evidence.dimensions.registry.server_id`) — the proved
 * link — or else by the package it installs. The report says which, because a
 * package match is weaker: two servers can claim one package.
 */
function ingestReport(db, snapshot) {
  checkSnapshot(snapshot);
  const latest = latestByServer(snapshot);
  const byServer = new Map();
  for (const r of snapshot.servers) {
    if (!byServer.has(r.name)) byServer.set(r.name, []);
    byServer.get(r.name).push(r);
  }

  const tools = [...((db && db.tools) || [])].sort((a, b) => cmp(a.name, b.name));
  const claimedServers = new Set();
  const matched = [];
  const withdrawn = [];

  for (const t of tools) {
    const reg = t.trust_evidence && t.trust_evidence.dimensions && t.trust_evidence.dimensions.registry;
    const pkg = entryPackage(t);
    let names = [];
    let by = null;
    if (reg && reg.server_id && byServer.has(reg.server_id)) {
      names = [reg.server_id];
      by = 'server_id';
    } else if (pkg) {
      names = [...byServer.keys()].filter((n) => byServer.get(n).some((r) => r.packages.some((p) => samePackage(pkg, p))));
      by = names.length ? 'package' : null;
    }
    if (!names.length) continue;
    for (const n of names.sort()) {
      claimedServers.add(n);
      const head = latest.get(n);
      // The version this DB pins, when the registry lists that exact version.
      const pinned = pkg && pkg.version
        ? byServer.get(n).find((r) => r.packages.some((p) => samePackage(pkg, p) && p.version === pkg.version)) || null
        : null;
      const row = { name: t.name, server_id: n, matched_by: by, latest: statusOf(head), pinned: statusOf(pinned) };
      matched.push(row);
      if (WITHDRAWN.has(head.status) || (pinned && WITHDRAWN.has(pinned.status))) withdrawn.push(row);
    }
  }

  // Candidates: listed, active, installable as a package, and not already
  // matched to an entry by name, package or repository.
  const repos = new Set(tools.map((t) => githubSlug(t.source_url)).filter(Boolean));
  const pkgs = tools.map(entryPackage).filter(Boolean);
  const newServers = [];
  for (const [n, r] of [...latest].sort((a, b) => cmp(a[0], b[0]))) {
    if (claimedServers.has(n) || r.status !== 'active' || !r.packages.length) continue;
    if (r.packages.some((p) => pkgs.some((q) => samePackage(q, p)))) continue;
    const slug = githubSlug(r.repository);
    if (slug && repos.has(slug)) continue;
    newServers.push({ name: n, version: r.version, package: r.packages[0], repository: r.repository });
  }

  return {
    schema:      'mcp-vault/registry-ingest@1',
    snapshot:    {
      source: snapshot.source || null, fetched_at: snapshot.fetched_at || null,
      scope: snapshot.scope || null, count: snapshot.servers.length,
    },
    db_entries:  tools.length,
    matched:     matched.length,
    withdrawn,
    new_servers_count: newServers.length,
    new_servers: newServers,
  };
}

/**
 * The snapshot in the shape `discover.cjs parseRegistryPage` reads — latest,
 * active versions only: a candidate that has already been withdrawn is not a
 * candidate.
 */
function snapshotAsRegistryPage(snapshot) {
  checkSnapshot(snapshot);
  const servers = [];
  for (const [, r] of [...latestByServer(snapshot)].sort((a, b) => cmp(a[0], b[0]))) {
    if (r.status !== 'active') continue;
    servers.push({
      server: {
        name:        r.name,
        title:       r.title || undefined,
        description: r.description || undefined,
        version:     r.version,
        repository:  r.repository ? { url: r.repository } : undefined,
        packages:    r.packages,
      },
    });
  }
  return { servers, metadata: {} };
}

module.exports = {
  REGISTRY, WITHDRAWN, PAGE_SIZE, DEFAULT_MAX_PAGES,
  fetchSnapshot, slimRecord, checkSnapshot, latestByServer, entryPackage, samePackage, ociRepo,
  ingestReport, snapshotAsRegistryPage,
};
