'use strict';
/**
 * The vault, served as a sub-registry of the official MCP Registry.
 *
 * A sub-registry is an aggregator that also implements the registry's own
 * read API (docs/reference/api/openapi.yaml in modelcontextprotocol/registry),
 * so a host that already speaks it — VS Code's `McpGalleryServiceUrl`, the
 * official CLI, ToolHive — can read this DB without learning a new format. The
 * registry spec reserves `_meta` for exactly this: a sub-registry puts its own
 * data under a reverse-DNS key it controls, and leaves the rest of server.json
 * alone.
 *
 * What goes under that key is the part the official registry cannot say:
 * the tier, the pinned version and its integrity, and the date each piece of
 * evidence was established. Nothing here re-derives a verdict — the tier comes
 * from lib/tiers.cjs, the artifact from lib/entry_model.cjs.
 *
 * Three decisions worth knowing before changing anything:
 *
 *   1. **Deterministic, by construction.** No clock. The tier is a function of
 *      the date (claims age out), so it is computed *as of* a date that comes
 *      from the data — the newest `checked_at` in the DB or the eval snapshot —
 *      and that date is written into every record. Same DB, same bytes: the
 *      export can be signed and diffed.
 *
 *   2. **Names are only borrowed when they were proved.** A server.json `name`
 *      is a namespace claim. An entry the official registry lists (recorded by
 *      `mcp-vault identity` as `registry.server_id`) keeps that name, so a
 *      host deduplicates it against the official listing. Every other entry is
 *      published under *our* namespace, `xyz.froggychips.mcp/<slug>` — deriving
 *      `io.github.<owner>/…` from a source URL would print a verified-looking
 *      namespace nobody verified.
 *
 *   3. **Fail closed.** An entry with nothing pinned to install (a git source,
 *      no version, an image without a digest) or a Deprecated tier is not
 *      exported: a host that ignores `_meta` would offer it as installable. The
 *      skip list, with reasons, is in the export manifest.
 *
 * API:
 *   NAMESPACE, META_KEY, SCHEMA_URL
 *   asOfDate(db, evals)                       -> 'YYYY-MM-DD' | null
 *   serverName(tool)                          -> { name, source }
 *   packageOf(tool)                           -> { package, pinned } | { skip }
 *   toServerJson(tool, { smoke, asOf, … })    -> { server } | { skip }
 *   buildExport(db, evals, { asOf, … })       -> { files: Map, manifest }
 */

const crypto = require('crypto');
const { toTypedEntry, artifactId } = require('./entry_model.cjs');
const { dockerImageRef, isExactVersion } = require('./install_cmd.cjs');
const { classifyEntry, evalIndex, TIER_ORDER } = require('./tiers.cjs');
const { githubRepoUrl } = require('./repo_url.cjs');

// Reverse-DNS of the domain the site is served from (mcp.froggychips.xyz), as
// the registry spec asks for `_meta` keys and extension paths. The domain, not
// `io.github.froggychips`: it is where these files live, so whoever controls
// the key controls the bytes behind it.
const NAMESPACE  = 'xyz.froggychips.mcp';
const META_KEY   = `${NAMESPACE}/vault`;
const SCHEMA_URL = 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json';
const API_PREFIX = 'v0.1';
const SITE       = 'https://mcp.froggychips.xyz';
const REPO       = 'https://github.com/froggychips/mcp-skills-vault';

// server.json constraints (2025-12-11 schema).
const NAME_RE        = /^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/;
const DESCRIPTION_MAX = 100;

// docker flags that the host adds itself when it runs an `oci` package, or
// that are ours to pass differently (`-e` becomes environmentVariables).
const DOCKER_IMPLIED = new Set(['-i', '--interactive', '--rm']);

/**
 * The date the export speaks for: the newest evidence date anywhere in the
 * data. A function of the files, not of the clock — see decision 1.
 */
function asOfDate(db, evals) {
  let max = '';
  const see = (d) => {
    const s = String(d || '').slice(0, 10);
    if (/^\d{4}-\d{2}-\d{2}$/.test(s) && s > max) max = s;
  };
  for (const t of (db && db.tools) || []) {
    const dims = (t.trust_evidence && t.trust_evidence.dimensions) || {};
    for (const v of Object.values(dims)) see(v && v.checked_at);
  }
  for (const r of (evals && evals.results) || []) see(r && r.checked_at);
  return max || null;
}

/** `@scope/pkg` → `scope.pkg`; anything outside the name alphabet → `-`. */
function slug(name) {
  return String(name || '')
    .replace(/^@/, '')
    .replace(/\//g, '.')
    .replace(/[^a-zA-Z0-9._-]/g, '-');
}

/** Which name this entry is published under, and why — decision 2. */
function serverName(tool) {
  const reg = tool && tool.trust_evidence && tool.trust_evidence.dimensions
    && tool.trust_evidence.dimensions.registry;
  const id = reg && reg.status === 'listed' ? reg.server_id : null;
  if (typeof id === 'string' && NAME_RE.test(id) && id.length <= 200) {
    return { name: id, source: 'official-registry' };
  }
  return { name: `${NAMESPACE}/${slug(tool && tool.name)}`, source: 'vault' };
}

/** The docker flags between `run` and the image, as server.json arguments. */
function dockerArguments(cmd, ref) {
  const tokens = String(cmd).trim().split(/\s+/).slice(2);
  const end = tokens.indexOf(ref);
  if (end === -1) return null;
  const flags = tokens.slice(0, end);
  const runtimeArguments = [];
  const environmentVariables = [];
  for (let i = 0; i < flags.length; i++) {
    const f = flags[i];
    if (DOCKER_IMPLIED.has(f)) continue;
    if (!f.startsWith('-')) return null;                     // a shape we do not claim to understand
    if (f === '-e' || f === '--env') {
      const v = flags[++i];
      // `-e NAME=value` would publish a value; only a bare name is a variable
      // for the user to supply.
      if (!v || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) return null;
      environmentVariables.push({ name: v, isRequired: true, isSecret: /TOKEN|KEY|SECRET|PASSWORD/i.test(v) });
      continue;
    }
    const eq = f.indexOf('=');
    if (eq !== -1) {
      runtimeArguments.push({ type: 'named', name: f.slice(0, eq), value: f.slice(eq + 1) });
    } else if (flags[i + 1] && !flags[i + 1].startsWith('-')) {
      runtimeArguments.push({ type: 'named', name: f, value: flags[++i] });
    } else {
      runtimeArguments.push({ type: 'named', name: f });
    }
  }
  return { runtimeArguments, environmentVariables };
}

/**
 * The server.json `packages[0]` for an entry, or why there is none.
 *
 * `pinned` is our record of what the gate checked — ecosystem, identifier,
 * version, integrity, artifact id — for `_meta`. `fileSha256` is not used:
 * the spec reserves it for a SHA-256 of the downloaded file, and an npm
 * `sha512-…` integrity is a different claim about a different encoding.
 */
function packageOf(tool) {
  const typed = toTypedEntry(tool);
  if (!typed) return { skip: 'no install command' };
  const a = typed.artifact || {};
  const pinned = (identifier, version) => ({
    ecosystem:   a.ecosystem,
    identifier,
    version:     version || null,
    integrity:   tool.pkg_integrity || null,
    artifact_id: artifactId(a),
  });

  if (a.ecosystem === 'npm' || a.ecosystem === 'pypi') {
    const runner = a.ecosystem === 'npm' ? 'npx' : 'uvx';
    if (!a.package) return { skip: 'launch command could not be parsed' };
    if (!isExactVersion(runner, a.version)) return { skip: `no exact version pinned (${a.version || 'none'})` };
    const pkg = {
      registryType:    a.ecosystem,
      registryBaseUrl: a.ecosystem === 'npm' ? 'https://registry.npmjs.org' : 'https://pypi.org',
      identifier:      a.package,
      version:         a.version,
      runtimeHint:     runner,
      transport:       { type: 'stdio' },
    };
    // Arguments after the package are positional. A `<placeholder>` is a value
    // the user supplies (the filesystem server's root), not a literal.
    const args = typed.launch.args || [];
    const at = args.findIndex((t) => t === a.package || t.startsWith(`${a.package}@`) || t.startsWith(`${a.package}==`));
    const rest = at === -1 ? [] : args.slice(at + 1);
    if (rest.length) {
      const packageArguments = [];
      for (const r of rest) {
        const ph = r.match(/^<([A-Za-z0-9_-]+)>$/);
        if (ph) packageArguments.push({ type: 'positional', valueHint: ph[1], isRequired: true });
        else if (!r.startsWith('-')) packageArguments.push({ type: 'positional', value: r });
        else return { skip: `launch arguments are not a shape the export understands: ${r}` };
      }
      pkg.packageArguments = packageArguments;
    }
    return { package: pkg, pinned: pinned(a.package, a.version) };
  }

  if (a.ecosystem === 'oci') {
    if (!a.image || !a.digest) return { skip: 'container image is not pinned by digest' };
    const ref = dockerImageRef(tool.install_cmd);
    const parsed = ref && dockerArguments(tool.install_cmd, ref);
    if (!parsed) return { skip: 'docker flags could not be translated' };
    const pkg = {
      registryType: 'oci',
      // The identifier is `registry/namespace/repository:tag`, and "the tag
      // can also be specified as a digest" (package-types.mdx). A digest is
      // the only honest pin; no `version`, which for oci would be a tag.
      identifier:   ociIdentifier(a.image, a.digest),
      runtimeHint:  'docker',
      transport:    { type: 'stdio' },
    };
    if (parsed.runtimeArguments.length) pkg.runtimeArguments = parsed.runtimeArguments;
    if (parsed.environmentVariables.length) pkg.environmentVariables = parsed.environmentVariables;
    return { package: pkg, pinned: pinned(pkg.identifier, null) };
  }

  if (a.ecosystem === 'git') return { skip: 'source install: no released artifact to pin' };
  return { skip: `ecosystem not exportable: ${a.ecosystem || 'unknown'}` };
}

/**
 * The server `version`. For npm/PyPI it is the pinned package version. An
 * image has none that means anything (`latest`, `latest@2026-05-09`), and
 * `latest` is also the API's alias for "newest" — a server literally versioned
 * `latest` would make `/versions/latest` ambiguous. So an image is versioned by
 * its digest.
 */
function serverVersion(tool, pkg) {
  if (pkg.registryType !== 'oci') return pkg.version;
  const v = tool.version;
  if (typeof v === 'string' && /^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$/.test(v)) return v;
  return `sha256-${pkg.identifier.split('@sha256:')[1].slice(0, 12)}`;
}

/**
 * server.json `repository`: the repository itself, and a monorepo path as
 * `subfolder` — `…/tree/main/src/filesystem` is not a clonable URL. Only
 * GitHub, through the one anchored parser (lib/repo_url.cjs); anything else is
 * left out rather than guessed at.
 */
function repositoryOf(url) {
  const base = githubRepoUrl(url);
  if (!base) return null;
  const out = { url: base, source: 'github' };
  const tree = String(url).match(/^https:\/\/(?:www\.)?github\.com\/[^/]+\/[^/]+\/tree\/[^/]+\/([^#?]+?)\/?(?:[#?].*)?$/i);
  if (tree && !tree[1].split('/').some((seg) => seg === '..' || seg === '.' || seg === '')) out.subfolder = tree[1];
  return out;
}

/**
 * `registry/namespace/repository` as the registry expects it. A bare Docker
 * Hub reference (`hashicorp/terraform-mcp-server`) gets its implied host, the
 * way docker itself resolves it.
 */
function ociIdentifier(image, digest) {
  const first = image.split('/')[0];
  const hasHost = image.includes('/') && (first.includes('.') || first.includes(':') || first === 'localhost');
  const full = hasHost ? image : `docker.io/${image.includes('/') ? image : `library/${image}`}`;
  return `${full}@${digest}`;
}

function describe(tool, tier) {
  const text = `${tool.category || 'MCP'} MCP server, pinned and checked by mcp-vault (${tier})`;
  return text.length <= DESCRIPTION_MAX ? text : `${text.slice(0, DESCRIPTION_MAX - 1)}…`;
}

/**
 * The first day, within `horizon` days, on which this entry's tier would get
 * worse if nothing were re-checked — so a reader of an old export can tell a
 * claim that has since lapsed from one that still holds.
 */
function tierHoldsUntil(tool, smoke, asOf, tier, horizon = 120) {
  const start = Date.parse(`${asOf}T00:00:00Z`);
  for (let d = 1; d <= horizon; d++) {
    const now = start + d * 86400000;
    const c = classifyEntry(tool, smoke, { now }).classification;
    if (TIER_ORDER[c] > TIER_ORDER[tier]) return new Date(now - 86400000).toISOString().slice(0, 10);
  }
  return null;
}

function toServerJson(tool, { smoke = null, asOf, minTier = 'Experimental' } = {}) {
  if (!asOf) throw new Error('toServerJson: asOf is required (the export has no clock)');
  const now  = Date.parse(`${asOf}T00:00:00Z`);
  const tier = classifyEntry(tool, smoke, { now });
  if (tier.classification === 'Deprecated') return { skip: `tier Deprecated: ${tier.why}` };
  if (TIER_ORDER[tier.classification] > TIER_ORDER[minTier]) {
    return { skip: `tier ${tier.classification} is below --min-tier ${minTier}` };
  }
  const p = packageOf(tool);
  if (p.skip) return { skip: p.skip };
  const { name, source } = serverName(tool);

  const dims = (tool.trust_evidence && tool.trust_evidence.dimensions) || {};
  const evidence = {};
  for (const k of Object.keys(dims).sort()) {
    const v = dims[k] || {};
    evidence[k] = { status: v.status ?? null, checked_at: v.checked_at ?? null };
  }

  const server = {
    $schema:     SCHEMA_URL,
    name,
    title:       String(tool.name).slice(0, 100),
    description: describe(tool, tier.classification),
    version:     serverVersion(tool, p.package),
  };
  const repository = repositoryOf(tool.source_url);
  if (repository) server.repository = repository;
  server.packages = [p.package];
  server._meta = {
    [META_KEY]: {
      vault_name:  tool.name,
      name_source: source,
      as_of:       asOf,
      tier:        tier.classification,
      tier_reason: tier.why,
      tier_holds_until: tierHoldsUntil(tool, smoke, asOf, tier.classification),
      trust:       tool.trust ?? null,
      category:    tool.category ?? null,
      license:     tool.license ?? null,
      health_score: tool.health_score ?? null,
      est_tools_count: Number.isFinite(tool.est_tools_count) ? tool.est_tools_count : null,
      pinned:      p.pinned,
      install_cmd: tool.install_cmd,
      evidence,
      smoke: smoke
        ? { status: smoke.status ?? null, tools: smoke.tool_count ?? null, checked_at: String(smoke.checked_at || '').slice(0, 10) || null }
        : null,
      explain: {
        command: `npx -y @froggychips/mcp-vault explain ${tool.name}`,
        page:    `${SITE}/registry.html`,
        source:  `${REPO}/blob/master/mcp-ecosystem-intelligence/assets/tools_database.json`,
      },
    },
  };
  return { server };
}

// ── static layout ─────────────────────────────────────────────────────────

const json = (v) => `${JSON.stringify(v, null, 2)}\n`;

/**
 * Where each endpoint lives on a static host.
 *
 * `/v0.1/servers` is both a document and the parent of `/v0.1/servers/<name>`,
 * and a file cannot also be a directory — so list endpoints are
 * `…/index.html` (a static host redirects `servers` → `servers/` and serves
 * it) and single-version endpoints are extensionless files.
 *
 * `serverName` must be URL-encoded in the path (`io.github.o%2Fname`), and
 * static hosts disagree about `%2F`: some look for a file literally named
 * `io.github.o%2Fname`, some decode it into a subdirectory. Both are written.
 */
function serverDirs(name) {
  const encoded = `${API_PREFIX}/servers/${encodeURIComponent(name)}`;
  const decoded = `${API_PREFIX}/servers/${name}`;
  return encoded === decoded ? [encoded] : [encoded, decoded];
}

function versionLeaves(version) {
  const enc = encodeURIComponent(version);
  return enc === version ? [version] : [enc, version];
}

function buildExport(db, evals, { asOf = null, minTier = 'Experimental' } = {}) {
  const at = asOf || asOfDate(db, evals);
  if (!at) throw new Error('no evidence date in the data, and no --as-of given');
  const smokeByName = evalIndex((evals && evals.results) || []);
  const exported = [];
  const skipped  = [];

  const tools = [...((db && db.tools) || [])].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const t of tools) {
    const r = toServerJson(t, { smoke: smokeByName.get(t.name) || null, asOf: at, minTier });
    if (r.skip) skipped.push({ name: t.name, reason: r.skip });
    else exported.push(r.server);
  }

  // Two entries claiming one name would make the second silently shadow the
  // first on every host. Refuse, rather than pick.
  const byName = new Map();
  for (const s of exported) {
    if (byName.has(s.name)) {
      throw new Error(`two entries export as ${s.name}: ${byName.get(s.name)._meta[META_KEY].vault_name} and ${s._meta[META_KEY].vault_name}`);
    }
    byName.set(s.name, s);
  }
  exported.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  // Registry-managed metadata lives beside `server`, not in it. We do not
  // write `io.modelcontextprotocol.registry/official`: that key is the
  // official registry's, and a sub-registry filling it in would be speaking
  // for it.
  const response = (s) => ({ server: s, _meta: { [META_KEY]: { isLatest: true, as_of: at } } });

  const files = new Map();
  files.set(`${API_PREFIX}/servers/index.html`, json({
    servers:  exported.map(response),
    metadata: { count: exported.length },
  }));
  for (const s of exported) {
    const one = json(response(s));
    const list = json({ servers: [response(s)], metadata: { count: 1 } });
    for (const dir of serverDirs(s.name)) {
      files.set(`${dir}/versions/index.html`, list);
      files.set(`${dir}/versions/latest`, one);
      for (const leaf of versionLeaves(s.version)) files.set(`${dir}/versions/${leaf}`, one);
    }
  }

  // ToolHive reads one file in its "upstream" format: server.json objects
  // under `data.servers`, which is why our data sits in the server's `_meta`
  // and not only in the response envelope.
  files.set(`${API_PREFIX}/x/${NAMESPACE}/toolhive.json`, json({
    $schema: 'https://raw.githubusercontent.com/stacklok/toolhive-core/main/registry/types/data/upstream-registry.schema.json',
    version: '1.0.0',
    meta:    { last_updated: `${at}T00:00:00Z` },
    data:    { servers: exported },
  }));

  const digests = {};
  for (const k of [...files.keys()].sort()) {
    digests[k] = `sha256-${crypto.createHash('sha256').update(files.get(k)).digest('hex')}`;
  }
  const manifest = {
    schema:     'mcp-vault/subregistry-export@1',
    as_of:      at,
    namespace:  NAMESPACE,
    meta_key:   META_KEY,
    server_schema: SCHEMA_URL,
    api:        API_PREFIX,
    min_tier:   minTier,
    exported:   exported.length,
    skipped,
    files:      digests,
  };
  files.set(`${API_PREFIX}/x/${NAMESPACE}/export.json`, json(manifest));
  return { files, manifest, servers: exported };
}

module.exports = {
  NAMESPACE, META_KEY, SCHEMA_URL, API_PREFIX, NAME_RE,
  asOfDate, slug, serverName, packageOf, dockerArguments, serverVersion, repositoryOf, ociIdentifier,
  toServerJson, tierHoldsUntil, buildExport, serverDirs, versionLeaves,
};
