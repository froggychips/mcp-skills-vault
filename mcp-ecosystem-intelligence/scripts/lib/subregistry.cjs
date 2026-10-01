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
 * the verdict and the rule that decided it, the tier, the pinned version and
 * its integrity, and the date each piece of evidence was established. Nothing
 * here decides anything (docs/adr/0001-findings-and-time.md): the verdict is
 * the Decision `decide()` makes over the entry's stored evidence — the same
 * model `explain` renders (explain.cjs `explainModel`) — the tier comes from
 * lib/tiers.cjs, the artifact from lib/entry_model.cjs.
 *
 * Three decisions worth knowing before changing anything:
 *
 *   1. **Deterministic, by construction.** No clock here. The verdict and the
 *      tier are functions of the instant they are judged at (claims age out),
 *      so `asOf` is a required input — read once by the CLI (lib/clock.cjs,
 *      `--as-of`) — and it is written into every record. Same DB, same
 *      policy, same asOf: same bytes, so the export can be signed and diffed.
 *
 *   2. **Names are only borrowed when they were proved.** A server.json `name`
 *      is a namespace claim. An entry the official registry lists (recorded by
 *      `mcp-vault identity` as `registry.server_id`) keeps that name, so a
 *      host deduplicates it against the official listing. Every other entry is
 *      published under *our* namespace, `xyz.froggychips.mcp/<slug>` — deriving
 *      `io.github.<owner>/…` from a source URL would print a verified-looking
 *      namespace nobody verified.
 *
 *   3. **Fail closed.** An entry the Decision denies, one with a Deprecated
 *      tier, or one with nothing pinned to install (a git source, no version,
 *      an image without a digest) is not exported: a host that ignores `_meta`
 *      would offer it as installable. The skip list, with reasons, is in the
 *      export manifest; the decisions are in the findings@1 document.
 *
 * API:
 *   NAMESPACE, META_KEY, SCHEMA_URL, DEFAULT_BASE_URL
 *   normalizeBaseUrl(url)                     -> 'https://host[/path]' (no trailing slash)
 *   serverName(tool)                          -> { name, source }
 *   packageOf(tool)                           -> { package, pinned } | { skip }
 *   entryModel(tool, { smoke, asOf, policy }) -> explain's model: { subject, observations, findings, decision, facts }
 *   tierHoldsUntil(observations, asOf)        -> ISO instant | null   (min expires_at still ahead)
 *   toServerJson(tool, { smoke, asOf, policy, baseUrl, … }) -> { server, model } | { skip, model }
 *   buildExport(db, evals, { asOf, policy, baseUrl, … })    -> { files: Map, manifest, servers, findings }
 */

const crypto = require('crypto');
const { toTypedEntry, artifactId } = require('./entry_model.cjs');
const { dockerImageRef, isExactVersion } = require('./install_cmd.cjs');
const { classifyEntry, evalIndex, TIER_ORDER } = require('./tiers.cjs');
const { githubRepoUrl } = require('./repo_url.cjs');
const { requireAsOf, isoInstant } = require('./clock.cjs');
const { findingsDocument, toJson, observationState } = require('./finding.cjs');
const { effectivePolicy } = require('./policy_rules.cjs');
const { DEFAULTS } = require('./policy.cjs');
const { trustScore, behaviour } = require('./scores.cjs');
const { DEFAULT_MAX_AGE_DAYS, dbAsOf, evalResultsAsOf } = require('./evidence.cjs');

// Reverse-DNS of the domain the site is served from (mcp.froggychips.xyz), as
// the registry spec asks for `_meta` keys and extension paths. The domain, not
// `io.github.froggychips`: it is where these files live, so whoever controls
// the key controls the bytes behind it.
//
// THE ONE PLACE the namespace is spelled. Everything else — the `_meta` key,
// the names of unlisted entries, the `v0.1/x/<namespace>/` directory, the
// tests — derives from it. Changing it changes every published name, so it is
// an owner's decision, not a refactor.
const NAMESPACE  = 'xyz.froggychips.mcp';
const META_KEY   = `${NAMESPACE}/vault`;
const SCHEMA_URL = 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json';
const API_PREFIX = 'v0.1';
// Where the site is served. Only the default: every absolute URL the export
// writes is built from the `baseUrl` option (`--base-url`), so a mirror or a
// staging copy does not point readers back at production.
const DEFAULT_BASE_URL = 'https://mcp.froggychips.xyz';
const REPO       = 'https://github.com/froggychips/mcp-skills-vault';

// server.json constraints (2025-12-11 schema).
const NAME_RE        = /^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/;
const DESCRIPTION_MAX = 100;

// docker flags that the host adds itself when it runs an `oci` package, or
// that are ours to pass differently (`-e` becomes environmentVariables).
const DOCKER_IMPLIED = new Set(['-i', '--interactive', '--rm']);

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
 * When the verdict stops resting on current evidence: the earliest
 * `expires_at` among the entry's observations that is still ahead of asOf
 * (docs/adr/0001, #126). One that has already lapsed is not a future date — it
 * is in the Decision already, as `evidence/stale`. `null`: nothing it rests on
 * ages.
 */
function tierHoldsUntil(observations, asOf) {
  const at = requireAsOf(asOf, 'tierHoldsUntil');
  let min = null;
  for (const o of observations || []) {
    if (!o.expires_at || observationState(o, at) === 'stale') continue;
    if (min === null || o.expires_at < min) min = o.expires_at;
  }
  return min;
}

// The policy an export is judged under when the caller names none: the
// defaults, normalised and frozen the way `loadEffectivePolicy` does when no
// policy file applies.
let defaultPolicy = null;
const DEFAULT_POLICY = () => defaultPolicy || (defaultPolicy = effectivePolicy(null, {}, { defaults: DEFAULTS }));

/**
 * The entry's Decision, from its stored evidence, as `explain` makes it —
 * the same function, so the export and `explain <name> --as-of` cannot give
 * one entry two answers. Evidence counts only for the artifact it was
 * collected on, as in explain.
 */
function entryModel(tool, { smoke = null, asOf, policy = DEFAULT_POLICY() } = {}) {
  const at = requireAsOf(asOf, 'entryModel');
  // Required lazily: explain.cjs is a command module with its own imports.
  const { explainModel } = require('../explain.cjs');
  let currentId = null;
  try { const t = toTypedEntry(tool); currentId = t ? artifactId(t.artifact) : null; } catch { currentId = null; }
  const ev = tool.trust_evidence;
  const evidence = ev && (!ev.artifact_id || !currentId || ev.artifact_id === currentId) ? ev : null;
  const maxAgeDays = policy.maxEvidenceAgeDays || DEFAULT_MAX_AGE_DAYS;
  const trust = trustScore(evidence, { maxAgeDays, now: at });
  return explainModel({ tool, policy, trust, behav: behaviour(smoke), budget: null, evidence, asOf: at, maxAgeDays });
}

/** The Decision as `_meta` carries it: what, which rule, why, when. */
function verdictOf(decision) {
  const deciding = decision.rules.find((r) => r.rule === decision.decided_by && r.effect === decision.effect);
  return {
    effect:     decision.effect,
    decided_by: decision.decided_by,
    reason:     (deciding && deciding.detail) || null,
    as_of:      decision.as_of,
  };
}

/** An http(s) URL with no query, fragment or trailing slash; throws otherwise. */
function normalizeBaseUrl(url) {
  let u;
  try { u = new URL(String(url)); } catch { throw new Error(`base URL is not a URL: ${url}`); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error(`base URL must be http(s): ${url}`);
  if (u.search || u.hash || u.username || u.password) throw new Error(`base URL must be a plain origin or path: ${url}`);
  return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
}

function toServerJson(tool, { smoke = null, asOf, policy = DEFAULT_POLICY(), minTier = 'Experimental', baseUrl = DEFAULT_BASE_URL } = {}) {
  const at   = requireAsOf(asOf, 'toServerJson');
  const site = normalizeBaseUrl(baseUrl);
  const model = entryModel(tool, { smoke, asOf: at, policy });
  const verdict = verdictOf(model.decision);
  // Rendering the Decision, not making one: a denied entry is not offered.
  if (verdict.effect === 'deny') return { skip: `denied by ${verdict.decided_by}: ${verdict.reason || 'see explain'}`, model };
  const tier = classifyEntry(tool, smoke, { now: at });
  if (tier.classification === 'Deprecated') return { skip: `tier Deprecated: ${tier.why}`, model };
  if (TIER_ORDER[tier.classification] > TIER_ORDER[minTier]) {
    return { skip: `tier ${tier.classification} is below --min-tier ${minTier}`, model };
  }
  const p = packageOf(tool);
  if (p.skip) return { skip: p.skip, model };
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
      as_of:       isoInstant(at),
      // The Decision (lib/finding.cjs decide()), as `explain` would print it.
      verdict,
      tier:        tier.classification,
      tier_reason: tier.why,
      tier_holds_until: tierHoldsUntil(model.observations, at),
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
        page:    `${site}/registry.html`,
        source:  `${REPO}/blob/master/mcp-ecosystem-intelligence/assets/tools_database.json`,
      },
    },
  };
  return { server, model };
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

/**
 * GitHub Pages picks the Content-Type from the extension: `index.html` is
 * `text/html`, an extensionless file `application/octet-stream`. The API paths
 * have to be those files (a client builds `/v0.1/servers/<name>/versions/latest`
 * itself), but every endpoint also gets a `.json` twin with the same bytes,
 * served as `application/json`, for anything given a URL rather than a base:
 *
 *   v0.1/servers/index.html            -> v0.1/servers.json
 *   …/versions/index.html              -> …/versions.json
 *   …/versions/latest, …/versions/<v>  -> …/versions/latest.json, …/<v>.json
 */
function jsonTwin(rel) {
  return rel.endsWith('/index.html') ? `${rel.slice(0, -'/index.html'.length)}.json` : `${rel}.json`;
}

function buildExport(db, evals, { asOf, policy = DEFAULT_POLICY(), minTier = 'Experimental', baseUrl = DEFAULT_BASE_URL } = {}) {
  const at = requireAsOf(asOf, 'buildExport');
  const site = normalizeBaseUrl(baseUrl);
  const iso = isoInstant(at);
  // The record as it stood at asOf: a look dated later did not exist then.
  const smokeByName = evalIndex(evalResultsAsOf((evals && evals.results) || [], at));
  const exported = [];
  const skipped  = [];
  const observations = [];
  const findings = [];
  const decisions = [];
  const facts = {};

  const asOfDb = dbAsOf(db, at);
  const tools = [...((asOfDb && asOfDb.tools) || [])].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const t of tools) {
    const r = toServerJson(t, { smoke: smokeByName.get(t.name) || null, asOf: at, policy, minTier, baseUrl: site });
    observations.push(...r.model.observations);
    findings.push(...r.model.findings);
    decisions.push(r.model.decision);
    Object.assign(facts, r.model.facts);
    if (r.skip) skipped.push({ name: t.name, reason: r.skip });
    else exported.push(r.server);
  }
  // Every entry's Decision, with the policy and facts it was made on, so
  // `decide(doc.findings, doc.policy, doc.as_of, …)` reproduces it.
  const doc = toJson(findingsDocument({ asOf: at, observations, findings, decisions, scope: 'database', policy, facts }));

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
  const response = (s) => ({ server: s, _meta: { [META_KEY]: { isLatest: true, as_of: iso } } });

  const files = new Map();
  const endpoint = (rel, body) => { files.set(rel, body); files.set(jsonTwin(rel), body); };
  endpoint(`${API_PREFIX}/servers/index.html`, json({
    servers:  exported.map(response),
    metadata: { count: exported.length },
  }));
  for (const s of exported) {
    const one = json(response(s));
    const list = json({ servers: [response(s)], metadata: { count: 1 } });
    for (const dir of serverDirs(s.name)) {
      endpoint(`${dir}/versions/index.html`, list);
      endpoint(`${dir}/versions/latest`, one);
      for (const leaf of versionLeaves(s.version)) endpoint(`${dir}/versions/${leaf}`, one);
    }
  }

  // ToolHive reads one file in its "upstream" format: server.json objects
  // under `data.servers`, which is why our data sits in the server's `_meta`
  // and not only in the response envelope.
  files.set(`${API_PREFIX}/x/${NAMESPACE}/toolhive.json`, json({
    $schema: 'https://raw.githubusercontent.com/stacklok/toolhive-core/main/registry/types/data/upstream-registry.schema.json',
    version: '1.0.0',
    meta:    { last_updated: iso, source: `${site}/${API_PREFIX}/servers.json` },
    data:    { servers: exported },
  }));

  const digests = {};
  for (const k of [...files.keys()].sort()) {
    digests[k] = `sha256-${crypto.createHash('sha256').update(files.get(k)).digest('hex')}`;
  }
  const manifest = {
    schema:     'mcp-vault/subregistry-export@1',
    as_of:      iso,
    namespace:  NAMESPACE,
    base_url:   site,
    meta_key:   META_KEY,
    server_schema: SCHEMA_URL,
    api:        API_PREFIX,
    min_tier:   minTier,
    exported:   exported.length,
    skipped,
    files:      digests,
  };
  files.set(`${API_PREFIX}/x/${NAMESPACE}/export.json`, json(manifest));
  return { files, manifest, servers: exported, findings: doc };
}

module.exports = {
  NAMESPACE, META_KEY, SCHEMA_URL, API_PREFIX, NAME_RE, DEFAULT_BASE_URL,
  normalizeBaseUrl, jsonTwin,
  slug, serverName, packageOf, dockerArguments, serverVersion, repositoryOf, ociIdentifier,
  entryModel, verdictOf, toServerJson, tierHoldsUntil, buildExport, serverDirs, versionLeaves,
};
