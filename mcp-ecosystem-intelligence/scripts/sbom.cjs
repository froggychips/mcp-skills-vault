#!/usr/bin/env node
/**
 * CycloneDX SBOM for MCP servers — the vault DB, or the servers a project
 * actually runs.
 *
 * Why bother, when the DB is already a JSON file anyone can read: because a
 * bill of materials is what the tools on the other side of a security review
 * consume. `grype`, `trivy`, Dependency-Track and every corporate intake form
 * read CycloneDX; none of them read `tools_database.json`. Exporting the same
 * facts in a format those tools already understand is most of what "can we use
 * this at work" takes.
 *
 * What goes in, and what deliberately does not:
 *
 *   components   one per server (type: application), with its purl, its
 *                integrity value as a hash, its licence and its repository.
 *                With --deps, one per transitive package as well.
 *   dependencies the graph, so a scanner can tell a direct dependency from
 *                something six levels down. Only present with --deps: an
 *                empty `dependencies` array would assert that these servers
 *                have no dependencies, which is false for every one of them.
 *   properties   what this repo knows and CycloneDX has no field for — trust
 *                tier, evidence dates, tool count, behavioural status. Namespaced
 *                `mcp-vault:` so a consumer can ignore them.
 *
 * Licence ids are emitted only from a checked list; see SPDX_IDS below. The
 * first version of this trusted anything SPDX-shaped and produced a document
 * that failed CycloneDX validation on `NOASSERTION`.
 *
 * Hashes: npm publishes sha512 base64 (`sha512-…`), PyPI sha256 hex, OCI a
 * sha256 digest. CycloneDX wants hex, so base64 is converted — and an integrity
 * value whose length does not match its declared algorithm is dropped rather
 * than emitted as a hash that would fail verification for the wrong reason.
 *
 * Usage:
 *   node scripts/sbom.cjs [--installed] [--cwd <path>] [--entry <name>]
 *                         [--deps] [--out <file>] [--spec 1.5|1.6]
 *
 * Exit codes:
 *   0  written
 *   2  bad arguments / nothing to describe
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { classifyEntry } = require('./lib/tiers.cjs');
const { readInstalledServers, toInstallCmd } = require('./lib/installed.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { resolveNpmTreeCached, summarizeTree } = require('./lib/deps.cjs');
const { purlFor } = require('./lib/npm_signatures.cjs');
const { behaviour } = require('./lib/scores.cjs');
const { staleDimensions } = require('./lib/evidence.cjs');
const { OSI_APPROVED } = require('./calculate_health.cjs');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');
const PKG_PATH  = path.resolve(__dirname, '../../package.json');

const SUPPORTED_SPECS = ['1.5', '1.6'];

function parseArgs(argv) {
  const opts = { installed: false, cwd: process.cwd(), entry: null, deps: false, out: null, spec: '1.6', help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--installed') opts.installed = true;
    else if (a === '--deps') opts.deps = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--cwd') opts.cwd = argv[++i] || opts.cwd;
    else if (a === '--entry') opts.entry = argv[++i] || null;
    else if (a === '--out') opts.out = argv[++i] || null;
    else if (a === '--spec') opts.spec = argv[++i] || opts.spec;
    else return { ...opts, error: `unknown flag ${a}` };
  }
  if (!SUPPORTED_SPECS.includes(opts.spec)) {
    return { ...opts, error: `--spec must be one of ${SUPPORTED_SPECS.join(' | ')}` };
  }
  return opts;
}

const HELP = `sbom — CycloneDX bill of materials for MCP servers

  node scripts/sbom.cjs [--installed] [--cwd <path>] [--entry <name>] [--deps]
                        [--out <file>] [--spec 1.5|1.6]

  (default)      describe every entry in the vault DB
  --installed    describe the servers this project's hosts are configured to run
  --entry <name> one entry
  --deps         include transitive packages and the dependency graph
                 (resolves each npm tree — slow, and needs network)
  --out <file>   write here instead of stdout
  --spec <v>     CycloneDX spec version (default 1.6)
`;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

/**
 * `sha512-<base64>` / `sha256-<hex>` → a CycloneDX hash entry.
 *
 * Returns null when the value does not decode to the length its algorithm
 * requires: a truncated or mis-prefixed integrity value emitted as a hash would
 * fail verification downstream and look like tampering.
 */
function toHash(integrity) {
  const m = String(integrity || '').match(/^(sha256|sha384|sha512)-(.+)$/);
  if (!m) return null;
  const want = { sha256: 32, sha384: 48, sha512: 64 }[m[1]];
  const body = m[2];
  let buf = null;
  if (/^[a-f0-9]+$/i.test(body) && body.length === want * 2) {
    buf = Buffer.from(body, 'hex');
  } else {
    try { buf = Buffer.from(body, 'base64'); } catch { return null; }
  }
  if (!buf || buf.length !== want) return null;
  return { alg: `SHA-${m[1].slice(3)}`, content: buf.toString('hex') };
}

/** A component's stable identity within the document. */
function bomRef(prefix, id) {
  return `${prefix}:${id}`;
}

// SPDX ids we will put in `license.id`. CycloneDX validates that field against
// an enum of 826 identifiers, and anything outside it makes the whole document
// invalid — `NOASSERTION` and `Unknown`, both of which the DB contains, are not
// in it. Shipping the full enum would be 15KB of data that goes stale, so the
// rule is inverted: an id is emitted only when it is on this list, and anything
// else becomes `license.name`, which is free text and always valid. Worst case
// a real SPDX id is expressed as a name — still valid, and still says what the
// licence is.
//
// This list is the repo's OSI set (calculate_health.cjs) plus the
// source-available identifiers that show up on npm. Every entry was checked
// against CycloneDX's spdx.schema.json enum.
const SPDX_IDS = new Set([
  ...OSI_APPROVED,
  'FSL-1.1-ALv2', 'FSL-1.1-MIT', 'BUSL-1.1', 'SSPL-1.0', 'Elastic-2.0',
  'PolyForm-Noncommercial-1.0.0',
  'CC0-1.0', 'CC-BY-4.0', 'CC-BY-SA-4.0', 'Unlicense', 'WTFPL', 'BSD-3-Clause-Clear',
]);

function licencesFor(license) {
  if (!license) return undefined;
  const value = String(license).trim();
  // "Unknown" and "NOASSERTION" are this repo's way of saying nobody has
  // established a licence. An SBOM should carry that rather than imply MIT by
  // omission, so it goes through as a name.
  if (/\s(AND|OR|WITH)\s/.test(value)) return [{ expression: value }];
  if (SPDX_IDS.has(value)) return [{ license: { id: value } }];
  return [{ license: { name: value } }];
}

/** The `mcp-vault:` properties for one entry — what CycloneDX has no field for. */
function propertiesFor(tool, evalResult) {
  const props = [];
  const put = (name, value) => {
    if (value === null || value === undefined || value === '') return;
    props.push({ name: `mcp-vault:${name}`, value: String(value) });
  };
  put('trust', tool.trust);
  // Derived from the evidence below rather than stored — see lib/tiers.cjs.
  // The `last-checked` property is deliberately gone: it was one entry-level
  // date that no longer tracked anything, and every `evidence.*` property here
  // already carries the date its own claim was established.
  put('classification', classifyEntry(tool, evalResult).classification);
  put('category', tool.category);
  put('health-score', tool.health_score);
  put('tools-estimated', tool.est_tools_count);
  put('launch-command', tool.install_cmd);

  const ev = tool.trust_evidence && tool.trust_evidence.dimensions;
  if (ev) {
    for (const [dimension, value] of Object.entries(ev)) {
      // Each claim with the date it was established, because that is the part
      // a reader of an SBOM three months from now needs.
      put(`evidence.${dimension}`, `${value.status} (${value.verified_at || value.checked_at})`);
    }
    const stale = staleDimensions(tool.trust_evidence);
    if (stale.length) put('evidence.stale', stale.map((s) => `${s.dimension} (${s.age_days}d)`).join(', '));
  }

  if (evalResult) {
    const b = behaviour(evalResult);
    put('behaviour', b.state);
    put('behaviour.detail', b.reason);
    put('tools-observed', evalResult.tool_count);
    if (evalResult.surface && evalResult.surface.sha256) put('tool-surface-sha256', evalResult.surface.sha256);
  }
  return props.length ? props : undefined;
}

/** One server → a CycloneDX component. */
function componentFor(tool, evalResult) {
  const typed = toTypedEntry(tool);
  const a = typed ? typed.artifact : {};
  const id = artifactId(a) || tool.name;

  const component = {
    type:    'application',
    'bom-ref': bomRef('server', id),
    name:    a.package || a.image || tool.name,
    version: a.version || a.digest || undefined,
    description: tool.notes || undefined,
    purl:    a.ecosystem === 'npm' ? purlFor('npm', a.package, a.version)
      : a.ecosystem === 'pypi' ? purlFor('pypi', a.package, a.version)
        : a.ecosystem === 'oci' && a.image
          ? `pkg:oci/${a.image.split('/').pop()}@${a.digest || a.tag || ''}?repository_url=${a.image}`
          : undefined,
    licenses: licencesFor(tool.license),
    properties: propertiesFor(tool, evalResult),
  };

  const hash = toHash(a.ecosystem === 'oci' && a.digest ? a.digest.replace(':', '-') : a.integrity);
  if (hash) component.hashes = [hash];

  if (tool.source_url) {
    component.externalReferences = [{ type: 'vcs', url: tool.source_url }];
  }
  return component;
}

/** A transitive npm package → a component. */
function depComponent(pkg) {
  const c = {
    type:    'library',
    'bom-ref': bomRef('npm', `${pkg.name}@${pkg.version}`),
    name:    pkg.name,
    version: pkg.version || undefined,
    purl:    purlFor('npm', pkg.name, pkg.version),
    scope:   pkg.dev ? 'excluded' : undefined,   // CycloneDX: not shipped
  };
  const hash = toHash(pkg.integrity);
  if (hash) c.hashes = [hash];
  if (pkg.hasInstallScript) {
    // The single most useful property this repo can add to a dependency in an
    // SBOM: it runs code at install time.
    c.properties = [{ name: 'mcp-vault:install-script', value: 'true' }];
  }
  return c;
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`sbom: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }

  const db    = readJson(DB_PATH, { tools: [] }).tools || [];
  const evals = readJson(EVAL_PATH, { results: [] }).results || [];
  const pkg   = readJson(PKG_PATH, { name: '@froggychips/mcp-vault', version: '0.0.0' });
  const evalBy = new Map(evals.map((r) => [r.name, r]));

  let subjects;
  const unreadableConfigs = [];
  let subjectName;
  if (opts.entry) {
    subjects = db.filter((t) => t.name === opts.entry);
    subjectName = `mcp server ${opts.entry}`;
    if (!subjects.length) { process.stderr.write(`sbom: no entry named "${opts.entry}"\n`); return 2; }
  } else if (opts.installed) {
    // The configured servers, with DB entries attached where they exist. A
    // server that is not in the vault still belongs in the SBOM — "we run this
    // and know nothing about it" is exactly what an SBOM is for.
  // A host config we could not read is not a host with no servers in it.
  // Collected so the caller can say so instead of quietly describing a subset.
    subjects = readInstalledServers({ cwd: opts.cwd, onUnreadable: (loc) => unreadableConfigs.push(loc) }).map((srv) => {
      const install_cmd = srv.install_cmd || toInstallCmd(srv);
      const entry = db.find((t) => t.name === srv.name)
        || db.find((t) => t.install_cmd && install_cmd && t.install_cmd === install_cmd);
      return entry
        ? { ...entry, _scope: srv.scope, _host: srv.host }
        : {
          name: srv.name, install_cmd, version: null, pkg_integrity: null,
          license: null, trust: 'unknown', _scope: srv.scope, _host: srv.host,
          _not_in_vault: true,
        };
    });
    subjectName = `MCP servers configured for ${opts.cwd}`;
    // A bill of materials that silently omits a host we could not read is a
    // bill of materials for an unknown subset of what runs.
    if (unreadableConfigs.length) {
      for (const u of unreadableConfigs) process.stderr.write(`sbom: ${u.path}: ${u.error}\n`);
      return 2;
    }
    if (!subjects.length) { process.stderr.write(`sbom: no MCP servers configured for ${opts.cwd}\n`); return 2; }
  } else {
    subjects = db;
    subjectName = 'mcp-vault server registry';
  }

  const components = [];
  const dependencies = [];

  for (const tool of subjects) {
    const component = componentFor(tool, evalBy.get(tool.name));
    if (tool._not_in_vault) {
      component.properties = [...(component.properties || []), { name: 'mcp-vault:in-registry', value: 'false' }];
    }
    components.push(component);
  }

  if (opts.deps) {
    const seen = new Set(components.map((c) => c['bom-ref']));
    for (const tool of subjects) {
      const typed = toTypedEntry(tool);
      const a = typed ? typed.artifact : {};
      if (a.ecosystem !== 'npm' || !a.package || !a.version) continue;
      process.stderr.write(`resolving ${tool.name}…\n`);
      const tree = await resolveNpmTreeCached(a.package, a.version);
      if (!tree.ok) {
        // Recorded as a gap in the document rather than skipped silently: an
        // SBOM missing a subtree, with nothing saying so, is worse than one
        // that admits the hole.
        const c = components.find((x) => x.name === (a.package || tool.name));
        if (c) c.properties = [...(c.properties || []), { name: 'mcp-vault:dependencies-unresolved', value: tree.error || 'unknown' }];
        continue;
      }
      const refs = [];
      for (const dep of tree.packages) {
        const ref = bomRef('npm', `${dep.name}@${dep.version}`);
        refs.push(ref);
        if (seen.has(ref)) continue;
        seen.add(ref);
        components.push(depComponent(dep));
      }
      dependencies.push({ ref: componentFor(tool, null)['bom-ref'], dependsOn: refs });
      const sum = summarizeTree(tree.packages);
      if (sum.withInstallScripts.length) {
        const c = components.find((x) => x['bom-ref'] === componentFor(tool, null)['bom-ref']);
        if (c) c.properties = [...(c.properties || []), { name: 'mcp-vault:tree-install-scripts', value: sum.withInstallScripts.join(', ') }];
      }
    }
  }

  const bom = {
    bomFormat:   'CycloneDX',
    specVersion: opts.spec,
    // A stable, content-derived serial number: two runs over the same data
    // produce the same document, which is what makes an SBOM diffable. A random
    // UUID per run would make every export look like a change.
    serialNumber: `urn:uuid:${contentUuid({ subjectName, components, dependencies })}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'mcp-vault', version: pkg.version, publisher: 'froggychips' }] },
      component: {
        type: 'application',
        'bom-ref': 'subject',
        name: subjectName,
        version: pkg.version,
      },
      properties: [
        { name: 'mcp-vault:subject', value: opts.installed ? 'installed' : (opts.entry ? 'entry' : 'registry') },
        { name: 'mcp-vault:includes-transitive-dependencies', value: String(opts.deps) },
      ],
    },
    components,
    ...(opts.deps ? { dependencies } : {}),
  };

  const json = `${JSON.stringify(bom, null, 2)}\n`;
  if (opts.out) {
    fs.writeFileSync(opts.out, json);
    const libs = components.filter((c) => c.type === 'library').length;
    process.stderr.write(`Wrote ${opts.out} — CycloneDX ${opts.spec}, ${components.length - libs} server(s)`
      + `${opts.deps ? `, ${libs} transitive package(s)` : ''}\n`);
  } else {
    process.stdout.write(json);
  }
  return 0;
}

/**
 * A UUID derived from the document's content, so the same inputs give the same
 * serial number. Formatted as a v4-shaped UUID because consumers validate the
 * shape; the version nibble is cosmetic here and the value is a digest, not a
 * random draw.
 */
function contentUuid(material) {
  const h = crypto.createHash('sha256').update(JSON.stringify(material)).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => exitAfterFlush(code)).catch((e) => {
    process.stderr.write(`sbom: ${e.stack || e.message}\n`);
    exitAfterFlush(2);
  });
}

module.exports = { parseArgs, toHash, licencesFor, SPDX_IDS, componentFor, depComponent, propertiesFor, contentUuid };
