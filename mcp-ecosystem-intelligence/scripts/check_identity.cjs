#!/usr/bin/env node
/**
 * Who published this, and were they entitled to the name?
 *
 * The official MCP Registry (registry.modelcontextprotocol.io) is the one feed
 * that can answer that. Its namespaces are ownership-verified at publish time:
 * `io.github.<owner>/<name>` requires authenticating as that GitHub account,
 * and a reverse-DNS namespace requires control of the domain. Nothing else in
 * this repo's evidence is *proved* in that sense — npm's `repository.url` is a
 * field the publisher types, and our own `source_url` is a field a pull request
 * types.
 *
 * So this is not a competing registry. It is a cross-reference:
 *
 *     official registry  →  who published it, under a name they proved they own
 *     mcp-vault          →  supply-chain evidence, policy, behaviour
 *
 * Four states, and the important design point is that **absence is not a
 * finding**: most of this DB is not listed, because listing is opt-in and the
 * registry is young. Only a contradiction counts.
 *
 *   listed        found, and everything comparable agrees
 *   unlisted      no record ships this package
 *   contradicted  the registry's repository, or its verified namespace owner,
 *                 disagrees with this entry
 *   withdrawn     the registry marks the server deleted or deprecated
 *
 * This check used to also audit `in_registry`, a hand-set boolean in the DB
 * that added 30 points to every health score and had never been compared with
 * anything. It disagreed with the live registry for 26 of 114 entries. The
 * field is gone: the answer is measured here, dated, and recorded as the
 * `registry` dimension, worth 5 points of trust.
 *
 * Usage:
 *   node scripts/check_identity.cjs [--json] [--write] [--entry <name>]
 *
 * Exit codes:
 *   0  nothing contradicts
 *   1  at least one contradiction / withdrawal
 *   2  bad arguments
 */

'use strict';

const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readDb, writeDb } = require('./lib/db_io.cjs');
const { mapLimit } = require('./lib/http.cjs');
const { npmPkgName, pypiPkgName } = require('./lib/install_cmd.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { buildEvidence, mergeEvidence } = require('./lib/evidence.cjs');
const { findByPackage, identityFindings, namespaceOwner } = require('./lib/mcp_registry.cjs');

const DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
// The registry's full-text search is slow; four in flight keeps a 114-entry
// sweep to a couple of minutes without hammering a community service.
const CONCURRENCY = 4;

const T  = process.stdout.isTTY;
const RD = T ? '\x1b[31m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

const FINDING_STATES = new Set(['contradicted', 'withdrawn']);

function parseArgs(argv) {
  const opts = { json: false, write: false, entry: null, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--write') opts.write = true;
    else if (a === '--entry') opts.entry = argv[++i] || null;
    else if (a === '-h' || a === '--help') opts.help = true;
    else return { ...opts, error: `unknown flag ${a}` };
  }
  return opts;
}

const HELP = `check_identity — who published this, per the official MCP registry

  node scripts/check_identity.cjs [--json] [--write] [--entry <name>]

  --write    record 'registry' evidence in the DB
  --entry    check one entry by name
`;

/** The package identifier to look the entry up by. */
function identifierFor(tool) {
  const typed = toTypedEntry(tool);
  const eco = typed ? typed.artifact.ecosystem : null;
  if (eco === 'npm')  return { ecosystem: 'npm',  identifier: npmPkgName(tool.install_cmd) };
  if (eco === 'pypi') return { ecosystem: 'pypi', identifier: pypiPkgName(tool.install_cmd) };
  if (eco === 'oci')  return { ecosystem: 'oci',  identifier: typed.artifact.image || null };
  return { ecosystem: eco, identifier: null };
}

async function checkEntry(tool, { find = findByPackage } = {}) {
  const { ecosystem, identifier } = identifierFor(tool);
  const typed = toTypedEntry(tool);
  const row = {
    name: tool.name,
    ecosystem,
    identifier,
    artifact_id: typed ? artifactId(typed.artifact) : null,
    registry: { state: 'unknown', findings: [] },
  };
  if (!identifier) {
    row.registry = { state: 'unknown', findings: ['no package identifier to look up'] };
    return row;
  }

  const found = await find(ecosystem, identifier);
  if (!found.ok) {
    // A feed that did not answer has established nothing. Recording "unlisted"
    // here would turn an outage into a finding about somebody's package.
    row.registry = { state: 'unknown', findings: [`the registry did not answer: ${found.error}`] };
    return row;
  }

  row.registry = identityFindings({ record: found.record, tool });
  if (found.candidates.length > 1) {
    // Two different verified namespaces claiming the same package identifier.
    row.registry.findings = [
      ...row.registry.findings,
      `${found.candidates.length} registry entries claim this package: ${found.candidates.join(', ')}`,
    ];
    if (row.registry.state === 'listed') row.registry.state = 'contradicted';
  }
  return row;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`check_identity: ${opts.error}\n\n${HELP}`); return Promise.resolve(2); }
  if (opts.help)  { process.stdout.write(HELP); return Promise.resolve(0); }

  const { db } = readDb(DB_PATH);
  const tools = (db.tools || []).filter((t) => !opts.entry || t.name === opts.entry);
  if (opts.entry && !tools.length) {
    process.stderr.write(`check_identity: no entry named "${opts.entry}"\n`);
    return Promise.resolve(2);
  }

  return mapLimit(tools, CONCURRENCY, (t) => checkEntry(t)).then((rows) => {
    const byState = (state) => rows.filter((r) => r.registry.state === state);
    const findings = rows.filter((r) => FINDING_STATES.has(r.registry.state));

    if (opts.write) {
      const byName = new Map(rows.map((r) => [r.name, r]));
      let recorded = 0;
      for (const tool of db.tools || []) {
        const row = byName.get(tool.name);
        if (!row || row.registry.state === 'unknown') continue;
        const fresh = buildEvidence({
          registry: {
            state:     row.registry.state,
            server_id: row.registry.server_id || null,
            detail:    row.registry.findings.length ? row.registry.findings[0].slice(0, 200) : null,
          },
        }, { artifactId: row.artifact_id });
        tool.trust_evidence = mergeEvidence(tool.trust_evidence, fresh);
        recorded++;
      }
      if (recorded) writeDb(DB_PATH, db);
      // No trust re-derivation here, deliberately: a registry listing is not
      // what makes an artifact verified, and one check does not get to restate
      // every other check's verdict (see check_availability.cjs for the time
      // that went wrong).
      process.stderr.write(`Recorded registry identity for ${recorded} entr${recorded === 1 ? 'y' : 'ies'} in ${DB_PATH}\n`);
    }

    if (opts.json) {
      process.stdout.write(`${JSON.stringify({
        schema: 'mcp-vault/identity@1',
        generated_at: new Date().toISOString(),
        checked: rows.length,
        summary: {
          listed:       byState('listed').length,
          unlisted:     byState('unlisted').length,
          contradicted: byState('contradicted').length,
          withdrawn:    byState('withdrawn').length,
          unknown:      byState('unknown').length,
        },
        entries: rows,
      }, null, 2)}\n`);
    } else {
      for (const r of rows) {
        if (r.registry.state === 'unlisted' || r.registry.state === 'unknown') continue;
        const colour = FINDING_STATES.has(r.registry.state) ? RD : GN;
        process.stdout.write(`${colour}${r.registry.state.padEnd(13)}${RS} ${r.name}${r.registry.server_id ? `  ${DM}${r.registry.server_id}${RS}` : ''}\n`);
        for (const f of r.registry.findings) process.stdout.write(`              ${DM}${f}${RS}\n`);
      }
      process.stdout.write(
        `\n${rows.length} checked — ${GN}${byState('listed').length} listed${RS}, ` +
        `${byState('unlisted').length} not in the official registry, ` +
        `${findings.length ? RD : ''}${findings.length} contradicted/withdrawn${RS}, ` +
        `${byState('unknown').length} not checkable\n`
      );
      process.stdout.write(`${DM}"Not listed" is not a finding: listing is opt-in and the registry is young.${RS}\n`);
    }

    if (findings.length) return 1;
    return 0;
  });
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => exitAfterFlush(code)).catch((e) => {
    process.stderr.write(`check_identity: ${e.stack || e.message}\n`);
    exitAfterFlush(2);
  });
}

module.exports = { parseArgs, identifierFor, checkEntry, namespaceOwner, FINDING_STATES };
