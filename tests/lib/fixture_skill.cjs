'use strict';
/**
 * A copy of the skill whose vault DB holds evidence this test controls — so a
 * test about how a command *reads* the record does not depend on what the
 * shipped DB says today, or on when it was last refreshed (docs/adr/0001: time
 * is an input). The code is the real one (DB_PATH resolves next to the
 * scripts); only the data is staged. Pair it with an explicit `--as-of`.
 *
 * Every entry below pins the version its test launches and carries a complete
 * record observed on OBSERVED (STALE_OBSERVED for `stale` ones):
 *
 *   playwright-mcp      npx -y @playwright/mcp@0.0.75          clean
 *   mongodb-mcp-server  npx -y mongodb-mcp-server@1.10.0       clean
 *   mcp-server-aws      uvx awslabs.core-mcp-server==1.0.27    availability: yanked
 *   mcp-atlassian       uvx mcp-atlassian==0.22.0              advisories: vulnerable
 *
 * The shipped DB's other entries are kept as they are; no test here launches
 * them.
 *
 * API:
 *   fixtureSkill({ stale = [], with = [] }) -> { root, scripts, dbFile, launches, run(script, args, opts), cleanup() }
 *   OBSERVED, STALE_OBSERVED, AS_OF (a day after OBSERVED), LATE (past every shelf life)
 */

const fs   = require('node:fs');
const os   = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const OBSERVED = '2026-06-01';
const STALE_OBSERVED = '2026-04-01';
const AS_OF = '2026-06-02T12:00:00Z';
const LATE = '2026-08-15T12:00:00Z';

const NPM_CLEAN = {
  availability: 'present', artifact: 'verified', signature: 'verified', provenance: 'bound',
  source_binding: 'verified', registry: 'listed', advisories: 'clean',
};
const PYPI_CLEAN = { availability: 'present', artifact: 'verified', source_binding: 'verified', registry: 'listed', advisories: 'clean' };

const ENTRIES = {
  'playwright-mcp':     { cmd: 'npx -y @playwright/mcp@0.0.75',        id: 'npm:@playwright/mcp@0.0.75',          dims: NPM_CLEAN },
  'mongodb-mcp-server': { cmd: 'npx -y mongodb-mcp-server@1.10.0',     id: 'npm:mongodb-mcp-server@1.10.0',       dims: NPM_CLEAN },
  'mcp-server-aws':     { cmd: 'uvx awslabs.core-mcp-server==1.0.27',  id: 'pypi:awslabs.core-mcp-server@1.0.27', dims: { ...PYPI_CLEAN, availability: 'yanked' } },
  'mcp-atlassian':      { cmd: 'uvx mcp-atlassian==0.22.0',            id: 'pypi:mcp-atlassian@0.22.0',           dims: { ...PYPI_CLEAN, advisories: 'vulnerable' } },
};

const POSITIVE = new Set(['present', 'verified', 'bound', 'listed', 'clean']);

function record(dims, day) {
  const out = {};
  for (const [dim, status] of Object.entries(dims)) {
    out[dim] = { status, checked_at: day, ...(POSITIVE.has(status) ? { verified_at: day } : {}) };
  }
  return out;
}

function fixtureSkill({ stale = [], env = process.env, with: extra = [] } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-fixture-skill-'));
  // `with`: more of the repository beside the skill (bin/, package.json,
  // action.yml) for a test that runs the CLI or the Action from the copy.
  // Never the DB signature: a staged DB has none.
  for (const p of ['mcp-ecosystem-intelligence', ...extra]) {
    fs.cpSync(path.join(ROOT, p), path.join(root, p), { recursive: true, filter: (src) => !src.endsWith('.sig') });
  }
  const dbFile = path.join(root, 'mcp-ecosystem-intelligence', 'assets', 'tools_database.json');
  const db = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
  const launches = {};
  for (const [name, spec] of Object.entries(ENTRIES)) {
    const t = db.tools.find((x) => x.name === name);
    if (!t) throw new Error(`fixture_skill: ${name} is no longer in the DB; pick another entry`);
    t.install_cmd = spec.cmd;
    t.version = spec.cmd.split(/@|==/).pop();
    t.pkg_integrity = t.pkg_integrity || (spec.cmd.startsWith('npx') ? 'sha512-fixture' : 'sha256-fixture');
    t.trust_evidence = { artifact_id: spec.id, dimensions: record(spec.dims, stale.includes(name) ? STALE_OBSERVED : OBSERVED) };
    const [command, ...args] = spec.cmd.split(/\s+/);
    launches[name] = { command, args };
  }
  fs.writeFileSync(dbFile, JSON.stringify(db, null, 2));
  const scripts = path.join(root, 'mcp-ecosystem-intelligence', 'scripts');
  return {
    root, scripts, dbFile, launches,
    run: (script, args, { cwd = root, env: e = env } = {}) => spawnSync(process.execPath, [path.join(scripts, script), ...args], {
      cwd, encoding: 'utf8', env: e, maxBuffer: 64 * 1024 * 1024,
    }),
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}

module.exports = { fixtureSkill, OBSERVED, STALE_OBSERVED, AS_OF, LATE };
