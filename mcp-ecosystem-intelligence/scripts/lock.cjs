#!/usr/bin/env node
/**
 * mcp-vault lock — freeze what was verified, and notice when it moves.
 *
 * The gap: the gate verifies `server@1.2.3` down to its transitive tree, then
 * `.mcp.json` launches `npx -y server@1.2.3` and npm re-resolves that tree at
 * every start. A pinned root does not pin its dependencies — `server@1.2.3`
 * depending on `lib: ^2` runs whatever `lib` published most recently. The tree
 * that was checked and the tree that runs are related only by hope.
 *
 * Three commands:
 *
 *   lock                write mcp.lock.json for the servers this project
 *                       configures (or --entry <name> from the vault DB)
 *   lock --check        resolve again and diff against the lockfile; exit 1 on
 *                       any difference. This is the CI form.
 *   lock --vendor       install the locked tree into .mcp-vault/<name>/ with
 *                       `npm ci --ignore-scripts` and print the launch command
 *                       that runs *that* copy instead of resolving at start.
 *
 * `--check` is the one worth running on a schedule: a dependency that resolved
 * to a new version is ordinary, a dependency that resolved to the *same*
 * version with different bytes is not, and neither is a tree that grew an
 * install script since it was locked. Those read differently in the output.
 *
 * `--vendor` is the only one that actually stops the re-resolution, and it is
 * opt-in because it puts a node_modules tree in the project. Without it the
 * lockfile is a tripwire rather than a guarantee — which is still worth having,
 * and is honest about which it is.
 *
 * Usage:
 *   node scripts/lock.cjs [--cwd <path>] [--entry <name>] [--check] [--vendor]
 *                         [--json] [--results <eval.json>]
 *
 * Exit codes:
 *   0  lock written, or --check found no difference
 *   1  --check found a difference (or --vendor failed)
 *   2  bad arguments / nothing to lock
 */

'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readInstalledServers, toInstallCmd } = require('./lib/installed.cjs');
const { toTypedEntry, artifactId } = require('./lib/entry_model.cjs');
const { resolveNpmTree } = require('./lib/deps.cjs');
const { isExactVersion } = require('./lib/install_cmd.cjs');
const {
  LOCK_FILENAME, emptyLock, lockEntry, lockPath, readLock, writeLock, diffLock, vendorFiles,
} = require('./lib/lockfile.cjs');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');
const VENDOR_DIR = '.mcp-vault';

const T  = process.stdout.isTTY;
const B  = T ? '\x1b[1m'  : '';
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

// Changes that are not explained by an upgrade. Reported separately because
// they are the ones with no innocent reading.
const SUSPICIOUS = new Set(['tree-integrity', 'surface-only', 'install-script']);

function parseArgs(argv) {
  const opts = {
    cwd: process.cwd(), entry: null, check: false, vendor: false,
    json: false, results: null, help: false,
    // A lockfile lives in a project and gets committed. Locking the *user*
    // scope's servers would write one developer's global config into a shared
    // file and then fail --check on everyone else's machine.
    includeUser: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--check') opts.check = true;
    else if (a === '--vendor') opts.vendor = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--include-user') opts.includeUser = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--cwd') opts.cwd = argv[++i] || opts.cwd;
    else if (a === '--entry') opts.entry = argv[++i] || null;
    else if (a === '--results') opts.results = argv[++i] || null;
    else return { ...opts, error: `unknown flag ${a}` };
  }
  if (opts.check && opts.vendor) return { ...opts, error: '--check and --vendor do different things; run one at a time' };
  return opts;
}

const HELP = `lock — freeze the verified dependency tree, and notice when it moves

  node scripts/lock.cjs [--cwd <path>] [--entry <name>] [--check] [--vendor] [--json]

  (no flags)        write mcp.lock.json for this project's configured servers
  --entry <name>    lock one vault DB entry instead of what is configured
  --check           resolve again and diff against the lockfile (exit 1 on drift)
  --vendor          npm ci the locked tree into .mcp-vault/<name>/ and print the
                    launch command that uses it
  --results <file>  eval results to take tool-surface fingerprints from
                    (default: assets/eval_results.json)
  --include-user    also lock user-scope servers (~/.claude.json and friends).
                    Off by default: a committed lockfile should not describe
                    one developer's global config.
`;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

/** The servers to lock: one DB entry, or everything this project configures. */
function subjects(opts, db) {
  if (opts.entry) {
    const tool = (db.tools || []).find((t) => t.name === opts.entry);
    return tool ? [tool] : [];
  }
  // A configured server is the subject of record: the lockfile describes what
  // this project runs, and the DB is consulted for the pin to compare against.
  return readInstalledServers({ cwd: opts.cwd })
    .filter((srv) => !srv.remote)
    .filter((srv) => opts.includeUser || srv.scope !== 'user')
    .map((srv) => {
      const install_cmd = srv.install_cmd || toInstallCmd(srv);
      const dbEntry = (db.tools || []).find((t) => t.name === srv.name)
        || (db.tools || []).find((t) => t.install_cmd && install_cmd && t.install_cmd === install_cmd);
      return {
        name:        srv.name,
        install_cmd,
        version:     dbEntry ? dbEntry.version : null,
        pkg_integrity: dbEntry ? dbEntry.pkg_integrity : null,
        source_url:  dbEntry ? dbEntry.source_url : null,
        _scope:      srv.scope,
        _in_vault:   Boolean(dbEntry),
      };
    });
}

/** Resolve one server into a lock record. */
async function lockOne(tool, { surfaceByName }) {
  const typed = toTypedEntry(tool);
  if (!typed) return { name: tool.name, error: 'no launch command to lock' };
  const a = typed.artifact;

  const artifact = {
    ecosystem: a.ecosystem,
    id:        artifactId(a),
    package:   a.package || null,
    version:   a.version || null,
    image:     a.image || null,
    digest:    a.digest || null,
    integrity: a.integrity || null,
  };

  const entry = { tool, artifact, surface: surfaceByName.get(tool.name) || null };

  // An unpinned launch cannot be locked, and pretending otherwise is worse than
  // refusing. `npx -y pkg` and `pkg@latest` resolve at every start, so a tree
  // resolved here describes a moment, not the thing that will run —
  // `chrome-devtools-mcp@latest` produced a one-package "tree" that would then
  // have failed --check the next day for no reason anyone could act on.
  const runner = String(tool.install_cmd || '').trim().split(/\s+/)[0];
  const pinned = a.ecosystem === 'oci'
    ? Boolean(a.digest)
    : isExactVersion(runner, a.version);
  artifact.pinned = pinned;
  if (!pinned) {
    return {
      name:  tool.name,
      error: a.version
        ? `launch asks for "${a.version}", which resolves at every start — pin it before locking`
        : 'launch command carries no version, so it resolves at every start — pin it before locking',
      entry: lockEntry(entry),
    };
  }

  // Only npm has a way to resolve a whole tree without building anything. PyPI
  // resolution means building wheels, and an OCI digest already pins every
  // byte in the image — so for those the lockfile records the artifact and says
  // nothing about a tree, rather than recording an empty one as if it had
  // looked.
  if (a.ecosystem === 'npm' && a.package) {
    const tree = await resolveNpmTree(a.package, a.version, { keepLockfile: true });
    if (!tree.ok) return { name: tool.name, error: `could not resolve the dependency tree: ${tree.error}`, entry: lockEntry(entry) };
    entry.tree = { ...tree, resolved_at: new Date().toISOString().slice(0, 10) };
  }

  return { name: tool.name, entry: lockEntry(entry), tree_resolved: Boolean(entry.tree) };
}

/**
 * Install the locked tree, so that nothing is resolved at launch.
 *
 * `npm ci` against the *stored* lockfile, never a fresh resolve. The first
 * version of this ran `npm install --package-lock-only` first and then `npm
 * ci`, which quietly defeated the whole feature: by the time it ran,
 * `content-type` had published a new release, so the tree that got installed
 * was not the tree that was locked. A vendor step that re-resolves is just a
 * slower `npx`.
 *
 * `--ignore-scripts` because the point is that nothing in this tree runs code
 * before it is launched, and `npm ci` because it refuses to proceed when
 * package.json and the lockfile disagree — the package.json is generated from
 * the lockfile's own root entry so they cannot.
 */
function vendorOne(name, entry, cwd) {
  const files = vendorFiles(entry);
  if (!files) {
    return {
      name, ok: false,
      error: entry?.artifact?.ecosystem === 'npm'
        ? 'no stored npm lockfile for this server — re-run `mcp-vault lock` to record one'
        : `only npm servers can be vendored (this one is ${entry?.artifact?.ecosystem || 'unknown'})`,
    };
  }
  const dir = path.join(cwd, VENDOR_DIR, name.replace(/[^A-Za-z0-9._@/-]/g, '_').replace(/\//g, '__'));
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), `${JSON.stringify(files.packageJson, null, 2)}\n`);
    fs.writeFileSync(path.join(dir, 'package-lock.json'), `${JSON.stringify(files.packageLock, null, 2)}\n`);
    execFileSync('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund', '--silent'],
      { cwd: dir, stdio: 'pipe', timeout: 300000 });
  } catch (e) {
    const detail = (e.stderr && e.stderr.toString().split('\n').find((l) => l.trim())) || e.message;
    return { name, ok: false, error: detail.slice(0, 200) };
  }

  // The launch command: whatever bin the package declares, inside our tree.
  const pkgDir = path.join(dir, 'node_modules', entry.artifact.package);
  let bin = null;
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
    const names = typeof meta.bin === 'string' ? [path.basename(entry.artifact.package)] : Object.keys(meta.bin || {});
    bin = names[0] || null;
  } catch { /* no bin: the caller is told, rather than handed a guess */ }

  const rel = path.relative(cwd, dir);
  return {
    name, ok: true, dir: rel,
    launch: bin ? path.join(rel, 'node_modules', '.bin', bin) : null,
    note: bin ? null : 'the package declares no bin; launch it by its own entry point',
  };
}

async function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`lock: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }

  const db      = readJson(DB_PATH, { tools: [] });
  const evals   = readJson(opts.results || EVAL_PATH, { results: [] }).results || [];
  const surfaceByName = new Map(
    evals.filter((r) => r.surface && r.surface.sha256)
      .map((r) => [r.name, { ...r.surface, observed_at: (r.checked_at || '').slice(0, 10) || null }])
  );

  const targets = subjects(opts, db);
  if (!targets.length) {
    process.stderr.write(opts.entry
      ? `lock: no entry named "${opts.entry}" in the vault DB\n`
      : `lock: no local MCP servers configured for ${opts.cwd}\n`);
    return 2;
  }

  const file  = lockPath(opts.cwd);
  const found = readLock(file);
  if (!found.ok) { process.stderr.write(`lock: ${found.error}\n`); return 2; }

  const fresh = emptyLock();
  const errors = [];
  for (const tool of targets) {
    if (!opts.json) process.stderr.write(`resolving ${tool.name}…\n`);
    const res = await lockOne(tool, { surfaceByName });
    if (res.error) errors.push(res);
    if (res.entry) fresh.servers[res.name] = res.entry;
  }

  // ── --vendor ──
  if (opts.vendor) {
    const results = [];
    for (const [name, entry] of Object.entries(fresh.servers)) {
      if (!opts.json) process.stderr.write(`vendoring ${name}…\n`);
      results.push(vendorOne(name, entry, opts.cwd));
    }
    writeLock(file, fresh);
    if (opts.json) {
      process.stdout.write(`${JSON.stringify({ schema: 'mcp-vault/lock-vendor@1', lockfile: file, vendored: results }, null, 2)}\n`);
    } else {
      for (const r of results) {
        if (!r.ok) { process.stdout.write(`${RD}FAIL${RS} ${r.name} — ${r.error}\n`); continue; }
        process.stdout.write(`${GN}OK${RS}   ${r.name} → ${r.dir}\n`);
        if (r.launch) process.stdout.write(`     launch with: ${B}${r.launch}${RS}\n`);
        if (r.note)   process.stdout.write(`     ${DM}${r.note}${RS}\n`);
      }
      process.stdout.write(`\nLockfile: ${file}\n`);
      process.stdout.write(`${DM}Point your host config at the launch paths above; nothing is resolved at start.\n`
        + `Add ${VENDOR_DIR}/ to .gitignore unless you mean to commit the tree.${RS}\n`);
    }
    return results.some((r) => !r.ok) ? 1 : 0;
  }

  // ── --check ──
  if (opts.check) {
    if (found.missing) {
      process.stderr.write(`lock: no ${LOCK_FILENAME} in ${opts.cwd} — run \`mcp-vault lock\` first\n`);
      return 2;
    }
    const diff = diffLock(found.lock, fresh);
    const suspicious = diff.servers.filter((s) => s.changes.some((c) => SUSPICIOUS.has(c.kind)));
    if (opts.json) {
      process.stdout.write(`${JSON.stringify({
        schema: 'mcp-vault/lock-check@1',
        lockfile: file,
        locked_at: found.lock.generated_at,
        changed: diff.servers.length,
        suspicious: suspicious.map((s) => s.name),
        servers: diff.servers,
        errors: errors.map((e) => ({ name: e.name, error: e.error })),
      }, null, 2)}\n`);
    } else if (!diff.servers.length) {
      process.stdout.write(`${GN}No change${RS} — every locked tree resolves the same as when ${LOCK_FILENAME} was written (${found.lock.generated_at.slice(0, 10)}).\n`);
    } else {
      for (const s of diff.servers) {
        const bad = s.changes.some((c) => SUSPICIOUS.has(c.kind));
        process.stdout.write(`${bad ? RD : YL}${s.name}${RS}\n`);
        for (const c of s.changes) {
          process.stdout.write(`  ${SUSPICIOUS.has(c.kind) ? RD : DM}${c.kind.padEnd(15)}${RS} ${c.detail}\n`);
        }
      }
      process.stdout.write(`\n${diff.servers.length} server${diff.servers.length === 1 ? '' : 's'} differ from the lockfile`);
      process.stdout.write(suspicious.length
        ? `, ${RD}${suspicious.length} with a change that an upgrade does not explain${RS}.\n`
        : `. All of it looks like ordinary dependency movement — review, then \`mcp-vault lock\` to accept.\n`);
    }
    for (const e of errors) process.stderr.write(`${YL}could not check ${e.name}: ${e.error}${RS}\n`);
    // An entry that could not be resolved is not a clean check: --check exists
    // to answer "is it still the same", and "we don't know" is not a yes.
    return diff.servers.length || errors.length ? 1 : 0;
  }

  // ── write ──
  writeLock(file, fresh);
  if (opts.json) {
    process.stdout.write(`${JSON.stringify({ schema: 'mcp-vault/lock-write@1', lockfile: file, servers: Object.keys(fresh.servers), errors: errors.map((e) => ({ name: e.name, error: e.error })) }, null, 2)}\n`);
  } else {
    const trees = Object.values(fresh.servers).filter((s) => s.tree).length;
    const surfaces = Object.values(fresh.servers).filter((s) => s.surface).length;
    const pkgs = Object.values(fresh.servers).reduce((n, s) => n + (s.tree ? s.tree.count : 0), 0);
    // The size is worth saying: the file carries npm's own lockfile per server,
    // which is what makes `--vendor` install the locked tree rather than a
    // fresh resolve, and it is not small.
    let kb = null;
    try { kb = Math.round(fs.statSync(file).size / 1024); } catch { /* just a nicety */ }
    process.stdout.write(`Wrote ${file}${kb === null ? '' : ` (${kb} KB)`}\n`);
    process.stdout.write(`  ${Object.keys(fresh.servers).length} server(s), ${trees} with a resolved tree (${pkgs} packages), ${surfaces} with a tool-surface fingerprint\n`);
    for (const e of errors) process.stdout.write(`  ${YL}${e.name}: ${e.error}${RS}\n`);
    process.stdout.write(`${DM}\`mcp-vault lock --check\` compares a fresh resolve against this file.\n`
      + `\`mcp-vault lock --vendor\` installs the locked tree so nothing resolves at launch.${RS}\n`);
  }
  return 0;
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => exitAfterFlush(code)).catch((e) => {
    process.stderr.write(`lock: ${e.stack || e.message}\n`);
    exitAfterFlush(2);
  });
}

module.exports = { parseArgs, subjects, lockOne, vendorOne, SUSPICIOUS, VENDOR_DIR };
