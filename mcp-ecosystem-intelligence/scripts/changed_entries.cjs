#!/usr/bin/env node
/**
 * changed_entries.cjs — which DB entries changed in a way that warrants a re-smoke.
 *
 * "Changed" is deliberately narrow: `install_cmd` and `version`. Those are the
 * two fields that decide *what artifact actually gets executed*, so they're the
 * only ones whose change can alter behaviour. Metric churn (stars,
 * health_score, last_checked) rewrites most of the file every week and must
 * not drag ~100 entries through a behavioural smoke for nothing.
 *
 * An entry absent from the base is reported as changed — a newly promoted
 * server has never been smoked at this version.
 *
 * Extracted from an inline `node -e` script that lived in security-scan.yml so
 * two jobs can share one definition of "changed" instead of drifting apart:
 *   - mcp-eval-pr      diffs the PR against its base sha
 *   - refresh-hashes   diffs the freshly written DB against HEAD, because the
 *                      PR-triggered job can never see the bot's own PR
 *                      (GitHub doesn't trigger workflows for PRs opened with
 *                      GITHUB_TOKEN)
 *
 * Usage:
 *   changed_entries.cjs                     diff working tree against HEAD
 *   changed_entries.cjs --base <git-ref>    diff against an explicit ref
 *   changed_entries.cjs --db <path>         override DB path
 *   changed_entries.cjs --json              emit a JSON array instead of lines
 *
 * Output: one entry name per line on stdout (empty output = nothing changed),
 * with a human-readable count on stderr. A base ref that has no DB yet — a
 * fresh repo, an orphan branch — yields "everything changed" rather than an
 * error, which is the safe direction for a smoke gate.
 *
 * Exit codes:
 *   0  comparison completed (whether or not anything changed)
 *   2  bad arguments / unreadable working-tree DB
 */

'use strict';

const path = require('path');
const cp   = require('child_process');
const { readDb } = require('./lib/db_io.cjs');

const DEFAULT_DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');
// Repo-relative path is what `git show <ref>:<path>` needs.
const DB_REPO_PATH = 'mcp-ecosystem-intelligence/assets/tools_database.json';

function parseArgs(argv) {
  const opts = { base: 'HEAD', db: DEFAULT_DB_PATH, dbRepoPath: DB_REPO_PATH, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const next = argv[i + 1];
    switch (argv[i]) {
      case '--base': opts.base = next; i++; break;
      case '--db':   opts.db   = next; i++; break;
      case '--json': opts.json = true; break;
      case '-h':
      case '--help': opts.help = true; break;
      default:
        if (argv[i].startsWith('--')) {
          process.stderr.write(`Unknown flag: ${argv[i]}\n`);
          opts.help = true;
        }
    }
  }
  return opts;
}

// The behavioural identity of an entry: change either half and you are
// running different code than the last smoke covered.
function smokeKey(tool) {
  return JSON.stringify([tool.install_cmd ?? null, tool.version ?? null]);
}

// Pure core, so the diff rule is testable without a git repo.
function changedEntries(baseTools, headTools) {
  const base = new Map((baseTools || []).map(t => [t.name, smokeKey(t)]));
  return (headTools || [])
    .filter(t => base.get(t.name) !== smokeKey(t))
    .map(t => t.name);
}

// Returns [] when the ref carries no DB — caller treats that as
// "everything in head is new".
function loadFromRef(ref, dbRepoPath) {
  try {
    const raw = cp.execSync(`git show ${ref}:${dbRepoPath}`, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 64 * 1024 * 1024,
    });
    return JSON.parse(raw).tools || [];
  } catch {
    return [];
  }
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write('changed_entries.cjs [--base <ref>] [--db <path>] [--json]\n');
    return 0;
  }

  let headTools;
  try {
    headTools = readDb(opts.db).db.tools || [];
  } catch (e) {
    process.stderr.write(`cannot read working-tree DB at ${opts.db}: ${e.message}\n`);
    return 2;
  }

  const changed = changedEntries(loadFromRef(opts.base, opts.dbRepoPath), headTools);

  process.stdout.write(opts.json
    ? JSON.stringify(changed, null, 2) + '\n'
    : (changed.length ? changed.join('\n') + '\n' : ''));
  process.stderr.write(`changed entries vs ${opts.base}: ${changed.length ? changed.join(', ') : '(none)'}\n`);
  return 0;
}

if (require.main === module) process.exit(main());

module.exports = { changedEntries, smokeKey, parseArgs };
