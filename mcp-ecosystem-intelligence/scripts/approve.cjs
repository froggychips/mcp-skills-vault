#!/usr/bin/env node
/**
 * mcp-vault approve <server> — approve a server's tools, one by one if need be.
 *
 * With `"toolApproval": "require"` in the policy, a tool reaches the gate's
 * "allow" only once its description and input schema hashes are recorded as
 * approved in mcp.lock.json. A new tool, or one whose description or schema
 * changed since, blocks `verify` / `install` / `explain` until somebody runs
 * this and commits the lockfile — so the approval is a reviewed diff with an
 * author, not a side effect of regenerating a file. See lib/tool_approval.cjs.
 *
 * What it shows before writing is the point: which tools are new, which
 * changed and in what — description or schema, and with a raw tools/list
 * (`--tools`) the new description text and which parameters appeared,
 * disappeared or changed type.
 *
 * Where the observation comes from:
 *   --tools <file>    a saved tools/list result (array, { tools }, or
 *                     { result: { tools } }). Full detail.
 *   --results <file>  eval results (default: assets/eval_results.json), keyed by
 *                     server name. Hashes only — the diff says which fields
 *                     changed, not how.
 *
 * Usage:
 *   node scripts/approve.cjs <server> [--tool <name>]... [--tools <file>]
 *                            [--results <file>] [--cwd <path>] [--dry-run] [--json]
 *
 * Exit codes:
 *   0  approved, or nothing was pending
 *   1  --dry-run, and something is pending approval
 *   2  bad arguments, no observed tool surface, or an unreadable lockfile
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { emptyLock, lockPath, readLock, writeLock } = require('./lib/lockfile.cjs');
const {
  APPROVALS_KEY, parseToolsFile, observeTools, observationFromSurface,
  pendingTools, approve, describePending, describeLines, HASHES_ONLY_NOTE,
} = require('./lib/tool_approval.cjs');

const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');

const T  = process.stdout.isTTY;
const B  = T ? '\x1b[1m'  : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

const HELP = `approve — approve a server's tools in mcp.lock.json

  node scripts/approve.cjs <server> [--tool <name>]... [--tools <file>] [--dry-run] [--json]

  --tool <name>     approve only this tool (repeatable); the rest stay pending
  --tools <file>    a saved tools/list result: shows the new descriptions and
                    which parameters changed, and records parameter shapes
  --results <file>  eval results to read the observed surface from
                    (default: assets/eval_results.json; hashes only)
  --cwd <path>      the project whose mcp.lock.json is updated
  --dry-run         show what is pending and exit 1 if anything is; write nothing
`;

function parseArgs(argv) {
  const opts = { server: null, tools: [], toolsFile: null, results: null, cwd: process.cwd(), dryRun: false, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--dry-run') opts.dryRun = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--tool') { const v = argv[++i]; if (!v) return { ...opts, error: '--tool needs a tool name' }; opts.tools.push(v); }
    else if (a === '--tools') { opts.toolsFile = argv[++i] || null; if (!opts.toolsFile) return { ...opts, error: '--tools needs a file' }; }
    else if (a === '--results') { opts.results = argv[++i] || null; if (!opts.results) return { ...opts, error: '--results needs a file' }; }
    else if (a === '--cwd') opts.cwd = argv[++i] || opts.cwd;
    else if (a.startsWith('--')) return { ...opts, error: `unknown flag ${a}` };
    else if (!opts.server) opts.server = a;
    else return { ...opts, error: 'approve takes one server name' };
  }
  if (!opts.server && !opts.help) return { ...opts, error: 'which server? `mcp-vault approve <server>`' };
  return opts;
}

/** What the server presents now, and where that was read from. */
function observe(opts) {
  if (opts.toolsFile) {
    let doc;
    try { doc = JSON.parse(fs.readFileSync(opts.toolsFile, 'utf8')); }
    catch (e) { return { error: `could not read ${opts.toolsFile}: ${e.message}` }; }
    const tools = parseToolsFile(doc);
    if (!tools) return { error: `${opts.toolsFile} is not a tools/list result (expected an array, { tools } or { result: { tools } })` };
    return { observation: observeTools(tools), source: opts.toolsFile };
  }
  const file = opts.results || EVAL_PATH;
  let doc;
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return { error: `could not read ${file}: ${e.message}` }; }
  const row = (doc.results || []).find((r) => r && r.name === opts.server);
  const observation = row ? observationFromSurface(row.surface) : null;
  if (!observation) {
    return { error: `no tool surface recorded for "${opts.server}" in ${file} — run \`mcp-vault eval --name ${opts.server} --sandbox\`, or pass --tools <tools.json>` };
  }
  return { observation, source: `${file}${row.checked_at ? ` (${String(row.checked_at).slice(0, 10)})` : ''}` };
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`approve: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }

  const seen = observe(opts);
  if (seen.error) { process.stderr.write(`approve: ${seen.error}\n`); return 2; }
  const { observation, source } = seen;

  const file = lockPath(opts.cwd);
  const found = readLock(file);
  if (!found.ok) { process.stderr.write(`approve: ${found.error}\n`); return 2; }
  const lock = found.lock || emptyLock();
  const approvals = { ...(lock[APPROVALS_KEY] || {}) };
  const before = approvals[opts.server] || null;

  const pending = pendingTools(before, observation);
  const details = describePending(pending, before, observation);
  const pendingCount = pending.added.length + pending.changed.length;

  let result = null;
  if (!opts.dryRun && (pendingCount || pending.removed.length || opts.tools.length)) {
    result = approve(before, observation, { tools: opts.tools });
    if (result.error) { process.stderr.write(`approve: ${result.error}\n`); return 2; }
    approvals[opts.server] = result.record;
    lock[APPROVALS_KEY] = Object.fromEntries(Object.keys(approvals).sort().map((k) => [k, approvals[k]]));
    writeLock(file, lock);
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify({
      schema:   'mcp-vault/approve@1',
      server:   opts.server,
      lockfile: file,
      observed: { source, count: observation.fingerprint.count, detailed: observation.detailed },
      previously_approved_at: before ? before.approved_at : null,
      pending:  details,
      approved: result ? result.approved : [],
      remaining: result ? result.remaining : [...pending.added, ...pending.changed.map((c) => c.name)].sort(),
      dropped:  result ? result.dropped : [],
      wrote:    Boolean(result),
    }, null, 2)}\n`);
  } else {
    process.stdout.write(`${B}${opts.server}${RS}  ${DM}observed ${observation.fingerprint.count} tools from ${source}${RS}\n`);
    process.stdout.write(before
      ? `${DM}last approved ${before.approved_at} (${before.count} tools)${RS}\n`
      : `${DM}nothing approved for this server yet${RS}\n`);
    if (!details.length) {
      process.stdout.write(`\n${GN}Nothing pending${RS} — every tool matches its approval.\n`);
    } else {
      process.stdout.write('\n');
      for (const line of describeLines(details)) {
        const colour = line.startsWith('+') || line.startsWith('~') ? YL : (line.startsWith('-') ? DM : '');
        process.stdout.write(`  ${colour}${line}${colour ? RS : ''}\n`);
      }
      if (!observation.detailed && details.some((d) => d.change !== 'removed')) process.stdout.write(`\n${DM}${HASHES_ONLY_NOTE}${RS}\n`);
    }
    if (opts.dryRun) {
      process.stdout.write(pendingCount ? `\n${pendingCount} tool(s) pending — nothing written (--dry-run).\n` : '');
    } else if (result) {
      process.stdout.write(`\n${GN}Approved${RS} ${result.approved.length ? result.approved.join(', ') : '(no pending tools)'} in ${file}\n`);
      if (result.remaining.length) process.stdout.write(`${YL}Still pending: ${result.remaining.join(', ')}${RS}\n`);
      if (result.dropped.length) process.stdout.write(`${DM}Dropped approvals for tools no longer offered: ${result.dropped.join(', ')}${RS}\n`);
      process.stdout.write(`${DM}Commit ${path.basename(file)}: the approval is that diff.${RS}\n`);
    }
  }

  return opts.dryRun && pendingCount ? 1 : 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, observe, main };
