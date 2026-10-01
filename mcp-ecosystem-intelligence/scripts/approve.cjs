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
 * The exit code is a Decision (docs/adr/0001): what is still pending after
 * this run — everything, with --dry-run — becomes findings `org/tool-approval`
 * on the server, and `decide()` over the project's effective policy says
 * whether that blocks. It blocks under `toolApproval: "require"`; without
 * it, pending tools are reported and nothing refuses.
 *
 * An approval names the artifact it was made on (the vault entry's, or the
 * configured launch's): after an upgrade, every tool is pending again.
 *
 * Exit codes:
 *   0  nothing left pending, or the policy does not require approval
 *   1  under toolApproval: require, a tool is still pending (--dry-run: before
 *      anything is written; otherwise what --tool left out)
 *   2  bad arguments, no observed tool surface, or an unreadable lockfile
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readWallClock } = require('./lib/clock.cjs');
const { loadEffectivePolicy } = require('./lib/policy_rules.cjs');
const { subject, decide, exitCode, findingsDocument, toJson } = require('./lib/finding.cjs');
const { subjectForTool } = require('./lib/findings_from.cjs');
const { subjectFacts, toolApprovalModel } = require('./lib/org_policy.cjs');
const { readInstalledServers, toInstallCmd } = require('./lib/installed.cjs');
const { emptyLock, lockPath, readLock, writeLock } = require('./lib/lockfile.cjs');
const {
  APPROVALS_KEY, parseToolsFile, observeTools, observationFromSurface,
  pendingTools, approvalFor, approve, describePending, describeLines, HASHES_ONLY_NOTE,
} = require('./lib/tool_approval.cjs');

const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');
const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');

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
  --dry-run         show what is pending and write nothing; exit 1 if the
                    policy (toolApproval: require) would block on it
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

/**
 * What `server` launches: the vault entry of that name, or the project's
 * configured server of that name. Its artifact is what the approval is for.
 */
function launched(server, cwd) {
  let db = [];
  try { db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8')).tools || []; } catch { db = []; }
  const entry = db.find((t) => t.name === server);
  if (entry) return entry;
  let srv = null;
  try { srv = readInstalledServers({ cwd }).find((x) => x.name === server && !x.remote) || null; } catch { srv = null; }
  return srv ? { name: server, install_cmd: srv.install_cmd || toInstallCmd(srv) } : null;
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`approve: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }
  // When an approval was made is an observation: the wall clock, read once.
  // There is no --as-of: a replayed instant must never date a real approval.
  const now = readWallClock();
  const tool = launched(opts.server, opts.cwd);
  const artifactId = tool ? subjectFacts(tool).artifact_id : null;
  const subj = tool ? subjectForTool(tool) : subject.artifact({ entry: opts.server });

  // The policy that governs this approval, loaded and checked before
  // anything is written: an invalid one is not a policy, and approving under
  // it would change mcp.lock.json on a bar nobody set.
  const loaded = loadEffectivePolicy(opts.cwd);
  if (!loaded.ok) {
    process.stderr.write(`approve: policy error in ${loaded.path || '.mcp-vault.policy.json'}:\n`);
    for (const e of loaded.errors) process.stderr.write(`  - ${e}\n`);
    return 2;
  }

  const seen = observe(opts);
  if (seen.error) { process.stderr.write(`approve: ${seen.error}\n`); return 2; }
  const { observation, source } = seen;

  const file = lockPath(opts.cwd);
  const found = readLock(file);
  if (!found.ok) { process.stderr.write(`approve: ${found.error}\n`); return 2; }
  const lock = found.lock || emptyLock(now);
  const approvals = { ...(lock[APPROVALS_KEY] || {}) };
  const before = approvals[opts.server] || null;
  // An approval of another artifact does not count for this one.
  const bound = approvalFor(before, artifactId);

  const pending = pendingTools(bound, observation);
  const details = describePending(pending, bound, observation);
  const pendingCount = pending.added.length + pending.changed.length;

  let result = null;
  if (!opts.dryRun && (pendingCount || pending.removed.length || opts.tools.length)) {
    result = approve(before, observation, { tools: opts.tools, now, artifactId });
    if (result.error) { process.stderr.write(`approve: ${result.error}\n`); return 2; }
    approvals[opts.server] = result.record;
    lock[APPROVALS_KEY] = Object.fromEntries(Object.keys(approvals).sort().map((k) => [k, approvals[k]]));
    writeLock(file, lock);
  }

  // What is pending now, as findings, and the policy's answer to it.
  const model = toolApprovalModel({
    subject: subj, server: opts.server, approved: result ? result.record : before,
    observation, currentArtifactId: artifactId, asOf: now,
  });
  const facts = { [subj.id]: { mode: 'approval', org: { tool_approval: model.fact } } };
  const decisions = decide(model.findings, loaded.policy, now, { subjects: [subj], facts });

  if (opts.json) {
    process.stdout.write(`${JSON.stringify({
      schema:   'mcp-vault/approve@1',
      server:   opts.server,
      lockfile: file,
      observed: { source, count: observation.fingerprint.count, detailed: observation.detailed },
      artifact_id: artifactId,
      previously_approved_at: before ? before.approved_at : null,
      // Set when the previous approval was made on another artifact.
      previous_artifact_id: before && !bound ? before.artifact_id || null : null,
      pending:  details,
      approved: result ? result.approved : [],
      remaining: result ? result.remaining : [...pending.added, ...pending.changed.map((c) => c.name)].sort(),
      dropped:  result ? result.dropped : [],
      wrote:    Boolean(result),
      // Additive (mcp-vault/findings@1): what is still pending, and the
      // Decision the exit code is.
      findings: toJson(findingsDocument({ asOf: now, findings: model.findings, decisions, scope: 'approval', policy: loaded.policy, facts })),
    }, null, 2)}\n`);
  } else {
    process.stdout.write(`${B}${opts.server}${RS}  ${DM}observed ${observation.fingerprint.count} tools from ${source}${RS}\n`);
    process.stdout.write(before
      ? `${DM}last approved ${before.approved_at} (${before.count} tools${before.artifact_id ? `, ${before.artifact_id}` : ''})${RS}\n`
      : `${DM}nothing approved for this server yet${RS}\n`);
    if (before && !bound) process.stdout.write(`${YL}that approval is for ${before.artifact_id}; ${opts.server} now launches ${artifactId} — every tool is pending again${RS}\n`);
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

  const [d] = decisions;
  if (d.fails && !opts.json) process.stdout.write(`${YL}Blocked by ${d.decided_by} (toolApproval: require)${RS}\n`);
  return exitCode(decisions) === 1 ? 1 : 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, observe, main };
