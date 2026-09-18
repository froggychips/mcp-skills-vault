#!/usr/bin/env node
/**
 * What your MCP servers cost in context, before you ask them anything.
 *
 * Every enabled server injects its whole tool list into the model's system
 * prompt: name, description and JSON schema per tool, on every single request.
 * This repo's own README notes the spread — `mcp-server-fetch` has 1 tool,
 * `gitlab-mcp` has 153 — but nothing ever added it up for a real config. A
 * server you installed once and forgot is a standing cost.
 *
 * Numbers come from the best source available per server, and the source is
 * always stated:
 *   measured  — a tools/list payload recorded by mcp_eval (bytes, ÷4 ≈ tokens)
 *   eval      — the tool count mcp_eval observed
 *   db        — `est_tools_count` from the vault DB
 *   unknown   — nothing to go on; counted as a range, flagged as a guess
 *
 * A token estimate is an estimate. Where only a tool count is known, the range
 * is 200–500 tokens per tool (the figure this repo already documents), and the
 * midpoint is used for the total. Where a payload was measured, bytes÷4 is used
 * — still an approximation, but of the actual text rather than of a count.
 *
 * Usage:
 *   node scripts/token_budget.cjs [--cwd <path>] [--json] [--context <n>]
 *                                 [--all] [--budget <pct>]
 *
 * Exit codes:
 *   0  under budget (or no budget given)
 *   1  --budget exceeded
 *   2  bad arguments
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { readInstalledServers } = require('./lib/installed.cjs');
const {
  estimateServer, matchDbEntry, summarise,
  TOKENS_PER_TOOL_LOW, TOKENS_PER_TOOL_HIGH, TOKENS_PER_TOOL_MID, BYTES_PER_TOKEN,
} = require('./lib/budget.cjs');

const DB_PATH   = path.resolve(__dirname, '../assets/tools_database.json');
const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');

function parseArgs(argv) {
  const opts = { cwd: process.cwd(), json: false, context: 200000, all: false, budget: null, help: false, results: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--all') opts.all = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--cwd') opts.cwd = argv[++i] || opts.cwd;
    else if (a === '--results') opts.results = argv[++i] || null;
    else if (a === '--context') opts.context = Number(argv[++i]);
    else if (a === '--budget') opts.budget = Number(argv[++i]);
    else if (a.startsWith('--')) return { ...opts, error: `unknown flag ${a}` };
  }
  if (!Number.isFinite(opts.context) || opts.context <= 0) return { ...opts, error: '--context must be a positive number' };
  if (opts.budget !== null && (!Number.isFinite(opts.budget) || opts.budget <= 0 || opts.budget > 100)) {
    return { ...opts, error: '--budget must be a percentage between 0 and 100' };
  }
  return opts;
}

const HELP = `token_budget — what your MCP servers cost in context

  node scripts/token_budget.cjs [--cwd <path>] [--json]
                                [--context <tokens>] [--budget <pct>] [--all]

  --cwd <path>       project whose config to read (default: cwd)
  --results <path>   eval results to take measurements from
                     (default: assets/eval_results.json; produce one with
                     \`mcp-vault eval --installed --unsafe --results <path>\`)
  --context <n>      context window to measure against (default: 200000)
  --budget <pct>     exit 1 if the tool surface exceeds this % of the window
  --all              also list the DB entries you don't have installed
  --json             machine-readable
`;

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

function main(argv) {
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`token_budget: ${opts.error}\n\n${HELP}`); return 2; }
  if (opts.help)  { process.stdout.write(HELP); return 0; }

  const db      = (readJson(DB_PATH, { tools: [] }).tools) || [];
  const evals   = (readJson(opts.results || EVAL_PATH, { results: [] }).results) || [];
  const evalBy  = new Map(evals.map((r) => [r.name, r]));
  // A host config we could not read is not a host with no servers in it, and
  // a token total that quietly omits one is worse than no total.
  const unreadable = [];
  const servers = readInstalledServers({ cwd: opts.cwd, onUnreadable: (loc) => unreadable.push(loc) });

  const rows = servers.map((srv) => {
    const dbEntry = matchDbEntry(srv, db);
    const est = estimateServer({ name: srv.name, dbEntry, evalEntry: evalBy.get(srv.name) || (dbEntry && evalBy.get(dbEntry.name)) });
    return {
      ...est,
      host:     srv.host,
      scope:    srv.scope,
      in_vault: !!dbEntry,
      remote:   !!srv.remote,
      // The DB records how to shrink a server's surface where upstream allows it.
      toolsets: dbEntry?.toolsets || null,
    };
  });

  const unknown   = rows.filter((r) => r.tokens === null);
  const totals    = summarise(rows, opts.context);
  const total     = totals.tokens;
  const totalLow  = totals.tokens_low;
  const totalHigh = totals.tokens_high;
  const pct       = (total / opts.context) * 100;

  // Servers the DB says can be narrowed, that are installed at full width.
  const trimmable = rows
    .filter((r) => r.toolsets && (r.tools === null || r.tools > 10))
    .map((r) => ({ name: r.name, tools: r.tools, hint: r.toolsets }));

  const report = {
    schema: 'mcp-vault/token-budget@1',
    unreadable,
    generated_at: new Date().toISOString(),
    cwd: opts.cwd,
    context_window: opts.context,
    servers: rows.sort((a, b) => (b.tokens || 0) - (a.tokens || 0)),
    totals,
    trimmable,
    method: {
      bytes_per_token: BYTES_PER_TOKEN,
      tokens_per_tool: { low: TOKENS_PER_TOOL_LOW, high: TOKENS_PER_TOOL_HIGH, used: TOKENS_PER_TOOL_MID },
      note: 'measured = tools/list payload bytes ÷ 4 (from mcp_eval); eval/db = tool count × per-tool midpoint',
    },
  };

  if (opts.all) {
    const installedNames = new Set(rows.map((r) => r.name));
    report.not_installed = db
      .filter((t) => !installedNames.has(t.name) && Number.isFinite(t.est_tools_count))
      .sort((a, b) => b.est_tools_count - a.est_tools_count)
      .slice(0, 20)
      .map((t) => ({ name: t.name, tools: t.est_tools_count, tokens: Math.round(t.est_tools_count * TOKENS_PER_TOOL_MID) }));
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    if (!rows.length) {
      // …unless a config could not be read, in which case "none configured"
      // is a claim about a file nobody managed to open. Falls through to the
      // exit-2 branch below.
      if (!unreadable.length) {
        process.stdout.write(`No MCP servers configured for ${opts.cwd}.\n`);
        return 0;
      }
    }
    const w = Math.max(20, ...rows.map((r) => r.name.length), 20);
    process.stdout.write(`${'server'.padEnd(w)}  ${'tools'.padStart(6)}  ${'tokens'.padStart(8)}  source\n`);
    process.stdout.write(`${'-'.repeat(w)}  ${'-'.repeat(6)}  ${'-'.repeat(8)}  ------\n`);
    for (const r of report.servers) {
      const tools  = r.tools === null ? '?' : String(r.tools);
      const tokens = r.tokens === null ? '?' : r.tokens.toLocaleString('en-US');
      process.stdout.write(`${r.name.padEnd(w)}  ${tools.padStart(6)}  ${tokens.padStart(8)}  ${r.source}${r.remote ? ' (remote)' : ''}\n`);
    }
    process.stdout.write(`${'-'.repeat(w)}  ${'-'.repeat(6)}  ${'-'.repeat(8)}  ------\n`);
    process.stdout.write(
      `${'TOTAL'.padEnd(w)}  ${String(report.totals.tools).padStart(6)}  ${report.totals.tokens.toLocaleString('en-US').padStart(8)}  ` +
      `≈${report.totals.percent_of_context}% of a ${opts.context.toLocaleString('en-US')}-token window\n`
    );
    process.stdout.write(`${''.padEnd(w)}  ${''.padStart(6)}  range ${totalLow.toLocaleString('en-US')}–${totalHigh.toLocaleString('en-US')}\n`);
    if (unknown.length) {
      process.stdout.write(`\n${unknown.length} server${unknown.length === 1 ? '' : 's'} with no tool count: ${unknown.map((r) => r.name).join(', ')}\n`);
      process.stdout.write(`Run \`mcp-vault eval --name <server> --sandbox\` to measure one.\n`);
    }
    if (trimmable.length) {
      process.stdout.write('\nCan be narrowed (upstream supports it):\n');
      for (const t of trimmable) process.stdout.write(`  ${t.name}${t.tools ? ` (${t.tools} tools)` : ''} — ${t.hint}\n`);
    }
  }

  if (opts.budget !== null && pct > opts.budget) {
    process.stderr.write(`\nTool surface is ${report.totals.percent_of_context}% of the context window, over the ${opts.budget}% budget.\n`);
    return 1;
  }
  // A total that silently omits a config we could not read is not "under
  // budget"; it is a total of an unknown fraction of the servers.
  if (unreadable.length) {
    for (const u of unreadable) process.stderr.write(`token_budget: ${u.path}: ${u.error}\n`);
    return 2;
  }
  return 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

// estimateServer / matchDbEntry are re-exported so the existing tests (and
// anything else importing them from here) keep working after the move to
// lib/budget.cjs.
module.exports = { estimateServer, matchDbEntry, parseArgs, TOKENS_PER_TOOL_LOW, TOKENS_PER_TOOL_HIGH, BYTES_PER_TOKEN };
