'use strict';
/**
 * What a set of MCP servers costs in context, before anything is asked of them.
 *
 * Every enabled server injects its whole tool list into the model's system
 * prompt — name, description and JSON schema per tool, on every single request.
 * `token_budget` could already add that up for a config; the number was a
 * report nobody ran at the moment it mattered, which is the moment before
 * adding one more server. This module exists so the same arithmetic can be
 * done by the installer, by the report, and by a policy, with one definition of
 * where the numbers come from.
 *
 * Provenance is always attached, because these are estimates of different
 * quality and collapsing them into one number would be the usual lie:
 *
 *   measured  a tools/list payload recorded by mcp_eval (bytes ÷ 4 ≈ tokens)
 *   eval      the tool count mcp_eval observed
 *   db        `est_tools_count` from the vault DB
 *   unknown   nothing to go on — counted as nothing, reported as a gap
 *
 * An unknown server is the honest hole in any total: it is not zero, it is
 * unmeasured, and a budget check that silently treats it as zero will pass a
 * config that is over. Callers get `unknown_servers` and are expected to say so.
 *
 * API:
 *   estimateServer({ name, dbEntry, evalEntry })  -> { tools, tokens, low, high, source }
 *   matchDbEntry(server, db)                      -> entry | null
 *   summarise(rows, contextWindow)                -> { tokens, percent_of_context, … }
 *   wouldExceed({ rows, adding, policy, context }) -> { over, … } | null
 */

const { npmPkgName, pypiPkgName } = require('./install_cmd.cjs');

// The per-tool range this repo documents. Used when all we have is a count.
const TOKENS_PER_TOOL_LOW  = 200;
const TOKENS_PER_TOOL_HIGH = 500;
const TOKENS_PER_TOOL_MID  = (TOKENS_PER_TOOL_LOW + TOKENS_PER_TOOL_HIGH) / 2;
// Rough bytes-per-token for English text with JSON punctuation.
const BYTES_PER_TOKEN = 4;
// What a "context window" means when nobody said. Claude Code's default.
const DEFAULT_CONTEXT = 200000;

/**
 * Tool count and token estimate for one server, with its provenance.
 *
 * A run that listed *no* tools is not a measurement of a free server: it is a
 * server that did not work. `mcp-atlassian` answered with an empty list (72
 * tools in the DB, 0 observed) and the payload arithmetic turned that into
 * "≈1 token" — a config full of broken servers would have looked free. A
 * zero-tool result falls back to what the DB says, and failing that, to
 * 'unknown'.
 */
function usableMeasurement(evalEntry) {
  return Boolean(evalEntry)
    && Number.isFinite(evalEntry.tools_payload_bytes) && evalEntry.tools_payload_bytes > 0
    && Number.isFinite(evalEntry.tool_count) && evalEntry.tool_count > 0;
}

function estimateServer({ name, dbEntry, evalEntry }) {
  if (usableMeasurement(evalEntry)) {
    const tokens = Math.round(evalEntry.tools_payload_bytes / BYTES_PER_TOKEN);
    return {
      name,
      tools:  Number.isFinite(evalEntry.tool_count) ? evalEntry.tool_count : null,
      tokens, low: tokens, high: tokens,
      source: 'measured',
    };
  }
  const observed = Number.isFinite(evalEntry?.tool_count) && evalEntry.tool_count > 0 ? evalEntry.tool_count : null;
  const count = observed !== null ? observed
    : (Number.isFinite(dbEntry?.est_tools_count) ? dbEntry.est_tools_count : null);
  if (count === null) {
    return { name, tools: null, tokens: null, low: null, high: null, source: 'unknown' };
  }
  return {
    name,
    tools:  count,
    tokens: Math.round(count * TOKENS_PER_TOOL_MID),
    low:    count * TOKENS_PER_TOOL_LOW,
    high:   count * TOKENS_PER_TOOL_HIGH,
    source: observed !== null ? 'eval' : 'db',
  };
}

/** Match a configured server to a DB entry by name, then by package name. */
function matchDbEntry(server, db) {
  const byName = db.find((t) => t.name === server.name);
  if (byName) return byName;
  const pkg = server.install_cmd
    ? (npmPkgName(server.install_cmd) || pypiPkgName(server.install_cmd))
    : null;
  if (!pkg) return null;
  return db.find((t) => {
    const other = t.install_cmd ? (npmPkgName(t.install_cmd) || pypiPkgName(t.install_cmd)) : null;
    return other && other === pkg;
  }) || null;
}

/** Totals for a set of per-server estimates. */
function summarise(rows, contextWindow = DEFAULT_CONTEXT) {
  const known   = rows.filter((r) => r.tokens !== null);
  const unknown = rows.filter((r) => r.tokens === null);
  const tokens  = known.reduce((n, r) => n + r.tokens, 0);
  return {
    servers:            rows.length,
    tools:              known.reduce((n, r) => n + (r.tools || 0), 0),
    tokens,
    tokens_low:         known.reduce((n, r) => n + r.low, 0),
    tokens_high:        known.reduce((n, r) => n + r.high, 0),
    percent_of_context: Number(((tokens / contextWindow) * 100).toFixed(1)),
    unknown_servers:    unknown.length,
    unknown_names:      unknown.map((r) => r.name),
  };
}

/**
 * Would adding one more server put this config over the policy's ceiling?
 *
 * Returns null when no ceiling is configured — a policy that says nothing about
 * context is not a policy that says "unlimited", it is one that has no opinion,
 * and the caller should stay quiet rather than invent a default bar.
 *
 * `over` is only true when the *known* total crosses the line. Where servers
 * could not be measured, `unknown_servers` says how much of the config was not
 * counted, so "under budget" is never claimed with more confidence than the
 * inputs support.
 */
function wouldExceed({ rows = [], adding = null, policy = {}, context = DEFAULT_CONTEXT } = {}) {
  const ceiling = Number.isFinite(policy.maxContextTokens) ? policy.maxContextTokens : null;
  const pct     = Number.isFinite(policy.maxContextPercent) ? policy.maxContextPercent : null;
  if (ceiling === null && pct === null) return null;

  const limit = ceiling !== null
    ? ceiling
    : Math.round((pct / 100) * context);

  // The server being added may already be configured — an upgrade or a
  // re-install is not a second copy of its tool surface.
  const withoutIt = adding ? rows.filter((r) => r.name !== adding.name) : rows;
  const before    = summarise(withoutIt, context);
  const after     = summarise(adding ? [...withoutIt, adding] : withoutIt, context);

  return {
    limit,
    server_count:    after.servers,
    limit_source:    ceiling !== null ? 'maxContextTokens' : 'maxContextPercent',
    context,
    before:          before.tokens,
    after:           after.tokens,
    adding:          adding ? { name: adding.name, tokens: adding.tokens, tools: adding.tools, source: adding.source } : null,
    over:            after.tokens > limit,
    was_already_over: before.tokens > limit,
    headroom:        limit - after.tokens,
    unknown_servers: after.unknown_servers,
    unknown_names:   after.unknown_names,
  };
}

module.exports = {
  estimateServer, matchDbEntry, summarise, wouldExceed, usableMeasurement,
  TOKENS_PER_TOOL_LOW, TOKENS_PER_TOOL_HIGH, TOKENS_PER_TOOL_MID,
  BYTES_PER_TOKEN, DEFAULT_CONTEXT,
};
