#!/usr/bin/env node
/**
 * smoke_compare.cjs — judge a smoke of changed DB entries against the base line.
 *
 * The PR smoke (`.github/actions/smoke-changed-entries`) used to call every
 * changed entry that came back CRASH or NO_TOOLS "breaking". That conflates two
 * very different things: a server that worked before and stopped, and a server
 * that never started in the sandbox in the first place (it wants a token or a
 * kubeconfig at boot). A re-pin PR touching five of the latter went red for a
 * regression that did not exist.
 *
 * The verdict is therefore relative to what eval_results.json recorded for the
 * same entry on the base ref:
 *
 *   breaking           was PASS (≥1 tool), now not PASS; or fewer tools at the
 *                      same `version` (same artifact, smaller surface)
 *   shrunk             fewer tools, but the version changed — a new release may
 *                      drop tools on purpose; a warning, read the surface diff
 *   unchanged-failing  was not PASS, still not PASS (class may differ)
 *   improved           was not PASS, now PASS
 *   ok                 was PASS, still PASS with at least as many tools
 *   new-pass           no base line, PASS
 *   new-failing        no base line, not PASS — a warning: there is nothing to
 *                      regress from, and the DB already gates on trust tiers
 *   unchecked          the runner could not run it (launcher / sandbox missing)
 *
 * Only `breaking` fails the gate.
 *
 * States are normalised first: `pass` with tool_count 0 and `NO_TOOLS` are the
 * same state (eval_results.json records the former, a fresh run's
 * failure_class says the latter).
 *
 * A not-PASS row whose stderr says it is missing a token / env var /
 * kubeconfig is tagged `needs-credentials`. The sandbox deliberately gets no
 * credentials — real or fake — so that tag explains the row, it does not
 * excuse a regression.
 *
 * Usage:
 *   smoke_compare.cjs --runs <file> [--base <git-ref>] [--gate] [--title <s>]
 *                     [--summary <file>]
 *
 *   --runs     concatenated `mcp_eval --json` documents (the action's ndjson)
 *   --base     ref whose eval_results.json / tools_database.json is the base
 *              line (default HEAD)
 *   --summary  append the Markdown table here (default $GITHUB_STEP_SUMMARY,
 *              else stdout)
 *   --gate     exit 1 when anything is `breaking`
 */

'use strict';

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { exitAfterFlush } = require('./lib/exit.cjs');

const RESULTS_REPO_PATH = 'mcp-ecosystem-intelligence/assets/eval_results.json';
const DB_REPO_PATH = 'mcp-ecosystem-intelligence/assets/tools_database.json';
const DEFAULT_DB_PATH = path.resolve(__dirname, '../assets/tools_database.json');

const FAILING_VERDICTS = new Set(['breaking']);

// Missing credentials, as servers phrase it at boot. Wider than
// classifyFailure's NEEDS_ENV on purpose (kubeconfig, "required" phrasing):
// that one decides a failure class, this one only annotates a row.
const NEEDS_CREDENTIALS_RE = new RegExp([
  'kube_?config',
  'no configuration has been provided',
  'missing\\b.*\\b(token|key|secret|credential|env|environment|password)',
  '\\b(token|api[_ -]?key|secret|credentials?|password)\\b.*\\b(is |are )?(required|not set|not provided|missing|must be (set|provided))',
  'environment variables?\\b.*\\b(required|not set|missing)',
  'env(ironment)? var',
  '\\bunauthori[sz]ed\\b',
  '\\b401\\b',
].join('|'), 'i');

function isUnchecked(r) {
  return r.failure_class === 'SANDBOX_UNAVAILABLE'
    || (r.status === 'skip' && /^launcher unavailable: /.test(r.error_code || ''));
}

/**
 * Collapse a result row to the one thing the comparison needs.
 * Returns null for "no row". kind: PASS | NO_TOOLS | <failure class> | SKIP.
 */
function normalizeState(r) {
  if (!r) return null;
  const tools = Number.isInteger(r.tool_count) ? r.tool_count : null;
  if (r.status === 'pass') {
    if (!tools || r.failure_class === 'NO_TOOLS') return { kind: 'NO_TOOLS', tools: 0 };
    return { kind: 'PASS', tools };
  }
  if (r.failure_class === 'NO_TOOLS') return { kind: 'NO_TOOLS', tools: 0 };
  if (r.status === 'skip') return { kind: r.failure_class ? `SKIP:${r.failure_class}` : 'SKIP', tools: null };
  return { kind: r.failure_class || 'FAIL', tools: null };
}

function stateLabel(s) {
  if (!s) return '—';
  return s.kind === 'PASS' ? `PASS (${s.tools})` : s.kind;
}

function needsCredentials(r) {
  if (!r || r.status === 'pass') return false;
  if (r.failure_class === 'NEEDS_ENV') return true;
  return NEEDS_CREDENTIALS_RE.test(`${r.error_code || ''}\n${r.stderr_tail || ''}`);
}

/**
 * Pure verdict for one entry.
 *   base, current   result rows (base may be null)
 *   versionChanged  true when the DB version differs between base and head
 */
function verdictFor(base, current, { versionChanged = false } = {}) {
  if (isUnchecked(current)) return 'unchecked';
  const was = normalizeState(base);
  const now = normalizeState(current);
  if (!was) return now.kind === 'PASS' ? 'new-pass' : 'new-failing';
  if (was.kind === 'PASS') {
    if (now.kind !== 'PASS') return 'breaking';
    if (now.tools < was.tools) return versionChanged ? 'shrunk' : 'breaking';
    return 'ok';
  }
  return now.kind === 'PASS' ? 'improved' : 'unchanged-failing';
}

/**
 * baseResults: eval_results.json rows on the base ref.
 * runs:        rows from this smoke.
 * baseTools / headTools: DB entries, only for "did the version change".
 */
function compare(baseResults, runs, { baseTools = [], headTools = [] } = {}) {
  const baseByName = new Map((baseResults || []).map((r) => [r.name, r]));
  const baseVer = new Map((baseTools || []).map((t) => [t.name, t.version ?? null]));
  const headVer = new Map((headTools || []).map((t) => [t.name, t.version ?? null]));
  return (runs || []).map((r) => {
    const base = baseByName.get(r.name) || null;
    const versionChanged = baseVer.has(r.name) && headVer.has(r.name)
      && baseVer.get(r.name) !== headVer.get(r.name);
    const verdict = verdictFor(base, r, { versionChanged });
    const tags = [];
    if (needsCredentials(r)) tags.push('needs-credentials');
    return {
      name: r.name,
      was: stateLabel(normalizeState(base)),
      now: stateLabel(normalizeState(r)),
      verdict,
      tags,
      sandboxed: r.sandboxed,
    };
  });
}

const cell = (v) => String(v == null ? '' : v)
  .replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ').trim();

function toMarkdown(rows, { title = 'MCP eval (sandboxed, changed entries)', baseRef = '' } = {}) {
  const out = [`## ${title}`, ''];
  const count = (v) => rows.filter((r) => r.verdict === v).length;
  const breaking = count('breaking');
  out.push(breaking
    ? `**${breaking} breaking** against the base line${baseRef ? ` (\`${cell(baseRef)}\`)` : ''}.`
    : `No regressions against the base line${baseRef ? ` (\`${cell(baseRef)}\`)` : ''}.`);
  const parts = ['unchanged-failing', 'improved', 'shrunk', 'new-failing', 'unchecked']
    .map((v) => [v, count(v)]).filter(([, n]) => n).map(([v, n]) => `${v}: ${n}`);
  if (parts.length) out.push('', parts.join(' · '));
  out.push('', '| entry | was | now | verdict | notes | sandboxed |', '|---|---|---|---|---|---|');
  for (const r of rows) {
    const v = FAILING_VERDICTS.has(r.verdict) ? `**${r.verdict}**` : r.verdict;
    out.push(`| ${cell(r.name)} | ${cell(r.was)} | ${cell(r.now)} | ${v} | ${cell(r.tags.join(', ') || '-')} | ${cell(r.sandboxed)} |`);
  }
  const unchecked = count('unchecked');
  if (unchecked) {
    out.push('', `> ${unchecked} entr${unchecked === 1 ? 'y' : 'ies'} went unchecked — launcher or sandbox missing on this runner. Not a pass.`);
  }
  if (rows.some((r) => r.tags.includes('needs-credentials'))) {
    out.push('', '> `needs-credentials`: the server wants a token / env var / kubeconfig at boot. The sandbox gets none on purpose; this explains the row, it does not excuse a regression.');
  }
  return out.join('\n') + '\n';
}

// `mcp_eval --json` pretty-prints, so the action's file is a stream of
// multi-line documents: split where a new top-level object opens.
function parseRuns(text) {
  return String(text || '').trim().split(/\n(?=\{)/).filter(Boolean)
    .map((s) => JSON.parse(s)).flatMap((r) => r.results || []);
}

function gitShowJson(ref, repoPath) {
  try {
    const raw = cp.execFileSync('git', ['show', `${ref}:${repoPath}`], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024,
    });
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function parseArgs(argv) {
  const opts = { runs: null, base: 'HEAD', gate: false, title: undefined, summary: process.env.GITHUB_STEP_SUMMARY || null, db: DEFAULT_DB_PATH };
  for (let i = 0; i < argv.length; i++) {
    const next = argv[i + 1];
    switch (argv[i]) {
      case '--runs': opts.runs = next; i++; break;
      case '--base': opts.base = next; i++; break;
      case '--title': opts.title = next; i++; break;
      case '--summary': opts.summary = next; i++; break;
      case '--db': opts.db = next; i++; break;
      case '--gate': opts.gate = true; break;
      default:
        process.stderr.write(`Unknown argument: ${argv[i]}\n`);
        return null;
    }
  }
  return opts.runs ? opts : null;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts) {
    process.stderr.write('usage: smoke_compare.cjs --runs <file> [--base <ref>] [--gate] [--title <s>] [--summary <file>]\n');
    return 2;
  }
  const runs = parseRuns(fs.readFileSync(opts.runs, 'utf8'));
  if (!runs.length) { process.stderr.write('no results to report\n'); return 0; }

  const baseResults = (gitShowJson(opts.base, RESULTS_REPO_PATH) || {}).results || [];
  const baseTools = (gitShowJson(opts.base, DB_REPO_PATH) || {}).tools || [];
  let headTools = [];
  try { headTools = JSON.parse(fs.readFileSync(opts.db, 'utf8')).tools || []; } catch { /* versions unknown → no "shrunk" leniency */ }

  const rows = compare(baseResults, runs, { baseTools, headTools });
  const md = toMarkdown(rows, { title: opts.title, baseRef: opts.base });
  if (opts.summary) fs.appendFileSync(opts.summary, md);
  else process.stdout.write(md);

  for (const v of ['breaking', 'shrunk', 'new-failing', 'unchanged-failing', 'improved', 'unchecked']) {
    const hit = rows.filter((r) => r.verdict === v);
    if (hit.length) process.stderr.write(`${v}: ${hit.map((r) => `${r.name}(${r.was} → ${r.now})`).join(', ')}\n`);
  }
  const breaking = rows.filter((r) => FAILING_VERDICTS.has(r.verdict));
  return breaking.length && opts.gate ? 1 : 0;
}

if (require.main === module) exitAfterFlush(main());

module.exports = {
  normalizeState, stateLabel, needsCredentials, verdictFor, compare, toMarkdown, parseRuns, parseArgs,
  FAILING_VERDICTS,
};
