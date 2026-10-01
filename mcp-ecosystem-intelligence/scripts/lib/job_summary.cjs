'use strict';
/**
 * The GitHub Action's job summary: a `verify --json` run's Decisions as a
 * Markdown table.
 *
 * It renders the findings@1 document the report carries (docs/adr/0001) and
 * nothing else — no counting of legacy `failures`, no re-reading of tags.
 * The verdict line is the decisions' exit code; each row is one subject (for
 * `--config`, a host-config line: `path:line`), its effect, the rule that
 * decided it, and every rule outcome that was not `allow`. A summary that
 * judged on its own would be a second place deciding, which is what the
 * findings model exists to prevent.
 *
 * API:
 *   toMarkdown(report, { base })   -> Markdown (the `verify --json` document)
 */

const path = require('path');
const { exitCode } = require('./finding.cjs');

// Backslashes first: escaping only the pipe leaves `\|` in the input able to
// close the cell it was escaped for.
const cell = (v) => String(v == null ? '' : v)
  .replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ').trim();

function relTo(base, p) {
  if (!p || !base || !path.isAbsolute(p)) return p;
  const r = path.relative(base, p);
  return r && !r.startsWith('..') && !path.isAbsolute(r) ? r.split(path.sep).join('/') : p;
}

const nameOf = (s) => s.server || s.entry || s.name || s.id;
const whereOf = (s, base) => (s.type === 'host-config' ? `${relTo(base, s.path)}${s.line ? `:${s.line}` : ''}` : '');

function verdictOf(decisions) {
  const code = exitCode(decisions);
  if (code === 1) return 'FAIL';
  if (code === 2) return 'INCOMPLETE';
  if (decisions.some((d) => d.effect === 'unknown')) return 'UNVERIFIED';
  if (decisions.some((d) => d.effect === 'warn')) return 'WARN';
  return 'OK';
}

function toMarkdown(report, { base = null } = {}) {
  const doc = report && report.findings;
  const lines = ['## mcp-vault', ''];
  if (!doc || !Array.isArray(doc.decisions)) {
    lines.push('The report carries no `mcp-vault/findings@1` document (a CLI older than `verify --config`?) — nothing to render.', '');
    return lines.join('\n');
  }
  const decisions = doc.decisions;
  const failing = decisions.filter((d) => d.fails).length;
  const unknown = decisions.filter((d) => d.effect === 'unknown').length;
  const n = decisions.length;
  lines.push(
    `**${verdictOf(decisions)}** — ${n} server${n === 1 ? '' : 's'} checked, ${failing} failing, ${unknown} unverified `
      + `(fail on: ${decisions.length ? decisions[0].fail_on : (doc.policy && doc.policy.fail_on) || 'deny'}, `
      + `mode: ${report.mode || 'unknown'}, as of ${doc.as_of}).`,
    '',
  );
  if (report.note) lines.push(cell(report.note), '');
  if (n) {
    lines.push('| Server | Effect | Decided by | Config | Why |', '|---|---|---|---|---|');
    for (const d of decisions) {
      const why = d.rules.filter((o) => o.effect !== 'allow').map((o) => `${o.rule}: ${o.detail || o.effect}`);
      lines.push(`| ${cell(nameOf(d.subject))} | ${cell(d.effect)}${d.fails ? ' (fails)' : ''} | ${cell(d.decided_by)} | ${cell(whereOf(d.subject, base))} | ${cell(why.join('; ') || '—')} |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

module.exports = { toMarkdown };
