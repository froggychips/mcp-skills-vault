#!/usr/bin/env node
/**
 * Secrets written in plain text into MCP host configs.
 *
 * Reads the same host configs `status` and `verify --installed` read — Claude
 * Code (.mcp.json, ~/.claude.json including its per-project entries), Claude
 * Desktop, Cursor, VS Code, Codex — and reports every credential-shaped value
 * in a server's env, args, headers or url. The value itself is never printed,
 * in any format: a finding is a type, a file, a path, a length and a masked
 * prefix of at most four characters. See `lib/secrets.cjs`.
 *
 * A config tracked by git is reported at severity `high`: the value is in
 * history, and removing it from the file does not remove it from there.
 *
 * Findings are lib/finding.cjs findings — `secrets/<rule>` on a host-config
 * subject (`path:line`) — and the verdict is `decide()`'s over the
 * `secrets/*` row of lib/policy_rules.cjs (docs/adr/0001). This file builds
 * the findings and renders the Decisions; it decides nothing.
 *
 * Usage:
 *   node scripts/check_secrets.cjs [--cwd <dir>] [--json | --sarif] [--fix-suggest] [--explain] [--as-of <date>]
 *
 * Exit codes (lib/finding.cjs exitCode):
 *   0  no plain-text secret found in any config this could read
 *   1  at least one plain-text secret found
 *   2  bad arguments, or a host config exists and is unreadable (and nothing was found elsewhere)
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { scanHostConfigs, toFindings } = require('./lib/secrets.cjs');
const F = require('./lib/finding.cjs');
const { loadEffectivePolicy } = require('./lib/policy_rules.cjs');
const { asOfFromArgv, stripAsOf } = require('./lib/clock.cjs');

const T  = process.stdout.isTTY && !process.env.NO_COLOR;
const B  = T ? '\x1b[1m'  : '';
const DM = T ? '\x1b[2m'  : '';
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const CY = T ? '\x1b[36m' : '';
const RS = T ? '\x1b[0m'  : '';

const HELP = `mcp-vault secrets — plain-text secrets in MCP host configs

  node scripts/check_secrets.cjs [--cwd <dir>] [--json | --sarif] [--fix-suggest] [--explain]

  --cwd           project whose configs to read (default: the current directory)
  --json          machine-readable (schema mcp-vault/secrets@1; the findings and
                  decisions are mcp-vault/findings@1 under "findings")
  --sarif         SARIF 2.1.0, for code scanning
  --fix-suggest   print a suggested edit per finding (nothing is changed)
  --explain       print the decision trace: rule → finding, per config
  --no-git        do not ask git whether a config is tracked
  --as-of         the instant the decision is stamped with (YYYY-MM-DD or an
                  ISO-8601 instant); the configs are always read as they are now

Detects known token formats (GitHub, GitLab, AWS, Slack, OpenAI, Anthropic,
Stripe, Google, JWT, PEM private keys, database URLs with a password, Bearer
tokens, credentials in URL query strings) and literal high-entropy values under
credential-named keys. The value is never printed: only the type, file, path,
length and a masked prefix of at most 4 characters.
`;

function parseArgs(argv) {
  const when = asOfFromArgv(argv);
  if (when.error) return { error: when.error };
  const o = { cwd: process.cwd(), json: false, sarif: false, fix: false, explain: false, git: true, help: false, asOf: when.asOf };
  argv = stripAsOf(argv);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a === '--explain') o.explain = true;
    else if (a === '--sarif') o.sarif = true;
    else if (a === '--fix-suggest') o.fix = true;
    else if (a === '--no-git') o.git = false;
    else if (a === '--help' || a === '-h') o.help = true;
    else if (a === '--cwd') { o.cwd = argv[++i]; if (!o.cwd) return { error: '--cwd needs a directory' }; }
    else return { error: `unknown argument: ${a}` };
  }
  if (o.json && o.sarif) return { error: '--json and --sarif are exclusive' };
  return o;
}

const RULE_HELP = 'A credential is written into an MCP host config in plain text. Reference it from the environment instead, in the syntax this host documents, and rotate it if the file was ever shared or committed.';

/**
 * The run as findings, decided. The effective policy is the gate's own rows
 * only (`noPolicy`): a policy@1 file speaks about DB entries — licence, tier,
 * health — and none of that is a question about a config file.
 */
function model(scan, { cwd, asOf }) {
  const { findings, subjects, details } = toFindings(scan, { cwd });
  const { policy } = loadEffectivePolicy(cwd, { noPolicy: true });
  const decisions = F.decide(findings, policy, asOf, { subjects });
  const doc = F.toJson(F.findingsDocument({ asOf, findings, decisions, scope: 'host-configs', policy, facts: {} }));
  return { doc, details };
}

function toSarif(doc) {
  const ruleHelp = {};
  for (const f of doc.findings) if (f.rule.startsWith('secrets/')) ruleHelp[f.rule] = RULE_HELP;
  return F.toSarif(doc.findings, { toolName: 'mcp-vault secrets', ruleHelp });
}

function printReport(doc, details, { fix, explain }) {
  const out = (s) => process.stdout.write(s);
  const byId = new Map(details.map((d) => [d.finding, d]));
  const secrets = doc.findings.filter((f) => f.rule.startsWith('secrets/'));
  const files = new Set(doc.decisions.filter((d) => !d.unanswered).map((d) => d.subject.path));
  out(`\n${B}Secrets in host configs${RS} ${DM}· ${files.size} config${files.size === 1 ? '' : 's'} read${RS}\n`);
  if (!secrets.length && !doc.findings.length) out(`${GN}No plain-text secrets found.${RS}\n\n`);

  // Tracked files first: there the value is already in history.
  const ordered = [...secrets].sort((a, b) => (b.severity === 'high') - (a.severity === 'high'));
  let lastFile = null;
  for (const f of ordered) {
    const s = f.subject;
    const d = byId.get(f.id) || {};
    if (s.path !== lastFile) {
      lastFile = s.path;
      out(`\n${B}${s.path}${RS} ${DM}(${s.host}, ${s.scope})${RS}`
        + (d.tracked ? ` ${RD}${B}tracked by git${RS}` : (d.tracked === null ? ` ${DM}git status unknown${RS}` : '')) + '\n');
    }
    const color = f.severity === 'high' ? RD : YL;
    out(`  ${color}✗${RS} ${d.path}${s.line ? `${DM}:${s.line}${RS}` : ''}  ${d.type}`
      + ` ${DM}(${d.length} chars, ${d.masked}${f.confidence !== 'high' ? ', heuristic' : ''})${RS}\n`);
    if (fix) {
      const sug = d.fix_suggestion || {};
      if (sug.lines) for (const l of sug.lines) out(`      ${l.startsWith('-') ? RD : GN}${l}${RS}\n`);
      else if (sug.manual) out(`      ${DM}${sug.manual}${RS}\n`);
    }
  }
  for (const f of doc.findings.filter((x) => x.state !== 'observed')) out(`\n  ${YL}?${RS} ${f.message}\n`);

  if (secrets.length) {
    const seen = new Set();
    out(`\n${B}What to do${RS}\n`);
    for (const f of secrets) {
      const h = `${f.subject.host}:${f.subject.scope}`;
      if (seen.has(h)) continue;
      seen.add(h);
      out(`  ${DM}${h}${RS}  ${String(byId.get(f.id).recommendation).replace(/^This file is tracked by git, so the value is in history: rotate it, then /, '')}\n`);
    }
    if (secrets.some((f) => byId.get(f.id).tracked)) {
      out(`  ${RD}A tracked config has the value in git history: rotate the credential, removing it from the file is not enough.${RS}\n`);
    }
    if (!fix) out(`\n${DM}--fix-suggest prints a suggested edit per finding; nothing is changed.${RS}\n`);
  }
  if (explain) {
    out(`\n${B}Decision trace${RS} ${DM}(as of ${doc.as_of})${RS}\n`);
    for (const l of F.renderTrace(F.explainTrace(doc))) out(`  ${CY}${l}${RS}\n`);
  }
  out('\n');
}

function main(argv) {
  const o = parseArgs(argv);
  if (o.error) { process.stderr.write(`secrets: ${o.error}\n\n${HELP}`); return 2; }
  if (o.help) { process.stdout.write(HELP); return 0; }
  try {
    if (!fs.statSync(o.cwd).isDirectory()) throw new Error('not a directory');
  } catch (e) {
    process.stderr.write(`secrets: cannot read ${o.cwd}: ${e.message}\n`);
    return 2;
  }

  const scan = scanHostConfigs({ cwd: o.cwd, git: o.git });
  const { doc, details } = model(scan, { cwd: o.cwd, asOf: o.asOf });

  if (o.sarif) {
    process.stdout.write(`${JSON.stringify(toSarif(doc), null, 2)}\n`);
  } else if (o.json) {
    // The envelope keeps only what is not a finding: the masked shape of each
    // value and the advice. Everything that is — rule, subject, severity,
    // state, and the verdict — is the findings@1 document.
    process.stdout.write(`${JSON.stringify(F.toJson({
      schema: 'mcp-vault/secrets@1',
      cwd: o.cwd,
      secrets: details.map((d) => {
        const copy = { ...d };
        if (!o.fix) delete copy.fix_suggestion;
        return copy;
      }),
      findings: doc,
    }), null, 2)}\n`);
  } else {
    printReport(doc, details, { fix: o.fix, explain: o.explain });
  }

  for (const f of doc.findings) if (f.state !== 'observed') process.stderr.write(`secrets: ${f.message}\n`);
  // A finding outranks an incomplete scope (docs/COMPATIBILITY.md) — that
  // ordering is exitCode's.
  return F.exitCode(doc.decisions);
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, model, toSarif, main };
