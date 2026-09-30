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
 * Usage:
 *   node scripts/check_secrets.cjs [--cwd <dir>] [--json | --sarif] [--fix-suggest]
 *
 * Exit codes:
 *   0  no plain-text secret found in any config this could read
 *   1  at least one plain-text secret found
 *   2  bad arguments, or a host config exists and is unreadable (and nothing was found elsewhere)
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const { scanHostConfigs } = require('./lib/secrets.cjs');

const T  = process.stdout.isTTY && !process.env.NO_COLOR;
const B  = T ? '\x1b[1m'  : '';
const DM = T ? '\x1b[2m'  : '';
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const RS = T ? '\x1b[0m'  : '';

const HELP = `mcp-vault secrets — plain-text secrets in MCP host configs

  node scripts/check_secrets.cjs [--cwd <dir>] [--json | --sarif] [--fix-suggest]

  --cwd           project whose configs to read (default: the current directory)
  --json          machine-readable (schema mcp-vault/secrets@1)
  --sarif         SARIF 2.1.0, for code scanning
  --fix-suggest   print a suggested edit per finding (nothing is changed)
  --no-git        do not ask git whether a config is tracked

Detects known token formats (GitHub, GitLab, AWS, Slack, OpenAI, Anthropic,
Stripe, Google, JWT, PEM private keys, database URLs with a password, Bearer
tokens, credentials in URL query strings) and literal high-entropy values under
credential-named keys. The value is never printed: only the type, file, path,
length and a masked prefix of at most 4 characters.
`;

function parseArgs(argv) {
  const o = { cwd: process.cwd(), json: false, sarif: false, fix: false, git: true, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
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

function toSarif(result, cwd) {
  const rules = [...new Set(result.findings.map((f) => f.rule))].sort();
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'mcp-vault secrets',
        informationUri: 'https://github.com/froggychips/mcp-skills-vault',
        rules: rules.map((id) => ({
          id: `host-config-secret/${id}`,
          shortDescription: { text: `plain-text secret: ${id.replace(/-/g, ' ')}` },
          fullDescription: { text: RULE_HELP },
          help: { text: RULE_HELP },
          defaultConfiguration: { level: 'error' },
        })),
      } },
      results: result.findings.map((f) => {
        const rel = path.relative(cwd, f.file);
        const uri = rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel.split(path.sep).join('/') : f.file;
        return {
          ruleId: `host-config-secret/${f.rule}`,
          level: f.tracked ? 'error' : 'warning',
          message: { text: `${f.type} in plain text at ${f.path} (${f.length} chars, ${f.masked})`
            + `${f.tracked ? '; the file is tracked by git' : ''}. ${f.recommendation}` },
          locations: [{ physicalLocation: {
            artifactLocation: { uri },
            ...(f.line ? { region: { startLine: f.line } } : {}),
          } }],
          partialFingerprints: { secretPath: `${f.host}:${f.path}:${f.rule}` },
        };
      }),
    }],
  };
}

function printReport(result, { fix }) {
  const out = (s) => process.stdout.write(s);
  out(`\n${B}Secrets in host configs${RS} ${DM}· ${result.files.length} config${result.files.length === 1 ? '' : 's'} read${RS}\n`);
  if (!result.findings.length) {
    if (!result.unreadable.length) out(`${GN}No plain-text secrets found.${RS}\n\n`);
  }
  const ordered = [...result.findings].sort((a, b) => (b.tracked === true) - (a.tracked === true));
  let lastFile = null;
  for (const f of ordered) {
    if (f.file !== lastFile) {
      lastFile = f.file;
      out(`\n${B}${f.file}${RS} ${DM}(${f.host}, ${f.scope})${RS}`
        + (f.tracked ? ` ${RD}${B}tracked by git${RS}` : (f.tracked === null ? ` ${DM}git status unknown${RS}` : '')) + '\n');
    }
    const color = f.tracked ? RD : YL;
    out(`  ${color}✗${RS} ${f.path}${f.line ? `${DM}:${f.line}${RS}` : ''}  ${f.type}`
      + ` ${DM}(${f.length} chars, ${f.masked}${f.confidence === 'heuristic' ? ', heuristic' : ''})${RS}\n`);
    if (fix) {
      const s = f.fix_suggestion || {};
      if (s.lines) for (const l of s.lines) out(`      ${l.startsWith('-') ? RD : GN}${l}${RS}\n`);
      else if (s.manual) out(`      ${DM}${s.manual}${RS}\n`);
    }
  }
  if (result.findings.length) {
    const hosts = [...new Set(result.findings.map((f) => `${f.host}:${f.scope}`))];
    out(`\n${B}What to do${RS}\n`);
    for (const h of hosts) {
      const f = result.findings.find((x) => `${x.host}:${x.scope}` === h);
      out(`  ${DM}${h}${RS}  ${f.recommendation.replace(/^This file is tracked by git, so the value is in history: rotate it, then /, '')}\n`);
    }
    if (result.findings.some((f) => f.tracked)) {
      out(`  ${RD}A tracked config has the value in git history: rotate the credential, removing it from the file is not enough.${RS}\n`);
    }
    if (!fix) out(`\n${DM}--fix-suggest prints a suggested edit per finding; nothing is changed.${RS}\n`);
    out('\n');
  }
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

  const result = scanHostConfigs({ cwd: o.cwd, git: o.git });
  const findings = result.findings.map((f) => {
    const copy = { ...f };
    if (!o.fix) delete copy.fix_suggestion;
    return copy;
  });

  if (o.sarif) {
    process.stdout.write(`${JSON.stringify(toSarif(result, o.cwd), null, 2)}\n`);
  } else if (o.json) {
    process.stdout.write(`${JSON.stringify({
      schema: 'mcp-vault/secrets@1',
      cwd: o.cwd,
      files: result.files,
      unreadable: result.unreadable.map((u) => ({ host: u.host, scope: u.scope, path: u.path, error: u.error })),
      counts: {
        findings: findings.length,
        tracked: findings.filter((f) => f.tracked === true).length,
        heuristic: findings.filter((f) => f.confidence === 'heuristic').length,
      },
      findings,
    }, null, 2)}\n`);
  } else {
    printReport(result, { fix: o.fix });
  }

  for (const u of result.unreadable) process.stderr.write(`secrets: ${u.path}: ${u.error}\n`);
  // A finding outranks an incomplete scope (docs/COMPATIBILITY.md).
  if (result.findings.length) return 1;
  if (result.unreadable.length) return 2;
  return 0;
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, toSarif, main };
