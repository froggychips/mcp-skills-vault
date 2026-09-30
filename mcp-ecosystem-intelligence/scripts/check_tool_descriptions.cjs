#!/usr/bin/env node
/**
 * mcp-vault tool-scan — read what a server's tool descriptions tell the model.
 *
 * A tool description is an instruction the model follows, delivered on every
 * request, and nothing that checks the artifact can see what it says. This
 * command runs the rule table in lib/tool_scan.cjs over a `tools/list` result:
 * hidden Unicode (decoded), terminal escapes, injected instructions, credential
 * paths, and input schemas with a catch-all parameter nobody explained.
 *
 * Two inputs, both offline:
 *
 *   a file     a `tools/list` payload you captured — `{ "tools": [...] }`, a
 *              JSON-RPC response, or a bare array. `-` reads stdin. The report
 *              shows excerpts and decoded hidden text, escaped for the terminal.
 *              An empty list is `no-data`, not clean.
 *   (nothing)  the scans `mcp-vault eval` stored in assets/eval_results.json.
 *              Those carry rule, tool and location only — never the text
 *              (see toStored() in lib/tool_scan.cjs). For your own servers,
 *              `mcp-vault eval --installed --sandbox` stores them first. A
 *              passing row with no scan is `not-run`; a scan past the
 *              tool_descriptions shelf life (30 days) is `stale`. Both decide
 *              to `unknown`, never to allow.
 *
 * Findings are lib/finding.cjs findings (`tool-scan/<rule>` on a `tool`
 * subject); the verdict is decide() over the `tool-scan/*` row in
 * lib/policy_rules.cjs — this file renders it (docs/adr/0001).
 *
 * Usage:
 *   node scripts/check_tool_descriptions.cjs [<file>|-] [--server <name>]
 *        [--results <path>] [--name <entry>] [--json] [--sarif] [--strict]
 *        [--fail-unverified] [--as-of <date>] [--show-low] [--rules]
 *
 *   --rules            print the rule table (id, severity, why) and exit
 *   --json             mcp-vault/findings@1: findings, decisions, the policy
 *                      and facts they were decided on
 *   --strict           fail_on warn: medium findings fail, and so does a scan
 *                      that did not run or aged out
 *   --fail-unverified  fail_on unknown: a scan that did not run fails
 *   --as-of            decide as of this instant (stored scans dated after it
 *                      did not exist then; older ones may be stale by then)
 *   --sarif            SARIF 2.1.0 (lib/finding.cjs toSarif); high → error,
 *                      medium → warning, low omitted
 *
 * Exit codes (lib/finding.cjs exitCode):
 *   0  no decision fails at the threshold
 *   1  a decision fails (a high finding; more under --strict)
 *   2  bad arguments, unreadable input, or nothing was scanned
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { exitAfterFlush } = require('./lib/exit.cjs');
const ts = require('./lib/tool_scan.cjs');
const F  = require('./lib/finding.cjs');
const { loadEffectivePolicy, flagsFromArgv } = require('./lib/policy_rules.cjs');
const { asOfFromArgv, stripAsOf } = require('./lib/clock.cjs');
const { evalResultsAsOf } = require('./lib/evidence.cjs');

const EVAL_PATH = path.resolve(__dirname, '../assets/eval_results.json');

const T  = process.stdout.isTTY;
const B  = T ? '\x1b[1m'  : '';
const RD = T ? '\x1b[31m' : '';
const YL = T ? '\x1b[33m' : '';
const GN = T ? '\x1b[32m' : '';
const DM = T ? '\x1b[2m'  : '';
const RS = T ? '\x1b[0m'  : '';

function parseArgs(argv) {
  const opts = {
    file: null, server: null, results: EVAL_PATH, name: null,
    json: false, sarif: false, strict: false, failUnverified: false, showLow: false, rules: false, help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    try {
      if (a === '--json') opts.json = true;
      else if (a === '--sarif') opts.sarif = true;
      else if (a === '--strict') opts.strict = true;
      else if (a === '--fail-unverified') opts.failUnverified = true;
      else if (a === '--show-low') opts.showLow = true;
      else if (a === '--rules') opts.rules = true;
      else if (a === '-h' || a === '--help') opts.help = true;
      else if (a === '--server') opts.server = need();
      else if (a === '--results') opts.results = need();
      else if (a === '--name') opts.name = need();
      else if (a === '--file') opts.file = need();
      else if (a === '-' || !a.startsWith('-')) {
        if (opts.file) return { ...opts, error: 'tool-scan takes one file' };
        opts.file = a;
      } else return { ...opts, error: `unknown flag ${a}` };
    } catch (e) {
      return { ...opts, error: e.message };
    }
  }
  if (opts.json && opts.sarif) return { ...opts, error: '--json and --sarif are alternatives' };
  return opts;
}

/**
 * The tools array out of whatever shape was captured. A document with no tools
 * array is an error, not an empty server: `{}` scanning clean would be a
 * measurement nobody made.
 */
function toolsFrom(doc) {
  if (Array.isArray(doc)) return doc;
  if (doc && Array.isArray(doc.tools)) return doc.tools;
  if (doc && doc.result && Array.isArray(doc.result.tools)) return doc.result.tools;
  return null;
}

function readInput(file) {
  const raw = file === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(file, 'utf8');
  const tools = toolsFrom(JSON.parse(raw));
  if (!tools) throw new Error('no `tools` array (expected a tools/list result, a JSON-RPC response or an array)');
  return tools;
}

function printRules(json) {
  if (json) {
    process.stdout.write(`${JSON.stringify({ schema: 'mcp-vault/tool-scan-rules@1', rules_version: ts.RULES_VERSION, rules: ts.RULES }, null, 2)}\n`);
    return;
  }
  process.stdout.write(`tool-scan rules (v${ts.RULES_VERSION})\n\n`);
  for (const r of ts.RULES) {
    process.stdout.write(`  ${r.severity.padEnd(6)} ${B}${r.id}${RS}\n         ${r.summary}\n         ${DM}${r.explain}${RS}\n`);
  }
}

const EFFECT_COLOUR = { deny: RD, unknown: YL, warn: YL, allow: GN };

/** The decisions that say something, one line each — a rendering, not a verdict. */
function printDecisions(decisions) {
  for (const d of decisions) {
    if (d.effect === 'allow') continue;
    const r = d.rules.find((x) => x.rule === d.decided_by) || {};
    process.stdout.write(`  ${EFFECT_COLOUR[d.effect]}${d.effect.toUpperCase().padEnd(7)}${RS} ${d.subject.id}  ${DM}${d.decided_by}${r.detail ? ` — ${r.detail}` : ''}${d.fails ? ' (fails the run)' : ''}${RS}\n`);
  }
}

function main(argvIn) {
  const clock = asOfFromArgv(argvIn);
  if (clock.error) { process.stderr.write(`tool-scan: ${clock.error}\n`); return 2; }
  const argv = stripAsOf(argvIn);
  const opts = parseArgs(argv);
  if (opts.error) { process.stderr.write(`tool-scan: ${opts.error}\n`); return 2; }
  if (opts.help) {
    const head = fs.readFileSync(__filename, 'utf8').split('\n')
      .filter((l) => l.startsWith(' *') || l.startsWith('/**'))
      .map((l) => l.replace(/^ \* ?/, '').replace(/^\/\*\* ?/, '').replace(/^\*\/$/, ''))
      .join('\n');
    process.stdout.write(`${head}\n`);
    return 0;
  }
  if (opts.rules) { printRules(opts.json); return 0; }

  // A tool list is not an artifact, so the policy file's artifact rules do
  // not apply to it; its threshold comes from the flags (--strict, …).
  const { policy } = loadEffectivePolicy(process.cwd(), { flags: flagsFromArgv(argv), noPolicy: true });
  const asOf = clock.asOf;

  let model; let scans = []; let scope;
  if (opts.file) {
    // ── a captured tools/list ──
    let tools;
    try { tools = readInput(opts.file); } catch (e) {
      process.stderr.write(`tool-scan: ${opts.file}: ${e.message}\n`);
      return 2;
    }
    const server = opts.server || (opts.file === '-' ? 'stdin' : path.basename(opts.file));
    const scan = ts.scanTools(tools);
    scope = 'tool-list';
    const s = ts.serverSubject(server);
    const findings = ts.scanFindings(scan, { server, scope, detail: true });
    const subjects = [s];
    for (const f of findings) if (!subjects.some((x) => x.id === f.subject.id)) subjects.push(f.subject);
    model = {
      subjects, findings, scanned: scan.tools ? 1 : 0,
      facts: { [s.id]: { tool_scan: { scanned: scan.tools > 0, tools: scan.tools, strings: scan.strings, rules_version: scan.rules_version } } },
    };
    scans = [{ server, scan, live: true }];
  } else {
    // ── the scans eval stored ──
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(opts.results, 'utf8'));
    } catch (e) {
      process.stderr.write(`tool-scan: cannot read ${opts.results}: ${e.code || e.message}\n`);
      return 2;
    }
    let rows = evalResultsAsOf(Array.isArray(doc && doc.results) ? doc.results : [], asOf);
    if (opts.name) rows = rows.filter((r) => r.name === opts.name || String(r.name).toLowerCase().includes(opts.name.toLowerCase()));
    scope = 'eval-results';
    model = ts.evalRowsModel(rows, { asOf });
    if (!model.subjects.length) {
      process.stderr.write(`tool-scan: no passing eval result in ${opts.results} listed any tools — nothing to scan\n`);
      return 2;
    }
    if (!model.scanned) {
      process.stderr.write(
        `tool-scan: none of the ${model.subjects.length} passing eval result${model.subjects.length === 1 ? '' : 's'} in ${opts.results} carries a tool scan — `
        + 'run `mcp-vault eval --sandbox` (or `--installed --sandbox` for your own servers), or pass a tools/list file\n',
      );
    }
    scans = rows.filter((r) => r.status === 'pass' && r.tool_scan && Array.isArray(r.tool_scan.findings))
      .map((r) => ({ server: r.name, scan: r.tool_scan, live: false }));
  }

  const decisions = F.decide(model.findings, policy, asOf, { subjects: model.subjects, facts: model.facts });

  if (opts.sarif) {
    process.stdout.write(`${JSON.stringify(F.toSarif(model.findings, { toolName: 'mcp-vault tool-scan', ruleHelp: ts.SARIF_RULE_HELP }), null, 2)}\n`);
  } else if (opts.json) {
    process.stdout.write(`${JSON.stringify(F.toJson(F.findingsDocument({
      asOf, findings: model.findings, decisions, scope, policy, facts: model.facts,
    })), null, 2)}\n`);
  } else {
    for (const { server, scan, live } of scans) {
      if (!live && !scan.high && !scan.medium && !opts.showLow) continue;
      process.stdout.write(`\n${B}${ts.printable(server)}${RS}  ${DM}${scan.tools} tools, ${scan.strings} strings — ${scan.high} high, ${scan.medium} medium, ${scan.low} low${scan.truncated ? ' — first page only' : ''}${RS}\n`);
      for (const line of ts.describeScan(scan, { showLow: opts.showLow })) process.stdout.write(`  ${line}\n`);
    }
    process.stdout.write(`\n${B}Decisions${RS} ${DM}(as of ${clock.iso}, fail_on ${policy.fail_on})${RS}\n`);
    printDecisions(decisions);
    const counts = {};
    for (const d of decisions) counts[d.effect] = (counts[d.effect] || 0) + 1;
    process.stdout.write(`  ${Object.entries(counts).sort().map(([k, n]) => `${n} ${k}`).join(', ')}`
      + `${opts.file ? '' : ` — ${model.scanned} scanned (${DM}as stored by eval — rule, tool and location; no text${RS})`}\n`);
  }
  // The exit code is the decisions'. "Nothing was scanned" is a property of
  // the input, not a verdict, and keeps its 2 when no decision fails.
  return F.exitCode(decisions) || (model.scanned ? 0 : 2);
}

if (require.main === module) {
  exitAfterFlush(main(process.argv.slice(2)));
}

module.exports = { parseArgs, toolsFrom, main };
