#!/usr/bin/env node
/**
 * Generate a minimal MCP wrapper server from the template in
 * `assets/mcp-wrapper-template/`.
 *
 * Anti-bloat pattern: when a vendor MCP server exposes 50+ tools but you only
 * need 3–5, generate a thin custom server that exposes exactly the slice you
 * use and install it instead. Saves ~200–500 tokens per dropped tool.
 *
 * Usage:
 *   node scripts/generate_wrapper.cjs \
 *     --name my-cli-mcp \
 *     --tool "My CLI" \
 *     --out ./out \
 *     [--tools-file ./tools.json] \
 *     [--force]
 *
 * tools.json schema (array of MCP tool definitions):
 *   [
 *     {
 *       "name": "run_query",
 *       "description": "Execute a read-only SQL query.",
 *       "inputSchema": {
 *         "type": "object",
 *         "properties": { "sql": { "type": "string" } },
 *         "required": ["sql"]
 *       }
 *     }
 *   ]
 *
 * Exit codes:
 *   0  success
 *   2  bad arguments / output already exists (use --force to overwrite)
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const TEMPLATE_DIR = path.resolve(__dirname, '../assets/mcp-wrapper-template');

const argv = process.argv.slice(2);
const ARG  = (flag) => {
  const i = argv.indexOf(flag);
  return i !== -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : null;
};
const HAS  = (flag) => argv.includes(flag);

const NAME       = ARG('--name');
const TOOL_LABEL = ARG('--tool') || NAME;
const OUT        = ARG('--out');
const TOOLS_FILE = ARG('--tools-file');
const FORCE      = HAS('--force');
const HELP       = HAS('--help') || HAS('-h');

function die(msg, code = 2) {
  process.stderr.write(`generate_wrapper: ${msg}\n`);
  process.exit(code);
}

function usage() {
  process.stdout.write(`Usage:
  node scripts/generate_wrapper.cjs --name <kebab-name> [--tool "<label>"] --out <dir>
                                    [--tools-file <path>] [--force]

  --name        npm-package name for the wrapper (kebab-case, required)
  --tool        human-readable label for the wrapped target (defaults to --name)
  --out         output directory; will be created if missing (required)
  --tools-file  JSON file with an array of MCP tool definitions (optional)
  --force       overwrite existing files in --out

After generation:
  cd <out> && npm install && node server.js   # smoke test (Ctrl-C to exit)
`);
}

if (HELP) { usage(); process.exit(0); }
if (!NAME)        die('--name is required (kebab-case, e.g. my-cli-mcp)');
if (!OUT)         die('--out is required');
if (!/^[a-z][a-z0-9-]*$/.test(NAME)) {
  die(`--name must be kebab-case ([a-z][a-z0-9-]*), got "${NAME}"`);
}

// ── load tool definitions ──────────────────────────────────────────────────

let toolDefs = [];
if (TOOLS_FILE) {
  let raw;
  try { raw = fs.readFileSync(TOOLS_FILE, 'utf8'); }
  catch (e) { die(`cannot read --tools-file ${TOOLS_FILE}: ${e.message}`); }
  try { toolDefs = JSON.parse(raw); }
  catch (e) { die(`--tools-file is not valid JSON: ${e.message}`); }
  if (!Array.isArray(toolDefs)) die('--tools-file must contain a JSON array');
  for (const [i, t] of toolDefs.entries()) {
    if (!t || typeof t !== 'object') die(`tool[${i}] is not an object`);
    if (!t.name || typeof t.name !== 'string') die(`tool[${i}].name missing`);
    if (!/^[a-z_][a-z0-9_]*$/.test(t.name)) die(`tool[${i}].name must be snake_case`);
    if (!t.description) die(`tool[${i}].description missing`);
    if (!t.inputSchema || t.inputSchema.type !== 'object') die(`tool[${i}].inputSchema must be JSONSchema with type:"object"`);
  }
}

// ── output dir ─────────────────────────────────────────────────────────────

const outAbs = path.resolve(OUT);
if (fs.existsSync(outAbs)) {
  const entries = fs.readdirSync(outAbs).filter(f => !f.startsWith('.'));
  if (entries.length && !FORCE) {
    die(`output directory not empty: ${outAbs} (use --force to overwrite)`);
  }
}
fs.mkdirSync(outAbs, { recursive: true });

// ── render template files ──────────────────────────────────────────────────

function renderPlaceholders(src) {
  return src
    .replace(/\{\{name\}\}/g, NAME)
    .replace(/\{\{tool\}\}/g, TOOL_LABEL);
}

// Build the tools-array literal (pretty 6-space indent so it nests under
// `tools: [...]` cleanly).
function renderToolsBlock(defs) {
  if (!defs.length) {
    return [
      '      // No tools declared yet — replace this with your tool definitions.',
      '      // See ListToolsRequestSchema docs at https://modelcontextprotocol.io',
    ].join('\n');
  }
  return defs
    .map(t => JSON.stringify(t, null, 2).split('\n').map((l, i) => i === 0 ? '      ' + l : '      ' + l).join('\n'))
    .join(',\n');
}

// Build the switch-cases for CallToolRequestSchema (one stub per tool).
function renderCaseBlock(defs) {
  if (!defs.length) {
    return [
      '    // Add a `case "<tool_name>":` block for each tool above.',
    ].join('\n');
  }
  return defs.map(t => {
    const required = (t.inputSchema?.required || []).map(r => `"${r}"`).join(', ');
    const reqCheck = required
      ? `\n      for (const k of [${required}]) {\n        if (args?.[k] === undefined) {\n          return { isError: true, content: [{ type: "text", text: \`Missing required arg: \${k}\` }] };\n        }\n      }`
      : '';
    return [
      `    case "${t.name}": {${reqCheck}`,
      `      // TODO: implement ${t.name}`,
      `      return { content: [{ type: "text", text: "stub: ${t.name} not yet implemented" }] };`,
      `    }`,
    ].join('\n');
  }).join('\n\n');
}

const serverTpl = fs.readFileSync(path.join(TEMPLATE_DIR, 'server.js'), 'utf8');
let serverOut   = renderPlaceholders(serverTpl);

// Replace the commented-out example block in the ListTools handler.
const toolsBlock = renderToolsBlock(toolDefs);
serverOut = serverOut.replace(
  /tools: \[\n[\s\S]*?\n {4}\],/m,
  `tools: [\n${toolsBlock}\n    ],`,
);

// Replace the commented-out example block in the switch.
const caseBlock = renderCaseBlock(toolDefs);
serverOut = serverOut.replace(
  /switch \(name\) \{\n[\s\S]*?\n {4}default:/m,
  `switch (name) {\n${caseBlock}\n\n    default:`,
);

const packageTpl = fs.readFileSync(path.join(TEMPLATE_DIR, 'package.json'), 'utf8');
const packageOut = renderPlaceholders(packageTpl);

// Sanity-check the rendered server with Node's `--check` mode.
const tmpCheck = path.join(outAbs, '.server.tmp.js');
fs.writeFileSync(tmpCheck, serverOut);
const { spawnSync } = require('child_process');
const check = spawnSync(process.execPath, ['--check', tmpCheck], { encoding: 'utf8' });
fs.unlinkSync(tmpCheck);
if (check.status !== 0) {
  process.stderr.write(`generated server.js failed syntax check:\n${check.stderr}\n`);
  process.exit(1);
}

// ── write ───────────────────────────────────────────────────────────────────

fs.writeFileSync(path.join(outAbs, 'server.js'),    serverOut);
fs.writeFileSync(path.join(outAbs, 'package.json'), packageOut);

// .gitignore — avoid committing node_modules of a freshly-generated wrapper.
fs.writeFileSync(path.join(outAbs, '.gitignore'), 'node_modules/\n');

// README skeleton with install snippet for .mcp.json.
const readme = `# ${NAME}

MCP wrapper for **${TOOL_LABEL}**.

## Install

\`\`\`bash
cd ${path.basename(outAbs)}
npm install
\`\`\`

## Wire into a project

Add to your project's \`.mcp.json\`:

\`\`\`json
{
  "mcpServers": {
    "${NAME}": {
      "command": "node",
      "args": ["${path.resolve(outAbs, 'server.js')}"]
    }
  }
}
\`\`\`

Generated by \`mcp-skills-vault/scripts/generate_wrapper.cjs\`.
`;
fs.writeFileSync(path.join(outAbs, 'README.md'), readme);

process.stdout.write(`Generated wrapper at ${outAbs}\n`);
process.stdout.write(`  server.js     ${toolDefs.length} tool(s)\n`);
process.stdout.write(`  package.json  ${NAME}@0.1.0\n`);
process.stdout.write(`\nNext: cd ${outAbs} && npm install\n`);
