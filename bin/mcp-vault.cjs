#!/usr/bin/env node
// mcp-vault — supply-chain-safe MCP server installer + auditor.
// Thin pass-through to the scripts/ directory. Zero deps. Node built-ins only.

"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

const SCRIPTS_DIR = path.join(
  __dirname, "..", "mcp-ecosystem-intelligence", "scripts"
);

const COMMANDS = {
  audit:           "audit_setup.cjs",
  verify:          "verify_integrity.cjs",
  scan:            "orchestrate.cjs",
  install:         "orchestrate.cjs",
  list:            "list_entries.cjs",
  ls:              "list_entries.cjs",
  doctor:          "doctor.cjs",
  discover:        "discover.cjs",
  eval:            "mcp_eval.cjs",
  "docker-drift":  "check_docker_drift.cjs",
  "license-drift": "check_license_drift.cjs",
  health:          "calculate_health.cjs",
  refresh:         "refresh_scores.cjs",
  wrap:            "generate_wrapper.cjs",
  "site-registry": "generate_registry_page.cjs",
};

const HELP = `mcp-vault — make MCP supply-chain boring.

USAGE
  mcp-vault <command> [options]

COMMANDS
  scan              Detect project stack and recommend MCP servers
  list (ls)         Show every server in the vault DB (filters: --category, --tier, --query)
  doctor            Check local Node / gh / Docker / uvx / Claude MCP config readiness
  audit             Diff installed MCP servers against the vault DB
  verify            Integrity gate (hashes + advisories) over the whole DB
  install <pkg>     Integrity gate, then write .mcp.json
  discover          Harvest fresh MCP candidates from npm / gh / README
  eval              Behavioural smoke (handshake + tools/list + schema lint)
  docker-drift      Detect upstream Docker @sha256 drift
  license-drift     Detect MIT → BSL / SSPL relicensing
  health <args>     Score a candidate by stars / recency / license / registry
  refresh           Refresh pinned versions + integrity hashes from registries
  wrap              Generate MCP wrapper boilerplate for a CLI / API tool
  site-registry     Generate docs/site/registry.html from tools_database.json

COMMON OPTIONS
  --json            Machine-readable output
  --strict          Treat warnings as failures (exit 1)
  --no-audit        Skip advisory APIs; verify still checks live registries
  --offline         True offline verify mode; validate stored DB pins only
  --cwd <path>      Target project directory (scan / audit)

  Each command also accepts its own flags — run with --help for details.

QUICK START
  npx -y @froggychips/mcp-vault scan --cwd ./my-project
  npx -y @froggychips/mcp-vault audit --strict
  npx -y @froggychips/mcp-vault verify --offline

DOCS  https://github.com/froggychips/mcp-skills-vault
SITE  https://mcp.froggychips.xyz
`;

function showHelp(toStdout) {
  (toStdout ? process.stdout : process.stderr).write(HELP);
}

function showVersion() {
  const pkg = require(path.join(__dirname, "..", "package.json"));
  process.stdout.write(`mcp-vault ${pkg.version}\n`);
}

function main(argv) {
  const cmd = argv[0];

  if (!cmd || cmd === "-h" || cmd === "--help" || cmd === "help") {
    showHelp(true);
    process.exit(0);
  }

  if (cmd === "-v" || cmd === "--version" || cmd === "version") {
    showVersion();
    process.exit(0);
  }

  const script = COMMANDS[cmd];
  if (!script) {
    process.stderr.write(`mcp-vault: unknown command "${cmd}"\n\n`);
    showHelp(false);
    process.exit(2);
  }

  let passArgs = argv.slice(1);

  // `mcp-vault install <pkg> [--global]` → `orchestrate.cjs --install <pkg> [--global]`
  if (cmd === "install") {
    const firstNonFlag = passArgs.findIndex(a => !a.startsWith("-"));
    if (firstNonFlag === -1) {
      process.stderr.write(
        "mcp-vault install: package name required.\n\n" +
        "Find one:\n" +
        "  mcp-vault list                          # all 112 servers\n" +
        "  mcp-vault list --category database      # filter by category\n" +
        "  mcp-vault list --query github           # substring search\n" +
        "  mcp-vault scan --cwd ./your-project     # stack-aware recommendations\n\n" +
        "Then:\n" +
        "  mcp-vault install <name>                # writes ./.mcp.json\n" +
        "  mcp-vault install <name> --global       # writes ~/.claude.json\n"
      );
      process.exit(2);
    }
    const pkg = passArgs[firstNonFlag];
    passArgs = [
      ...passArgs.slice(0, firstNonFlag),
      ...passArgs.slice(firstNonFlag + 1),
      "--install", pkg,
    ];
  }

  const scriptPath = path.join(SCRIPTS_DIR, script);
  const result = spawnSync(process.execPath, [scriptPath, ...passArgs], {
    stdio: "inherit",
  });

  if (result.error) {
    process.stderr.write(`mcp-vault: failed to run ${script}: ${result.error.message}\n`);
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}

main(process.argv.slice(2));
