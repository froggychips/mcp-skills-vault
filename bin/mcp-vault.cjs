#!/usr/bin/env node
// mcp-vault — supply-chain-safe MCP server installer + auditor.
// Thin pass-through to the scripts/ directory. Zero deps. Node built-ins only.

"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

const SCRIPTS_DIR = path.join(
  __dirname, "..", "mcp-ecosystem-intelligence", "scripts"
);
const DB_PATH = path.join(
  __dirname, "..", "mcp-ecosystem-intelligence", "assets", "tools_database.json"
);

// Read the count instead of hardcoding it — the hardcoded "112" was already
// two entries stale, and a wrong number in the help text of a tool whose whole
// pitch is "deterministic" is the wrong first impression.
function dbEntryCount() {
  try {
    const db = JSON.parse(require("fs").readFileSync(DB_PATH, "utf8"));
    return Array.isArray(db.tools) ? db.tools.length : null;
  } catch {
    return null;
  }
}

const COMMANDS = {
  status:          "status.cjs",
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
  availability:    "check_availability.cjs",
  identity:        "check_identity.cjs",
  posture:         "check_posture.cjs",
  explain:         "explain.cjs",
  upgrade:         "suggest_upgrade.cjs",
  capabilities:    "check_capabilities.cjs",
  "license-drift": "check_license_drift.cjs",
  health:          "calculate_health.cjs",
  refresh:         "refresh_scores.cjs",
  wrap:            "generate_wrapper.cjs",
  "site-registry": "generate_registry_page.cjs",
  budget:          "token_budget.cjs",
  lock:            "lock.cjs",
  sbom:            "sbom.cjs",
};

const HELP = `mcp-vault — make MCP supply-chain boring.

USAGE
  mcp-vault <command> [options]

COMMANDS
  status            One screen: what is installed, what is wrong, what is missing
  scan              Detect project stack and recommend MCP servers
  list (ls)         Show every server in the vault DB (filters: --category, --tier, --query)
  doctor            Check local Node / gh / Docker / uvx / Claude MCP config readiness
  audit             Diff installed MCP servers against the vault DB
  verify            Integrity gate (hashes + advisories) over the whole DB
                    (--installed: over what your hosts actually launch)
  install <pkg>     Integrity gate, then write the host config
                    (--host claude-code|claude-desktop|cursor|vscode|codex)
  discover          Harvest fresh MCP candidates from npm / gh / README
  eval              Behavioural smoke (handshake + tools/list + schema lint)
  availability      Is every entry still published, and still the same thing?
  identity          Who published it, per the ownership-verified official registry
  posture           How each upstream repo is run (OpenSSF Scorecard via deps.dev)
  explain <name>    Why this entry is allowed or denied, with the evidence and the rule
  upgrade           Shortest version that clears the advisories against a pin
  capabilities      What a package can do, and what it gained since the last scan
  docker-drift      Detect upstream Docker @sha256 drift
  license-drift     Detect MIT → BSL / SSPL relicensing
  health <args>     Score a candidate by stars / recency / license / registry
  refresh           Refresh pinned versions + integrity hashes from registries
  wrap              Generate MCP wrapper boilerplate for a CLI / API tool
  site-registry     Generate docs/site/registry.html from tools_database.json
  budget            What your configured servers cost in context tokens
  sbom              CycloneDX bill of materials (--installed / --deps)
  lock              Freeze the verified dependency tree + tool surface (mcp.lock.json)
                    (--check: diff a fresh resolve against it; --vendor: install it)

COMMON OPTIONS
  --json            Machine-readable output
  --sarif           SARIF 2.1.0 for code scanning (verify)
  --strict          Treat warnings as failures (exit 1)
  --no-audit        Skip advisory APIs; verify still checks live registries
  --offline         True offline verify mode; validate stored DB pins only
  --fail-unverified Treat "could not check" as a failure (verify)
  --deep            Download artifacts and hash them locally (verify)
  --deps            Resolve and check dependency trees (verify)
  --show-policy     Print the .mcp-vault.policy.json in force (verify)
  --require-signatures  Unsigned npm release = failure (verify)
  --require-provenance  No provenance attestation = failure (verify)
  --allow-unpinned  Allow install to write a launch command with no version pin
  --allow-over-budget   Install even when the config would exceed the policy's
                        context ceiling (maxContextTokens / maxContextPercent)
  --cwd <path>      Target project directory (scan / audit)
  --host <id>       Which host config to write (install; --list-hosts to see them)
  --scope <s>       project or user (install; --global means --scope user)

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
        `  mcp-vault list                          # all ${dbEntryCount() ?? "available"} servers\n` +
        "  mcp-vault list --category database      # filter by category\n" +
        "  mcp-vault list --query github           # substring search\n" +
        "  mcp-vault scan --cwd ./your-project     # stack-aware recommendations\n\n" +
        "Then:\n" +
        "  mcp-vault install <name>                # writes ./.mcp.json\n" +
        "  mcp-vault install <name> --global       # writes ~/.claude.json\n" +
        "  mcp-vault install <name> --host cursor  # Cursor, VS Code, Claude Desktop, Codex\n" +
        "  mcp-vault install --list-hosts          # supported hosts and scopes\n"
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
