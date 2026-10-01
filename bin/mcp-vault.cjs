#!/usr/bin/env node
// mcp-vault — supply-chain-safe MCP server installer + auditor.
// Thin pass-through to the scripts/ directory. Zero deps. Node built-ins only.

"use strict";

const path = require("path");
const { spawnSync } = require("child_process");
const { loadTrustedKeys } = require("../mcp-ecosystem-intelligence/scripts/lib/signing.cjs");
const {
  checkDb, allowUnsignedFromEnv, signatureContext, ALLOW_FLAG,
} = require("../mcp-ecosystem-intelligence/scripts/lib/db_signature.cjs");
const { readWallClock } = require("../mcp-ecosystem-intelligence/scripts/lib/clock.cjs");

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
  check:           "check_configs.cjs",
  audit:           "audit_setup.cjs",
  secrets:         "check_secrets.cjs",
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
  "tool-scan":     "check_tool_descriptions.cjs",
  "license-drift": "check_license_drift.cjs",
  health:          "calculate_health.cjs",
  refresh:         "refresh_scores.cjs",
  wrap:            "generate_wrapper.cjs",
  "site-registry": "generate_registry_page.cjs",
  badge:           "badge.cjs",
  "export-registry": "export_subregistry.cjs",
  "registry-ingest": "registry_ingest.cjs",
  budget:          "token_budget.cjs",
  lock:            "lock.cjs",
  approve:         "approve.cjs",
  sbom:            "sbom.cjs",
  signature:       "check_signature.cjs",
  audits:          "audits.cjs",
};

// Commands that never read the DB, so its signature is not their business.
// `signature` reports on it itself, and must be reachable when it is broken.
const DB_FREE = new Set(["wrap", "health", "doctor", "signature"]);

const HELP = `mcp-vault — make MCP supply-chain boring.

USAGE
  mcp-vault <command> [options]

COMMANDS
  status            One screen: what is installed, what is wrong, what is missing
  check [paths…]    This repo's MCP configs in one pass, one exit code (CI, pre-commit):
                    pins, advisories, unpinned launches, secrets, lookalikes, flows
                    (offline by default; --online, --json, --sarif, --strict, --fail-on)
  scan              Detect project stack and recommend MCP servers
  list (ls)         Show every server in the vault DB (filters: --category, --tier, --query)
  doctor            Check local Node / gh / Docker / uvx / Claude MCP config readiness
  audit             Diff installed MCP servers against the vault DB
  secrets           Plain-text credentials in host configs (value never printed)
  verify            Integrity gate (hashes + advisories) over the whole DB
                    (--installed: over what your hosts actually launch;
                     --config <path>…: over exactly these config files)
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
  tool-scan [file]  Tool poisoning in descriptions/schemas: hidden Unicode, ANSI,
                    injected instructions (--sarif; --rules for the rule table)
  docker-drift      Detect upstream Docker @sha256 drift
  license-drift     Detect MIT → BSL / SSPL relicensing
  health <args>     Score a candidate by stars / recency / license / registry
  refresh           Refresh pinned versions + integrity hashes from registries
  wrap              Generate MCP wrapper boilerplate for a CLI / API tool
  site-registry     Generate registry.html from tools_database.json, every entry's
                    badge + evidence page, and the sub-registry export below
                    (--out <site root> --base-url <url>)
  badge <name>      README snippet for a "vetted by mcp-vault" badge, and what it says today
  export-registry   The DB as a static MCP sub-registry: <out>/v0.1/ (API v0.1)
                    (--out <site root, default docs/site> --base-url <url>)
  registry-ingest   Official registry snapshot → withdrawn entries + new servers
                    (--fetch --out <file> is the only networked step)
  budget            What your configured servers cost in context tokens
  sbom              CycloneDX bill of materials (--installed / --deps)
  lock              Freeze the verified dependency tree + tool surface (mcp.lock.json)
                    (--check: diff a fresh resolve against it; --vendor: install it)
  approve <server>  Approve a server's tools in mcp.lock.json (policy toolApproval)
                    (--tool X: one tool; shows what changed in descriptions/schemas)
  signature         Check the DB against its Ed25519 signature and the shipped keyring
  audits <sub>      Your audits and imported ones (list | add | export | fetch | check)

COMMON OPTIONS
  --json            Machine-readable output
  --sarif           SARIF 2.1.0 for code scanning (verify, tool-scan)
  --strict          Treat warnings as failures (exit 1)
  --no-audit        Skip advisory APIs; verify still checks live registries
  --offline         True offline verify mode: stored DB pins and stored evidence
                    (a recorded advisory or yanked release fails), no network
  --fail-unverified Treat "could not check" as a failure (verify)
  --fail-families <a,b>  Only these rule families fail the run (verify), e.g.
                    integrity,pin,oci,verify,policy for "is the DB consistent"
  --deep            Download artifacts and hash them locally (verify)
  --deps            Resolve and check dependency trees (verify)
  --show-policy     Print the .mcp-vault.policy.json in force (verify)
  --policy <path>   Use this policy file instead of searching for one (verify)
  --fail-on <effect> Exit threshold: deny | unknown (= --fail-unverified) | warn (= --strict) (verify)
  --require-signatures  Unsigned npm release = failure (verify)
  --require-provenance  No provenance attestation = failure (verify)
  --allow-unpinned  Allow install to write a launch command with no version pin
  --allow-over-budget   Install even when the config would exceed the policy's
                        context ceiling (maxContextTokens / maxContextPercent)
  --allow-lookalike <name>  A configured server shaped like a vault entry that
                        you know is yours: still reported, no longer fails
                        --strict (audit, verify --installed)
  --cwd <path>      Target project directory (scan / audit)
  --as-of <date>    Judge stored evidence as of YYYY-MM-DD or an ISO-8601 instant
                    instead of now (verify / status / explain / audit / list / scan);
                    stored evidence only, so verify needs --offline
  --host <id>       Which host config to write (install; --list-hosts to see them)
  --scope <s>       project or user (install; --global means --scope user)
  --allow-unsigned-db   Run on a DB whose signature does not verify (development,
                        forks). Loud on every run; also MCP_VAULT_ALLOW_UNSIGNED_DB=1

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

/**
 * Every DB this command will read: the bundled one, and each `--db` value
 * (`--db x` and `--db=x`, every occurrence). All of them, because the scripts
 * behind this wrapper disagree about which occurrence wins — most take the
 * last — and checking one while the script reads another is no check at all.
 */
function dbPathsOf(passArgs) {
  const dbs = [DB_PATH];
  for (let i = 0; i < passArgs.length; i++) {
    const a = passArgs[i];
    if (a === "--db" && passArgs[i + 1] !== undefined) dbs.push(path.resolve(passArgs[++i]));
    else if (a.startsWith("--db=")) dbs.push(path.resolve(a.slice("--db=".length)));
  }
  return [...new Set(dbs)];
}

/**
 * Check those DBs before the command reads them. Returns an exit code to stop
 * with, or null to carry on. The verdict is the `db/signature` row's, via
 * decide() (lib/db_signature.cjs); this only prints it.
 *
 * Where the CLI runs decides one thing: whether a *missing* signature refuses.
 * An installed package requires one; a git checkout (development, CI) does
 * not. A signature that is present must verify, everywhere.
 */
function dbSignatureRefusal(passArgs, allowUnsigned) {
  const keyring = loadTrustedKeys();
  const context = signatureContext();
  // The decision does not depend on the instant (key windows are checked
  // against the signed date); the document still says when it was made.
  const asOf = readWallClock();
  for (const dbPath of dbPathsOf(passArgs)) {
    const check = checkDb({
      dbPath, keys: keyring.keys, keyringOk: keyring.ok, keyringErrors: keyring.errors,
      allowUnsigned, context, asOf,
    });
    if (!check.proceed) {
      process.stderr.write(`${check.message}\n`);
      return 1;
    }
    if (check.state === "unsigned-allowed") process.stderr.write(`${check.message}\n`);
  }
  return null;
}

function main(rawArgv) {
  // Stripped here, in any position: it is a statement about the DB this
  // wrapper checks, not an option of the script behind it.
  // (`signature` keeps it: reporting on the override is part of its job.)
  const allowUnsigned = rawArgv.includes(ALLOW_FLAG) || allowUnsignedFromEnv(process.env);
  const argv = rawArgv[0] === "signature" ? rawArgv : rawArgv.filter((a) => a !== ALLOW_FLAG);
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

  if (!DB_FREE.has(cmd)) {
    const refusal = dbSignatureRefusal(passArgs, allowUnsigned);
    if (refusal !== null) process.exit(refusal);
  }

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
