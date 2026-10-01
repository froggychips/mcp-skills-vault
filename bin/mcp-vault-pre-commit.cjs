#!/usr/bin/env node
// mcp-vault-pre-commit — the entry of the `mcp-vault` pre-commit hook
// (.pre-commit-hooks.yaml). It runs `mcp-vault check` and nothing else.
//
// pre-commit installs the hook repository as a package (`npm pack` of the
// commit `rev:` pins, then `npm install -g` into its own node_env): no .git,
// and no DB signature, which is made at release and is not in git. The CLI
// requires a signature from an installed package, so the hook refused to run.
// Here, as in the Action's checkout mode, the pin is the integrity: the DB is
// the bytes of the commit `rev:` names, exactly as the code that checks it is.
//
// So this entry — and only it — asks the CLI to accept that, by setting
// MCP_VAULT_PRE_COMMIT_HOOK for its own child process. The CLI still decides
// (lib/db_signature.cjs preCommitPin): only when pre-commit runs the hook
// (PRE_COMMIT=1) and this package sits where pre-commit installs a hook, in a
// clone whose DB is byte-for-byte this one. A .sig that is present must still
// verify, and `mcp-vault` itself, or an npm/npx install, never relaxes.

"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const {
  PACKAGE_ROOT, PRE_COMMIT_ENV, preCommitPin, sigPathFor,
} = require("../mcp-ecosystem-intelligence/scripts/lib/db_signature.cjs");

const CLI = path.join(__dirname, "mcp-vault.cjs");
const DB_PATH = path.join(PACKAGE_ROOT, "mcp-ecosystem-intelligence", "assets", "tools_database.json");

function main(argv) {
  // The hook checks the vault's own DB. Another one is not what `rev:` pins.
  if (argv.some((a) => a === "--db" || String(a).startsWith("--db="))) {
    process.stderr.write("mcp-vault-pre-commit: --db is not accepted here — the hook checks against the DB its rev: pins\n");
    return 2;
  }
  const env = { ...process.env };
  const hasSig = fs.existsSync(sigPathFor(DB_PATH));
  if (hasSig) {
    delete env[PRE_COMMIT_ENV];
    process.stderr.write("mcp-vault: DB integrity: Ed25519 signature, checked by the CLI\n");
  } else {
    const pin = preCommitPin({ root: PACKAGE_ROOT, env });
    if (pin.ok) {
      env[PRE_COMMIT_ENV] = "1";
      process.stderr.write("mcp-vault: DB integrity: pinned by pre-commit rev\n");
    } else {
      // Not pre-commit's install: the CLI's own rule applies, and says why.
      delete env[PRE_COMMIT_ENV];
    }
  }
  const r = spawnSync(process.execPath, [CLI, "check", ...argv], { stdio: "inherit", env });
  if (r.error) {
    process.stderr.write(`mcp-vault-pre-commit: failed to run check: ${r.error.message}\n`);
    return 1;
  }
  return r.status ?? 1;
}

process.exit(main(process.argv.slice(2)));
