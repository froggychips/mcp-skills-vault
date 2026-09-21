'use strict';
/**
 * One place that decides where this tool's cache lives.
 *
 * There were two copies of the same expression — in `http.cjs` and `deps.cjs` —
 * and both ended in `os.homedir() || os.tmpdir()`. The fallback is the part
 * worth being careful about: with no home directory, every user on the machine
 * got the *same* guessable path under the system temp dir, and a cache entry is
 * a file this process later reads back and believes. That is CWE-377, and
 * CodeQL flagged it three times (`js/insecure-temporary-file`) — once per write
 * that the fallback could reach.
 *
 * So the fallback is a private directory made by `mkdtemp`, once per process:
 * unguessable, owned by us, and still a real directory, so the cache keeps
 * working for the length of the run instead of silently turning itself off.
 *
 * Order, unchanged from the two copies this replaces:
 *   MCP_VAULT_CACHE_DIR   — used as-is, the escape hatch the tests take
 *   XDG_CACHE_HOME        — $XDG_CACHE_HOME/mcp-vault
 *   $HOME                 — $HOME/.cache/mcp-vault
 *   (none of the above)   — a fresh mkdtemp directory
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

let scratch = null;   // the mkdtemp fallback, made at most once per process

function cacheRoot() {
  if (process.env.MCP_VAULT_CACHE_DIR) return process.env.MCP_VAULT_CACHE_DIR;
  if (process.env.XDG_CACHE_HOME) return path.join(process.env.XDG_CACHE_HOME, 'mcp-vault');
  const home = os.homedir();
  if (home) return path.join(home, '.cache', 'mcp-vault');
  if (!scratch) scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-cache-'));
  return scratch;
}

/** A named subtree of the cache: `cacheRoot()/<name>`. */
function cacheDir(name) {
  return path.join(cacheRoot(), name);
}

module.exports = { cacheRoot, cacheDir };
