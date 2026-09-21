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
 *
 * `null` when even that fails — no home directory *and* no writable temp dir.
 * The expression this replaces did no I/O and so could not fail, and callers
 * were written against that: `resolveNpmTreeCached` builds its cache path
 * outside either `try`, so a throw here would abort `verify --deps` over a
 * cache. A cache that cannot be created is not an error worth failing a scan
 * for — it is no cache. Callers treat `null` as "skip the cache".
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

// undefined = not attempted, string = the directory, null = attempted and failed
let scratch;

/** The cache root, or `null` if this process cannot have one. */
function cacheRoot() {
  if (process.env.MCP_VAULT_CACHE_DIR) return process.env.MCP_VAULT_CACHE_DIR;
  if (process.env.XDG_CACHE_HOME) return path.join(process.env.XDG_CACHE_HOME, 'mcp-vault');
  const home = os.homedir();
  if (home) return path.join(home, '.cache', 'mcp-vault');
  if (scratch === undefined) {
    // Tried once: a temp dir that is missing or read-only will not become
    // writable later in the run, and retrying per call would turn one failure
    // into a syscall on every cache lookup.
    try { scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-vault-cache-')); }
    catch { scratch = null; }
  }
  return scratch;
}

/** A named subtree of the cache: `cacheRoot()/<name>`, or `null` for no cache. */
function cacheDir(name) {
  const root = cacheRoot();
  return root ? path.join(root, name) : null;
}

module.exports = { cacheRoot, cacheDir };
