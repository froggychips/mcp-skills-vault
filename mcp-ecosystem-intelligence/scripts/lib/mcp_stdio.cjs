'use strict';
/**
 * mcp_stdio.cjs — shared, zero-dependency stdio JSON-RPC primitives for the
 * MCP behavioural layer. Vendored (not an npm dep) to keep the zero-runtime-deps
 * promise; the sister project mcp-trace can vendor the same file so the two
 * tools share one wire layer instead of two drifting copies.
 *
 * Three concerns, all pure / side-effect-light:
 *   1. JSON-RPC framing over newline-delimited stdio (request/notification/read)
 *   2. sandboxWrap()      — wrap a launch command in a locked-down container
 *   3. classifyFailure()  — map a raw failure into an honest failure class
 *
 * Node builtins only.
 */

// ── 1. JSON-RPC framing ─────────────────────────────────────────────────────

function jsonRpcRequest(id, method, params) {
  return JSON.stringify({ jsonrpc: '2.0', id, method, params: params || {} }) + '\n';
}

function jsonRpcNotification(method, params) {
  return JSON.stringify({ jsonrpc: '2.0', method, params: params || {} }) + '\n';
}

// Reads from a stream and resolves with the first JSON-RPC message whose `id`
// matches `wantedId`. Non-JSON lines (servers that wrongly log to stdout) and
// messages for other ids are skipped. `buffer` is a {value:string} carry-over
// so leftover bytes survive across calls. Outer timeout is the caller's job.
function readResponse(stdout, wantedId, buffer) {
  return new Promise((resolve, reject) => {
    function tryParseBuffer() {
      let nl;
      while ((nl = buffer.value.indexOf('\n')) !== -1) {
        const line = buffer.value.slice(0, nl).trim();
        buffer.value = buffer.value.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); }
        catch { continue; } // log line on stdout — ignore, keep reading
        if (msg && msg.id === wantedId) {
          stdout.removeListener('data', onData);
          stdout.removeListener('error', onError);
          stdout.removeListener('end', onEnd);
          return resolve(msg);
        }
      }
    }
    function onData(chunk) { buffer.value += chunk.toString('utf8'); tryParseBuffer(); }
    function onError(err)  { stdout.removeListener('data', onData); reject(err); }
    function onEnd()       { stdout.removeListener('data', onData); reject(new Error('stdout closed before response')); }
    stdout.on('data', onData);
    stdout.on('error', onError);
    stdout.on('end', onEnd);
    tryParseBuffer();
  });
}

// ── 2. Sandbox wrapper ───────────────────────────────────────────────────────

// Wrap a parsed {command,args} launch in an ephemeral, locked-down container.
//
// IMPORTANT: network is intentionally LEFT ON. `npx`/`uvx` fetch the package at
// launch, so `--network none` would break the very thing we're smoking. The
// jail here is everything *else* — no capabilities, read-only rootfs, non-root,
// memory/pid caps, install hooks disabled, auto-removed (`--rm`). Egress
// isolation (prefetch-then-run with `--network none`) is a separate, heavier
// mode and is deliberately not the default.
//
// `docker run` entries are already containerized by their own flags, so they
// pass through unchanged (sandboxed:false).
function sandboxWrap(parsed, opts = {}) {
  if (!parsed || typeof parsed.command !== 'string') return parsed;
  if (parsed.command === 'docker') {
    return { ...parsed, sandboxed: false, sandbox_note: 'docker entry is already containerized' };
  }
  const image = opts.image || (parsed.command === 'uvx'
    ? 'ghcr.io/astral-sh/uv:python3.12-bookworm-slim'  // ships uv/uvx
    : 'node:22-alpine');                               // ships node/npx
  const jail = [
    'run', '--rm', '-i',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--memory', opts.memory || '512m',
    '--pids-limit', String(opts.pidsLimit || 256),
    '--read-only',
    '--tmpfs', '/tmp:exec',
    '--tmpfs', '/home/node/.npm',
    '-e', 'HOME=/home/node',
    '-e', 'npm_config_ignore_scripts=true', // install hooks already vetted by verify_integrity
    '-u', 'node',
    image,
    parsed.command, ...parsed.args,
  ];
  return { command: 'docker', args: jail, sandboxed: true, image };
}

// ── 3. Failure classification ────────────────────────────────────────────────

const FAILURE_CLASS = {
  TIMEOUT:   'TIMEOUT',    // no response within the per-entry timeout
  NEEDS_ENV: 'NEEDS_ENV',  // server demanded credentials/config and bailed
  NEEDS_NET: 'NEEDS_NET',  // server failed reaching the network
  NO_TOOLS:  'NO_TOOLS',   // handshake fine, zero tools advertised
  CRASH:     'CRASH',      // exited / protocol error for some other reason
};

// Map a raw failure into one honest class. Pure function over the signals the
// smoke already collects (error_code string + stderr tail + tool count).
// Returns null when nothing failed.
function classifyFailure({ status, errorCode = '', stderr = '', toolCount = null } = {}) {
  if (status === 'pass') {
    return toolCount === 0 ? FAILURE_CLASS.NO_TOOLS : null;
  }
  if (status !== 'fail') return null;
  const ec = String(errorCode || '');
  if (/timeout/i.test(ec)) return FAILURE_CLASS.TIMEOUT;
  const s = `${ec}\n${stderr}`.toLowerCase();
  if (/api[_ ]?key|token|credential|unauthor|forbidden|missing .*(key|token|secret)|env(ironment)? var|not set/.test(s)) return FAILURE_CLASS.NEEDS_ENV;
  if (/econnrefused|enotfound|etimedout|eai_again|network|fetch failed|getaddrinfo|socket hang up|dns/.test(s)) return FAILURE_CLASS.NEEDS_NET;
  return FAILURE_CLASS.CRASH;
}

module.exports = {
  jsonRpcRequest,
  jsonRpcNotification,
  readResponse,
  sandboxWrap,
  classifyFailure,
  FAILURE_CLASS,
};
