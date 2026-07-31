#!/usr/bin/env node
/**
 * mcp_eval.cjs — deterministic behavioural smoke for MCP servers.
 *
 * Spawns each DB entry as a subprocess, performs the canonical JSON-RPC
 * handshake (`initialize` → `tools/list`), and validates each tool's
 * `inputSchema` with a *minimal* JSON Schema lint that intentionally
 * covers only the structural properties Claude Code actually reads
 * (`type`, `properties`, `required`, `enum`, `description`).
 *
 * Why this exists: the integrity gate (`verify_integrity.cjs`) checks
 * that the artifact you got matches the hash you expected. It does
 * NOT check that the artifact actually starts and exposes a usable
 * tool surface. This script closes that "behavioural integrity" gap
 * flagged in SECURITY.md — deterministically, with zero runtime deps
 * and no LLM in the critical path.
 *
 * Results are written to a separate file (`assets/eval_results.json`),
 * never back into `tools_database.json` — DB stays the deterministic
 * source of truth for what to install, eval results are an evidence
 * stream a maintainer can inspect.
 *
 * Network policy:
 *   - Real smoke is NOT offline. `npx` and `uvx` need to fetch the
 *     package; `docker run` needs to pull the image. This is documented;
 *     the CI job runs cron-only (never on PRs).
 *   - `--no-spawn` re-lints schemas from an existing results file
 *     without spawning anything. That path IS offline.
 *
 * Usage:
 *   mcp_eval.cjs                        smoke every entry with a recognized install method
 *   mcp_eval.cjs --name <name>          smoke one entry by exact or substring match
 *   mcp_eval.cjs --all                  explicit form of default
 *   mcp_eval.cjs --timeout <ms>         per-entry timeout (default 30000)
 *   mcp_eval.cjs --json                 machine-readable summary on stdout
 *   mcp_eval.cjs --no-spawn             schema-lint over existing eval_results.json (offline)
 *   mcp_eval.cjs --sandbox              run each server in a locked-down container (needs docker)
 *   mcp_eval.cjs --unsafe               run servers directly on the host (explicit opt-out of the sandbox)
 *   mcp_eval.cjs --db <path>            override DB path
 *   mcp_eval.cjs --results <path>       override results file path
 *   mcp_eval.cjs --strict               exit 1 on any failure or unavailable launcher
 *   mcp_eval.cjs --help                 print this help
 *
 * Spawn policy (default-deny): a live smoke executes third-party server code,
 * so you must pick how. Pass `--sandbox` (jailed ephemeral container — safe for
 * PR CI on a shared/host runner) or `--unsafe` (run on the host — fine for the
 * cron job on a trusted runner). Without either, the live smoke refuses to run.
 * `--no-spawn` is exempt: it never executes anything.
 *
 * Exit codes:
 *   0  smoke completed (and, under --strict, all entries passed)
 *   1  --strict: at least one entry failed, or an entry went unchecked
 *      because its launcher was missing on this host (a CI gap, not a pass)
 *   2  bad arguments
 */

'use strict';

const fs            = require('fs');
const path          = require('path');
const { spawn }     = require('child_process');
const { performance } = require('perf_hooks');
const { exitAfterFlush } = require('./lib/exit.cjs');
const stdio         = require('./lib/mcp_stdio.cjs'); // shared framing + sandbox + classifier (vendored, zero-dep)

// ── Constants ──────────────────────────────────────────────────────────────

const VERSION = '0.1.0';
const DEFAULT_DB_PATH      = path.resolve(__dirname, '../assets/tools_database.json');
const DEFAULT_RESULTS_PATH = path.resolve(__dirname, '../assets/eval_results.json');
const DEFAULT_TIMEOUT_MS   = 30000;
const SHUTDOWN_GRACE_MS    = 2000;
const PROTOCOL_VERSION     = '2025-06-18';
const CLIENT_INFO          = { name: 'mcp-eval', version: VERSION };

// ── CLI parsing (mirrors orchestrate.cjs style) ────────────────────────────

function parseArgs(argv) {
  const opts = {
    name:     null,
    all:      false,
    timeout:  DEFAULT_TIMEOUT_MS,
    json:     false,
    noSpawn:  false,
    sandbox:  false,
    unsafe:   false,
    db:       DEFAULT_DB_PATH,
    results:  DEFAULT_RESULTS_PATH,
    strict:   false,
    help:     false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = argv[i + 1];
    switch (a) {
      case '--name':    opts.name    = next; i++; break;
      case '--all':     opts.all     = true; break;
      case '--timeout': opts.timeout = Math.max(1000, parseInt(next, 10) || DEFAULT_TIMEOUT_MS); i++; break;
      case '--json':    opts.json    = true; break;
      case '--no-spawn':opts.noSpawn = true; break;
      case '--sandbox': opts.sandbox = true; break;
      case '--unsafe':  opts.unsafe  = true; break;
      case '--db':      opts.db      = next; i++; break;
      case '--results': opts.results = next; i++; break;
      case '--strict':  opts.strict  = true; break;
      case '-h':
      case '--help':    opts.help    = true; break;
      default:
        if (a.startsWith('--')) {
          process.stderr.write(`Unknown flag: ${a}\n`);
          opts.help = true;
        }
    }
  }
  return opts;
}

function printHelp() {
  const head = fs.readFileSync(__filename, 'utf8')
    .split('\n')
    .filter(l => l.startsWith(' *') || l.startsWith('/**') || l.startsWith(' */'))
    .map(l => l.replace(/^ \* ?/, '').replace(/^\/\*\* ?/, '').replace(/^ \*\/$/, ''))
    .join('\n');
  process.stdout.write(head + '\n');
}

// ── install_cmd parser ─────────────────────────────────────────────────────

// Recognized install methods → { command, args }. Anything else returns
// null and is recorded as `status: skipped` with reason "unrecognized
// install method" — including `uvx --from git+…` which is intentionally
// unsupported (no integrity, no determinism).
function parseInstallCmd(cmd) {
  if (typeof cmd !== 'string') return null;
  const trimmed = cmd.trim();
  if (!trimmed) return null;
  const parts = trimmed.split(/\s+/);
  const head  = parts[0];

  if (head === 'npx') {
    // `npx -y <pkg>[@ver] [extra args]`. We require -y so a real eval doesn't
    // hang on the npm install prompt.
    if (parts[1] !== '-y') return null;
    if (!parts[2])         return null;
    return { command: 'npx', args: parts.slice(1) };
  }

  if (head === 'uvx') {
    // `uvx --from git+…` is rejected — explicitly unsupported.
    if (parts[1] === '--from') return null;
    if (!parts[1])              return null;
    return { command: 'uvx', args: parts.slice(1) };
  }

  if (head === 'docker') {
    if (parts[1] !== 'run') return null;
    return { command: 'docker', args: parts.slice(1) };
  }

  return null;
}

// ── Minimal JSON Schema lint ───────────────────────────────────────────────

// Deliberately narrower than Draft 2020-12. Validates only the surface
// Claude Code actually reads from `tool.inputSchema`:
//   - top-level must be an object with `type: "object"`
//   - `properties`, when present, must be an object
//   - `required`, when present, must be an array of strings, all of
//     which exist in `properties`
//   - each property may declare `type` / `properties` / `enum` /
//     `description` / `items` / `additionalProperties` / `default`
//   - `$ref` is hard-rejected: we don't resolve external schemas
//
// Returns an array of human-readable error strings; empty array means
// the schema passed the lint.
const ALLOWED_PROP_KEYS = new Set([
  'type', 'properties', 'required', 'enum', 'description',
  'items', 'additionalProperties', 'default', 'examples',
  'minimum', 'maximum', 'minLength', 'maxLength', 'pattern',
  'format', 'title', 'oneOf', 'anyOf', 'allOf',
]);
const ALLOWED_TYPES = new Set([
  'string', 'number', 'integer', 'boolean', 'array', 'object', 'null',
]);

function lintSchema(schema) {
  const errors = [];

  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    errors.push('inputSchema must be a JSON object');
    return errors;
  }

  if ('$ref' in schema) {
    errors.push('top-level $ref is not supported (external refs unresolved)');
  }

  if (schema.type !== 'object') {
    errors.push(`top-level type must be "object", got ${JSON.stringify(schema.type)}`);
  }

  if ('properties' in schema) {
    const props = schema.properties;
    if (props === null || typeof props !== 'object' || Array.isArray(props)) {
      errors.push('properties must be an object');
    } else {
      for (const [name, propSchema] of Object.entries(props)) {
        lintPropSchema(propSchema, name, errors);
      }
    }
  }

  if ('required' in schema) {
    const req = schema.required;
    if (!Array.isArray(req)) {
      errors.push('required must be an array');
    } else {
      for (const r of req) {
        if (typeof r !== 'string') {
          errors.push(`required must contain only strings (got ${typeof r})`);
        } else if (schema.properties && typeof schema.properties === 'object' && !(r in schema.properties)) {
          errors.push(`required references unknown property: "${r}"`);
        }
      }
    }
  }

  return errors;
}

function lintPropSchema(propSchema, name, errors, depth = 0) {
  // Defensive cap — pathological self-referential schemas shouldn't hang
  // the linter. Real MCP tool schemas top out at 3–4 levels.
  if (depth > 10) {
    errors.push(`property "${name}" exceeds nesting depth (10)`);
    return;
  }

  if (propSchema === null || typeof propSchema !== 'object' || Array.isArray(propSchema)) {
    errors.push(`property "${name}" must be an object`);
    return;
  }

  if ('$ref' in propSchema) {
    errors.push(`property "${name}" uses $ref — unresolved external schemas are rejected`);
  }

  // `type` may be a string or an array of strings (union types).
  if ('type' in propSchema) {
    const t = propSchema.type;
    const types = Array.isArray(t) ? t : [t];
    for (const tt of types) {
      if (typeof tt !== 'string' || !ALLOWED_TYPES.has(tt)) {
        errors.push(`property "${name}" has unknown type ${JSON.stringify(tt)}`);
      }
    }
  }

  if ('enum' in propSchema && !Array.isArray(propSchema.enum)) {
    errors.push(`property "${name}".enum must be an array`);
  }

  // Recurse into nested objects.
  if ('properties' in propSchema) {
    const inner = propSchema.properties;
    if (inner === null || typeof inner !== 'object' || Array.isArray(inner)) {
      errors.push(`property "${name}".properties must be an object`);
    } else {
      for (const [k, v] of Object.entries(inner)) {
        lintPropSchema(v, `${name}.${k}`, errors, depth + 1);
      }
    }
  }

  // Recurse into array item schemas.
  if ('items' in propSchema && propSchema.items && typeof propSchema.items === 'object') {
    lintPropSchema(propSchema.items, `${name}[]`, errors, depth + 1);
  }

  // Unknown keys are non-fatal — schemas often carry vendor extensions
  // (`x-...`) or fields outside the lint surface. We don't warn so the
  // linter stays predictable in the face of harmless extras.
  void ALLOWED_PROP_KEYS;
}

// ── JSON-RPC framing over child stdio ──────────────────────────────────────

// Framing primitives now live in the shared, vendored core so mcp-trace can
// reuse the identical wire layer. MCP uses newline-delimited JSON over the
// spawned process's stdin/stdout; readResponse() resolves with the first
// message whose id matches, ignoring log lines and other ids.
const { jsonRpcRequest, jsonRpcNotification, readResponse } = stdio;

// Resolves when the child exits or the timeout elapses, whichever comes
// first. `isExited` is a thunk because the caller closes over a mutable
// flag we don't want to thread through arguments.
function waitForExitOrTimeout(child, ms, isExited) {
  return new Promise((resolve) => {
    if (isExited()) return resolve();
    const t = setTimeout(resolve, ms);
    child.once('exit', () => { clearTimeout(t); resolve(); });
  });
}

// ── Smoke one entry ────────────────────────────────────────────────────────

async function smokeEntry(tool, opts) {
  const result = {
    name:             tool.name,
    status:           'skip',
    boot_ms:          null,
    list_latency_ms:  null,
    tool_count:       null,
    tool_count_db:    typeof tool.est_tools_count === 'number' ? tool.est_tools_count : null,
    tool_count_drift: false,
    schema_errors:    [],
    stderr_tail:      null,
    error_code:       null,
    failure_class:    null,
    sandboxed:        false,
    checked_at:       new Date().toISOString(),
  };

  // `_evalSpawn` is a test-only escape hatch: it lets tests inject a
  // pre-resolved {command, args} so the fake server (which doesn't
  // look like npx/uvx/docker) can drive the smoke loop end-to-end
  // without forking the parser. Production DB entries never carry it.
  const parsed = tool._evalSpawn || parseInstallCmd(tool.install_cmd);
  if (!parsed) {
    result.error_code = 'unrecognized install method';
    return result;
  }

  // Once a process is actually talking to us the verdict is pass/fail;
  // `skip` stays reserved for "we never got to ask" — an install_cmd we
  // couldn't parse, or a launcher binary missing on this host (below).
  result.status = 'fail';

  // Sandbox real entries when asked; the test fake-server (_evalSpawn) always
  // runs on the host. docker-run entries pass through (already containerized).
  const launch = (opts.sandbox && !tool._evalSpawn) ? stdio.sandboxWrap(parsed) : parsed;
  result.sandboxed = !!launch.sandboxed;

  // Track stderr for failure diagnostics (last 4 lines, capped at 4KB).
  const stderrChunks = [];
  const stderrLimit  = 4096;
  let stderrSize = 0;

  let child;
  try {
    child = spawn(launch.command, launch.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      // Production smoke needs PATH for npx/uvx/docker; we don't pass a
      // scrubbed env. Test fixtures spawn `node` directly and don't care.
    });
  } catch (e) {
    result.status     = 'fail';
    result.error_code = `spawn error: ${e.code || e.message}`;
    return result;
  }

  // The catch above only sees synchronous throws. A missing launcher
  // (docker/npx/uvx not on PATH) is reported asynchronously as an 'error'
  // event instead — and with no listener Node escalates it to an uncaught
  // exception, killing the whole eval and losing every other entry's
  // verdict. Attach a listener before anything else can emit.
  child.on('error', () => {});
  // stdin is torn down with the failed spawn; its EPIPE is redundant noise
  // on top of the 'error' above, and would itself be unhandled.
  child.stdin.on('error', () => {});

  // A spawn that never started leaves pid undefined — synchronous, so we
  // can bail before writing a handshake into a dead pipe. This is a gap in
  // the host environment, not a verdict on the server: `fail` would brand
  // every docker-based entry as broken on a runner that simply lacks docker.
  if (child.pid === undefined) {
    result.status     = 'skip';
    result.error_code = `launcher unavailable: ${launch.command}`;
    return result;
  }

  child.stderr.on('data', (chunk) => {
    if (stderrSize >= stderrLimit) return;
    stderrChunks.push(chunk);
    stderrSize += chunk.length;
  });

  const buffer = { value: '' };
  let timedOut = false;
  let exited   = false;
  let exitCode = null;

  child.on('exit', (code) => { exited = true; exitCode = code; });

  // Outer timeout for the whole handshake.
  const timeout = new Promise((resolve) => {
    setTimeout(() => { timedOut = true; resolve('timeout'); }, opts.timeout);
  });

  try {
    // 1. initialize
    const t0 = performance.now();
    child.stdin.write(jsonRpcRequest(1, 'initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: CLIENT_INFO,
    }));
    const initResp = await Promise.race([readResponse(child.stdout, 1, buffer), timeout]);
    if (timedOut || initResp === 'timeout') {
      result.status     = 'fail';
      result.error_code = 'timeout';
      throw new Error('timeout');
    }
    result.boot_ms = Math.round(performance.now() - t0);

    if (initResp && initResp.error) {
      result.status     = 'fail';
      result.error_code = `initialize error: ${initResp.error.code} ${initResp.error.message || ''}`.trim();
      throw new Error('initialize error');
    }

    // 2. initialized notification (one-way, no response expected)
    child.stdin.write(jsonRpcNotification('notifications/initialized'));

    // 3. tools/list
    const t1 = performance.now();
    child.stdin.write(jsonRpcRequest(2, 'tools/list'));
    const listResp = await Promise.race([readResponse(child.stdout, 2, buffer), timeout]);
    if (timedOut || listResp === 'timeout') {
      result.status     = 'fail';
      result.error_code = 'timeout';
      throw new Error('timeout');
    }
    result.list_latency_ms = Math.round(performance.now() - t1);

    if (listResp && listResp.error) {
      result.status     = 'fail';
      result.error_code = `tools/list error: ${listResp.error.code} ${listResp.error.message || ''}`.trim();
      throw new Error('tools/list error');
    }

    const tools = (listResp && listResp.result && Array.isArray(listResp.result.tools))
      ? listResp.result.tools
      : [];
    result.tool_count = tools.length;
    if (typeof result.tool_count_db === 'number') {
      result.tool_count_drift = result.tool_count !== result.tool_count_db;
    }

    // 4. Lint each tool's inputSchema
    for (const t of tools) {
      const name = (t && typeof t.name === 'string') ? t.name : '<unnamed>';
      if (!t || !('inputSchema' in t)) {
        result.schema_errors.push({ tool: name, error: 'no inputSchema field' });
        continue;
      }
      const errs = lintSchema(t.inputSchema);
      for (const e of errs) result.schema_errors.push({ tool: name, error: e });
    }

    // Schema errors don't flip the verdict — a server may legitimately
    // expose a schema we don't fully model. We surface them; humans
    // decide. Status stays "pass" if the handshake worked.
    result.status = 'pass';
  } catch {
    // status / error_code already set on the result above
  } finally {
    // Clean shutdown: close stdin and wait — well-behaved servers exit
    // when stdin closes. Escalate to SIGTERM then SIGKILL if they don't.
    try { child.stdin.end(); } catch {}
    if (!exited) {
      await waitForExitOrTimeout(child, SHUTDOWN_GRACE_MS, () => exited);
      if (!exited) {
        try { child.kill('SIGTERM'); } catch {}
        await waitForExitOrTimeout(child, 200, () => exited);
        if (!exited) {
          try { child.kill('SIGKILL'); } catch {}
        }
      }
    }
  }

  if (result.status === 'fail') {
    const stderr = Buffer.concat(stderrChunks).toString('utf8');
    const lines  = stderr.split('\n').filter(Boolean).slice(-4);
    if (lines.length) result.stderr_tail = lines.join('\n');
    if (!result.error_code && exitCode !== null && exitCode !== 0) {
      result.error_code = `exit ${exitCode}`;
    }
  }

  // Honest failure class on top of the raw error_code (TIMEOUT / NEEDS_ENV /
  // NEEDS_NET / NO_TOOLS / CRASH). null when the smoke passed with ≥1 tool.
  result.failure_class = stdio.classifyFailure({
    status:    result.status,
    errorCode: result.error_code,
    stderr:    result.stderr_tail || '',
    toolCount: result.tool_count,
  });

  return result;
}

// ── Filtering helpers (substring like orchestrate.cjs) ─────────────────────

function pickTools(db, opts) {
  if (opts.name) {
    // Exact match first, fall back to case-insensitive substring.
    const exact = db.tools.find(t => t.name === opts.name);
    if (exact) return [exact];
    const needle = opts.name.toLowerCase();
    const subs = db.tools.filter(t => t.name.toLowerCase().includes(needle));
    return subs;
  }
  // Default = --all: every entry whose install_cmd we can parse.
  return db.tools.filter(t => parseInstallCmd(t.install_cmd));
}

// ── Results file IO ────────────────────────────────────────────────────────

function readResults(resultsPath) {
  try {
    return JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
  } catch {
    return { generated_at: null, generator: `mcp_eval.cjs v${VERSION}`, results: [] };
  }
}

function writeResults(resultsPath, payload) {
  // Sort by name for deterministic diffs.
  const sorted = {
    ...payload,
    results: [...payload.results].sort((a, b) => a.name.localeCompare(b.name)),
  };
  fs.writeFileSync(resultsPath, JSON.stringify(sorted, null, 2) + '\n');
}

// ── No-spawn mode: re-lint inputSchemas in existing results ────────────────

// Used as the offline self-test path. We don't re-spawn; we re-run the
// schema lint against any embedded `schemas` blob found in the results
// file. The default results file ships with `results: []` so this mode
// is a no-op until a real smoke has populated the file — which is
// intentional. The point is: this code path does not network.
function noSpawnLint(payload) {
  const out = [];
  for (const r of payload.results || []) {
    // Re-lint any schemas embedded as `{tool: name, schema: {...}}`
    // entries. The default smoke run doesn't embed full schemas
    // (keeps the file small), but a future flag could. For now we
    // just re-affirm that the existing schema_errors are well-formed.
    const errs = [];
    for (const e of r.schema_errors || []) {
      if (!e || typeof e.tool !== 'string' || typeof e.error !== 'string') {
        errs.push({ tool: '<malformed>', error: 'malformed schema_errors entry' });
      }
    }
    out.push({ name: r.name, status: r.status, schema_errors_recheck: errs });
  }
  return out;
}

// ── Spawn policy (default-deny) ─────────────────────────────────────────────

// A live smoke executes third-party server code. Force an explicit choice
// between the sandbox and an explicit host opt-out. `--no-spawn` never spawns,
// so it's exempt. Pure function so it's unit-testable without running main().
function spawnPolicy(opts) {
  if (opts.noSpawn) return { allowed: true, reason: 'no-spawn (offline)' };
  if (opts.sandbox) return { allowed: true, reason: 'sandbox' };
  if (opts.unsafe)  return { allowed: true, reason: 'unsafe (host)' };
  return {
    allowed: false,
    reason: 'refusing to run a live smoke without a spawn policy — pass --sandbox (jailed container) or --unsafe (run on host); --no-spawn is offline',
  };
}

// ── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { printHelp(); process.exit(0); }

  // --no-spawn: schema-lint over the existing results file. Offline-safe.
  if (opts.noSpawn) {
    const existing = readResults(opts.results);
    const recheck  = noSpawnLint(existing);
    const malformed = recheck.filter(r => r.schema_errors_recheck.length > 0);
    if (opts.json) {
      process.stdout.write(JSON.stringify({
        mode: 'no-spawn',
        results_path: opts.results,
        entries: recheck.length,
        malformed: malformed.length,
        details: recheck,
      }, null, 2) + '\n');
    } else {
      process.stdout.write(`no-spawn mode: lint over ${opts.results}\n`);
      process.stdout.write(`  entries:   ${recheck.length}\n`);
      process.stdout.write(`  malformed: ${malformed.length}\n`);
      for (const m of malformed) {
        process.stdout.write(`  - ${m.name}: ${m.schema_errors_recheck.length} malformed entries\n`);
      }
    }
    exitAfterFlush(opts.strict && malformed.length ? 1 : 0);
  }

  // Default-deny: refuse a live smoke unless a spawn policy was chosen.
  const policy = spawnPolicy(opts);
  if (!policy.allowed) {
    process.stderr.write(policy.reason + '\n');
    process.exit(2);
  }

  // Live smoke.
  let db;
  try {
    db = JSON.parse(fs.readFileSync(opts.db, 'utf8'));
  } catch (e) {
    process.stderr.write(`Failed to read DB ${opts.db}: ${e.message}\n`);
    process.exit(2);
  }

  const picked = pickTools(db, opts);
  if (opts.name && picked.length === 0) {
    process.stderr.write(`No entries match --name "${opts.name}"\n`);
    process.exit(2);
  }

  const payload = readResults(opts.results);
  // We replace any existing record for the same name (per-run freshness),
  // but keep records for entries we didn't touch this run.
  const touched = new Set(picked.map(t => t.name));
  const kept = (payload.results || []).filter(r => !touched.has(r.name));

  const newResults = [];
  for (const tool of picked) {
    if (!opts.json) process.stderr.write(`smoking ${tool.name}…\n`);
    const r = await smokeEntry(tool, opts);
    newResults.push(r);
    if (!opts.json) {
      const tag = r.status === 'pass' ? 'PASS' : (r.status === 'fail' ? 'FAIL' : 'SKIP');
      const drift = r.tool_count_drift ? ` (drift ${r.tool_count_db}→${r.tool_count})` : '';
      const detail = r.status === 'fail'
        ? ` — ${r.error_code || 'unknown error'}`
        : (r.status === 'skip' ? ` — ${r.error_code || ''}` : ` — ${r.tool_count} tools, boot ${r.boot_ms}ms${drift}`);
      process.stderr.write(`  ${tag} ${tool.name}${detail}\n`);
    }
  }

  const finalPayload = {
    $schema: payload.$schema || 'describes shape; not enforced',
    generated_at: new Date().toISOString(),
    generator:    `mcp_eval.cjs v${VERSION}`,
    results:      [...kept, ...newResults],
  };
  writeResults(opts.results, finalPayload);

  const pass = newResults.filter(r => r.status === 'pass').length;
  const fail = newResults.filter(r => r.status === 'fail').length;
  const skip = newResults.filter(r => r.status === 'skip').length;
  // Broken out of `skip` on purpose: "the host couldn't run this check" is a
  // CI problem that must not read as a clean pass. Everything else under
  // skip is a deliberate we-didn't-ask.
  const skippedLauncher = newResults.filter(
    r => r.status === 'skip' && /^launcher unavailable: /.test(r.error_code || '')
  ).length;

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      mode: 'spawn',
      results_path: opts.results,
      checked: newResults.length,
      pass, fail, skip,
      skipped_launcher: skippedLauncher,
      results: newResults,
    }, null, 2) + '\n');
  } else {
    process.stderr.write(`\n${newResults.length} checked — ${pass} pass, ${fail} fail, ${skip} skip\n`);
    process.stderr.write(`Results written to ${opts.results}\n`);
  }
  if (skippedLauncher > 0) {
    const missing = [...new Set(newResults
      .filter(r => /^launcher unavailable: /.test(r.error_code || ''))
      .map(r => r.error_code.replace('launcher unavailable: ', '')))].sort();
    process.stderr.write(
      `WARNING: ${skippedLauncher} entr${skippedLauncher === 1 ? 'y' : 'ies'} not checked — ` +
      `launcher missing on this host: ${missing.join(', ')}\n`
    );
  }

  // --json writes the whole result set to stdout just above; process.exit()
  // would truncate it mid-object into "Unexpected end of JSON input".
  exitAfterFlush(opts.strict && (fail > 0 || skippedLauncher > 0) ? 1 : 0);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`fatal: ${e.stack || e.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  parseInstallCmd,
  lintSchema,
  pickTools,
  smokeEntry,
  readResults,
  writeResults,
  noSpawnLint,
  spawnPolicy,
  sandboxWrap: stdio.sandboxWrap,
  classifyFailure: stdio.classifyFailure,
  VERSION,
};
