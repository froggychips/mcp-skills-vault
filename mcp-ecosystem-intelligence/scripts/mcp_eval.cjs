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
 *   mcp_eval.cjs --fail-surface-drift   exit 1 if any server's tool surface changed
 *   mcp_eval.cjs --fail-unexplained-surface-drift
 *                                       exit 1 only when a surface changed and the
 *                                       artifact demonstrably did not
 *   mcp_eval.cjs --timeout <ms>         per-entry deadline (default 30s on the host,
 *                                       90s under --sandbox: a container starts cold)
 *   mcp_eval.cjs --sandbox              run each server in a locked-down container (needs docker)
 *   mcp_eval.cjs --unsafe               run servers directly on the host (explicit opt-out of the sandbox)
 *   mcp_eval.cjs --db <path>            override DB path
 *   mcp_eval.cjs --pace <ms>            gap between container starts (default 400)
 *   mcp_eval.cjs --record-evidence      write the smoke result into the DB as
 *                                       dated evidence (smoke dimension)
 *   mcp_eval.cjs --installed            smoke the servers your hosts launch,
 *                                       not DB entries (feeds `mcp-vault budget`)
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
const { readInstalledServers } = require('./lib/installed.cjs');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Is the container runtime actually unavailable?
 *
 * Text matching alone cannot answer this: a server can print "Cannot connect to
 * the Docker daemon" and exit 1 before ever answering initialize, and be
 * recorded as an infrastructure failure — skipped rather than failed, with
 * three of them stopping the run. The runtime itself is the authority, so ask
 * it. Cached per process: the answer does not change mid-run in a way worth
 * paying for repeatedly, and a genuine outage is confirmed once.
 */
let dockerAliveCache = null;
function dockerIsAlive() {
  if (dockerAliveCache !== null) return dockerAliveCache;
  const probe = require('child_process').spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], {
    encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'],
  });
  dockerAliveCache = probe.status === 0 && /\S/.test(probe.stdout || '');
  return dockerAliveCache;
}

// Is this launch spec a single, immutable version? `latest`, a range, or a tag
// is not, and a smoke result against one cannot be attributed to a release.
function isExactVersion(installCmd, version) {
  if (!version) return false;
  if (/^docker\s+run/.test(String(installCmd))) return /^sha256:[a-f0-9]{64}$/.test(version);
  if (/^npx\s/.test(String(installCmd))) return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version);
  return /^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[0-9A-Za-z.]+)?$/.test(version);
}
const { dockerImageRef, npmPkgName, pypiPkgName , pinInstallCmd } = require('./lib/install_cmd.cjs');

// Which version a launch command actually asks for; null means it resolves at
// launch time, so no result can be attributed to a specific release.
function versionFromInstallCmd(cmd) {
  if (typeof cmd !== 'string' || !cmd) return null;
  if (/^docker\s+run/.test(cmd)) {
    const ref = dockerImageRef(cmd);
    const m = ref && ref.match(/@(sha256:[a-f0-9]{64})$/);
    return m ? m[1] : null;
  }
  const npm = npmPkgName(cmd);
  if (npm) {
    const token = cmd.split(/\s+/).find((t) => t.startsWith(`${npm}@`));
    return token ? token.slice(npm.length + 1) : null;
  }
  const py = pypiPkgName(cmd);
  if (py) {
    const token = cmd.split(/\s+/).find((t) => t.startsWith(`${py}==`));
    return token ? token.slice(py.length + 2) : null;
  }
  return null;
}
const { readDb, writeDb } = require('./lib/db_io.cjs');
const crypto = require('crypto');
const { toTypedEntry, artifactId, comparableArtifactId, isExactArtifact } = require('./lib/entry_model.cjs');
const { smokeEvidence, mergeEvidence } = require('./lib/evidence.cjs');
const { fingerprintTools, diffSurface, describeDiff, isEmpty: surfaceUnchanged } = require('./lib/surface.cjs');
const stdio         = require('./lib/mcp_stdio.cjs'); // shared framing + sandbox + classifier (vendored, zero-dep)

// ── Constants ──────────────────────────────────────────────────────────────

const VERSION = '0.1.0';
const DEFAULT_DB_PATH      = path.resolve(__dirname, '../assets/tools_database.json');
const DEFAULT_RESULTS_PATH = path.resolve(__dirname, '../assets/eval_results.json');
const DEFAULT_TIMEOUT_MS   = 30000;
// A sandboxed launch starts from an empty cache inside a fresh container, so
// the clock covers downloading the package before the server has run a line of
// its own code. Measured boot times under `--sandbox`: 25s, 36s, 38s, 44s, 45s
// for five entries that the 30s default recorded as TIMEOUT — and "times out"
// read as "does not work" everywhere downstream. The host path keeps 30s,
// where the package is usually already in the npx cache.
const SANDBOX_TIMEOUT_MS   = 90000;
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
    installed: false,
    recordEvidence: false,
    // Breathing room between container starts. 113 back-to-back `docker run`s
    // took the daemon down on a developer laptop, and every entry after that
    // was reported as a crashed server. Cheap insurance for a job whose whole
    // output is a claim about other people's software.
    paceMs: 400,
    cwd:      process.cwd(),
    strict:   false,
    timeoutExplicit: false,
    // Two different questions, so two flags. `--fail-surface-drift` fails on
    // *any* change to a tool surface, which is a reasonable bar for a pinned
    // production config. `--fail-unexplained-surface-drift` fails only when the
    // surface moved and the artifact demonstrably did not — the narrower,
    // more interesting case. The comment here used to describe the second while
    // the code did the first.
    failSurfaceDrift: false,
    failUnexplainedDrift: false,
    help:     false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = argv[i + 1];
    switch (a) {
      case '--name':    opts.name    = next; i++; break;
      case '--all':     opts.all     = true; break;
      case '--timeout': opts.timeout = Math.max(1000, parseInt(next, 10) || DEFAULT_TIMEOUT_MS); opts.timeoutExplicit = true; i++; break;
      case '--json':    opts.json    = true; break;
      case '--no-spawn':opts.noSpawn = true; break;
      case '--installed': opts.installed = true; break;
      case '--record-evidence': opts.recordEvidence = true; break;
      case '--pace':    opts.paceMs = Number(next); i++; break;
      case '--sandbox': opts.sandbox = true; break;
      case '--unsafe':  opts.unsafe  = true; break;
      case '--db':      opts.db      = next; i++; break;
      case '--cwd':     opts.cwd     = next; i++; break;
      case '--results': opts.results = next; i++; break;
      case '--strict':  opts.strict  = true; break;
      case '--fail-surface-drift': opts.failSurfaceDrift = true; break;
      case '--fail-unexplained-surface-drift': opts.failUnexplainedDrift = true; break;
      case '-h':
      case '--help':    opts.help    = true; break;
      default:
        if (a.startsWith('--')) {
          process.stderr.write(`Unknown flag: ${a}\n`);
          opts.help = true;
        }
    }
  }
  // The sandbox pays for a cold cache; give it the time that takes unless the
  // caller said otherwise.
  if (opts.sandbox && !opts.timeoutExplicit) opts.timeout = SANDBOX_TIMEOUT_MS;
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

/**
 * What ran, as comparable fields.
 *
 * `launch_digest` is over the *contract* — the command and arguments the entry
 * asks for — not over the sandbox-wrapped invocation, so it changes when the
 * entry changes and not when our jail flags do.
 *
 * Every field can be null, and a null is not a mismatch: a comparison against
 * a missing field is `unknown`, which is the third answer this repo insists on
 * having.
 */
function artifactIdentity(tool, parsed, { launchedPinned = null } = {}) {
  const typed = toTypedEntry(tool);
  const contract = parsed ? `${parsed.command} ${(parsed.args || []).join(' ')}`.trim() : null;
  // Affirmative validation against the *actual* launch, rather than trust in a
  // flag the caller passed. `launchedPinned === false` was cleared and `null`
  // was not, so any path that skipped pinning — `_evalSpawn`, which a
  // submitted DB row can set, and `--installed` — kept an id it had not
  // earned. What survives is an id the launched command itself names, exactly.
  // Validated on the argv array, not on a joined string. A single argument
  // containing a space — `['-y', 'pkg@1.0.0 something-else']` — rejoins into a
  // command that parses as a clean pin while the process receives one token
  // that is not that pin at all. A token with whitespace in it cannot be
  // reconstructed, so it is refused rather than guessed at.
  const tokens = parsed ? [parsed.command, ...(parsed.args || [])] : null;
  const reconstructable = Boolean(tokens && tokens.every((t) => typeof t === 'string' && t.length && !/\s/.test(t)));
  const launched = reconstructable ? toTypedEntry({ install_cmd: tokens.join(' ') }) : null;
  const launchedId = launched && isExactArtifact(launched.artifact)
    ? comparableArtifactId(launched.artifact)
    : null;
  const claimedId = typed ? comparableArtifactId(typed.artifact) : null;
  const attributable = Boolean(launchedId && claimedId && launchedId === claimedId);
  // `artifact_id` says *which artifact this run was about*, and a run that
  // launched an unpinned command was about whatever the registry served at
  // start-up. 80 of the DB's 114 entries ship an unpinned `install_cmd` — the
  // verified version lives in the `version` field and `install` pins it on the
  // way out — so reading the id off `toTypedEntry` recorded `npm:pkg@1.0.0`
  // for a run of `npx -y pkg`. Consumers then attributed the result to bytes
  // nobody had pinned. `null` is the honest answer, and the tier treats a null
  // identity as unattributable rather than as a pass.
  const id = typed ? artifactId(typed.artifact) : null;
  return {
    artifact_id:        attributable ? id : null,
    artifact_integrity: tool.pkg_integrity || null,
    db_version:         tool.version || null,
    launch_digest:      contract ? crypto.createHash('sha256').update(contract).digest('hex').slice(0, 32) : null,
    // What was actually launched, so a reader can see why an id is absent.
    launch_pinned:      launchedPinned,
    launched_artifact:  launchedId,
  };
}

/**
 * Which identity fields mean anything for a given artifact.
 *
 * An OCI image has no npm integrity value and no DB "version" in the semver
 * sense — its digest *is* its identity, carried inside artifact_id. A git
 * source install has neither. Demanding the same four fields everywhere would
 * make every OCI comparison permanently `unknown`, which is its own kind of
 * dishonesty: refusing to answer a question that can be answered.
 */
function relevantIdentityFields(identity) {
  const id = (identity && identity.artifact_id) || '';
  if (id.startsWith('oci:')) return ['artifact_id', 'launch_digest'];
  if (id.startsWith('git:')) return ['artifact_id', 'launch_digest'];
  if (!id) return ['artifact_id', 'launch_digest'];
  return ['artifact_id', 'artifact_integrity', 'db_version', 'launch_digest'];
}

/**
 * Did the artifact change between two runs? yes / no / we cannot tell.
 *
 * The aggregation is the subtle part, and the first version got it wrong in a
 * way that reads as careful:
 *
 *   it compared only the fields present on *both* sides and, if those matched,
 *   answered `false` — "the artifact did not change". But when the integrity
 *   value and the launch digest were missing from one side, what it had
 *   actually established was "the parts I could measure are unchanged", which
 *   is not the same claim. A missing input had quietly become a value again,
 *   one level down from where that bug was just fixed.
 *
 * So:
 *   any field that differs on both sides         → true   (a proven change)
 *   no difference, but a relevant field is absent → null   (cannot tell)
 *   every relevant field present and equal        → false  (unchanged)
 */
function artifactChangedBetween(prior, fresh) {
  const a = prior && prior.identity;
  const b = fresh && fresh.identity;
  if (!a || !b) return null;

  // Two different ecosystems is itself a change, and nothing else about them
  // is comparable.
  const ecosystemOf = (id) => String(id || '').split(':')[0] || null;
  const ea = ecosystemOf(a.artifact_id);
  const eb = ecosystemOf(b.artifact_id);
  if (ea && eb && ea !== eb) return true;

  const fields = relevantIdentityFields(b.artifact_id ? b : a);
  let unknown = false;
  for (const field of fields) {
    if (a[field] == null || b[field] == null) { unknown = true; continue; }
    if (a[field] !== b[field]) return true;
  }
  return unknown ? null : false;
}

function surfaceDrift(prior, fresh) {
  if (!fresh.surface || !prior || !prior.surface) return null;
  const diff = diffSurface(prior.surface, fresh.surface);
  if (surfaceUnchanged(diff)) return null;
  const changed = artifactChangedBetween(prior, fresh);
  return {
    since:            prior.checked_at || null,
    // true / false / null, where null means the snapshot carried no identity
    // to compare against. Readers must not coerce it.
    artifact_changed: changed,
    artifact_comparison: changed === null ? 'not-recorded' : 'compared',
    previous_identity: (prior && prior.identity) || null,
    identity:          (fresh && fresh.identity) || null,
    previous_sha256:  prior.surface.sha256,
    sha256:           fresh.surface.sha256,
    added:            diff.added,
    removed:          diff.removed,
    changed:          diff.changed,
    lines:            describeDiff(diff),
  };
}

// ── Smoke one entry ────────────────────────────────────────────────────────

async function smokeEntry(tool, opts) {
  const result = {
    name:             tool.name,
    status:           'skip',
    boot_ms:          null,
    list_latency_ms:  null,
    tool_count:       null,
    // Size of the tools/list payload. This is what a server actually injects
    // into the system prompt on every request, so `token_budget` can measure a
    // config's cost instead of estimating it from a tool count.
    tools_payload_bytes: null,
    // { sha256, count, tools: { name: { description, schema } } } — hashes.
    surface:          null,
    surface_drift:    null,
    // What ran, as comparable fields; the baseline a later run diffs against.
    identity:         null,
    tools_truncated:  null,      // unknown until a tools/list actually answers
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
  // Captured before anything is launched: re-reading the DB afterwards can see
  // a different version than the one that actually ran.
  result.launched = {
    install_cmd: tool.install_cmd || null,
    db_version:  tool.version || null,
  };
  // Pin before launching, so the run is about the artifact the gate verified
  // rather than about whatever the registry serves this minute. An entry that
  // cannot be pinned (a git source, a shape the gate declines to parse) is
  // still smoked — a handshake is worth knowing — but the run carries no
  // artifact id, because nothing can name what it launched.
  let toLaunch = tool;
  let launchedPinned = null;
  if (!tool._evalSpawn && typeof tool.install_cmd === 'string') {
    const pin = pinInstallCmd(tool.install_cmd, tool.version);
    launchedPinned = pin.pinned;
    if (pin.pinned) {
      const pinnedCmd = pin.parts.join(' ');
      if (pinnedCmd !== tool.install_cmd) {
        toLaunch = { ...tool, install_cmd: pinnedCmd };
        result.launched.install_cmd = pinnedCmd;
        result.launched.pinned_from = tool.install_cmd;
      }
    } else {
      result.launched.unpinned_reason = pin.reason || null;
    }
  }
  const parsed = toLaunch._evalSpawn || parseInstallCmd(toLaunch.install_cmd);
  // The identity of what is about to run, as fields rather than as a string.
  //
  // Comparing `install_cmd` text answered "did the entry's prose change", which
  // is not the question: a reformatted command read as a different artifact,
  // and — worse — a snapshot that had dropped the field read as *no* artifact,
  // which made every later surface change look explained by a version bump.
  // See surfaceDrift().
  result.identity = artifactIdentity(toLaunch, parsed, { launchedPinned });
  if (!parsed) {
    result.error_code = 'unrecognized install method';
    return result;
  }

  // A command with a documented placeholder (`… server-filesystem <path>`) is
  // not runnable as written: launching it passes the literal string "<path>"
  // and the server exits. That is our harness failing, not the server, and
  // recording it as CRASH was a false accusation — it read as "never started"
  // in every report downstream.
  const placeholder = (tool._evalSpawn ? [] : [tool.install_cmd || ''])
    .join(' ')
    .match(/[<{][A-Za-z0-9_.\/-]+[>}]/);
  if (placeholder) {
    result.error_code    = `launch command needs an argument supplied by hand: ${placeholder[0]}`;
    result.failure_class = 'NEEDS_ARGS';
    return result;   // status stays 'skip'
  }

  // Once a process is actually talking to us the verdict is pass/fail;
  // `skip` stays reserved for "we never got to ask" — an install_cmd we
  // couldn't parse, or a launcher binary missing on this host (below).
  result.status = 'fail';

  // Sandbox real entries when asked; the test fake-server (_evalSpawn) always
  // runs on the host. docker-run entries pass through (already containerized).
  // Whether to jail is decided by the flags, never by a field in the entry.
  // `_evalSpawn` used to disable the sandbox, which meant (a) `--installed
  // --sandbox` ran local commands straight on the host, and (b) a DB entry
  // carrying `_evalSpawn` — the DB is a file a PR can edit — opted itself out
  // of the jail. `opts.hostSpawn` is the in-process escape hatch tests use; it
  // cannot be expressed in JSON.
  const launch = opts.sandbox && !opts.hostSpawn
    ? stdio.sandboxWrap(parsed, { imageRef: dockerImageRef(tool.install_cmd || '') })
    : parsed;
  result.sandboxed = !!launch.sandboxed;

  // sandboxWrap refuses a launch it cannot make safe — a docker entry with no
  // digest to rebuild from. Refusing and then running it anyway would be the
  // worst of both.
  if (launch.refused) {
    result.status = 'skip';
    result.error_code = launch.sandbox_note || 'sandbox refused this launch command';
    return result;
  }

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

    // A response with no `tools` array is malformed, and falling back to `[]`
    // invented a measurement: `result: {}` came out as a *passing* server with
    // a complete list of zero tools. An empty array is different — one entry
    // in this DB genuinely answers `tools: []` — so the two are kept apart.
    const listed = listResp && listResp.result && Array.isArray(listResp.result.tools)
      ? listResp.result.tools
      : null;
    if (listed === null) {
      result.status     = 'fail';
      result.error_code = 'tools/list answered without a `tools` array';
      result.failure_class = FAILURE_CLASS.PROTOCOL;
      throw new Error('tools/list malformed');
    }
    const tools = listed;
    result.tool_count = tools.length;
    // MCP paginates `tools/list`. This reads one page, so a server that
    // returns a cursor has more tools than this count — and until now nothing
    // downstream could tell a complete list from a first page. A 100-tool
    // server answering with 10 and a cursor was recorded as a 10-tool server,
    // which fed the token budget, the surface fingerprint and the
    // heavy-surface audit alike.
    //
    // Recorded rather than followed: following the cursor changes what the
    // smoke does and needs a live run to validate. What must not wait is the
    // qualification, because a partial count presented as a total is the
    // failure this project exists to prevent.
    result.tools_truncated = Boolean(listResp && listResp.result && listResp.result.nextCursor);
    // The payload, not the count: what the server injects into the system
    // prompt is this JSON, so its size is the honest input to a token budget.
    try { result.tools_payload_bytes = Buffer.byteLength(JSON.stringify(tools)); } catch { /* keep null */ }
    // The surface itself, as hashes. A count catches "how many"; this catches
    // "which, called what, taking what" — a renamed tool, a rewritten
    // description or a widened schema all keep the count and change what
    // reaches the model. Hashes only: a tool description is attacker-controlled
    // text and does not belong committed in this repository.
    result.surface = fingerprintTools(tools);
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
    // Once the handshake landed, the process is a server, and what it prints
    // is its own business — it may not reclassify itself as an infrastructure
    // failure and be skipped.
    handshakeReached: result.boot_ms !== null || result.tool_count !== null,
  });

  // A claimed infrastructure failure is only believed if the infrastructure
  // agrees. Otherwise it is a crashing server that found the magic words.
  if (result.failure_class === 'SANDBOX_UNAVAILABLE' && opts.sandbox && dockerIsAlive()) {
    result.failure_class = 'CRASH';
    result.error_code = `${result.error_code || 'exit failure'} (claimed a docker failure, but docker is up)`;
  }

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

/**
 * Subjects taken from the local host configs instead of the DB.
 *
 * `_evalSpawn` carries the command and args exactly as configured, so this
 * works for servers the install-command parsers know nothing about — a local
 * binary, a script, a wrapper. Remote servers are skipped: there is nothing to
 * spawn, and their tool surface costs context on the client's side only once
 * the client connects.
 */
function pickInstalledTools(opts, unreadable = null) {
  // A host config we could not read is not a host with no servers in it.
  // Collected so the caller can say so instead of quietly describing a subset.
  const servers = readInstalledServers({ cwd: opts.cwd, onUnreadable: unreadable ? (loc) => unreadable.push(loc) : null });
  const wanted = opts.name ? servers.filter(s => s.name === opts.name || s.name.toLowerCase().includes(opts.name.toLowerCase())) : servers;
  return wanted
    .filter(s => !s.remote && s.command)
    .map(s => ({
      name: s.name,
      install_cmd: s.install_cmd || `${s.command} ${(s.args || []).join(' ')}`.trim(),
      est_tools_count: null,
      _evalSpawn: { command: s.command, args: s.args || [] },
      _installed: { host: s.host, scope: s.scope, source: s.source },
    }));
}

// ── Results file IO ────────────────────────────────────────────────────────

/**
 * @param require_  when true, a file that exists and cannot be read or parsed
 *                  throws instead of yielding an empty snapshot. `--no-spawn`
 *                  needs that: `entries: 0, malformed: 0` and exit 0 over an
 *                  unreadable snapshot reads as a clean lint.
 */
function readResults(resultsPath, { require_ = false } = {}) {
  let raw;
  try { raw = fs.readFileSync(resultsPath, 'utf8'); }
  catch (e) {
    if (require_) throw new Error(`cannot read ${resultsPath}: ${e.code || e.message}`);
    return { generated_at: null, generator: `mcp_eval.cjs v${VERSION}`, results: [] };
  }
  try {
    const doc = JSON.parse(raw);
    if (require_ && (!doc || typeof doc !== 'object' || !Array.isArray(doc.results))) {
      throw new Error(`${resultsPath} has no \`results\` array`);
    }
    return doc;
  } catch (e) {
    if (require_) throw new Error(`cannot parse ${resultsPath}: ${e.message}`);
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
    // A results file that is not there is not a results file with nothing
    // wrong in it. `entries: 0, malformed: 0` and exit 0 read as a clean lint.
    let existing;
    try {
      existing = readResults(opts.results, { require_: true });
    } catch (e) {
      // Missing, unreadable, or not a results document: all three established
      // nothing, and 2 is the code for that.
      process.stderr.write(`mcp_eval: ${e.message} — nothing to lint\n`);
      return exitAfterFlush(2);
    }
    const recheck  = noSpawnLint(existing);
    const malformed = recheck.filter(r => r.schema_errors_recheck.length > 0);
    if (opts.json) {
      process.stdout.write(JSON.stringify({
        schema: 'mcp-vault/eval@1',
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
    // `return`, because exitAfterFlush() is asynchronous: it queues the real
    // process.exit() behind a stdout drain callback. Without the return, the
    // synchronous code below kept running in the same tick and reached
    // spawn() — `--no-spawn` executed the very third-party servers it promises
    // not to touch before the exit landed.
    return exitAfterFlush(opts.strict && malformed.length ? 1 : 0);
  }

  // Default-deny: refuse a live smoke unless a spawn policy was chosen.
  const policy = spawnPolicy(opts);
  if (!policy.allowed) {
    process.stderr.write(policy.reason + '\n');
    process.exit(2);
  }

  // Live smoke.
  let picked;
  if (opts.installed) {
    const unreadableConfigs = [];
    picked = pickInstalledTools(opts, unreadableConfigs);
    // Smoking an unknown subset of what runs, and reporting it as the set, is
    // the same overstatement everywhere else in this CLI refuses to make.
    if (unreadableConfigs.length) {
      for (const u of unreadableConfigs) process.stderr.write(`mcp_eval: ${u.path}: ${u.error}\n`);
      return exitAfterFlush(2);
    }
    if (!picked.length) {
      process.stderr.write(`No local (non-remote) MCP servers configured for ${opts.cwd}\n`);
      process.exit(2);
    }
  } else {
    let db;
    try {
      db = JSON.parse(fs.readFileSync(opts.db, 'utf8'));
    } catch (e) {
      process.stderr.write(`Failed to read DB ${opts.db}: ${e.message}\n`);
      process.exit(2);
    }
    picked = pickTools(db, opts);
    if (opts.name && picked.length === 0) {
      process.stderr.write(`No entries match --name "${opts.name}"\n`);
      process.exit(2);
    }
  }

  const payload = readResults(opts.results);
  // We replace any existing record for the same name (per-run freshness),
  // but keep records for entries we didn't touch this run.
  // Filled in as entries are actually smoked. Using the planned list meant an
  // early stop deleted the stored results of every entry the run never got to.
  const touched = new Set();
  const priorResults = payload.results || [];

  const priorByName = new Map(priorResults.map((r) => [r.name, r]));

  /**
   * Did this server's tool surface change since the last recorded run, and did
   * the artifact change with it?
   *
   * The pairing is the point. An upgrade that changes the surface is expected.
   * The *same* artifact presenting a different surface is the case with no
   * innocent explanation: for a local pinned server it means the launch is not
   * deterministic, and for a remote one it means the server was changed under
   * whoever trusted it.
   */
  /**
   * Attach everything that depends on the *final* result for an entry.
   *
   * Called once per entry, after a retry has decided the outcome. The drift
   * computation used to run only on the first attempt, so a transient sandbox
   * failure followed by a successful retry lost that run's surface comparison
   * entirely — the one run where something had just gone wrong.
   */
  function finalize(result) {
    result.surface_drift = surfaceDrift(priorByName.get(result.name), result);
    return result;
  }

  const newResults = [];
  let consecutiveSandboxFailures = 0;
  let runAborted = false;
  for (const tool of picked) {
    if (!opts.json) process.stderr.write(`smoking ${tool.name}…\n`);
    const r = await smokeEntry(tool, opts);
    touched.add(tool.name);
    // "The sandbox could not run" is not a finding about the entry. Retry once
    // after a pause — a daemon under load recovers — then report it as a skip,
    // and give up once it is plainly the environment: continuing produces a
    // report that blames 100 entries for one broken daemon.
    if (r.failure_class === 'SANDBOX_UNAVAILABLE' && opts.sandbox) {
      await sleep(Math.max(2000, (opts.paceMs || 0) * 5));
      const retry = await smokeEntry(tool, opts);
      if (retry.failure_class !== 'SANDBOX_UNAVAILABLE') {
        newResults.push(finalize(retry));
        consecutiveSandboxFailures = 0;
        if (opts.paceMs) await sleep(opts.paceMs);
        continue;
      }
    }
    if (r.failure_class === 'SANDBOX_UNAVAILABLE') {
      r.status = 'skip';
      consecutiveSandboxFailures++;
      if (consecutiveSandboxFailures >= 3) {
        newResults.push(finalize(r));
        runAborted = true;
        process.stderr.write(
          `\nStopping: the sandbox failed ${consecutiveSandboxFailures} times in a row ` +
          `(${r.error_code || 'docker unavailable'}). That is the environment, not these servers.\n`
        );
        break;
      }
    } else {
      consecutiveSandboxFailures = 0;
    }
    newResults.push(finalize(r));
    if (opts.paceMs) await sleep(opts.paceMs);
    if (!opts.json) {
      const tag = r.status === 'pass' ? 'PASS' : (r.status === 'fail' ? 'FAIL' : 'SKIP');
      const drift = r.tool_count_drift ? ` (drift ${r.tool_count_db}→${r.tool_count})` : '';
      const detail = r.status === 'fail'
        ? ` — ${r.error_code || 'unknown error'}`
        : (r.status === 'skip' ? ` — ${r.error_code || ''}` : ` — ${r.tool_count} tools, boot ${r.boot_ms}ms${drift}`);
      process.stderr.write(`  ${tag} ${tool.name}${detail}\n`);
      if (r.surface_drift) {
        const how = r.surface_drift.artifact_changed === null
          ? 'the previous snapshot recorded no identity, so the artifact cannot be compared'
          : (r.surface_drift.artifact_changed
            ? 'the artifact changed too'
            : 'THE ARTIFACT DID NOT CHANGE');
        process.stderr.write(`       tool surface changed since ${r.surface_drift.since || 'the last run'} — ${how}\n`);
        for (const line of r.surface_drift.lines) process.stderr.write(`         ${line}\n`);
      }
    }
  }

  // Behavioural evidence belongs in the same dated structure as everything
  // else, keyed to the artifact it was observed on — a smoke result for 1.2.3
  // says nothing about 1.2.4.
  if (opts.recordEvidence && !opts.installed) {
    try {
      const { db } = readDb(opts.db);
      let recorded = 0;
      for (const r of newResults) {
        const tool = (db.tools || []).find((t) => t.name === r.name);
        if (!tool) continue;
        const dim = smokeEvidence(r);
        if (!dim) continue;
        const typed = toTypedEntry(tool);
        // Only attribute the result to a version if that version is what
        // started. `npx -y pkg` resolves latest at launch, so attaching the
        // result to the DB's `version` would claim a release was smoked when
        // something else ran. Record it unattributed instead, and say so.
        // Attribution requires three things to line up: the launch command
        // names a version, that version is exact, and it is the version the DB
        // says was verified. `npx -y pkg@latest` satisfied the old check while
        // running anything at all, and a command pinned to 2.0.0 recorded its
        // result against the DB's 1.0.0.
        // Attribute against what was launched, recorded at spawn time — not
        // against whatever the DB says now. A refresh landing mid-run would
        // otherwise file this result under a version that never started.
        const launchedCmd = (r.launched && r.launched.install_cmd) || tool.install_cmd;
        const launchedDbVersion = r.launched ? r.launched.db_version : tool.version;
        // The command the *entry* asked for, which since pinning may differ
        // from the one that ran: `npx -y pkg` is launched as `npx -y pkg@1.0.0`
        // and `pinned_from` records the original. Comparing the launched
        // command against `tool.install_cmd` made 78 of the shipped entries
        // fail attribution for the sole reason that we had pinned them — so a
        // successful run wrote `smoke_unattributed` and a stale failing smoke
        // dimension survived it.
        const askedFor = (r.launched && r.launched.pinned_from) || launchedCmd;
        // And the run has to have *named* an artifact. `identity.artifact_id`
        // is the validated answer — it is null whenever the launch could not
        // be tied to the entry's artifact — while `launched.install_cmd` is
        // only what we intended to run: with `_evalSpawn` the two disagree,
        // and the old predicates all passed, so a fake server's `pass` would
        // have been filed under the real package.
        const runIdentified = Boolean(r.identity && r.identity.artifact_id);
        const stillSameEntry = runIdentified
          && askedFor === tool.install_cmd && launchedDbVersion === tool.version;
        const launched = versionFromInstallCmd(launchedCmd);
        const attributable = stillSameEntry
          && launched !== null
          && isExactVersion(launchedCmd, launched)
          && (!tool.version || launched === tool.version || launched === `sha256:${String(tool.pkg_integrity || '').replace(/^sha256-/, '')}`);

        if (attributable && typed) {
          tool.trust_evidence = mergeEvidence(tool.trust_evidence, {
            artifact_id: artifactId(typed.artifact),
            dimensions: { smoke: dim },
          });
        } else {
          // Unattributed: kept beside the evidence rather than merged into it.
          // Merging it with a null id made mergeEvidence treat the artifact as
          // different and discard artifact/signature/advisories wholesale.
          dim.launch = launched === null ? 'unpinned' : `ran ${launched}`;
          tool.smoke_unattributed = dim;
        }
        recorded++;
      }
      if (recorded) {
        writeDb(opts.db, db);
        process.stderr.write(`Recorded smoke evidence for ${recorded} entr${recorded === 1 ? 'y' : 'ies'}\n`);
      }
    } catch (e) {
      process.stderr.write(`Could not record evidence: ${e.message}\n`);
    }
  }

  const kept = priorResults.filter(r => !touched.has(r.name));

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
  // The sandbox failing is an infrastructure problem too: a run that could not
  // start containers has checked nothing, and must not exit 0 on the strength
  // of "no failures". `runAborted` covers the early stop, where most entries
  // were never attempted at all.
  const sandboxUnavailable = newResults.filter(r => r.failure_class === 'SANDBOX_UNAVAILABLE').length;
  const surfaceDrifted = newResults.filter(r => r.surface_drift);
  // Split on the one distinction that matters: an upgrade changing its surface
  // is expected, the same artifact changing its surface is not.
  // Strictly false, not falsy: `null` means the previous snapshot carried no
  // identity, and counting "we could not tell" as "the artifact did not change"
  // is the overstatement this distinction exists to prevent.
  const unexplainedDrift = surfaceDrifted.filter(r => r.surface_drift.artifact_changed === false);
  const uncomparableDrift = surfaceDrifted.filter(r => r.surface_drift.artifact_changed === null);
  const attempted = newResults.length;
  const notAttempted = Math.max(0, picked.length - attempted);

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      schema: 'mcp-vault/eval@1',
      mode: 'spawn',
      results_path: opts.results,
      checked: newResults.length,
      pass, fail, skip,
      skipped_launcher: skippedLauncher,
      sandbox_unavailable: sandboxUnavailable,
      surface_drift: surfaceDrifted.length,
      surface_drift_unexplained: unexplainedDrift.length,
      surface_drift_uncomparable: uncomparableDrift.length,
      aborted: runAborted,
      planned: picked.length,
      not_attempted: notAttempted,
      results: newResults,
    }, null, 2) + '\n');
  } else {
    process.stderr.write(`\n${newResults.length} checked — ${pass} pass, ${fail} fail, ${skip} skip\n`);
    if (notAttempted) process.stderr.write(`${notAttempted} of ${picked.length} entries were never attempted\n`);
    if (surfaceDrifted.length) {
      process.stderr.write(
        `${surfaceDrifted.length} server${surfaceDrifted.length === 1 ? '' : 's'} changed tool surface` +
        `${unexplainedDrift.length ? `, ${unexplainedDrift.length} of them without the artifact changing` : ''}\n`
      );
    }
    process.stderr.write(`Results written to ${opts.results}\n`);
  }
  if (unexplainedDrift.length) {
    // Said separately because it is the interesting case — and worded as
    // *unexplained* rather than impossible: an unvendored launch re-resolves
    // its dependency tree at every start, and flags, credentials and a remote
    // backend can each change what a server advertises.
    process.stderr.write(
      `\nUNEXPLAINED: ${unexplainedDrift.map(r => r.name).join(', ')} presented a different tool surface ` +
      `from the same artifact identity. Worth a look: an unvendored tree, a feature flag, or a changed server.\n`
    );
  }
  if (uncomparableDrift.length) {
    process.stderr.write(
      `NOTE: ${uncomparableDrift.length} surface change(s) could not be attributed — the previous ` +
      `snapshot recorded no artifact identity to compare against.\n`
    );
  }
  if (sandboxUnavailable > 0) {
    process.stderr.write(
      `WARNING: the sandbox was unavailable for ${sandboxUnavailable} entr${sandboxUnavailable === 1 ? 'y' : 'ies'}` +
      `${runAborted ? ' and the run stopped early' : ''} — those entries were not checked.\n`
    );
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
  // A run that was cut short, or that could not use the sandbox, has not
  // produced the evidence it was asked for — under --strict that is a failure
  // regardless of how few entries got as far as failing.
  const incomplete = runAborted || notAttempted > 0 || sandboxUnavailable > 0;
  const driftFails = (opts.failSurfaceDrift && surfaceDrifted.length > 0)
    // Strictly the unexplained ones: a drift we could not attribute (`null`)
    // is not evidence of anything, and failing a build on it would punish an
    // old snapshot rather than a changed server.
    || (opts.failUnexplainedDrift && unexplainedDrift.length > 0);
  // A run where *nothing* could be attempted established nothing, and the
  // CLI reserves 2 for that: the launcher was missing for every entry, or the
  // sandbox was unavailable throughout. Default mode reported 0 for it — a
  // clean smoke of no servers — and --strict reported 1, which reads as a
  // finding about somebody's code. A real finding still outranks it.
  const answered = newResults.filter((r) => r.status === 'pass' || r.status === 'fail').length;
  // A genuine finding first — but `skippedLauncher` and `incomplete` are not
  // findings about anybody's server, they are reasons this run established
  // nothing. Counting them as `hard` made `--strict` answer 1 for a run that
  // never started, which reads as a verdict on code nobody executed.
  const hard = (opts.strict && fail > 0) || driftFails;
  if (hard) return exitAfterFlush(1);
  if (picked.length > 0 && answered === 0) {
    process.stderr.write(
      `mcp_eval: none of the ${picked.length} selected entr${picked.length === 1 ? 'y' : 'ies'} could be run `
      + `(${skippedLauncher} missing a launcher, ${sandboxUnavailable} with no sandbox) — nothing was established\n`,
    );
    return exitAfterFlush(2);
  }
  // Something ran, and under --strict a partial run is still a failure to
  // deliver what was asked for.
  if (opts.strict && (skippedLauncher > 0 || incomplete)) return exitAfterFlush(1);
  exitAfterFlush(0);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`fatal: ${e.stack || e.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  artifactIdentity,
  relevantIdentityFields,
  artifactChangedBetween,
  surfaceDrift,
  parseInstallCmd,
  lintSchema,
  pickTools,
  pickInstalledTools,
  smokeEntry,
  readResults,
  writeResults,
  noSpawnLint,
  spawnPolicy,
  sandboxWrap: stdio.sandboxWrap,
  classifyFailure: stdio.classifyFailure,
  VERSION,
};
