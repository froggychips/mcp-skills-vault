'use strict';
const { test }   = require('node:test');
const assert     = require('node:assert/strict');
const fs         = require('node:fs');
const os         = require('node:os');
const path       = require('node:path');

const e = require('../mcp-ecosystem-intelligence/scripts/mcp_eval.cjs');

const FAKE_SERVER = path.resolve(__dirname, 'fixtures/fake_mcp_server.cjs');

// ── parseInstallCmd table ──────────────────────────────────────────────────

test('parseInstallCmd: npx with version', () => {
  const r = e.parseInstallCmd('npx -y @scope/pkg@1.2.3');
  assert.deepEqual(r, { command: 'npx', args: ['-y', '@scope/pkg@1.2.3'] });
});

test('parseInstallCmd: npx with trailing args after package', () => {
  const r = e.parseInstallCmd('npx -y pkg@1 --toolsets repos,issues');
  assert.deepEqual(r, { command: 'npx', args: ['-y', 'pkg@1', '--toolsets', 'repos,issues'] });
});

test('parseInstallCmd: uvx with pin', () => {
  const r = e.parseInstallCmd('uvx pkg==1.0.0');
  assert.deepEqual(r, { command: 'uvx', args: ['pkg==1.0.0'] });
});

test('parseInstallCmd: docker run --rm -i with image digest', () => {
  const r = e.parseInstallCmd('docker run --rm -i ghcr.io/x/y@sha256:abc');
  assert.deepEqual(r, { command: 'docker', args: ['run', '--rm', '-i', 'ghcr.io/x/y@sha256:abc'] });
});

test('parseInstallCmd: rejects uvx --from git+… (explicitly unsupported)', () => {
  assert.equal(e.parseInstallCmd('uvx --from git+https://github.com/redis/mcp-redis mcp-redis'), null);
});

test('parseInstallCmd: rejects unknown leader (pip, go run, anything else)', () => {
  assert.equal(e.parseInstallCmd('pip install foo'), null);
  assert.equal(e.parseInstallCmd('go run ./cmd'),    null);
  assert.equal(e.parseInstallCmd(''),                null);
  assert.equal(e.parseInstallCmd(null),              null);
});

test('parseInstallCmd: rejects npx without -y (would hang on prompt in CI)', () => {
  assert.equal(e.parseInstallCmd('npx some-pkg'), null);
});

// ── lintSchema ─────────────────────────────────────────────────────────────

test('lintSchema: valid minimal schema has no errors', () => {
  const errs = e.lintSchema({
    type: 'object',
    properties: { name: { type: 'string', description: 'a name' } },
    required: ['name'],
  });
  assert.deepEqual(errs, []);
});

test('lintSchema: missing top-level type → 1 error', () => {
  const errs = e.lintSchema({ properties: { x: { type: 'string' } } });
  assert.equal(errs.length, 1);
  assert.match(errs[0], /top-level type must be "object"/);
});

test('lintSchema: non-object (null, array, scalar) → 1 error', () => {
  assert.deepEqual(e.lintSchema(null),   ['inputSchema must be a JSON object']);
  assert.deepEqual(e.lintSchema([]),     ['inputSchema must be a JSON object']);
  assert.deepEqual(e.lintSchema('hi'),   ['inputSchema must be a JSON object']);
  assert.deepEqual(e.lintSchema(42),     ['inputSchema must be a JSON object']);
});

test('lintSchema: $ref at top level → reject', () => {
  const errs = e.lintSchema({ $ref: '#/definitions/Foo', type: 'object' });
  assert.equal(errs.length, 1);
  assert.match(errs[0], /\$ref is not supported/);
});

test('lintSchema: $ref in nested property → reject', () => {
  const errs = e.lintSchema({
    type: 'object',
    properties: { x: { $ref: '#/components/schemas/X' } },
  });
  assert.ok(errs.some(e => e.includes('uses $ref')), errs.join(' | '));
});

test('lintSchema: nested properties with mixed types → 0 errors', () => {
  const errs = e.lintSchema({
    type: 'object',
    properties: {
      filters: {
        type: 'object',
        properties: {
          status: { type: 'string', enum: ['open', 'closed'] },
          tags:   { type: 'array', items: { type: 'string' } },
        },
      },
      page: { type: 'integer', minimum: 1 },
    },
  });
  assert.deepEqual(errs, []);
});

test('lintSchema: required referencing missing property → flagged', () => {
  const errs = e.lintSchema({
    type: 'object',
    properties: { a: { type: 'string' } },
    required: ['a', 'b'],
  });
  assert.equal(errs.length, 1);
  assert.match(errs[0], /required references unknown property: "b"/);
});

test('lintSchema: unknown type string → flagged', () => {
  const errs = e.lintSchema({
    type: 'object',
    properties: { x: { type: 'WeirdType' } },
  });
  assert.equal(errs.length, 1);
  assert.match(errs[0], /unknown type/);
});

// ── End-to-end smoke against fake_mcp_server.cjs ───────────────────────────

function fakeTool(name, env = {}) {
  // Synthetic tool record. `_evalSpawn` bypasses the parser so we can
  // point at the fake fixture directly. Real DB entries don't carry it.
  return {
    name,
    install_cmd: 'fake',
    est_tools_count: null,
    _evalSpawn: { command: process.execPath, args: [FAKE_SERVER] },
    _env: env,
  };
}

// child_process.spawn() picks up env from the *parent process* unless
// overridden. Our smokeEntry doesn't pass an env override, so we set it
// on the test process before spawning each scenario.
async function smokeWithEnv(tool, opts) {
  const oldEnv = { ...process.env };
  for (const [k, v] of Object.entries(tool._env || {})) process.env[k] = v;
  try {
    return await e.smokeEntry(tool, opts);
  } finally {
    // Restore env
    for (const k of Object.keys(tool._env || {})) {
      if (k in oldEnv) process.env[k] = oldEnv[k]; else delete process.env[k];
    }
  }
}

test('e2e: happy path — fake server with 2 valid tools → pass', async () => {
  const tools = [
    { name: 'a', inputSchema: { type: 'object', properties: { x: { type: 'string' } } } },
    { name: 'b', inputSchema: { type: 'object', properties: { y: { type: 'integer' } }, required: ['y'] } },
  ];
  const t = fakeTool('happy', { FAKE_TOOLS_JSON: JSON.stringify(tools) });
  const r = await smokeWithEnv(t, { timeout: 5000 });
  assert.equal(r.status, 'pass');
  assert.equal(r.tool_count, 2);
  assert.deepEqual(r.schema_errors, []);
  assert.ok(typeof r.boot_ms === 'number' && r.boot_ms >= 0);
  assert.ok(typeof r.list_latency_ms === 'number' && r.list_latency_ms >= 0);
});

test('e2e: bad inputSchema → status pass + schema_errors populated', async () => {
  const tools = [
    { name: 'bad', inputSchema: { properties: { x: { type: 'string' } } } }, // missing type:object
    { name: 'ref-bad', inputSchema: { type: 'object', properties: { x: { $ref: '#/foo' } } } },
  ];
  const t = fakeTool('badschema', { FAKE_TOOLS_JSON: JSON.stringify(tools) });
  const r = await smokeWithEnv(t, { timeout: 5000 });
  assert.equal(r.status, 'pass'); // schema lint doesn't fail the handshake
  assert.equal(r.tool_count, 2);
  assert.ok(r.schema_errors.length >= 2, JSON.stringify(r.schema_errors));
  const toolNames = r.schema_errors.map(s => s.tool).sort();
  assert.deepEqual([...new Set(toolNames)], ['bad', 'ref-bad']);
});

test('e2e: fake server exits non-zero before responding → fail', async () => {
  const t = fakeTool('exit', { FAKE_FAIL: 'exit' });
  const r = await smokeWithEnv(t, { timeout: 3000 });
  assert.equal(r.status, 'fail');
  // Either we exit with an error code, or stdout closes before we can parse —
  // both surfaces are valid signals.
  assert.ok(r.error_code !== null);
  assert.ok(r.boot_ms === null);
});

test('e2e: fake server returns JSON-RPC error on initialize → fail', async () => {
  const t = fakeTool('init-err', { FAKE_FAIL: 'error' });
  const r = await smokeWithEnv(t, { timeout: 3000 });
  assert.equal(r.status, 'fail');
  assert.match(r.error_code || '', /initialize error/);
});

test('e2e: boot delay > timeout → fail with error_code "timeout"', async () => {
  const t = fakeTool('slow', { FAKE_BOOT_DELAY_MS: '2000', FAKE_TOOLS_JSON: '[]' });
  const r = await smokeWithEnv(t, { timeout: 500 });
  assert.equal(r.status, 'fail');
  assert.equal(r.error_code, 'timeout');
});

// ── tool_count_drift flag ──────────────────────────────────────────────────

test('drift: DB count matches server → drift false', async () => {
  const tools = [
    { name: 'a', inputSchema: { type: 'object' } },
    { name: 'b', inputSchema: { type: 'object' } },
    { name: 'c', inputSchema: { type: 'object' } },
  ];
  const t = fakeTool('drift-ok', { FAKE_TOOLS_JSON: JSON.stringify(tools) });
  t.est_tools_count = 3;
  const r = await smokeWithEnv(t, { timeout: 5000 });
  assert.equal(r.status, 'pass');
  assert.equal(r.tool_count, 3);
  assert.equal(r.tool_count_db, 3);
  assert.equal(r.tool_count_drift, false);
});

test('drift: DB count differs from server → drift true', async () => {
  const tools = [
    { name: 'a', inputSchema: { type: 'object' } },
    { name: 'b', inputSchema: { type: 'object' } },
  ];
  const t = fakeTool('drift-yes', { FAKE_TOOLS_JSON: JSON.stringify(tools) });
  t.est_tools_count = 5;
  const r = await smokeWithEnv(t, { timeout: 5000 });
  assert.equal(r.status, 'pass');
  assert.equal(r.tool_count, 2);
  assert.equal(r.tool_count_db, 5);
  assert.equal(r.tool_count_drift, true);
});

test('drift: DB est_tools_count null → drift false (no comparison possible)', async () => {
  const tools = [
    { name: 'a', inputSchema: { type: 'object' } },
    { name: 'b', inputSchema: { type: 'object' } },
  ];
  const t = fakeTool('drift-na', { FAKE_TOOLS_JSON: JSON.stringify(tools) });
  t.est_tools_count = null;
  const r = await smokeWithEnv(t, { timeout: 5000 });
  assert.equal(r.status, 'pass');
  assert.equal(r.tool_count, 2);
  assert.equal(r.tool_count_db, null);
  assert.equal(r.tool_count_drift, false);
});

// ── --no-spawn mode ────────────────────────────────────────────────────────

test('noSpawnLint: well-formed results file produces no malformed entries', () => {
  const sample = {
    generated_at: null,
    generator: 'mcp_eval.cjs v0.1.0',
    results: [
      { name: 'a', status: 'pass', schema_errors: [] },
      { name: 'b', status: 'pass', schema_errors: [{ tool: 't1', error: 'something' }] },
    ],
  };
  const out = e.noSpawnLint(sample);
  assert.equal(out.length, 2);
  for (const r of out) assert.deepEqual(r.schema_errors_recheck, []);
});

test('noSpawnLint: malformed schema_errors entries get surfaced', () => {
  const sample = {
    results: [
      { name: 'a', status: 'pass', schema_errors: [
        { tool: 'good', error: 'ok' },
        { tool: 42, error: 'tool is not a string' },     // bad
        { error: 'missing tool field' },                 // bad
        null,                                            // bad
      ]},
    ],
  };
  const out = e.noSpawnLint(sample);
  assert.equal(out.length, 1);
  assert.equal(out[0].schema_errors_recheck.length, 3);
});

// ── unrecognized install method ────────────────────────────────────────────

test('smokeEntry: unrecognized install method → skip without spawning', async () => {
  const r = await e.smokeEntry({
    name: 'unknown',
    install_cmd: 'pip install something',
    est_tools_count: null,
  }, { timeout: 1000 });
  assert.equal(r.status, 'skip');
  assert.equal(r.error_code, 'unrecognized install method');
  assert.equal(r.boot_ms, null);
});

// ── pickTools ──────────────────────────────────────────────────────────────

test('pickTools: --name exact match returns single entry', () => {
  const db = { tools: [
    { name: 'mcp-server-memory',     install_cmd: 'npx -y a@1' },
    { name: 'mcp-server-filesystem', install_cmd: 'npx -y b@1' },
  ]};
  const picked = e.pickTools(db, { name: 'mcp-server-memory' });
  assert.equal(picked.length, 1);
  assert.equal(picked[0].name, 'mcp-server-memory');
});

test('pickTools: --name substring matches multiple', () => {
  const db = { tools: [
    { name: 'mcp-server-memory',     install_cmd: 'npx -y a@1' },
    { name: 'mcp-server-filesystem', install_cmd: 'npx -y b@1' },
    { name: 'unrelated',             install_cmd: 'npx -y c@1' },
  ]};
  const picked = e.pickTools(db, { name: 'mcp-server' });
  assert.equal(picked.length, 2);
});

test('pickTools: default filters out entries with unrecognized install method', () => {
  const db = { tools: [
    { name: 'ok',         install_cmd: 'npx -y x@1' },
    { name: 'git-uvx',    install_cmd: 'uvx --from git+https://… pkg' },
    { name: 'pip',        install_cmd: 'pip install foo' },
    { name: 'docker-run', install_cmd: 'docker run --rm img@sha256:abc' },
  ]};
  const picked = e.pickTools(db, { name: null });
  assert.deepEqual(picked.map(t => t.name).sort(), ['docker-run', 'ok']);
});

// ── results file IO round-trip ─────────────────────────────────────────────

test('writeResults sorts by name and is deterministic', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'eval-results-'));
  const file = path.join(tmp, 'r.json');
  e.writeResults(file, {
    generated_at: '2026-05-22T00:00:00Z',
    generator: 'mcp_eval.cjs v0.1.0',
    results: [
      { name: 'zebra', status: 'pass' },
      { name: 'alpha', status: 'pass' },
      { name: 'mango', status: 'fail' },
    ],
  });
  const round = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(round.results.map(r => r.name), ['alpha', 'mango', 'zebra']);
});

test('readResults: missing file returns default skeleton', () => {
  const r = e.readResults('/nonexistent/path/eval_results.json');
  assert.equal(r.generated_at, null);
  assert.deepEqual(r.results, []);
});

// ── spawn policy (default-deny) ─────────────────────────────────────────────

test('spawnPolicy: no flag → denied', () => {
  const p = e.spawnPolicy({ noSpawn: false, sandbox: false, unsafe: false });
  assert.equal(p.allowed, false);
  assert.match(p.reason, /--sandbox|--unsafe/);
});

test('spawnPolicy: --sandbox / --unsafe / --no-spawn each allow', () => {
  assert.equal(e.spawnPolicy({ sandbox: true }).allowed, true);
  assert.equal(e.spawnPolicy({ unsafe: true }).allowed,  true);
  assert.equal(e.spawnPolicy({ noSpawn: true }).allowed, true);
});

// ── sandboxWrap ──────────────────────────────────────────────────────────────

test('sandboxWrap: npx is jailed but keeps network (npx must fetch)', () => {
  const w = e.sandboxWrap({ command: 'npx', args: ['-y', 'pkg@1.2.3'] });
  assert.equal(w.command, 'docker');
  assert.equal(w.sandboxed, true);
  assert.ok(w.args.includes('--cap-drop') && w.args.includes('ALL'));
  assert.ok(w.args.includes('--read-only'));
  assert.ok(w.args.includes('--security-opt') && w.args.includes('no-new-privileges'));
  // network isolation is intentionally NOT applied (would break the npx fetch)
  assert.ok(!w.args.includes('none'), 'must not pass --network none');
  // original launch is preserved at the tail
  assert.deepEqual(w.args.slice(-3), ['npx', '-y', 'pkg@1.2.3']);
});

test('sandboxWrap: uvx uses a uv-bearing image', () => {
  const w = e.sandboxWrap({ command: 'uvx', args: ['pkg==1.0.0'] });
  assert.equal(w.command, 'docker');
  assert.match(w.image, /uv/);
  assert.deepEqual(w.args.slice(-2), ['uvx', 'pkg==1.0.0']);
});

test('sandboxWrap: docker entry passes through (already containerized)', () => {
  const parsed = { command: 'docker', args: ['run', '--rm', '-i', 'ghcr.io/x/y@sha256:abc'] };
  const w = e.sandboxWrap(parsed);
  assert.equal(w.command, 'docker');
  assert.equal(w.sandboxed, false);
  assert.deepEqual(w.args, parsed.args);
});

// ── classifyFailure ──────────────────────────────────────────────────────────

test('classifyFailure: pass with tools → null; pass with 0 tools → NO_TOOLS', () => {
  assert.equal(e.classifyFailure({ status: 'pass', toolCount: 7 }), null);
  assert.equal(e.classifyFailure({ status: 'pass', toolCount: 0 }), 'NO_TOOLS');
});

test('classifyFailure: timeout → TIMEOUT', () => {
  assert.equal(e.classifyFailure({ status: 'fail', errorCode: 'timeout' }), 'TIMEOUT');
});

test('classifyFailure: missing credential → NEEDS_ENV', () => {
  assert.equal(e.classifyFailure({ status: 'fail', errorCode: 'exit 1', stderr: 'FATAL: Missing GITHUB_TOKEN environment variable' }), 'NEEDS_ENV');
});

test('classifyFailure: network error → NEEDS_NET', () => {
  assert.equal(e.classifyFailure({ status: 'fail', errorCode: 'exit 1', stderr: 'Error: getaddrinfo ENOTFOUND api.example.com' }), 'NEEDS_NET');
});

test('classifyFailure: unexplained exit → CRASH', () => {
  assert.equal(e.classifyFailure({ status: 'fail', errorCode: 'exit 1', stderr: 'Segmentation fault' }), 'CRASH');
});
