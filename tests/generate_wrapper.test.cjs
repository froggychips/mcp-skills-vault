'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs   = require('node:fs');
const os   = require('node:os');
const path = require('node:path');

const SCRIPT = path.resolve(__dirname, '../mcp-ecosystem-intelligence/scripts/generate_wrapper.cjs');

// Helpers ----------------------------------------------------------------

function mktmp(prefix = 'wrapper-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function run(args, opts = {}) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', ...opts });
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// ── argument validation ───────────────────────────────────────────────────

test('--help → exit 0 with usage', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Usage:/);
});

test('missing --name → exit 2', () => {
  const r = run(['--out', '/tmp/should-not-be-created-' + Date.now()]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--name is required/);
});

test('missing --out → exit 2', () => {
  const r = run(['--name', 'foo-mcp']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--out is required/);
});

test('non-kebab --name → exit 2', () => {
  const tmp = mktmp();
  try {
    const r = run(['--name', 'FooMCP', '--out', path.join(tmp, 'out')]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /kebab-case/);
  } finally {
    cleanup(tmp);
  }
});

// ── happy path: no tool definitions ───────────────────────────────────────

test('generates server.js, package.json, README.md, .gitignore', () => {
  const tmp = mktmp();
  const out = path.join(tmp, 'wrapper');
  try {
    const r = run(['--name', 'foo-mcp', '--tool', 'Foo', '--out', out]);
    assert.equal(r.status, 0, r.stderr);

    for (const f of ['server.js', 'package.json', 'README.md', '.gitignore']) {
      assert.ok(fs.existsSync(path.join(out, f)), `expected ${f} to exist`);
    }

    // No temp check file left behind.
    assert.ok(!fs.existsSync(path.join(out, '.server.tmp.js')));

    // server.js passes node --check (syntactic validity)
    const check = spawnSync(process.execPath, ['--check', path.join(out, 'server.js')], { encoding: 'utf8' });
    assert.equal(check.status, 0, check.stderr);

    // README mentions the kebab name and the human tool label
    const readme = fs.readFileSync(path.join(out, 'README.md'), 'utf8');
    assert.match(readme, /foo-mcp/);
    assert.match(readme, /Foo/);

    // package.json renders the name placeholder
    const pkg = JSON.parse(fs.readFileSync(path.join(out, 'package.json'), 'utf8'));
    assert.equal(pkg.name, 'foo-mcp');

    // .gitignore avoids leaking node_modules
    const gi = fs.readFileSync(path.join(out, '.gitignore'), 'utf8');
    assert.match(gi, /node_modules/);
  } finally {
    cleanup(tmp);
  }
});

test('--tool defaults to --name when omitted', () => {
  const tmp = mktmp();
  const out = path.join(tmp, 'wrapper');
  try {
    const r = run(['--name', 'plainwrap', '--out', out]);
    assert.equal(r.status, 0, r.stderr);
    const server = fs.readFileSync(path.join(out, 'server.js'), 'utf8');
    // {{tool}} placeholder gets replaced with --name
    assert.match(server, /plainwrap/);
    assert.doesNotMatch(server, /\{\{tool\}\}/);
    assert.doesNotMatch(server, /\{\{name\}\}/);
  } finally {
    cleanup(tmp);
  }
});

// ── happy path: with tools-file ───────────────────────────────────────────

test('--tools-file injects tool definitions into server.js', () => {
  const tmp = mktmp();
  const out = path.join(tmp, 'wrapper');
  const toolsFile = path.join(tmp, 'tools.json');
  fs.writeFileSync(toolsFile, JSON.stringify([{
    name: 'run_query',
    description: 'Execute a read-only SQL query.',
    inputSchema: {
      type: 'object',
      properties: { sql: { type: 'string' } },
      required: ['sql'],
    },
  }]));

  try {
    const r = run(['--name', 'sql-mcp', '--out', out, '--tools-file', toolsFile]);
    assert.equal(r.status, 0, r.stderr);

    const server = fs.readFileSync(path.join(out, 'server.js'), 'utf8');
    assert.match(server, /run_query/);                       // tool def present
    assert.match(server, /case "run_query"/);                // case generated
    assert.match(server, /Missing required arg/);            // required-args check generated
    assert.match(server, /Execute a read-only SQL query/);   // description preserved

    // Still syntactically valid Node
    const check = spawnSync(process.execPath, ['--check', path.join(out, 'server.js')], { encoding: 'utf8' });
    assert.equal(check.status, 0, check.stderr);

    // Banner reports 1 tool
    assert.match(r.stdout, /1 tool\(s\)/);
  } finally {
    cleanup(tmp);
  }
});

test('--tools-file: bad JSON → exit 2', () => {
  const tmp = mktmp();
  const toolsFile = path.join(tmp, 'tools.json');
  fs.writeFileSync(toolsFile, '{ not json');
  try {
    const r = run(['--name', 'foo-mcp', '--out', path.join(tmp, 'out'), '--tools-file', toolsFile]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /not valid JSON/);
  } finally {
    cleanup(tmp);
  }
});

test('--tools-file: snake_case enforced on tool name', () => {
  const tmp = mktmp();
  const toolsFile = path.join(tmp, 'tools.json');
  fs.writeFileSync(toolsFile, JSON.stringify([
    { name: 'CamelCase', description: 'x', inputSchema: { type: 'object' } },
  ]));
  try {
    const r = run(['--name', 'foo-mcp', '--out', path.join(tmp, 'out'), '--tools-file', toolsFile]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /snake_case/);
  } finally {
    cleanup(tmp);
  }
});

// ── overwrite protection ──────────────────────────────────────────────────

test('refuses to overwrite non-empty output without --force', () => {
  const tmp = mktmp();
  const out = path.join(tmp, 'wrapper');
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'existing.txt'), 'do not clobber');
  try {
    const r = run(['--name', 'foo-mcp', '--out', out]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /not empty/);
    assert.equal(fs.readFileSync(path.join(out, 'existing.txt'), 'utf8'), 'do not clobber');
  } finally {
    cleanup(tmp);
  }
});

test('--force overwrites existing non-empty output', () => {
  const tmp = mktmp();
  const out = path.join(tmp, 'wrapper');
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'existing.txt'), 'will remain (not in template)');
  try {
    const r = run(['--name', 'foo-mcp', '--out', out, '--force']);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(fs.existsSync(path.join(out, 'server.js')));
  } finally {
    cleanup(tmp);
  }
});
