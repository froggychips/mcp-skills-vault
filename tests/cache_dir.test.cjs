'use strict';
/**
 * Where the cache lands, and — the part CodeQL was right about — where it lands
 * when the process has no home directory.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const os       = require('node:os');
const path     = require('node:path');

const c = require('../mcp-ecosystem-intelligence/scripts/lib/cache_dir.cjs');

const ENV = ['MCP_VAULT_CACHE_DIR', 'XDG_CACHE_HOME'];

function withEnv(values, fn) {
  const saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
  try {
    for (const k of ENV) delete process.env[k];
    Object.assign(process.env, values);
    return fn();
  } finally {
    for (const k of ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

test('MCP_VAULT_CACHE_DIR is taken as-is and wins over everything else', () => {
  withEnv({ MCP_VAULT_CACHE_DIR: '/tmp/explicit', XDG_CACHE_HOME: '/tmp/xdg' }, () => {
    assert.equal(c.cacheRoot(), '/tmp/explicit');
    assert.equal(c.cacheDir('http'), path.join('/tmp/explicit', 'http'));
  });
});

test('XDG_CACHE_HOME gets the mcp-vault subdirectory', () => {
  withEnv({ XDG_CACHE_HOME: '/tmp/xdg' }, () => {
    assert.equal(c.cacheRoot(), path.join('/tmp/xdg', 'mcp-vault'));
    assert.equal(c.cacheDir('deps'), path.join('/tmp/xdg', 'mcp-vault', 'deps'));
  });
});

test('with neither variable set the cache hangs off $HOME/.cache', () => {
  withEnv({}, () => {
    assert.equal(c.cacheRoot(), path.join(os.homedir(), '.cache', 'mcp-vault'));
  });
});

test('no home directory: a private mkdtemp directory, not a guessable path in the temp dir', () => {
  const realHomedir = os.homedir;
  os.homedir = () => '';
  try {
    withEnv({}, () => {
      const first = c.cacheRoot();
      // Not a name anyone else could have predicted and pre-created…
      assert.ok(first.startsWith(path.join(os.tmpdir(), 'mcp-vault-cache-')), first);
      assert.notEqual(first, path.join(os.tmpdir(), 'mcp-vault-cache-'));
      // …it exists, is a directory, and only we can read it…
      const st = fs.statSync(first);
      assert.ok(st.isDirectory());
      if (process.platform !== 'win32') assert.equal(st.mode & 0o077, 0);
      // …and it is the *same* directory for the rest of the process, so the
      // cache still works instead of scattering one entry per call.
      assert.equal(c.cacheRoot(), first);
      fs.rmSync(first, { recursive: true, force: true });
    });
  } finally {
    os.homedir = realHomedir;
  }
});
