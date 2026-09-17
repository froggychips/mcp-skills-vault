'use strict';
/**
 * Security invariants of the CI manifests themselves.
 *
 * These are not unit tests of a function; they are assertions about the
 * workflow files, because the mistakes they catch are the kind that get
 * reintroduced by a one-line edit six months from now and are invisible in
 * review. Each one corresponds to a hole that was actually open in this repo:
 *
 *   - `unit-tests` and `smoke` ran `pull_request` code directly on the
 *     self-hosted runner, so a PR that added a test executed it on the
 *     maintainer's machine. No malicious MCP server needed — a malicious test
 *     was enough. GitHub-hosted runners don't start on this account, so the fix
 *     is a container on the same machine, not a different machine.
 *   - `mcp-eval-pr` ran PR-authored *code* to evaluate PR-authored *data*; it
 *     now takes the scripts from the PR's base commit.
 *   - the weekly eval ran 100+ third-party servers `--unsafe` on that same
 *     machine, on a supply-chain scanner whose own SECURITY.md says a hash
 *     proves which artifact you got, not that it is benign.
 *   - `curl -LsSf … | sh` installed uv, in a tool whose pitch is that
 *     installing an MCP server stops feeling like curl | bash.
 *   - every action was referenced by a mutable major tag, in a project that
 *     teaches `package@version + hash` and `image@sha256`.
 */

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const path     = require('node:path');

const WORKFLOW_DIR = path.resolve(__dirname, '../.github/workflows');
const ACTION_DIR   = path.resolve(__dirname, '../.github/actions');

function manifestFiles() {
  const out = [];
  for (const dir of [WORKFLOW_DIR, ACTION_DIR]) {
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        for (const inner of fs.readdirSync(full)) {
          if (/\.ya?ml$/.test(inner)) out.push(path.join(full, inner));
        }
      } else if (/\.ya?ml$/.test(entry.name)) {
        out.push(full);
      }
    }
  }
  return out;
}

const files = manifestFiles();
const sources = new Map(files.map((f) => [path.relative(path.resolve(__dirname, '..'), f), fs.readFileSync(f, 'utf8')]));

test('there are workflow manifests to check', () => {
  assert.ok(files.length >= 2, `expected workflows, found ${files.length}`);
});

test('pull_request builds do not execute PR code unprotected on the host', () => {
  // Either the step runs inside a container, or the job checks out the base
  // commit (trusted code). Running `node …` straight from a PR checkout on a
  // persistent runner is the thing this asserts against.
  const offenders = [];
  for (const [file, src] of sources) {
    if (!/^on:/m.test(src) || !/pull_request/.test(src)) continue;
    const jobBlocks = src.split(/\n  (?=[a-z0-9_-]+:\n)/i).slice(1);
    for (const block of jobBlocks) {
      const name = (block.match(/^([a-z0-9_-]+):/i) || [])[1] || '(unnamed)';
      if (!/^\s*runs-on:/m.test(block)) continue;
      const ifLine = (block.match(/^\s*if:\s*(.+)$/m) || [])[1] || '';
      const reachablePr = !/event_name\s*!=\s*'pull_request'/.test(ifLine)
        && !/event_name == 'schedule'/.test(ifLine)
        && !/event_name == 'push'/.test(ifLine);
      if (!reachablePr) continue;

      // Steps that execute repo code on the host.
      const runsRepoCode = /^\s*run:.*\bnode\s+(mcp-ecosystem-intelligence|tests|bin)/m.test(block)
        || /node --test/.test(block);
      if (!runsRepoCode) continue;

      const jailed = /docker run --rm --network none/.test(block);
      const usesBaseCommitCode = /ref:\s*\$\{\{\s*github\.event\.pull_request\.base\.sha/.test(block);
      const guardedByEventName = /if \[ "\$\{\{ github\.event_name \}\}" = "pull_request" \]/.test(block);

      if (!(usesBaseCommitCode || (jailed && guardedByEventName))) {
        offenders.push(`${file}:${name}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `pull_request code executed unprotected on the runner:\n${offenders.join('\n')}`);
});

test('a jailed step drops capabilities and the network', () => {
  for (const [file, src] of sources) {
    for (const m of src.matchAll(/docker run --rm --network none([\s\S]{0,240})/g)) {
      const tail = m[1];
      assert.match(tail, /--cap-drop ALL/, `${file}: jailed step without --cap-drop ALL`);
      assert.match(tail, /--security-opt no-new-privileges/, `${file}: jailed step without no-new-privileges`);
      assert.match(tail, /:ro\b/, `${file}: jailed step mounts the workspace writable`);
    }
  }
});

test('no workflow invokes mcp_eval --unsafe', () => {
  // `--unsafe` means "run this third-party server on the host with no jail".
  // A supply-chain scanner has no business doing that on a machine it keeps.
  for (const [file, src] of sources) {
    const invocations = src.split('\n').filter((line) => {
      const code = line.trim();
      if (code.startsWith('#')) return false;          // a comment explaining the flag is fine
      return /mcp_eval\.cjs[^\n]*--unsafe/.test(code) || /--unsafe[^\n]*mcp_eval\.cjs/.test(code);
    });
    assert.deepEqual(invocations, [], `${file}: --unsafe invocation:\n${invocations.join('\n')}`);
  }
});

test('no manifest pipes a downloaded script into a shell', () => {
  for (const [file, src] of sources) {
    const hits = src.split('\n').filter((l) => /(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh/.test(l) && !l.trim().startsWith('#'));
    assert.deepEqual(hits, [], `${file}: install-by-pipe is exactly what this tool argues against:\n${hits.join('\n')}`);
  }
});

test('every third-party action is pinned to a full commit SHA', () => {
  const offenders = [];
  for (const [file, src] of sources) {
    for (const m of src.matchAll(/^\s*(?:-\s+)?uses:\s*(\S+)/gm)) {
      const ref = m[1];
      if (ref.startsWith('./')) continue;                    // local composite action
      const [, version] = ref.split('@');
      if (!version || !/^[0-9a-f]{40}$/.test(version)) {
        offenders.push(`${file}: ${ref}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `mutable action refs (pin to a 40-char SHA, keep the version in a comment):\n${offenders.join('\n')}`);
});

test('the default GITHUB_TOKEN permission is declared, and is read', () => {
  // An undeclared `permissions:` inherits the repository default, which for
  // this repo was `write`. A job that needs write says so for itself.
  for (const [file, src] of sources) {
    if (!/^on:/m.test(src)) continue;                        // composite actions have no permissions block
    const topLevel = src.match(/^permissions:\n((?:\s{2}.+\n)+)/m);
    assert.ok(topLevel, `${file}: no top-level permissions block`);
    assert.match(topLevel[1], /contents:\s*read/, `${file}: top-level permissions should default to read`);
  }
});

test('every job has a timeout', () => {
  // A laptop runner that sleeps mid-job leaves the job hanging; one run in this
  // repo's history took 16h38m before GitHub gave up on it.
  const offenders = [];
  for (const [file, src] of sources) {
    if (!/^on:/m.test(src)) continue;
    const jobBlocks = src.split(/\n  (?=[a-z0-9_-]+:\n)/i).slice(1);
    for (const block of jobBlocks) {
      const name = (block.match(/^([a-z0-9_-]+):/i) || [])[1] || '(unnamed)';
      if (!/^\s*runs-on:/m.test(block)) continue;
      if (!/^\s*timeout-minutes:/m.test(block)) offenders.push(`${file}:${name}`);
    }
  }
  assert.deepEqual(offenders, [], `jobs with no timeout-minutes:\n${offenders.join('\n')}`);
});

test('the sandbox never passes a DB-supplied docker command through', () => {
  // Enforced in code by lib/mcp_stdio.cjs; asserted here because the
  // regression would be a one-line "pass it through, it is already a container".
  const stdio = require('../mcp-ecosystem-intelligence/scripts/lib/mcp_stdio.cjs');
  const digest = 'c'.repeat(64);
  const hostile = {
    command: 'docker',
    args: ['run', '-i', '--rm', '-v', '/:/host', '--privileged', `ghcr.io/x/y@sha256:${digest}`],
  };
  const wrapped = stdio.sandboxWrap(hostile);
  assert.equal(wrapped.sandboxed, true);
  assert.equal(wrapped.args.includes('-v'), false);
  assert.equal(wrapped.args.includes('--privileged'), false);
  assert.equal(wrapped.args.at(-1), `ghcr.io/x/y@sha256:${digest}`);
});
