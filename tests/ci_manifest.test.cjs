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
  // Checked per *step*, not per job. "The job has a jail somewhere" was
  // satisfiable by a PR that added a second, unjailed `run:` next to the
  // jailed one — which is exactly the edit an attacker would make.
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

      // A job that only ever runs base-commit code is fine as a whole.
      if (/ref:\s*\$\{\{\s*github\.event\.pull_request\.base\.sha/.test(block)) continue;

      // Split into steps and judge each one that executes repo code. The first
      // chunk is the job header (runs-on, if, comments) — not a step.
      const steps = block.split(/\n      - (?=name:|uses:|run:)/).slice(1);
      for (const step of steps) {
        // Comments explain; they don't execute.
        const code = step.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
        const runsRepoCode = /node\s+(--test|mcp-ecosystem-intelligence|tests|bin)/.test(code)
          || /npm (test|run)\b/.test(code);
        if (!runsRepoCode) continue;
        const jailed = /docker run --rm --network none/.test(code);
        const guarded = /if \[ "\$\{\{ github\.event_name \}\}" = "pull_request" \]/.test(code);
        if (!(jailed && guarded)) {
          const stepName = (step.match(/name:\s*(.+)/) || [])[1] || '(unnamed step)';
          offenders.push(`${file}:${name} → ${stepName.trim()}`);
        }
      }
    }
  }
  assert.deepEqual(offenders, [], `steps that execute PR code unprotected on the runner:\n${offenders.join('\n')}`);
});

test('no host-side redirect writes into the checkout on a pull_request path', () => {
  // A PR can commit the redirect target as a symlink to any file the runner
  // user can write; `-v …:ro` does not stop a redirect performed by the host
  // shell. Outputs belong under RUNNER_TEMP.
  const offenders = [];
  for (const [file, src] of sources) {
    if (!/pull_request/.test(src)) continue;
    for (const m of src.matchAll(/^\s*[^#\n]*?(?<![=!<>-])>\s*("?)([^\s"|;()]+)\1\s*$/gm)) {
      const line = m[0];
      // `>` inside inline JavaScript (node -e '…') is not a shell redirect.
      if (/=>|\)\s*;?\s*$|console\.|filter\(|map\(/.test(line)) continue;
      const target = m[2];
      if (target.startsWith('$RUNNER_TEMP') || target.startsWith('"$RUNNER_TEMP')) continue;
      if (target.startsWith('$GITHUB_') || target.includes('GITHUB_OUTPUT') || target.includes('GITHUB_STEP_SUMMARY')) continue;
      if (target.startsWith('/dev/')) continue;
      if (target === '&2' || target === '&1') continue;   // stream redirect, not a file
      if (target.startsWith('$out') || target.startsWith('"$out')) continue;
      if (target.includes('$RUNNER_TEMP')) continue;
      offenders.push(`${file}: > ${target}`);
    }
  }
  // Trusted-context jobs (cron/dispatch) may write in the checkout; they are
  // listed here explicitly so a new one has to be considered.
  const allowed = new Set(['.github/workflows/security-scan.yml: > eval_results_run.json']);
  const real = offenders.filter((o) => !allowed.has(o));
  assert.deepEqual(real, [], `host-side redirects into the workspace:\n${real.join('\n')}`);
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
  const image = `ghcr.io/x/y@sha256:${digest}`;
  const hostile = {
    command: 'docker',
    args: ['run', '-i', '--rm', '-v', '/:/host', '--privileged', image],
  };
  const wrapped = stdio.sandboxWrap(hostile, { imageRef: image });
  assert.equal(wrapped.sandboxed, true);
  assert.equal(wrapped.args.includes('-v'), false);
  assert.equal(wrapped.args.includes('--privileged'), false);
  assert.equal(wrapped.args.at(-1), `ghcr.io/x/y@sha256:${digest}`);
});

test('our own release ships with provenance, and does not fall back silently', () => {
  // A project that asks users to check provenance on other people's packages
  // should publish it on its own — and an unprovenanced release from that
  // project is worse than a late one, so the fallback is opt-in.
  const release = sources.get('.github/workflows/release.yml');
  assert.ok(release, 'release workflow missing');
  assert.match(release, /npm publish --access public --provenance/, 'publish without --provenance');
  assert.match(release, /id-token: write/, 'provenance needs an OIDC token');
  // The unprovenanced path exists but must be gated on an explicit input.
  const fallback = release.match(/npm publish --access public\s*$/m);
  if (fallback) {
    assert.match(release, /ALLOW_UNPROVENANCED|allow_unprovenanced/, 'a silent unprovenanced fallback');
  }
});

test('the publish job runs the suite before it ships anything', () => {
  // Comments mention `npm publish` while explaining past failures, so look at
  // the steps rather than at the whole file.
  const release = sources.get('.github/workflows/release.yml');
  const code = release.split('\n').filter((l) => !/^\s*#/.test(l));
  const testsIdx   = code.findIndex((l) => /node --test/.test(l));
  const publishIdx = code.findIndex((l) => /npm publish/.test(l));
  assert.ok(testsIdx !== -1, 'the publish job never runs the suite');
  assert.ok(testsIdx < publishIdx, 'tests must run before anything is published');
});

test('a pull_request build refuses to fall back to the host when it cannot isolate', () => {
  // The isolation depends on a container runtime. If that runtime is missing,
  // the only two options are "check nothing" and "run PR code on the host" —
  // and the second must never be reachable by accident.
  const src = sources.get('.github/workflows/security-scan.yml');
  assert.match(src, /Isolation preflight/, 'no preflight for the PR isolation');
  assert.match(src, /docker info/, 'the preflight does not actually probe the runtime');
  // The guarded steps still take the host path only when this is not a PR.
  const hostFallbacks = src.split('\n').filter((l) => /^\s+node (--test|mcp-ecosystem)/.test(l));
  assert.ok(hostFallbacks.length > 0, 'expected the trusted-context branches to exist');
});
