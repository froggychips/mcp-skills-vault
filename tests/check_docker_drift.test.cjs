'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const d = require('../mcp-ecosystem-intelligence/scripts/check_docker_drift.cjs');

test('parseImageRef: ghcr.io with digest', () => {
  const r = d.parseImageRef('ghcr.io/github/github-mcp-server@sha256:abc');
  assert.equal(r.registry, 'ghcr.io');
  assert.equal(r.repo,     'github/github-mcp-server');
  assert.equal(r.tag,      null);
  assert.equal(r.digest,   'sha256:abc');
});

test('parseImageRef: docker.io with implicit library/ prefix', () => {
  const r = d.parseImageRef('nginx:latest');
  assert.equal(r.registry, 'docker.io');
  assert.equal(r.repo,     'library/nginx');
  assert.equal(r.tag,      'latest');
  assert.equal(r.digest,   null);
});

test('parseImageRef: registry with port treated as registry, not tag', () => {
  // Port separator must not be mistaken for a tag.
  const r = d.parseImageRef('localhost:5000/myimage:v1');
  assert.equal(r.registry, 'localhost:5000');
  assert.equal(r.repo,     'myimage');
  assert.equal(r.tag,      'v1');
});

test('parseImageRef: tag + digest both present', () => {
  const r = d.parseImageRef('quay.io/foo/bar:v1@sha256:def');
  assert.equal(r.registry, 'quay.io');
  assert.equal(r.repo,     'foo/bar');
  assert.equal(r.tag,      'v1');
  assert.equal(r.digest,   'sha256:def');
});

test('dockerImageRef: skips -e env-var flag values', () => {
  const cmd = 'docker run -i --rm -e FOO=bar nginx:1';
  assert.equal(d.dockerImageRef(cmd), 'nginx:1');
});

test('dockerImageRef: returns null for non-docker commands', () => {
  assert.equal(d.dockerImageRef('npx -y pkg'),         null);
  assert.equal(d.dockerImageRef('docker pull nginx'),  null);  // not "run"
  assert.equal(d.dockerImageRef(''),                   null);
});

test('parseBearerChallenge: extracts realm + service + scope', () => {
  const h = 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:foo/bar:pull"';
  const c = d.parseBearerChallenge(h);
  assert.equal(c.realm,   'https://auth.docker.io/token');
  assert.equal(c.service, 'registry.docker.io');
  assert.equal(c.scope,   'repository:foo/bar:pull');
});

test('parseBearerChallenge: returns null on non-Bearer / malformed', () => {
  assert.equal(d.parseBearerChallenge('Basic realm="x"'), null);
  assert.equal(d.parseBearerChallenge(null),              null);
  assert.equal(d.parseBearerChallenge(''),                null);
});

// ── registry API host mapping ──────────────────────────────────────────────

test('apiHostFor: docker.io namespaces map to the registry API host', () => {
  // https://docker.io/v2/... answers 302 pointing at www.docker.com, so the
  // prober logged "probe HTTP 302" and every Docker Hub entry sat in a
  // permanent ERROR — which hid a real digest drift on
  // hashicorp/terraform-mcp-server rather than reporting it.
  assert.equal(d.apiHostFor('docker.io'), 'registry-1.docker.io');
  assert.equal(d.apiHostFor('index.docker.io'), 'registry-1.docker.io');
});

test('apiHostFor: other registries are passed through untouched', () => {
  assert.equal(d.apiHostFor('ghcr.io'), 'ghcr.io');
  assert.equal(d.apiHostFor('quay.io'), 'quay.io');
  assert.equal(d.apiHostFor('registry.gitlab.com'), 'registry.gitlab.com');
  assert.equal(d.apiHostFor('localhost:5000'), 'localhost:5000');
});

test('apiHostFor: the mapping only rewrites requests, not the stored namespace', () => {
  // parseImageRef must keep reporting docker.io so the DB and the report stay
  // in the user's vocabulary; only the HTTP hostname changes.
  const ref = d.parseImageRef('hashicorp/terraform-mcp-server:latest');
  assert.equal(ref.registry, 'docker.io');
  assert.notEqual(d.apiHostFor(ref.registry), ref.registry);
});

test('ALLOWED_REGISTRIES: the header list, enforced', () => {
  for (const host of ['docker.io', 'ghcr.io', 'quay.io', 'mcr.microsoft.com']) {
    assert.equal(d.ALLOWED_REGISTRIES.has(host), true, host);
  }
  // A DB entry must not be able to point the prober at an arbitrary host.
  for (const host of ['internal.corp:5000', 'localhost', '169.254.169.254', 'evil.example']) {
    assert.equal(d.ALLOWED_REGISTRIES.has(host), false, host);
  }
});

test('realmAllowed: only follows a bearer realm back to a known registry', () => {
  assert.equal(d.realmAllowed('https://auth.docker.io/token'),       true);
  assert.equal(d.realmAllowed('https://ghcr.io/token'),              true);
  assert.equal(d.realmAllowed('https://quay.io/v2/auth'),            true);
  assert.equal(d.realmAllowed('https://mcr.microsoft.com/oauth2/token'), true);
  // The realm arrives in a response header — untrusted input.
  assert.equal(d.realmAllowed('https://metadata.internal/token'),    false);
  assert.equal(d.realmAllowed('https://169.254.169.254/latest/meta-data'), false);
  assert.equal(d.realmAllowed('http://ghcr.io/token'),               false);  // plaintext
  assert.equal(d.realmAllowed('https://ghcr.io.evil.example/token'), false);  // suffix trick
  assert.equal(d.realmAllowed('not a url'),                          false);
  assert.equal(d.realmAllowed(undefined),                            false);
});

test('driftExitCode: a registry we could not read is never a pass', () => {
  assert.equal(d.driftExitCode({ drifts: 0, errors: 0, strict: false }), 0);
  // Was exit 0: `errors: 1, drifts: 0` read as "clean" to the CI step.
  assert.equal(d.driftExitCode({ drifts: 0, errors: 1, strict: false }), 1);
  assert.equal(d.driftExitCode({ drifts: 0, errors: 1, strict: true  }), 1);
  // Drift alone stays advisory unless --strict.
  assert.equal(d.driftExitCode({ drifts: 2, errors: 0, strict: false }), 0);
  assert.equal(d.driftExitCode({ drifts: 2, errors: 0, strict: true  }), 1);
  assert.equal(d.driftExitCode(), 0);
});
