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
