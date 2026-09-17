'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const s = require('../mcp-ecosystem-intelligence/scripts/lib/scores.cjs');

const NOW = Date.parse('2026-09-17T12:00:00Z');
const evidence = (dims) => ({ artifact_id: 'npm:p@1', dimensions: dims });
const fresh = (status) => ({ status, checked_at: '2026-09-17' });

test('trustScore: nothing recorded is thin, not trusted', () => {
  const r = s.trustScore(null, { now: NOW });
  assert.equal(r.score, 0);
  assert.equal(r.gate, 'thin');
  assert.match(r.reasons[0], /no evidence/);
});

test('trustScore: a verified artifact with signature and clean advisories clears the gate', () => {
  const r = s.trustScore(evidence({
    artifact: fresh('verified'), signature: fresh('verified'),
    source_binding: fresh('verified'), advisories: fresh('clean'),
  }), { now: NOW });
  assert.equal(r.gate, 'ok');
  assert.equal(r.score, 85);
});

test('trustScore: a mismatch blocks, whatever else is true', () => {
  const r = s.trustScore(evidence({
    artifact: fresh('mismatch'), signature: fresh('verified'),
    provenance: fresh('claimed'), advisories: fresh('clean'),
  }), { now: NOW });
  assert.equal(r.gate, 'block');
  assert.match(r.reasons.join(' '), /artifact: mismatch/);
});

test('trustScore: a vulnerable version blocks too', () => {
  const r = s.trustScore(evidence({ artifact: fresh('verified'), advisories: fresh('vulnerable') }), { now: NOW });
  assert.equal(r.gate, 'block');
});

test('trustScore: stale evidence earns half credit and says so', () => {
  const current = s.trustScore(evidence({ artifact: fresh('verified'), advisories: fresh('clean') }), { now: NOW });
  const old = s.trustScore(evidence({
    artifact:   { status: 'verified', checked_at: '2026-09-17' },
    advisories: { status: 'clean',    checked_at: '2026-08-01' },   // 47 days, limit 7
  }), { now: NOW });
  assert.ok(old.score < current.score, `${old.score} should be under ${current.score}`);
  assert.match(old.reasons.join(' '), /past its shelf life/);
});

test('fitScore: a universal tool fits anything; an unrelated one does not', () => {
  const stack = { cats: new Set(), dbs: new Set(), infra: new Set(), signals: [] };
  const universal = s.fitScore({ name: 'mcp-server-memory' }, stack, { universal: ['mcp-server-memory'] });
  assert.ok(universal.score >= 40);
  const unrelated = s.fitScore({ name: 'whatever', category: 'payments' }, stack, {});
  assert.equal(unrelated.score, 0);
});

test('fitScore: a Set of universal names works as well as an array', () => {
  const stack = { cats: new Set(), dbs: new Set(), infra: new Set(), signals: [] };
  const asSet = s.fitScore({ name: 'ctx' }, stack, { universal: new Set(['ctx']) });
  assert.ok(asSet.score >= 40);
});

test('fitScore: a signal\'s confidence carries into the fit', () => {
  const declared = {
    cats: new Set(['database']), dbs: new Set(['postgres']), infra: new Set(),
    signals: [{ value: 'postgres', kind: 'detected', sources: ['package.json dependency'], confidence: 0.95 }],
  };
  const guessed = {
    cats: new Set(['database']), dbs: new Set(['postgres']), infra: new Set(),
    signals: [{ value: 'postgres', kind: 'inferred', sources: ['.env key name'], confidence: 0.6 }],
  };
  const opts = { signalToTools: { postgres: ['pg-mcp'] } };
  const strong = s.fitScore({ name: 'pg-mcp', category: 'database' }, declared, opts);
  const weak   = s.fitScore({ name: 'pg-mcp', category: 'database' }, guessed, opts);
  assert.ok(strong.score > weak.score, `${strong.score} should beat ${weak.score}`);
  assert.match(strong.reasons.join(' '), /package\.json dependency/);
  assert.match(weak.reasons.join(' '), /\.env key name/);
});

test('fitScore: a large tool surface is a cost, and narrowing is mentioned', () => {
  const stack = { cats: new Set(['vcs']), dbs: new Set(), infra: new Set(), signals: [] };
  const small = s.fitScore({ name: 'a', category: 'vcs', est_tools_count: 5 }, stack, {});
  const huge  = s.fitScore({ name: 'b', category: 'vcs', est_tools_count: 153, toolsets: '--toolsets repos' }, stack, {});
  assert.ok(huge.score < small.score);
  assert.match(huge.reasons.join(' '), /153 tools/);
  assert.match(huge.reasons.join(' '), /can be narrowed/);
});

test('recommend: trust gates, it does not average', () => {
  // The whole point of three axes: 30k stars cannot outvote a bad pin.
  const blocked = s.recommend({
    trust: { score: 0, gate: 'block', reasons: ['artifact: mismatch (as of 2026-09-17)'] },
    health: 110,
    fit: { score: 100, reasons: [] },
  });
  assert.equal(blocked.verdict, 'avoid');
  assert.match(blocked.reasons[0], /mismatch/);
});

test('recommend: thin trust never reads as recommended', () => {
  const thin = s.recommend({
    trust: { score: 10, gate: 'thin', reasons: ['no evidence recorded for this entry'] },
    health: 90,
    fit: { score: 95, reasons: [] },
  });
  assert.equal(thin.verdict, 'consider');
  assert.match(thin.reasons.join(' '), /little is known/);
});

test('recommend: verified and fitting is the only path to recommended', () => {
  const good = s.recommend({
    trust: { score: 85, gate: 'ok', reasons: [] },
    health: 80,
    fit: { score: 75, reasons: [] },
  });
  assert.equal(good.verdict, 'recommended');

  const noUse = s.recommend({ trust: { score: 85, gate: 'ok', reasons: [] }, health: 80, fit: { score: 0, reasons: [] } });
  assert.equal(noUse.verdict, 'not-now');
  assert.match(noUse.reasons.join(' '), /nothing in this project points at it/);
});

test('recommend: low health is a reason, not a veto', () => {
  const r = s.recommend({ trust: { score: 85, gate: 'ok', reasons: [] }, health: 20, fit: { score: 70, reasons: [] } });
  assert.equal(r.verdict, 'recommended');
  assert.match(r.reasons.join(' '), /project health is low/);
});

test('trustScore: the gate is not a threshold on the sum', () => {
  // signature + provenance + source_binding + advisories reach 55 on their own.
  // Without a verified artifact that must still be 'thin': knowing which bytes
  // run is the claim the others qualify.
  const noArtifact = s.trustScore({
    artifact_id: 'npm:p@1',
    dimensions: {
      signature:      fresh('verified'),
      provenance:     fresh('claimed'),
      source_binding: fresh('verified'),
      advisories:     fresh('clean'),
    },
  }, { now: NOW });
  assert.ok(noArtifact.score >= 55, `score was ${noArtifact.score}`);
  assert.equal(noArtifact.gate, 'thin');
  assert.match(noArtifact.reasons[0], /artifact was never verified/);

  const unverifiedArtifact = s.trustScore({
    artifact_id: 'npm:p@1',
    dimensions: {
      artifact:       fresh('unverified'),
      signature:      fresh('verified'),
      provenance:     fresh('claimed'),
      source_binding: fresh('verified'),
      advisories:     fresh('clean'),
    },
  }, { now: NOW });
  assert.equal(unverifiedArtifact.gate, 'thin');
  assert.match(unverifiedArtifact.reasons[0], /artifact: unverified/);
});

test('trustScore: an artifact verified long ago does not hold the gate open', () => {
  const stale = s.trustScore({
    artifact_id: 'npm:p@1',
    dimensions: {
      artifact:       { status: 'verified', checked_at: '2026-01-01' },   // 259 days
      signature:      fresh('verified'),
      source_binding: fresh('verified'),
      advisories:     fresh('clean'),
    },
  }, { now: NOW });
  assert.equal(stale.gate, 'thin');
  assert.match(stale.reasons[0], /past its shelf life/);
});
