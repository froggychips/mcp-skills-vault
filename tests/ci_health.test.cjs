'use strict';
const { test } = require('node:test');
const assert   = require('node:assert/strict');

const e = require('../mcp-ecosystem-intelligence/scripts/ci_health.cjs');

const NOW = Date.parse('2026-07-31T12:00:00Z');
const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;

const run = (ageMin, id = 1) => ({ id, name: 'security-scan', createdAtMs: NOW - ageMin * MIN });
const base = (over = {}) => ({
  nowMs: NOW,
  queuedRuns: [],
  anyJobRunning: false,
  lastSuccessMs: NOW - 1 * DAY,
  ...over,
});

const find = (v, check) => v.findings.find(f => f.check === check);

test('healthy: empty queue and a recent success', () => {
  const v = e.evaluate(base());
  assert.equal(v.level, 'ok');
  assert.equal(find(v, 'queue').level, 'ok');
  assert.equal(find(v, 'staleness').level, 'ok');
});

test('queue under the threshold is not a finding', () => {
  const v = e.evaluate(base({ queuedRuns: [run(29)] }));
  assert.equal(find(v, 'queue').level, 'ok');
});

test('stalled queue with nothing running → fail', () => {
  const v = e.evaluate(base({ queuedRuns: [run(45)], anyJobRunning: false }));
  assert.equal(v.level, 'fail');
  assert.match(find(v, 'queue').message, /ни одна джоба не исполняется/);
});

test('stalled queue WITH a job running → warn, not fail', () => {
  // The regression that matters: one runner takes one job at a time, so a
  // backlog behind a long eval is saturation. Paging on it would train the
  // operator to ignore the alert.
  const v = e.evaluate(base({ queuedRuns: [run(45), run(90, 2)], anyJobRunning: true }));
  assert.equal(v.level, 'warn');
  assert.equal(find(v, 'queue').level, 'warn');
  assert.match(find(v, 'queue').message, /сатурация/);
});

test('warn does not mask a concurrent staleness failure', () => {
  const v = e.evaluate(base({
    queuedRuns: [run(45)], anyJobRunning: true, lastSuccessMs: NOW - 30 * DAY,
  }));
  assert.equal(v.level, 'fail');
  assert.equal(find(v, 'queue').level, 'warn');
  assert.equal(find(v, 'staleness').level, 'fail');
});

test('staleness at the threshold fails, one day under passes', () => {
  assert.equal(e.evaluate(base({ lastSuccessMs: NOW - 8 * DAY })).level, 'fail');
  assert.equal(e.evaluate(base({ lastSuccessMs: NOW - 7 * DAY })).level, 'ok');
});

test('never-succeeded is a failure, not an unknown', () => {
  // Silence because no history was found is precisely the blind spot this
  // script exists to close.
  const v = e.evaluate(base({ lastSuccessMs: null }));
  assert.equal(v.level, 'fail');
  assert.match(find(v, 'staleness').message, /ни одного успешного/);
});

test('reproduces the outage this was written for', () => {
  // 2026-07-06 .. 07-31: runner offline, runs queued for a full day before the
  // 24h kill, last successful scheduled run 2026-07-02.
  const v = e.evaluate({
    nowMs: Date.parse('2026-07-31T09:00:00Z'),
    queuedRuns: [{ id: 30529310017, name: 'security-scan', createdAtMs: Date.parse('2026-07-30T09:05:43Z') }],
    anyJobRunning: false,
    lastSuccessMs: Date.parse('2026-07-02T07:38:57Z'),
  });
  assert.equal(v.level, 'fail');
  assert.equal(find(v, 'queue').level, 'fail');
  assert.equal(find(v, 'staleness').level, 'fail');
  assert.match(find(v, 'staleness').message, /29 дн\./);
});

test('custom thresholds are honoured', () => {
  const v = e.evaluate(base({
    queuedRuns: [run(45)], lastSuccessMs: NOW - 10 * DAY,
    queueLimitMin: 120, staleLimitDays: 14,
  }));
  assert.equal(v.level, 'ok');
});

test('parseArgs: defaults, overrides, and rejection of junk values', () => {
  const d = e.parseArgs([]);
  assert.equal(d.queueLimitMin, e.DEFAULTS.queueLimitMin);
  assert.equal(d.staleLimitDays, e.DEFAULTS.staleLimitDays);
  assert.equal(d.workflow, e.DEFAULTS.workflow);
  assert.equal(d.notify, false);

  const o = e.parseArgs(['--repo', 'a/b', '--queue-limit-min', '120', '--stale-limit-days', '3', '--notify', '--json']);
  assert.equal(o.repo, 'a/b');
  assert.equal(o.queueLimitMin, 120);
  assert.equal(o.staleLimitDays, 3);
  assert.equal(o.notify, true);
  assert.equal(o.json, true);

  // A non-numeric or non-positive threshold must fall back, never become NaN —
  // NaN comparisons are all false, which would silently disable the check.
  assert.equal(e.parseArgs(['--queue-limit-min', 'abc']).queueLimitMin, e.DEFAULTS.queueLimitMin);
  assert.equal(e.parseArgs(['--stale-limit-days', '0']).staleLimitDays, e.DEFAULTS.staleLimitDays);
  assert.equal(e.parseArgs(['--nope']).help, true);
});
