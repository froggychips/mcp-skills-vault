'use strict';
/**
 * lib/budget: the arithmetic the installer and the report now share.
 *
 * The two things worth pinning down here are both about honesty of the total:
 * a server that could not be measured must not count as zero, and a server that
 * answered with an empty tool list must not count as free.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');

const b = require('../mcp-ecosystem-intelligence/scripts/lib/budget.cjs');

test('a measured payload beats a counted estimate', () => {
  const r = b.estimateServer({
    name: 'x',
    dbEntry:   { est_tools_count: 5 },
    evalEntry: { tool_count: 23, tools_payload_bytes: 17084 },
  });
  assert.equal(r.source, 'measured');
  assert.equal(r.tokens, Math.round(17084 / b.BYTES_PER_TOKEN));
  // A measurement has no range: it is the thing itself, not an estimate of it.
  assert.equal(r.low, r.high);
});

test('an empty tool list is a broken server, not a free one', () => {
  // mcp-atlassian: 72 tools in the DB, 0 observed. The payload arithmetic
  // turned that into "≈1 token", which made a config full of broken servers
  // look free.
  const r = b.estimateServer({
    name: 'atlassian',
    dbEntry:   { est_tools_count: 72 },
    evalEntry: { tool_count: 0, tools_payload_bytes: 6 },
  });
  assert.equal(r.source, 'db');
  assert.equal(r.tools, 72);
  assert.equal(r.tokens, 72 * b.TOKENS_PER_TOOL_MID);
});

test('nothing to go on is "unknown", which is not zero', () => {
  const r = b.estimateServer({ name: 'y', dbEntry: null, evalEntry: null });
  assert.equal(r.source, 'unknown');
  assert.equal(r.tokens, null);

  const totals = b.summarise([r, { name: 'z', tools: 10, tokens: 3500, low: 2000, high: 5000 }]);
  assert.equal(totals.tokens, 3500);
  assert.equal(totals.unknown_servers, 1);
  assert.deepEqual(totals.unknown_names, ['y']);
});

test('no ceiling in policy means no opinion, not "unlimited"', () => {
  assert.equal(b.wouldExceed({ rows: [], adding: null, policy: {} }), null);
  assert.equal(b.wouldExceed({ rows: [], adding: null, policy: { unverified: 'fail' } }), null);
});

test('maxContextTokens: over is over, and headroom is what is left', () => {
  const rows = [{ name: 'a', tools: 10, tokens: 3000, low: 2000, high: 5000 }];
  const adding = { name: 'b', tools: 20, tokens: 7000, low: 4000, high: 10000, source: 'db' };

  const over = b.wouldExceed({ rows, adding, policy: { maxContextTokens: 9000 } });
  assert.equal(over.over, true);
  assert.equal(over.after, 10000);
  assert.equal(over.headroom, -1000);
  assert.equal(over.limit_source, 'maxContextTokens');
  assert.equal(over.was_already_over, false);

  const under = b.wouldExceed({ rows, adding, policy: { maxContextTokens: 20000 } });
  assert.equal(under.over, false);
  assert.equal(under.headroom, 10000);
});

test('maxContextPercent resolves against the context window', () => {
  const rows = [{ name: 'a', tools: 10, tokens: 30000, low: 0, high: 0 }];
  const r = b.wouldExceed({ rows, adding: null, policy: { maxContextPercent: 10 }, context: 200000 });
  assert.equal(r.limit, 20000);
  assert.equal(r.limit_source, 'maxContextPercent');
  assert.equal(r.over, true);
});

test('re-installing a configured server is not a second copy of its surface', () => {
  const rows = [
    { name: 'a', tools: 10, tokens: 3000, low: 0, high: 0 },
    { name: 'b', tools: 20, tokens: 7000, low: 0, high: 0 },
  ];
  const adding = { name: 'b', tools: 20, tokens: 7000, low: 0, high: 0, source: 'db' };
  const r = b.wouldExceed({ rows, adding, policy: { maxContextTokens: 11000 } });
  assert.equal(r.after, 10000, 'b counted once, not twice');
  assert.equal(r.over, false);
});

test('a config already over the ceiling says so separately', () => {
  // Otherwise the entry being installed takes the blame for a config that was
  // over before anyone touched it.
  const rows = [{ name: 'a', tools: 100, tokens: 35000, low: 0, high: 0 }];
  const adding = { name: 'b', tools: 1, tokens: 350, low: 0, high: 0, source: 'db' };
  const r = b.wouldExceed({ rows, adding, policy: { maxContextTokens: 10000 } });
  assert.equal(r.was_already_over, true);
  assert.equal(r.over, true);
});

test('matchDbEntry falls back to the package name when the label differs', () => {
  const db = [{ name: 'playwright-mcp', install_cmd: 'npx -y @playwright/mcp@0.0.75' }];
  assert.equal(b.matchDbEntry({ name: 'playwright-mcp' }, db).name, 'playwright-mcp');
  assert.equal(b.matchDbEntry({ name: 'browser', install_cmd: 'npx -y @playwright/mcp@0.0.75' }, db).name, 'playwright-mcp');
  assert.equal(b.matchDbEntry({ name: 'unrelated', install_cmd: 'npx -y other-pkg' }, db), null);
  assert.equal(b.matchDbEntry({ name: 'remote' }, db), null);
});
