'use strict';
/**
 * The one place a decision learns what time it is.
 *
 * Evidence is dated and dates age, so every verdict this tool gives is a
 * function of *when* it was asked — a hash match holds for 90 days, "no
 * advisories" for 7. That was fine while the "when" was explicit. It stopped
 * being fine when half the library read `Date.now()` as a default parameter:
 * two tests went red a week after the evidence they read did, with no commit
 * behind the failure, and no invocation could be replayed to say what the gate
 * would have answered on a given day.
 *
 * So time is an input, like the DB and the policy (docs/adr/0001):
 *
 *   result = f(db, evidence, policy, asOf, rules_version)
 *
 * A CLI entry point reads the clock exactly once — or takes `--as-of` — and
 * passes the instant down explicitly. Library code that decides anything takes
 * it as a required argument and throws when it is missing, rather than quietly
 * reading the wall clock and becoming unreproducible again.
 *
 * Two kinds of time, kept apart:
 *   asOf       the instant a *decision* is made about. Replayable.
 *   wall clock when an observer *looked* (a check ran, a cache was written, a
 *              timeout fired). Not replayable, and not supposed to be: you
 *              cannot observe a registry in the past. `performance.now()` for
 *              durations is a third thing and is not restricted at all.
 *
 * The default is the wall clock: `mcp-vault verify` answers about now, as it
 * always did. `--as-of` exists for tests, for docs and for reproducing what a
 * run said on a given day — and the instant used is printed in every `--json`
 * document, so a reader can tell which one they are looking at.
 *
 * API:
 *   readWallClock()                 -> epoch ms (the only Date.now() in lib/)
 *   parseAsOf(text)                 -> epoch ms | throws RangeError
 *   asOfFromArgv(argv)              -> { asOf, source, iso } | { error }
 *   requireAsOf(value, where)       -> epoch ms | throws TypeError
 *   isoDay(ms), isoInstant(ms)      -> 'YYYY-MM-DD', full ISO-8601
 *   stripAsOf(argv)                 -> argv without --as-of and its value
 */

const DAY_MS = 86400000;

/** The wall clock. Everything else in lib/ gets time handed to it. */
function readWallClock() {
  return Date.now();
}

// A bare date is midnight UTC of that day. An instant has to carry its zone:
// `2026-09-30T10:00` means a different moment on every machine that parses
// it, which is exactly the non-determinism this module exists to remove.
const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;
const INSTANT   = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * `--as-of` accepts `YYYY-MM-DD` (midnight UTC) or a full ISO-8601 instant
 * with an explicit `Z` or offset. Anything else is refused, loudly: a date
 * that silently parses as something else would be a replay of the wrong day.
 */
function parseAsOf(text) {
  const s = String(text == null ? '' : text).trim();
  const d = s.match(DATE_ONLY);
  if (d) {
    const ms = Date.UTC(Number(d[1]), Number(d[2]) - 1, Number(d[3]));
    // Date.UTC rolls 2026-02-30 over into March; a date that does not exist
    // is a typo, not a request for the day after.
    if (new Date(ms).toISOString().slice(0, 10) !== s) {
      throw new RangeError(`--as-of: ${s} is not a calendar date`);
    }
    return ms;
  }
  if (INSTANT.test(s)) {
    const ms = Date.parse(s);
    if (Number.isFinite(ms)) return ms;
  }
  throw new RangeError(`--as-of: expected YYYY-MM-DD or an ISO-8601 instant with a zone (…Z or …+hh:mm), got ${JSON.stringify(s)}`);
}

/**
 * What a CLI entry point calls once. Returns `{ error }` rather than throwing
 * so that each command can keep its own usage-error path (exit 2).
 */
function asOfFromArgv(argv = []) {
  const args = Array.isArray(argv) ? argv : [];
  let raw = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--as-of') {
      raw = args[i + 1];
      if (raw === undefined || String(raw).startsWith('--')) return { error: '--as-of needs a date (YYYY-MM-DD) or an ISO-8601 instant' };
    } else if (typeof a === 'string' && a.startsWith('--as-of=')) {
      raw = a.slice('--as-of='.length);
    }
  }
  if (raw === null) {
    const asOf = readWallClock();
    return { asOf, source: 'wall-clock', iso: isoInstant(asOf) };
  }
  try {
    const asOf = parseAsOf(raw);
    return { asOf, source: 'as-of', iso: isoInstant(asOf) };
  } catch (e) {
    return { error: e.message };
  }
}

/**
 * The guard every time-dependent library function starts with. It used to be
 * `now = Date.now()`, which is how a decision became a function of the day
 * the tests happened to run.
 */
function requireAsOf(value, where = 'this function') {
  const ms = value instanceof Date ? value.getTime() : value;
  if (typeof ms !== 'number' || !Number.isFinite(ms)) {
    throw new TypeError(
      `${where}: asOf is required (got ${value === undefined ? 'nothing' : JSON.stringify(value)}). `
      + 'Read the clock once at the CLI entry point (lib/clock.cjs asOfFromArgv) and pass it down; '
      + 'see docs/adr/0001-findings-and-time.md');
  }
  return ms;
}

const isoDay     = (ms) => new Date(requireAsOf(ms, 'isoDay')).toISOString().slice(0, 10);
const isoInstant = (ms) => new Date(requireAsOf(ms, 'isoInstant')).toISOString();

/** argv with `--as-of` removed — for passing the rest through untouched. */
function stripAsOf(argv = []) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--as-of') { i++; continue; }
    if (typeof argv[i] === 'string' && argv[i].startsWith('--as-of=')) continue;
    out.push(argv[i]);
  }
  return out;
}

module.exports = {
  DAY_MS, readWallClock, parseAsOf, asOfFromArgv, requireAsOf, isoDay, isoInstant, stripAsOf,
};
