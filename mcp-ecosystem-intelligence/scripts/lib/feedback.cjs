'use strict';
/**
 * One line pointing at the issue tracker, for a person at a terminal. It is
 * only printed: nothing is collected, nothing is sent, no network. Not in
 * --json, not when stdout is a pipe, not in CI (`CI` set, as every CI sets
 * it) — there it is noise in a log nobody asked to read. Shared by `status`
 * and `check`, so both say it under the same conditions.
 *
 * API:
 *   FEEDBACK_URL
 *   feedbackLine({ isTTY, env })  -> string | null
 */

const FEEDBACK_URL = 'https://github.com/froggychips/mcp-skills-vault/issues/new';

function feedbackLine({ isTTY = process.stdout.isTTY, env = process.env } = {}) {
  const ci = env.CI !== undefined && env.CI !== '' && env.CI !== 'false' && env.CI !== '0';
  return isTTY && !ci ? `Something wrong, or did this help? → ${FEEDBACK_URL}` : null;
}

module.exports = { FEEDBACK_URL, feedbackLine };
