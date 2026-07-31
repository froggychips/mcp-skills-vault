'use strict';
/**
 * Flush-then-exit for CLIs that print a payload and then set an exit code.
 *
 * When stdout is a pipe — CI, `> file`, `| tee`, a `spawnSync` in a test,
 * command substitution — writes are asynchronous. `process.exit()` tears the
 * process down without draining them, so whatever is still buffered is lost.
 * A CLI that prints its verdict and exits immediately can therefore lose the
 * verdict; one that prints JSON can emit a truncated object that parses as
 * "Unexpected end of JSON input".
 *
 * Seen in CI: verify_integrity --offline produced every per-entry line and
 * then stopped exactly where the final `\n<N> entries checked` write began —
 * the leading newline made it out, the rest didn't.
 *
 * API:
 *   exitAfterFlush(code)  -> never returns
 *
 * The empty write queues its callback behind everything already buffered, so
 * it fires once the stream has drained that far. `process.exitCode` is set
 * first so that if the callback never runs — stdout already closed, EPIPE —
 * a natural exit still carries the right status instead of a silent 0.
 */

function exitAfterFlush(code) {
  process.exitCode = code;
  process.stdout.write('', () => process.exit(code));
}

module.exports = { exitAfterFlush };
