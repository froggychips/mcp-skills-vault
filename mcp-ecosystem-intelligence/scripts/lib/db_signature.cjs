'use strict';
/**
 * The DB's signature, as the CLI sees it: a file next to a file, checked before
 * anything reads the DB — as findings, decided by the `db/signature` row of
 * lib/policy_rules.cjs (docs/adr/0001-findings-and-time.md,
 * docs/adr/0001-addendum-121-signed-db.md).
 *
 * `lib/signing.cjs` is the mechanism. This module turns one check into
 * findings on the DB file (a `host-config` subject: a file, no line):
 *
 *   db/signature-verified         observed, info      the canonical DB matches its .sig,
 *                                                     signed by a key in the keyring,
 *                                                     inside that key's window
 *   db/signature-absent           observed, medium    there is no .sig next to the DB
 *   db/signature-invalid          observed, high      malformed, unknown or revoked key,
 *                                                     key out of window, tampered bytes,
 *                                                     unreadable DB
 *   db/signature-not-configured   not-run,  info      the keyring is empty: nothing to
 *                                                     check against (a property of the
 *                                                     build, never "verified")
 *   db/signature-keyring-invalid  observed, critical  the keyring cannot be read
 *
 * and says what the row needs to know about where it runs (facts):
 *
 *   required        whether a missing signature refuses. **Only an installed
 *                   package requires one** — see `signatureContext`.
 *   context         'package' | 'git checkout' | 'MCP_VAULT_REQUIRE_SIGNED_DB'
 *   allow_unsigned  the loud development override (--allow-unsigned-db /
 *                   MCP_VAULT_ALLOW_UNSIGNED_DB=1): a refusal becomes a warning,
 *                   printed on every run. A flag that goes quiet after the first
 *                   time becomes a setting nobody remembers turning on.
 *
 * The decision itself is decide()'s. `checkDb` renders it for the wrapper.
 *
 * API:
 *   PACKAGE_ROOT, ALLOW_ENV, REQUIRE_ENV, ALLOW_FLAG
 *   sigPathFor(file)                                 -> `${file}.sig`
 *   verifyFile(file, { keys, artifact? })            -> verifyCanonical result (+ 'unreadable', 'no-signature')
 *   signFile(file, { privateKeyPem, now })           -> envelope (written to sigPathFor(file))
 *   allowUnsignedFromEnv(env)                        -> boolean
 *   signatureContext({ root?, env? })                -> { required, context, reason }
 *   signatureFindings(files, { keyring, keyringPath, context, allowUnsigned, root? })
 *                                                    -> { subjects, findings, facts }
 *   signatureDocument(files, { keyring, keyringPath, context, allowUnsigned, asOf, policy })
 *                                                    -> { doc, decisions }   (mcp-vault/findings@1)
 *   checkDb({ dbPath, keys, keyringOk?, keyringErrors?, allowUnsigned, context, asOf })
 *                                                    -> { proceed, state, message, decision }
 */

const fs   = require('fs');
const path = require('path');
const { canonicalBytes, signCanonical, verifyCanonical } = require('./signing.cjs');
const { subject, finding, decide, findingsDocument, toJson, exitCode } = require('./finding.cjs');
const { effectivePolicy } = require('./policy_rules.cjs');
const { requireAsOf } = require('./clock.cjs');

const ALLOW_ENV   = 'MCP_VAULT_ALLOW_UNSIGNED_DB';
const REQUIRE_ENV = 'MCP_VAULT_REQUIRE_SIGNED_DB';
const ALLOW_FLAG  = '--allow-unsigned-db';
// The package root: bin/, mcp-ecosystem-intelligence/, package.json.
const PACKAGE_ROOT = path.resolve(__dirname, '../../..');

const sigPathFor = (file) => `${file}.sig`;

function readCanonical(file) {
  try { return { ok: true, bytes: canonicalBytes(fs.readFileSync(file, 'utf8')) }; }
  catch (e) { return { ok: false, error: e.message }; }
}

function verifyFile(file, { keys, artifact = path.basename(file) } = {}) {
  const content = readCanonical(file);
  if (!content.ok) return { ok: false, code: 'unreadable', error: `could not read ${file} as JSON: ${content.error}` };
  const sigFile = sigPathFor(file);
  let text;
  // Read, not exists-then-read: one syscall decides, so there is no window
  // between the check and the use.
  try { text = fs.readFileSync(sigFile, 'utf8'); }
  catch (e) {
    if (e.code === 'ENOENT') return { ok: false, code: 'no-signature', error: `no signature file (${path.basename(sigFile)})` };
    return { ok: false, code: 'malformed', error: `could not read ${path.basename(sigFile)}: ${e.message}` };
  }
  let envelope;
  try { envelope = JSON.parse(text); }
  catch (e) { return { ok: false, code: 'malformed', error: `could not read ${path.basename(sigFile)}: ${e.message}` }; }
  return verifyCanonical(content.bytes, envelope, keys, { artifact });
}

function signFile(file, { privateKeyPem, now } = {}) {
  requireAsOf(now, 'signFile');
  const content = readCanonical(file);
  if (!content.ok) throw new Error(`could not read ${file} as JSON: ${content.error}`);
  const envelope = signCanonical(content.bytes, { privateKeyPem, artifact: path.basename(file), now });
  fs.writeFileSync(sigPathFor(file), `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
  return envelope;
}

const yes = (v) => ['1', 'true', 'yes'].includes(String(v || '').trim().toLowerCase());
const allowUnsignedFromEnv = (env = process.env) => yes(env[ALLOW_ENV]);

/**
 * Where this CLI runs, and so whether a missing signature refuses.
 *
 * The owner's rule: a signature is mandatory for the *installed npm package*,
 * not for a git checkout (development, CI, every PR that touches the DB).
 * Signing happens at release, so a checkout never has a `.sig`, and refusing
 * there broke every CLI step that ran from one.
 *
 * The signal is a `.git` entry (a directory, or the file a worktree has) at the
 * package root itself — not in any parent. It is the right signal because:
 *
 *   - npm never packs `.git`: npm-packlist ignores it unconditionally, whatever
 *     `files` or `.npmignore` say, so no tarball — ours or a tampered one —
 *     can carry it, and `npm install` / `npx` never produce it.
 *   - It is read at the package root, not found by walking up, so a package
 *     installed inside somebody's repository (node_modules under a project
 *     with its own `.git`) is still a package.
 *   - The default is the strict one. Anything that is *not* recognisably a
 *     checkout — a tarball, a copy, a source zip, a container image built
 *     without `.git` — requires the signature. Only a positive development
 *     signal relaxes it, never an absence.
 *   - Creating `.git` inside an installed package needs write access to the
 *     package directory, which is write access to the code that does this
 *     check: it is not a weaker boundary than the code itself.
 *
 * `MCP_VAULT_REQUIRE_SIGNED_DB=1` makes a checkout behave like a package (a
 * release rehearsal, the tests). It can only tighten.
 *
 * Whatever the context, a signature that is *present* must verify, and the
 * keyring must be readable: `required` is only about a missing `.sig`.
 */
function signatureContext({ root = PACKAGE_ROOT, env = process.env } = {}) {
  if (yes(env[REQUIRE_ENV])) {
    return { required: true, context: REQUIRE_ENV, reason: `${REQUIRE_ENV} is set` };
  }
  let checkout = false;
  try { fs.lstatSync(path.join(root, '.git')); checkout = true; } catch { checkout = false; }
  return checkout
    ? { required: false, context: 'git checkout', reason: `${path.join(root, '.git')} exists — development, CI or a PR` }
    : { required: true, context: 'package', reason: `no .git at ${root} — an installed package` };
}

// The DB as a subject: a file. Inside the package it is named relative to the
// package root, so the same DB is the same subject on every machine.
function fileSubject(file, root = PACKAGE_ROOT) {
  const rel = path.relative(root, file);
  const shown = rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel.split(path.sep).join('/') : file;
  return subject.hostConfig({ path: shown, scope: 'database' });
}

/**
 * One check per file, as findings. `keyring` is loadTrustedKeys()'s result:
 * `{ ok, keys, errors }`.
 */
function signatureFindings(files, { keyring, keyringPath = null, context, allowUnsigned = false, root = PACKAGE_ROOT } = {}) {
  const subjects = [];
  const findings = [];
  const facts = {};
  for (const file of files) {
    const s = fileSubject(file, root);
    const name = path.basename(file);
    subjects.push(s);
    let result = null;
    if (!keyring || !keyring.ok) {
      findings.push(finding({
        rule: 'db/signature-keyring-invalid', subject: s, severity: 'critical',
        message: `the shipped keyring is unreadable (${((keyring && keyring.errors) || []).join('; ') || 'no keyring'}); refusing to trust the DB`,
      }));
    } else if (!keyring.keys.length) {
      findings.push(finding({
        rule: 'db/signature-not-configured', subject: s, severity: 'info', state: 'not-run',
        message: `${name}: this build ships no trusted signing key, so the DB signature is not checked`,
      }));
    } else {
      result = verifyFile(file, { keys: keyring.keys });
      if (result.ok) {
        findings.push(finding({
          rule: 'db/signature-verified', subject: s, severity: 'info',
          message: `${name}: signature verified (key ${result.key_id}, signed ${result.signed_at})`,
        }));
      } else if (result.code === 'no-signature') {
        findings.push(finding({
          rule: 'db/signature-absent', subject: s, severity: 'medium',
          message: `${name}: ${result.error} [${result.code}]`,
        }));
      } else {
        findings.push(finding({
          rule: 'db/signature-invalid', subject: s, severity: 'high',
          message: `${name}: ${result.error} [${result.code}]`,
        }));
      }
    }
    facts[s.id] = {
      file,
      required: Boolean(context && context.required),
      context: (context && context.context) || null,
      allow_unsigned: Boolean(allowUnsigned),
      keyring: {
        path: keyringPath,
        keys: ((keyring && keyring.keys) || []).map((k) => ({ key_id: k.key_id, valid_from: k.valid_from, valid_until: k.valid_until, revoked: k.revoked })),
      },
      result: result ? {
        code: result.code, key_id: result.key_id || null, signed_at: result.signed_at || null, sha256: result.sha256 || null,
      } : null,
    };
  }
  return { subjects, findings, facts };
}

// The gate's own switches only: no policy file speaks about the DB signature.
// --strict / --fail-unverified still tighten fail_on, as everywhere.
const signaturePolicy = (flags = {}) => effectivePolicy(null, flags, { policyRules: false });

function signatureDocument(files, { keyring, keyringPath = null, context, allowUnsigned = false, asOf, policy = signaturePolicy(), root = PACKAGE_ROOT } = {}) {
  requireAsOf(asOf, 'signatureDocument');
  const { subjects, findings, facts } = signatureFindings(files, { keyring, keyringPath, context, allowUnsigned, root });
  const decisions = decide(findings, policy, asOf, { subjects, facts });
  const doc = toJson(findingsDocument({ asOf, findings, decisions, scope: 'db-signature', policy, facts }));
  return { doc, decisions, exit: exitCode(decisions) };
}

/**
 * What the wrapper asks before a command reads a DB: the Decision, rendered.
 * `state` is a label of the decision for the message, not a second verdict.
 */
function checkDb({ dbPath, keys, keyringOk = true, keyringErrors = [], allowUnsigned = false, context = signatureContext(), asOf }) {
  const name = path.basename(dbPath);
  const keyring = { ok: keyringOk, keys: keys || [], errors: keyringErrors };
  const { doc, decisions } = signatureDocument([dbPath], { keyring, context, allowUnsigned, asOf });
  const d = decisions[0];
  const f = doc.findings[0];
  const why = f.message;
  if (d.fails) {
    return {
      proceed: false, state: 'refused', decision: d, doc,
      message: [
        `mcp-vault: refusing to use the DB — ${why}`,
        '',
        context.required
          ? `A signature is required here: ${context.reason}.`
          : `A missing signature would be allowed here (${context.context}), but one that is present has to verify.`,
        'The DB decides what `install` writes into your config, so it has to be the one',
        'the maintainers signed. If you are developing on a copy without .git or running a fork',
        `with its own DB, pass ${ALLOW_FLAG} or set ${ALLOW_ENV}=1 — knowingly.`,
        'Check it on its own: mcp-vault signature --json',
      ].join('\n'),
    };
  }
  let state = 'verified';
  if (f.rule === 'db/signature-not-configured') state = 'not-configured';
  else if (f.rule === 'db/signature-absent' && !context.required) state = 'not-required';
  else if (d.effect === 'warn') state = 'unsigned-allowed';
  const message = state === 'unsigned-allowed'
    ? [
      '!!! ─────────────────────────────────────────────────────────────── !!!',
      `!!! DB SIGNATURE NOT VERIFIED — ${why}`,
      `!!! Running anyway because ${ALLOW_FLAG} / ${ALLOW_ENV} is set.`,
      '!!! Every recommendation and install below trusts a DB nobody vouched for.',
      '!!! ─────────────────────────────────────────────────────────────── !!!',
    ].join('\n')
    : d.rules.map((r) => r.detail).filter(Boolean)[0] || why;
  return { proceed: true, state, decision: d, doc, message };
}

module.exports = {
  PACKAGE_ROOT, ALLOW_ENV, REQUIRE_ENV, ALLOW_FLAG,
  sigPathFor, verifyFile, signFile, allowUnsignedFromEnv,
  signatureContext, signatureFindings, signaturePolicy, signatureDocument, checkDb,
};
