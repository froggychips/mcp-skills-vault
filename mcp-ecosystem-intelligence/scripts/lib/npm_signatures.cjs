'use strict';
/**
 * npm registry signatures and provenance attestations.
 *
 * Two different claims, often confused, kept apart here:
 *
 *   1. Registry signature (`dist.signatures`). npm signs the string
 *      `<name>@<version>:<integrity>` with one of its published ECDSA keys.
 *      Verifying it proves the registry vouched for this exact integrity value,
 *      so a tampered `dist.integrity` in a response cannot pass. This is a
 *      complete cryptographic check and it is what `npm audit signatures`
 *      does. Node's crypto does it with no dependencies.
 *
 *   2. Provenance attestation (`dist.attestations`). A sigstore bundle tying
 *      the artifact to the CI run and source commit that built it. Verifying
 *      that bundle properly means checking a Fulcio certificate chain and a
 *      Rekor inclusion proof — out of scope here, and pretending otherwise
 *      would be worse than not doing it. What this module does instead is
 *      read the in-toto statement and report *what it claims*: the source
 *      repository and workflow. Callers compare that with the DB's source_url,
 *      which catches the case that matters in practice — a package whose
 *      provenance points at a repository nobody reviewed.
 *
 * The distinction is preserved in the output: "signature verified" is a proof,
 * "provenance claims X" is a claim.
 *
 * API:
 *   signatureMessage(name, version, integrity)    -> string            (pure)
 *   verifyRegistrySignature({...})                -> { state, ... }    (pure)
 *   provenanceClaim(attestationsDocument)         -> { ... } | null    (pure)
 *   keysUrl(registry)                             -> string            (pure)
 */

const crypto = require('crypto');

// What npm signs. Documented under "Verifying signatures" in the npm docs and
// reproduced by `npm audit signatures`.
function signatureMessage(name, version, integrity) {
  return `${name}@${version}:${integrity}`;
}

function keysUrl(registry = 'https://registry.npmjs.org') {
  return `${String(registry).replace(/\/+$/, '')}/-/npm/v1/keys`;
}

/**
 * Verify a registry signature.
 *
 * `keys` is the registry's key document: { keys: [{ keyid, key, expires, … }] }
 * where `key` is base64 SPKI DER. Returns:
 *   { state: 'ok',         keyid }
 *   { state: 'fail',       keyid, reason }   signature did not verify — tampering
 *   { state: 'unverified', reason }          nothing to check against
 *
 * 'unverified' and 'fail' are deliberately different: a package published
 * before npm signed anything has no signature (unverified), while a signature
 * that does not verify is an attack or a corrupted response (fail).
 */
function verifyRegistrySignature({ name, version, integrity, signatures, keys, now = Date.now() }) {
  if (!integrity) return { state: 'unverified', reason: 'no integrity value to verify' };
  if (!Array.isArray(signatures) || signatures.length === 0) {
    return { state: 'unverified', reason: 'the registry published no signature for this version' };
  }
  const keyList = (keys && keys.keys) || [];
  if (!keyList.length) return { state: 'unverified', reason: 'registry signing keys unavailable' };

  const message = signatureMessage(name, version, integrity);

  for (const sig of signatures) {
    const key = keyList.find((k) => k.keyid === sig.keyid);
    if (!key) continue;
    if (key.expires && Date.parse(key.expires) <= now) {
      return { state: 'unverified', keyid: sig.keyid, reason: `signing key ${sig.keyid} expired ${key.expires}` };
    }
    let ok = false;
    try {
      const publicKey = crypto.createPublicKey({
        key:    Buffer.from(key.key, 'base64'),
        format: 'der',
        type:   'spki',
      });
      ok = crypto.verify('sha256', Buffer.from(message), publicKey, Buffer.from(sig.sig, 'base64'));
    } catch (e) {
      return { state: 'unverified', keyid: sig.keyid, reason: `could not check the signature: ${e.message}` };
    }
    if (ok) return { state: 'ok', keyid: sig.keyid };
    return {
      state:  'fail',
      keyid:  sig.keyid,
      reason: `the registry signature over "${message}" does not verify against published key ${sig.keyid}`,
    };
  }

  return {
    state:  'unverified',
    reason: `no published key matches the signature's keyid (${signatures.map((s) => s.keyid).join(', ')})`,
  };
}

/**
 * Read what a provenance attestation *claims*, without asserting it is valid.
 *
 * `doc` is the document from `dist.attestations.url`:
 *   { attestations: [ { predicateType, bundle: { dsseEnvelope: { payload } } } ] }
 * where `payload` is a base64 in-toto statement. SLSA v0.2 and v1 keep the
 * source in different places, so both are checked.
 */
function provenanceClaim(doc) {
  const list = (doc && doc.attestations) || [];
  for (const att of list) {
    const payload = att?.bundle?.dsseEnvelope?.payload;
    if (!payload) continue;
    let statement;
    try { statement = JSON.parse(Buffer.from(payload, 'base64').toString('utf8')); }
    catch { continue; }

    const predicate = statement.predicate || {};
    // SLSA v1: buildDefinition.externalParameters.workflow.repository
    // SLSA v0.2: invocation.configSource.uri (git+https://github.com/o/r@refs/…)
    const workflow = predicate?.buildDefinition?.externalParameters?.workflow || {};
    const configUri = predicate?.invocation?.configSource?.uri || null;
    const repo = workflow.repository
      || (configUri ? String(configUri).replace(/^git\+/, '').replace(/@refs\/.*$/, '') : null);

    if (!repo) continue;
    return {
      predicateType: att.predicateType || statement.predicateType || null,
      repository:    repo,
      ref:           workflow.ref || predicate?.invocation?.configSource?.digest?.sha1 || null,
      workflowPath:  workflow.path || null,
      builder:       predicate?.runDetails?.builder?.id || predicate?.builder?.id || null,
      subjects:      (statement.subject || []).map((s) => s.name).filter(Boolean),
    };
  }
  return null;
}

module.exports = { signatureMessage, verifyRegistrySignature, provenanceClaim, keysUrl };
