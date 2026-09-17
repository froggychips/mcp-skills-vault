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
 *      the *bundle* properly means checking a Fulcio certificate chain and a
 *      Rekor inclusion proof — out of scope here, and pretending otherwise
 *      would be worse than not doing it.
 *
 *      Three things inside it can be checked without that chain, and they are
 *      the three that catch the case that matters — a package whose provenance
 *      belongs to something else:
 *
 *        a. the in-toto statement's *subject*: a purl and a sha512 digest. That
 *           digest is over the same tarball as `dist.integrity`, which the
 *           registry signature above proves the registry vouched for. So
 *           "this attestation is about the bytes we verified" is decidable —
 *           and before this, an attestation for a *different artifact entirely*
 *           read as provenance for this one.
 *        b. the signing certificate's SAN, which Fulcio sets to the workflow
 *           identity: `https://github.com/<owner>/<repo>/<workflow>@<ref>`.
 *           Compared with the DB's source_url, this answers "built by that
 *           repository's own CI?" rather than "claims to have been".
 *        c. the builder id in the statement (`…/actions/runner/github-hosted`),
 *           which says the build ran on a GitHub-hosted runner.
 *
 *      What is still NOT done, and is not claimed anywhere in the output: the
 *      certificate chain is not validated against Fulcio's root, the Rekor
 *      inclusion proof is not checked, and the DSSE signature over the
 *      statement is not verified. A forged bundle would pass (a), (b) and (c).
 *      The OIDC issuer extension (OID 1.3.6.1.4.1.57264.1.8) is deliberately
 *      not read either: it needs an ASN.1 walk this module does not have, and
 *      a hand-rolled DER scan in a supply-chain tool is a bad trade.
 *
 * The distinction is preserved in the output: "signature verified" is a proof,
 * "provenance is bound to this artifact" is a check over unproven material,
 * "provenance claims X" is a claim.
 *
 * API:
 *   signatureMessage(name, version, integrity)    -> string            (pure)
 *   verifyRegistrySignature({...})                -> { state, ... }    (pure)
 *   provenanceClaim(attestationsDocument)         -> { ... } | null    (pure)
 *   certIdentity(bundle)                          -> { ... } | null    (pure)
 *   checkProvenance({ claim, ... })               -> { state, ... }    (pure)
 *   purlFor(ecosystem, name, version)             -> string            (pure)
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
      // The subject with its digests, which is what ties the attestation to an
      // artifact. `subjects` above stays a list of names because callers (and
      // tests) read it that way.
      subjectDigests: (statement.subject || [])
        .filter((s) => s && s.digest)
        .map((s) => ({ name: s.name || null, digest: { ...s.digest } })),
      certificate:   certIdentity(att.bundle),
    };
  }
  return null;
}

/**
 * The signing certificate's identity, as Fulcio issued it.
 *
 * Sigstore bundles carry the leaf either as `verificationMaterial.certificate`
 * (current) or as the first entry of `verificationMaterial.x509CertificateChain`
 * (older bundles). npm's *publish* attestation has no certificate at all — it
 * is signed with a registry key — so a null here is normal for that one and
 * means "this bundle has no workflow identity", not "the identity is wrong".
 *
 * Node parses the certificate; nothing here validates it. `issuer` is read for
 * reporting only: an unvalidated chain cannot establish that sigstore issued
 * anything, and the field is never treated as proof.
 */
function certIdentity(bundle) {
  const vm  = bundle?.verificationMaterial;
  const raw = vm?.certificate?.rawBytes
    || vm?.x509CertificateChain?.certificates?.[0]?.rawBytes
    || null;
  if (!raw) return null;
  let cert;
  try { cert = new crypto.X509Certificate(Buffer.from(raw, 'base64')); }
  catch (e) { return { error: `certificate could not be parsed: ${e.message}` }; }

  // Fulcio puts the workflow identity in a SAN URI:
  //   https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>
  const san = cert.subjectAltName || null;
  const uri = san ? (String(san).split(',').map((s) => s.trim()).find((s) => s.startsWith('URI:')) || null) : null;
  const identity = uri ? uri.slice(4) : null;

  let repository = null, workflowPath = null, ref = null;
  if (identity) {
    const at = identity.lastIndexOf('@');
    const left = at === -1 ? identity : identity.slice(0, at);
    ref = at === -1 ? null : identity.slice(at + 1);
    const m = left.match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/(.+)$/);
    if (m) { repository = `https://github.com/${m[1]}`; workflowPath = m[2]; }
  }

  return {
    identity,
    repository,
    workflowPath,
    ref,
    issuer:    cert.issuer ? String(cert.issuer).replace(/\n/g, ', ') : null,
    valid_from: cert.validFrom || null,
    valid_to:   cert.validTo || null,
  };
}

/** The package URL an in-toto subject uses. npm scopes arrive percent-encoded. */
function purlFor(ecosystem, name, version) {
  if (!name) return null;
  const encoded = String(name).startsWith('@')
    ? `%40${String(name).slice(1)}`     // pkg:npm/%40scope/pkg — only the @ is encoded
    : String(name);
  return `pkg:${ecosystem}/${encoded}${version ? `@${version}` : ''}`;
}

/** sha512-<base64> → lowercase hex, which is how in-toto writes digests. */
function integrityToHex(integrity) {
  const m = String(integrity || '').match(/^(sha256|sha384|sha512)-(.+)$/);
  if (!m) return null;
  let buf;
  try { buf = Buffer.from(m[2], 'base64'); } catch { return null; }
  const expected = { sha256: 32, sha384: 48, sha512: 64 }[m[1]];
  if (buf.length !== expected) return null;
  return { algorithm: m[1], hex: buf.toString('hex') };
}

/**
 * What a provenance attestation establishes about *this* artifact.
 *
 * Returns { state, issuer, subject_match, repository, findings } where state is
 *   'bound'      — the statement's subject is the artifact we verified, and the
 *                  signing identity belongs to the repository the DB records
 *   'claimed'    — readable and consistent, but nothing tied it to these bytes
 *   'mismatch'   — it describes a different repository or different bytes
 *   'unreadable' — there is an attestation but no statement could be read
 *
 * 'bound' is deliberately not called "verified": see the note at the top of
 * this file about what is still unchecked.
 */
function checkProvenance({ claim, sourceUrl = null, name = null, version = null, integrity = null, normalizeRepo = (u) => u } = {}) {
  if (!claim) return { state: 'unreadable', findings: ['attestation present but no in-toto statement could be read'] };

  const findings = [];
  const storedRepo = sourceUrl ? String(normalizeRepo(sourceUrl) || '').toLowerCase() : null;

  // ── who built it ──
  const builder = claim.builder || null;
  const cert    = claim.certificate && !claim.certificate.error ? claim.certificate : null;
  const issuer  = /\/actions\/runner\//.test(String(builder || '')) ? 'github-actions'
    : (cert && /github\.com/.test(String(cert.identity || '')) ? 'github-actions' : 'unknown');
  if (issuer !== 'github-actions') {
    findings.push(`builder is not a GitHub Actions runner (${builder || 'builder id absent'})`);
  }
  if (claim.certificate && claim.certificate.error) findings.push(claim.certificate.error);

  // ── which repository signed ──
  // The certificate's SAN is the stronger statement of the two: the workflow in
  // the statement is self-reported build metadata, while the SAN is what the
  // identity token was issued for.
  let repoMatch = 'unknown';
  const certRepo = cert && cert.repository ? String(normalizeRepo(cert.repository) || '').toLowerCase() : null;
  if (storedRepo && certRepo) {
    repoMatch = certRepo === storedRepo ? 'ok' : 'mismatch';
    if (repoMatch === 'mismatch') {
      findings.push(`the signing identity belongs to ${cert.repository}, not to ${sourceUrl}`);
    }
  } else if (storedRepo && claim.repository) {
    const claimed = String(normalizeRepo(claim.repository) || '').toLowerCase();
    repoMatch = claimed === storedRepo ? 'ok' : 'mismatch';
    if (repoMatch === 'mismatch') {
      findings.push(`provenance names ${claim.repository}, not ${sourceUrl}`);
    }
  }

  // ── which bytes ──
  let subjectMatch = 'unknown';
  const want = integrityToHex(integrity);
  const purl = purlFor('npm', name, version);
  if (want && Array.isArray(claim.subjectDigests) && claim.subjectDigests.length) {
    const hit = claim.subjectDigests.find((s) => String(s.digest?.[want.algorithm] || '').toLowerCase() === want.hex);
    if (hit) {
      subjectMatch = 'ok';
      // A digest match with the wrong name is still a match on the bytes, but
      // worth saying out loud.
      if (purl && hit.name && hit.name !== purl) findings.push(`attestation subject is named ${hit.name}, expected ${purl}`);
    } else {
      subjectMatch = 'mismatch';
      const seen = claim.subjectDigests.map((s) => s.name || '(unnamed)').join(', ');
      findings.push(`no attestation subject matches this artifact's ${want.algorithm} (subjects: ${seen})`);
    }
  } else if (!want) {
    findings.push('no integrity value to compare the attestation subject against');
  } else {
    findings.push('attestation carries no subject digest');
  }

  let state;
  if (repoMatch === 'mismatch' || subjectMatch === 'mismatch') state = 'mismatch';
  else if (subjectMatch === 'ok' && repoMatch === 'ok' && issuer === 'github-actions') state = 'bound';
  else state = 'claimed';

  return {
    state,
    issuer,
    subject_match: subjectMatch,
    repo_match:    repoMatch,
    repository:    (cert && cert.repository) || claim.repository || null,
    identity:      cert ? cert.identity : null,
    workflow:      (cert && cert.workflowPath) || claim.workflowPath || null,
    findings,
  };
}

module.exports = {
  signatureMessage, verifyRegistrySignature, provenanceClaim, keysUrl,
  certIdentity, checkProvenance, purlFor, integrityToHex,
};
