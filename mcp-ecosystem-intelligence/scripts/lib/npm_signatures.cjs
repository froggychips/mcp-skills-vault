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
 *   provenanceClaim(attestationsDocument)         -> { ..., records } | null
 *   attestationRecords(attestationsDocument)      -> [{ ... }]          (pure)
 *   certIdentity(bundle)                          -> { ... } | null    (pure)
 *   checkProvenance({ claim, ... })               -> { state, ... }    (pure)
 *   verifyEnvelope(dsseEnvelope, key)             -> { state, ... }    (pure)
 *   pae(payloadType, payload)                     -> Buffer            (pure)
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
  const records = attestationRecords(doc);
  // The flat shape callers already use: the first record that names a source
  // repository. `records` carries all of them, which is what the binding check
  // needs — npm publishes two attestations per release and the useful fields
  // are split between them.
  const primary = records.find((r) => r.repository) || null;
  if (!primary) return null;
  return {
    predicateType: primary.predicateType,
    repository:    primary.repository,
    ref:           primary.ref,
    workflowPath:  primary.workflowPath,
    builder:       primary.builder,
    subjects:      primary.subjects,
    subjectDigests: primary.subjectDigests,
    certificate:   primary.certificate,
    records,
  };
}

/**
 * Every attestation in the document, parsed, with what is needed to check it.
 *
 * npm publishes two per release and they carry different things: the *publish*
 * attestation is signed by npm's own registry key (the trust root we already
 * use for `dist.signatures`) and carries the subject digest; the *SLSA
 * provenance* attestation is signed by a Fulcio-issued certificate and carries
 * the workflow identity. Reading only the first one that mentioned a repository
 * meant the digest and the identity were never checked together.
 */
function attestationRecords(doc) {
  const list = (doc && doc.attestations) || [];
  const out = [];
  for (const att of list) {
    const envelope = att?.bundle?.dsseEnvelope || null;
    const payload = envelope && envelope.payload;
    if (!payload) continue;
    let statement;
    try { statement = JSON.parse(Buffer.from(payload, 'base64').toString('utf8')); }
    catch { continue; }

    const predicate = statement.predicate || {};
    const workflow = predicate?.buildDefinition?.externalParameters?.workflow || {};
    const configUri = predicate?.invocation?.configSource?.uri || null;
    const repo = workflow.repository
      || (configUri ? String(configUri).replace(/^git\+/, '').replace(/@refs\/.*$/, '') : null);

    const vm = att?.bundle?.verificationMaterial || {};
    out.push({
      predicateType: att.predicateType || statement.predicateType || null,
      repository:    repo,
      ref:           workflow.ref || predicate?.invocation?.configSource?.digest?.sha1 || null,
      workflowPath:  workflow.path || null,
      builder:       predicate?.runDetails?.builder?.id || predicate?.builder?.id || null,
      subjects:      (statement.subject || []).map((s) => s.name).filter(Boolean),
      subjectDigests: (statement.subject || [])
        .filter((s) => s && s.digest)
        .map((s) => ({ name: s.name || null, digest: { ...s.digest } })),
      certificate:   certIdentity(att.bundle),
      // Kept so the signature can actually be checked rather than assumed.
      envelope,
      certificateDer: vm?.certificate?.rawBytes
        || vm?.x509CertificateChain?.certificates?.[0]?.rawBytes
        || null,
      publicKeyId: (envelope.signatures || []).map((sig) => sig && sig.keyid).find(Boolean) || null,
    });
  }
  return out;
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

/**
 * `sha512-<base64>` → lowercase hex, which is how in-toto writes digests.
 *
 * Strict on purpose. `Buffer.from(x, 'base64')` ignores everything it does not
 * recognise, so a value with trailing junk after a padded digest decoded to
 * exactly 64 bytes and compared equal — an integrity string that npm would
 * never accept could still reach a digest comparison here. An SRI value may
 * also carry several space-separated tokens; rather than silently taking the
 * first, that is refused, because "which one did we compare" should not be a
 * question a reader has to ask.
 */
const BASE64_ONLY = /^[A-Za-z0-9+/]+={0,2}$/;

function integrityToHex(integrity) {
  const raw = String(integrity || '').trim();
  if (!raw || /\s/.test(raw)) return null;              // multiple SRI tokens
  const m = raw.match(/^(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)$/);
  if (!m) return null;
  if (!BASE64_ONLY.test(m[2])) return null;
  const expected = { sha256: 32, sha384: 48, sha512: 64 }[m[1]];
  // A padded base64 digest of N bytes has a known length; anything else is not
  // this digest, whatever it decodes to.
  if (m[2].length !== Math.ceil(expected / 3) * 4) return null;
  let buf;
  try { buf = Buffer.from(m[2], 'base64'); } catch { return null; }
  if (buf.length !== expected) return null;
  return { algorithm: m[1], hex: buf.toString('hex') };
}

/**
 * DSSE Pre-Authentication Encoding (dsse v1):
 *   "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
 *
 * This is what a DSSE signature actually covers. Verifying it is what ties the
 * in-toto statement — and therefore the subject digest we compare against the
 * artifact — to the key that signed it.
 */
function pae(payloadType, payload) {
  const type = Buffer.from(String(payloadType), 'utf8');
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'utf8'), type,
    Buffer.from(` ${body.length} `, 'utf8'), body,
  ]);
}

/**
 * Verify a DSSE envelope's signature against a key we already have.
 *
 * Why this matters, and why its absence was the hole: the registry signs
 * `name@version:integrity` (verifyRegistrySignature above), and the attestation
 * document is served separately. Without checking the envelope, a hostile
 * endpoint could take a *genuine* bundle for some other artifact, replace the
 * subject digest with the integrity value npm signed for ours, keep the
 * original certificate, and every comparison downstream would agree. The
 * signature is now the thing that makes the statement's subject digest mean
 * something.
 *
 * `key` is a KeyObject, or a base64 SPKI DER string, or an X509Certificate.
 * Returns { state: 'ok' | 'fail' | 'unverified', reason }.
 */
function verifyEnvelope(envelope, key) {
  const payload = envelope && envelope.payload;
  const sigs = (envelope && envelope.signatures) || [];
  if (!payload) return { state: 'unverified', reason: 'envelope carries no payload' };
  if (!sigs.length) return { state: 'unverified', reason: 'envelope carries no signature' };
  if (!key) return { state: 'unverified', reason: 'no key to verify against' };

  let publicKey;
  try {
    if (key instanceof crypto.X509Certificate) publicKey = key.publicKey;
    else if (typeof key === 'string') {
      publicKey = crypto.createPublicKey({ key: Buffer.from(key, 'base64'), format: 'der', type: 'spki' });
    } else publicKey = key;
  } catch (e) {
    return { state: 'unverified', reason: `unusable key: ${e.message}` };
  }

  const message = pae(envelope.payloadType || 'application/vnd.in-toto+json', Buffer.from(payload, 'base64'));
  for (const sig of sigs) {
    if (!sig || !sig.sig) continue;
    try {
      if (crypto.verify('sha256', message, publicKey, Buffer.from(sig.sig, 'base64'))) {
        return { state: 'ok', keyid: sig.keyid || null };
      }
    } catch (e) {
      return { state: 'unverified', reason: `could not check the envelope signature: ${e.message}` };
    }
  }
  return { state: 'fail', reason: 'the envelope signature does not verify against this key' };
}

/**
 * What a provenance attestation *establishes* about *this* artifact.
 *
 * Returns { state, issuer, subject_match, repo_match, signature, findings }
 * where state is
 *   'bound'      — **npm's own registry key** signed a statement saying this
 *                  name@version has this digest, that digest is the artifact we
 *                  verified, and a certificate claims the repository the DB
 *                  records built it
 *   'claimed'    — readable and not contradicted, but something in that chain
 *                  is missing: no verifiable signature, no certificate, or no
 *                  digest to compare
 *   'mismatch'   — it describes a different repository or different bytes, or
 *                  a signature did not verify
 *   'unreadable' — there is an attestation but no statement could be read
 *
 * Three holes closed here after review, all the same shape — a comparison that
 * looked like a proof and was not:
 *
 *   1. **The statement was never tied to a key.** The subject digest was read
 *      out of an unauthenticated document. A hostile endpoint could take a
 *      genuine bundle for another artifact, replace its subject digest with the
 *      integrity value npm signed for ours, keep the original certificate, and
 *      every comparison downstream agreed. Now the DSSE envelope must verify:
 *      against npm's published registry key for the publish attestation (the
 *      same trust root as `dist.signatures`), or against the embedded
 *      certificate for the SLSA one.
 *   2. **`bound` did not require a certificate.** Without one the code fell
 *      back to the statement's *self-reported* repository — a field the
 *      publisher writes — and called a match "bound".
 *   3. **The builder check was a substring.** `https://evil/actions/runner/x`
 *      passed as GitHub Actions. It is anchored now.
 *
 * What is still NOT established, and is stated rather than implied:
 *
 *   - The certificate chain is not validated against Fulcio's root, and the
 *     Rekor inclusion proof is not checked. So a certificate in a bundle proves
 *     only that *someone holding its key* signed the statement — anybody can
 *     mint a certificate with any SAN in it. That is why the **digest** half of
 *     `bound` requires npm's registry key (which an attacker cannot supply)
 *     while the **identity** half remains a claim about a repository, and why
 *     the word "verified" never appears next to provenance in the output.
 *   - Consequently a package whose bundle carries only a certificate-signed
 *     statement reaches `claimed`, with the reason given. In practice npm
 *     publishes both attestations, so this costs nothing for real packages and
 *     refuses a forged document that carries only the forgeable half.
 */
function checkProvenance({
  claim, sourceUrl = null, name = null, version = null, integrity = null,
  keys = null, normalizeRepo = (u) => u,
} = {}) {
  if (!claim) return { state: 'unreadable', findings: ['attestation present but no in-toto statement could be read'] };

  const findings = [];
  const storedRepo = sourceUrl ? String(normalizeRepo(sourceUrl) || '').toLowerCase() : null;
  const records = Array.isArray(claim.records) && claim.records.length
    ? claim.records
    // A caller holding only the flat legacy shape: usable for a claim, never
    // for a binding, because there is no envelope to verify.
    : [{ ...claim, envelope: null, certificateDer: null }];

  // ── verify what can be verified ──
  const verified = [];
  let anyFailure = null;
  for (const rec of records) {
    let result = { state: 'unverified', reason: 'no key available for this attestation' };
    if (rec.envelope && rec.certificateDer) {
      try {
        result = verifyEnvelope(rec.envelope, new crypto.X509Certificate(Buffer.from(rec.certificateDer, 'base64')));
        if (result.state === 'ok') result.trust = 'certificate (chain not validated)';
      } catch (e) {
        result = { state: 'unverified', reason: `certificate unusable: ${e.message}` };
      }
    } else if (rec.envelope && rec.publicKeyId && keys) {
      const key = ((keys && keys.keys) || []).find((k) => k.keyid === rec.publicKeyId);
      result = key
        ? verifyEnvelope(rec.envelope, key.key)
        : { state: 'unverified', reason: `no published key matches ${rec.publicKeyId}` };
      if (result.state === 'ok') result.trust = 'npm registry key';
    }
    rec._signature = result;
    if (result.state === 'ok') verified.push(rec);
    if (result.state === 'fail') anyFailure = { rec, result };
  }

  if (anyFailure) {
    findings.push(`the signature over the ${anyFailure.rec.predicateType || 'attestation'} statement does not verify`);
  }

  // ── which bytes: only from a statement whose signature checked out ──
  const want = integrityToHex(integrity);
  const purl = purlFor('npm', name, version);
  let subjectMatch = 'unknown';
  let subjectSource = null;
  if (!want) {
    findings.push('no usable integrity value to compare the attestation subject against');
  } else {
    const digestsOf = (pool) => pool.flatMap((rec) => (rec.subjectDigests || []).map((sd) => ({ rec, sd })));
    const matches = (entry) => String(entry.sd.digest?.[want.algorithm] || '').toLowerCase() === want.hex;
    const signedHit = digestsOf(verified).find(matches);
    const anyHit    = signedHit || digestsOf(records).find(matches);

    if (signedHit) {
      // Which key signed it decides what the match is worth. npm's registry
      // key is the one trust root here that an attacker cannot supply: the
      // certificate in a bundle is *unvalidated* (no Fulcio chain, no Rekor
      // proof), so anybody can mint one with any identity in it and sign a
      // statement about any bytes. A digest confirmed only that way is a claim.
      subjectSource = signedHit.rec._signature.trust || 'signature verified';
      subjectMatch = subjectSource === 'npm registry key' ? 'ok' : 'self-signed';
      if (subjectMatch === 'self-signed') {
        findings.push('the subject digest was confirmed only against the bundle\'s own certificate, which is not validated against a trust root');
      }
      if (purl && signedHit.sd.name && signedHit.sd.name !== purl) {
        findings.push(`attestation subject is named ${signedHit.sd.name}, expected ${purl}`);
      }
    } else if (anyHit) {
      // The digest matches, but nothing authenticated the document it came
      // from. That is a claim, not a binding, and must not read as one.
      subjectMatch = 'unsigned';
      findings.push('the subject digest matches, but no signature over that statement could be verified');
    } else {
      const seen = records.flatMap((rec) => (rec.subjectDigests || []).map((sd) => sd.name || '(unnamed)'));
      subjectMatch = 'mismatch';
      findings.push(`no attestation subject matches this artifact's ${want.algorithm}`
        + `${seen.length ? ` (subjects: ${seen.join(', ')})` : ' (no subject digest published)'}`);
    }
  }

  // ── which repository: the certificate's SAN, which is what an identity token
  //    was issued for, rather than the statement's own prose ──
  const certRec = records.find((rec) => rec.certificate && !rec.certificate.error && rec.certificate.repository);
  const cert = certRec ? certRec.certificate : null;
  let repoMatch = 'unknown';
  if (storedRepo && cert) {
    const certRepo = String(normalizeRepo(cert.repository) || '').toLowerCase();
    repoMatch = certRepo === storedRepo ? 'ok' : 'mismatch';
    if (repoMatch === 'mismatch') findings.push(`the signing identity belongs to ${cert.repository}, not to ${sourceUrl}`);
  } else if (storedRepo) {
    const claimed = records.map((rec) => rec.repository).find(Boolean);
    if (claimed) {
      const norm = String(normalizeRepo(claimed) || '').toLowerCase();
      repoMatch = norm === storedRepo ? 'self-reported' : 'mismatch';
      if (repoMatch === 'mismatch') findings.push(`provenance names ${claimed}, not ${sourceUrl}`);
      else findings.push('the repository is self-reported: no signing certificate was published with this attestation');
    }
  }
  for (const rec of records) if (rec.certificate && rec.certificate.error) findings.push(rec.certificate.error);

  // ── who built it. Anchored: a substring match accepted
  //    `https://evil/actions/runner/x` as GitHub Actions. ──
  const builder = records.map((rec) => rec.builder).find(Boolean) || null;
  const builderIsGha = /^https:\/\/github\.com\/actions\/runner\//.test(String(builder || ''));
  const identityIsGha = Boolean(cert && /^https:\/\/github\.com\//.test(String(cert.identity || '')));
  const issuer = (builderIsGha || identityIsGha) ? 'github-actions' : 'unknown';
  if (issuer !== 'github-actions') findings.push(`builder is not a GitHub Actions runner (${builder || 'builder id absent'})`);

  let state;
  if (repoMatch === 'mismatch' || subjectMatch === 'mismatch' || anyFailure) state = 'mismatch';
  else if (subjectMatch === 'ok' && repoMatch === 'ok' && issuer === 'github-actions') state = 'bound';
  else state = 'claimed';

  return {
    state,
    issuer,
    subject_match: subjectMatch,
    subject_verified_by: subjectSource,
    repo_match:    repoMatch,
    signature:     records.map((rec) => ({
      predicateType: rec.predicateType,
      state:  rec._signature ? rec._signature.state : 'unverified',
      trust:  rec._signature ? (rec._signature.trust || null) : null,
      reason: rec._signature ? (rec._signature.reason || null) : null,
    })),
    repository: (cert && cert.repository) || records.map((rec) => rec.repository).find(Boolean) || null,
    identity:   cert ? cert.identity : null,
    workflow:   (cert && cert.workflowPath) || records.map((rec) => rec.workflowPath).find(Boolean) || null,
    findings,
  };
}


module.exports = {
  signatureMessage, verifyRegistrySignature, provenanceClaim, keysUrl,
  certIdentity, checkProvenance, purlFor, integrityToHex, attestationRecords,
  verifyEnvelope, pae,
};
