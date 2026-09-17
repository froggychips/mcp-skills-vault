'use strict';
/**
 * Typed artifact + launch model for a DB entry.
 *
 * `install_cmd` is one string doing five jobs at once: display text, package
 * locator, execution spec, version source, and ecosystem discriminator. Every
 * subsystem re-parsed it — the gate, the eval, the audit, both drift checks,
 * discovery, the orchestrator — and the copies disagreed about which token was
 * the package. Centralising the parser (lib/install_cmd.cjs) removed the
 * disagreement; it did not remove the reason the disagreement was possible.
 *
 * The typed form separates what the entry *is* from how it is *run*:
 *
 *   artifact: what is being verified
 *     { ecosystem: 'npm',  package: '@scope/pkg', version: '1.2.3', integrity: 'sha512-…' }
 *     { ecosystem: 'pypi', package: 'pkg',        version: '1.2.3', integrity: 'sha256-…' }
 *     { ecosystem: 'oci',  image: 'ghcr.io/o/r',  digest: 'sha256:…' }
 *     { ecosystem: 'git',  source: 'git+https://…' }          — not verifiable
 *
 *   launch: how it starts
 *     { command: 'npx', args: ['-y', '@scope/pkg@1.2.3'] }
 *
 * Direction of truth is deliberate: the typed record is the source, and
 * `renderInstallCommand()` produces the string. Until every consumer reads the
 * typed form, `install_cmd` stays in the DB and a test asserts the two agree —
 * a migration that can be verified at every step rather than a rewrite.
 *
 * API:
 *   toTypedEntry(tool)            -> { artifact, launch, warnings } | null
 *   renderInstallCommand(typed)   -> string | null
 *   validateEntry(tool)           -> { ok, errors, typed }
 *   artifactId(artifact)          -> 'npm:@scope/pkg@1.2.3' | 'oci:ghcr.io/o/r@sha256:…'
 */

const { npmPkgName, pypiPkgName, dockerImageRef, dockerDigestPinned } = require('./install_cmd.cjs');

/**
 * Derive the typed form from an entry's existing fields.
 *
 * `warnings` carries what could not be derived, rather than throwing: the DB
 * legitimately contains entries with no verifiable artifact (a git source
 * install), and the caller decides what that means.
 */
function toTypedEntry(tool) {
  if (!tool || typeof tool.install_cmd !== 'string') return null;
  const cmd = tool.install_cmd.trim();
  const parts = cmd.split(/\s+/);
  const warnings = [];

  // ── OCI ──
  if (/^docker\s+run/.test(cmd)) {
    const ref = dockerImageRef(cmd);
    if (!ref) {
      warnings.push('docker launch command could not be parsed');
      return { artifact: { ecosystem: 'oci' }, launch: { command: 'docker', args: parts.slice(1) }, warnings };
    }
    const at = ref.indexOf('@sha256:');
    const image  = at === -1 ? ref.replace(/:[^:/]+$/, '') : ref.slice(0, at);
    const digest = at === -1 ? null : ref.slice(at + 1);
    const tag    = at === -1 && /:[^:/]+$/.test(ref) ? ref.slice(ref.lastIndexOf(':') + 1) : null;
    if (!digest) warnings.push('image is referenced by tag, not by digest');
    return {
      artifact: { ecosystem: 'oci', image, digest, tag, integrity: tool.pkg_integrity ?? null },
      launch:   { command: 'docker', args: parts.slice(1) },
      warnings,
    };
  }

  // ── git / URL source install (uvx --from, and anything else unparsable) ──
  if (/^uvx\s+--from/.test(cmd)) {
    const src = parts[parts.indexOf('--from') + 1] || null;
    warnings.push('source install: no released artifact to verify');
    return {
      artifact: { ecosystem: 'git', source: src },
      launch:   { command: 'uvx', args: parts.slice(1) },
      warnings,
    };
  }

  // ── npm / PyPI ──
  const isNpm = /^npx\s/.test(cmd);
  const pkg = isNpm ? npmPkgName(cmd) : pypiPkgName(cmd);
  if (!pkg) {
    warnings.push(`launch command is not a shape this model understands: ${cmd.slice(0, 60)}`);
    return {
      artifact: { ecosystem: isNpm ? 'npm' : (/^uvx\s/.test(cmd) ? 'pypi' : 'unknown') },
      launch:   { command: parts[0], args: parts.slice(1) },
      warnings,
    };
  }

  const sep = isNpm ? '@' : '==';
  const token = parts.find((t) => t === pkg || t.startsWith(pkg + sep));
  const inCmd = token && token !== pkg ? token.slice(pkg.length + sep.length) : null;
  // The DB's `version` field is the verified one; a version inside the command
  // that disagrees with it is a finding, not a fact.
  if (inCmd && tool.version && inCmd !== tool.version) {
    warnings.push(`launch command asks for ${inCmd} but the verified version is ${tool.version}`);
  }
  if (!inCmd && !tool.version) warnings.push('no version anywhere: neither in the launch command nor in the entry');

  return {
    artifact: {
      ecosystem: isNpm ? 'npm' : 'pypi',
      package:   pkg,
      version:   tool.version ?? inCmd ?? null,
      integrity: tool.pkg_integrity ?? null,
    },
    launch: { command: parts[0], args: parts.slice(1) },
    warnings,
  };
}

/** The launch command a typed record describes. */
function renderInstallCommand(typed) {
  if (!typed || !typed.launch || typeof typed.launch.command !== 'string') return null;
  const { command, args } = typed.launch;
  return [command, ...(args || [])].join(' ');
}

/**
 * A stable identity for an artifact, for cross-referencing evidence.
 * Deliberately includes the version: evidence about 1.2.3 says nothing about
 * 1.2.4.
 */
function artifactId(artifact) {
  if (!artifact) return null;
  switch (artifact.ecosystem) {
    case 'npm':
    case 'pypi':
      return artifact.package ? `${artifact.ecosystem}:${artifact.package}${artifact.version ? `@${artifact.version}` : ''}` : null;
    case 'oci':
      return artifact.image ? `oci:${artifact.image}${artifact.digest ? `@${artifact.digest}` : (artifact.tag ? `:${artifact.tag}` : '')}` : null;
    case 'git':
      return artifact.source ? `git:${artifact.source}` : null;
    default:
      return null;
  }
}

/**
 * Check an entry against its typed form.
 *
 * The invariant that makes the migration safe: rendering the typed record must
 * reproduce `install_cmd` exactly. If it doesn't, one of the two is wrong and
 * the entry needs a human, not a silent coercion.
 */
function validateEntry(tool) {
  const errors = [];
  const typed = toTypedEntry(tool);
  if (!typed) return { ok: false, errors: ['entry has no install_cmd'], typed: null };

  const rendered = renderInstallCommand(typed);
  const original = String(tool.install_cmd).trim().replace(/\s+/g, ' ');
  if (rendered !== original) {
    errors.push(`rendering the typed form does not reproduce install_cmd:\n  stored:   ${original}\n  rendered: ${rendered}`);
  }

  const a = typed.artifact;
  if (a.ecosystem === 'npm' || a.ecosystem === 'pypi') {
    if (!a.package) errors.push('no package name could be derived');
    if (a.integrity && !/^sha(256|384|512)-/.test(a.integrity)) errors.push(`integrity "${a.integrity}" has no recognised algorithm prefix`);
  }
  if (a.ecosystem === 'oci') {
    if (!a.image) errors.push('no image could be derived');
    if (a.digest && !dockerDigestPinned(`${a.image}@${a.digest}`)) errors.push(`digest "${a.digest}" is not a sha256 digest`);
  }

  return { ok: errors.length === 0, errors, typed };
}

module.exports = { toTypedEntry, renderInstallCommand, validateEntry, artifactId };
