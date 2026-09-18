'use strict';
/**
 * Parsers for the `install_cmd` strings stored in tools_database.json.
 *
 * These used to live as near-identical regexes in verify_integrity.cjs,
 * check_docker_drift.cjs and orchestrate.cjs. Three copies meant three answers
 * for the same command: the gate checked one package, the pinner pinned a
 * different token, and the drift prober read a third. They belong in one place.
 *
 * Every parser here is deliberately conservative. Returning null ("I don't
 * understand this command") is a useful answer in a supply-chain tool: callers
 * surface it as UNVERIFIED and refuse to pin. Guessing is the failure mode —
 * `npx -y --cache /tmp/x pkg` once parsed as the package "--cache", so the gate
 * checked a package that does not exist while the real one went unchecked.
 *
 * API:
 *   npmPkgName(cmd)         -> "@scope/pkg" | null
 *   pypiPkgName(cmd)        -> "pkg" | null
 *   dockerImageRef(cmd)     -> "ghcr.io/o/r@sha256:…" | null
 *   dockerDigestPinned(ref) -> boolean
 *   isExactVersion(runner, version) -> boolean
 */

// "npx -y @scope/pkg@1.2.3 args" → "@scope/pkg"
// Scopes may contain dots (npm accepts `@yoda.digital/…`).
function npmPkgName(cmd) {
  const m = String(cmd).match(/^npx\s+-y\s+((?:@[\w.-]+\/)?[\w.-]+?)(?:@[^\s]+)?(?:\s|$)/);
  // A leading `-` means we matched a flag, not a package. Commands with flags
  // between `-y` and the package name (including `--package`) are not a shape
  // this parser claims to understand.
  if (!m || m[1].startsWith('-')) return null;
  return m[1];
}

// "uvx pkg-name==1.2.3 args" → "pkg-name"; null when --from is used
// (git/URL installs have no PyPI release to verify).
// The version class allows PEP 440 extras (`1.0+local`, `1!2.0`) so a pinned
// command isn't dropped as unparsable.
function pypiPkgName(cmd) {
  const s = String(cmd);
  if (/^uvx\s+--from/.test(s)) return null;
  const m = s.match(/^uvx\s+([\w.-]+?)(?:==[\w.!+-]+)?(?:\s|$)/);
  if (!m || m[1].startsWith('-')) return null;
  return m[1];
}

// docker flags that consume the next token as their value.
const DOCKER_VALUE_FLAGS = new Set([
  '-e', '--env', '--env-file', '-v', '--volume', '--mount', '--tmpfs',
  '-p', '--publish', '--expose', '--name', '--hostname', '-h', '--user', '-u',
  '--network', '--network-alias', '--link', '--add-host', '--dns', '--dns-search',
  '--cap-add', '--cap-drop', '--security-opt', '--device', '--ulimit', '--sysctl',
  '--entrypoint', '--workdir', '-w', '--label', '-l', '--restart', '--pull',
  '--platform', '--log-driver', '--log-opt', '--memory', '-m', '--memory-swap',
  '--cpus', '--cpu-shares', '--pids-limit', '--shm-size', '--gpus', '--ipc',
  '--pid', '--uts', '--userns', '--volumes-from', '--stop-signal', '--stop-timeout',
  '--health-cmd', '--health-interval', '--health-retries', '--health-timeout',
  '--group-add', '--runtime', '--storage-opt', '--tmpfs', '--sig-proxy',
]);

// docker flags that stand alone.
const DOCKER_BOOL_FLAGS = new Set([
  '-i', '-t', '-it', '-ti', '-d', '--interactive', '--tty', '--detach', '--rm',
  '--init', '--read-only', '--privileged', '--no-healthcheck', '-P',
  '--publish-all', '--quiet', '-q', '--disable-content-trust',
]);

/**
 * "docker run ... ghcr.io/foo/bar[@digest|:tag] [args]" → the image reference.
 *
 * Returns null when the command contains a flag we don't know, because we then
 * cannot tell whether the following token is that flag's value or the image:
 * `docker run --pull always ghcr.io/x/y@sha256:…` used to parse as the image
 * "always", and `--strict` then failed a correctly pinned entry.
 */
function dockerImageRef(cmd) {
  const s = String(cmd);
  if (!/^docker\s+run/.test(s)) return null;
  const tokens = s.split(/\s+/).slice(2);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith('-')) {
      if (t.includes('=')) continue;            // --flag=value carries its own value
      if (DOCKER_VALUE_FLAGS.has(t)) { i++; continue; }
      if (DOCKER_BOOL_FLAGS.has(t))  { continue; }
      return null;                              // unknown flag: don't guess
    }
    return t;                                   // first non-flag token is the image
  }
  return null;
}

/**
 * Anchored on purpose: a digest terminates the reference. Unanchored, a
 * reference with trailing junk (`img@sha256:<64hex>oops`) read as "pinned".
 */
function dockerDigestPinned(ref) {
  return /@sha256:[a-f0-9]{64}$/.test(String(ref || ''));
}

// "Exact" has to mean exact. `1`, `1.2` and `1.x` are ranges wearing a pin's
// clothes: they resolve to whatever was published most recently, so a command
// carrying one launches something other than the artifact that was verified.
//   npm:  semver, three components, optional pre-release/build
//   PyPI: PEP 440 release segment, optional pre/post/dev/local
const EXACT_NPM_VERSION  = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
// A local segment is `+` followed by dot-separated alphanumerics, each part
// non-empty: `1.0+.` and `1.0+..` were accepted, and neither is a version.
const EXACT_PYPI_VERSION = /^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$/;

function isExactVersion(runner, version) {
  if (typeof version !== 'string' || !version) return false;
  return runner === 'npx' ? EXACT_NPM_VERSION.test(version) : EXACT_PYPI_VERSION.test(version);
}


// Pin the package token of an install command to the version the DB records —
// and that verify_integrity actually hashed.
//
// Most DB entries store the command unpinned (`npx -y @scope/mcp-server`) with
// the checked version in a separate `version` field. Copying that command into
// .mcp.json verbatim means npx resolves `latest` every time the server starts:
// the artifact that runs is not the artifact whose sha512 the gate compared, so
// a compromised release published after our last refresh installs itself
// silently. Synthesise the pin instead.
//
// Returns { parts, pinned, reason } — `parts` is the argv-style token list.
//
// "Pinned" means: the launch command names the exact version the gate verified.
// A command that already carries *some* specifier is not automatically fine —
// `pkg@latest`, `pkg@^1.2` and a stale `pkg@1.0.0` all launch something other
// than the artifact whose hash was compared, so they get rewritten to the DB's
// version rather than trusted.
function pinInstallCmd(cmd, version) {
  const raw    = String(cmd).trim();
  const parts  = raw.split(/\s+/);
  const runner = parts[0];

  if (runner === 'docker') {
    // The image is the first non-flag token; a digest sitting in some other
    // argument (`-e REF=img@sha256:…`) is not a pin on the image that runs.
    const ref = dockerImageRef(raw);
    if (!ref) return { parts, pinned: false, reason: 'cannot parse the docker image reference' };
    const ok = dockerDigestPinned(ref);
    return { parts, pinned: ok, reason: ok ? null : `docker image ${ref} is not pinned by @sha256 digest` };
  }

  if (runner !== 'npx' && runner !== 'uvx') {
    return { parts, pinned: false, reason: `unknown runner "${runner}" — cannot pin` };
  }

  // Resolve the package with the gate's own parser: a command shaped in a way
  // the gate declines to check (flags before the package, --package, uvx
  // --from/--with) must not be pinnable here either.
  const pkg = runner === 'npx' ? npmPkgName(raw) : pypiPkgName(raw);
  if (!pkg) {
    return {
      parts, pinned: false,
      reason: runner === 'npx'
        ? 'not a plain `npx -y <pkg>` command — the gate cannot check it either'
        : 'not a plain `uvx <pkg>` command (--from / --with / flags) — the gate cannot check it either',
    };
  }

  const sep = runner === 'npx' ? '@' : '==';
  const idx = parts.findIndex((p) => p === pkg || p.startsWith(pkg + sep));
  if (idx === -1) return { parts, pinned: false, reason: 'cannot locate the package token in install_cmd' };

  const current = parts[idx] === pkg ? null : parts[idx].slice(pkg.length + sep.length);

  if (!version) {
    return {
      parts, pinned: false,
      reason: current
        ? `install_cmd asks for "${current}", but the DB entry has no verified \`version\` — run verify_integrity.cjs --update`
        : 'no `version` in the DB entry — run verify_integrity.cjs --update',
    };
  }
  if (!isExactVersion(runner, version)) {
    return {
      parts, pinned: false,
      reason: `DB version "${version}" is not an exact ${runner === 'npx' ? 'semver' : 'PEP 440'} version — a range is not a pin`,
    };
  }
  if (current === version) return { parts, pinned: true, reason: null };

  // Unpinned, or pinned to something the gate did not verify: rewrite it.
  const pinnedParts = [...parts];
  pinnedParts[idx] = `${pkg}${sep}${version}`;
  return { parts: pinnedParts, pinned: true, reason: null };
}


module.exports = {
  pinInstallCmd,
  isExactVersion,
  EXACT_NPM_VERSION,
  EXACT_PYPI_VERSION,
  npmPkgName,
  pypiPkgName,
  dockerImageRef,
  dockerDigestPinned,
  DOCKER_VALUE_FLAGS,
  DOCKER_BOOL_FLAGS,
};
