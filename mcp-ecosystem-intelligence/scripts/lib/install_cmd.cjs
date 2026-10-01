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
 *   parseLaunch(cmd | {command,args}) -> { ecosystem, package, version, exact, bin, … } | null
 *   canonicalInstallCmd(launch)       -> "npx -y pkg@1.2.3 …" | null
 *   launcherOf(command, args)         -> { family, runner, rest } | null
 *   npmPkgName(cmd)         -> "@scope/pkg" | null
 *   pypiPkgName(cmd)        -> "pkg" | null
 *   dockerImageRef(cmd)     -> "ghcr.io/o/r@sha256:…" | null
 *   dockerDigestPinned(ref) -> boolean
 *   ociIntegrity(digest)    -> "sha256-<hex>" | null   (either spelling in)
 *   dockerIntegrityMismatch(tool) -> null | "why install_cmd and pkg_integrity disagree"
 *   isExactVersion(runner, version) -> boolean
 */

// ── npm / PyPI launch commands, read the way the runner reads them ─────────
//
// Real configs do not look like the DB's `npx -y pkg`. Seen in public
// `.mcp.json` / `.vscode/mcp.json` files: `npx --yes pkg`, `npx -y -p
// @example/tool-mcp@^14 tool-mcp-start`, `pnpx chrome-devtools-mcp@latest`, `npx
// playwright run-test-mcp-server`. A regex anchored on `npx -y <pkg>` called
// all of those "unknown install method" — the servers were in the config and
// nobody checked them.
//
// So the argument list is walked like npm's own option parser walks it:
// options are skipped with their values, `--` ends them, `-p/--package` names
// the package(s) and the first positional is then the binary, otherwise the
// first positional is the package. Still conservative where it matters: an
// option we do not know might take a value, and then we cannot tell the
// package from that value (`npx -y --cache /tmp/x pkg` once read as the
// package "--cache"), so an unknown option is "cannot parse", never a guess.
// Options that change *what* is fetched (`--registry`, an index URL, `-c`)
// are refused with a reason: the artifact the gate would check is not the
// one that runs.

// npm exec / npx (npm ≥ 7) options. Value-taking ones consume the next token.
const NPX_VALUE_FLAGS = new Set([
  '-p', '--package', '--cache', '--userconfig', '--globalconfig', '--prefix',
  '--loglevel', '--node-options', '-w', '--workspace', '--script-shell',
  '--shell', '--include', '--omit', '--before', '--location', '--color',
]);
const NPX_BOOL_FLAGS = new Set([
  '-y', '--yes', '--no-yes', '--no', '-q', '--quiet', '-s', '--silent', '-d',
  '--verbose', '--prefer-offline', '--prefer-online', '--offline',
  '--ignore-existing', '--no-install', '--legacy-peer-deps', '--ignore-scripts',
  '--no-audit', '--no-fund', '--no-update-notifier', '--ws', '--workspaces',
  '--include-workspace-root', '--foreground-scripts', '--no-color',
]);
// These change the artifact or the command; the gate cannot vouch for either.
const NPX_REFUSED_FLAGS = {
  '--registry': 'installs from another registry (--registry), not the one the gate checks',
  '-c':         'runs a shell string (-c), not a package binary',
  '--call':     'runs a shell string (--call), not a package binary',
};

// The other npm-registry runners: same idea, their own option names.
//   pnpm dlx / pnpx  https://pnpm.io/cli/dlx
//   bunx / bun x     https://bun.sh/docs/cli/bunx
//   yarn dlx (berry) https://yarnpkg.com/cli/dlx
const NPM_RUNNERS = {
  npx:  { value: NPX_VALUE_FLAGS, bool: NPX_BOOL_FLAGS, refused: NPX_REFUSED_FLAGS },
  pnpm: {
    value: new Set(['--package', '--allow-build', '--reporter', '--dir', '-C']),
    bool:  new Set(['--silent', '-s', '--yes', '-y']),
    refused: { '-c': 'runs a shell string (pnpm dlx -c)', '--shell-mode': 'runs a shell string (pnpm dlx --shell-mode)', '--registry': NPX_REFUSED_FLAGS['--registry'] },
  },
  bun: {
    value: new Set(['-p', '--package', '--cwd']),
    bool:  new Set(['--bun', '--silent', '--verbose', '--no-install', '-y', '--yes']),
    refused: { '--registry': NPX_REFUSED_FLAGS['--registry'] },
  },
  yarn: {
    value: new Set(['-p', '--package']),
    bool:  new Set(['-q', '--quiet']),
    refused: {},
  },
};

// A registry package spec: `name`, `@scope/name`, either with `@<range|tag>`.
// Anything else (`github:o/r`, `git+https://…`, `./dir`, `file:…`, a tarball
// URL) is not a registry release.
const NPM_SPEC = /^((?:@[\w.-]+\/)?[\w.-]+)(?:@([^\s@/]+))?$/;

function splitNpmSpec(spec) {
  const m = String(spec || '').match(NPM_SPEC);
  if (!m || m[1].startsWith('-') || m[1].startsWith('.')) return null;
  return { name: m[1], version: m[2] || null };
}

const fail = (error) => ({ ecosystem: null, error });

/**
 * Walk an npm runner's arguments. `argv` excludes the runner itself.
 * -> { ecosystem: 'npm', package, version, packages, bin, args } | { error }
 */
function parseNpmArgs(argv, runner = 'npx') {
  const table = NPM_RUNNERS[runner] || NPM_RUNNERS.npx;
  const packages = [];
  let i = 0;
  for (; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--') { i++; break; }
    if (!t.startsWith('-') || t === '-') break;
    const eq = t.indexOf('=');
    const flag = eq === -1 ? t : t.slice(0, eq);
    if (table.refused[flag]) return fail(table.refused[flag]);
    if (flag === '-p' || flag === '--package') {
      const v = eq === -1 ? argv[++i] : t.slice(eq + 1);
      if (v === undefined) return fail(`${flag} has no value`);
      packages.push(v);
      continue;
    }
    if (table.value.has(flag)) { if (eq === -1) i++; continue; }
    if (table.bool.has(flag)) continue;
    return fail(`unknown ${runner} option ${flag} — cannot tell the package from its value`);
  }
  const positional = argv.slice(i);
  if (!packages.length && !positional.length) return fail('no package named');

  if (packages.length) {
    // `-p pkg bin`: the package is what -p says, the binary is separate.
    // With several -p, the one the binary belongs to is the server; the rest
    // are installed alongside it (and listed in `packages`).
    const specs = packages.map(splitNpmSpec);
    if (specs.some((s) => !s)) return fail(`--package ${packages[specs.findIndex((s) => !s)]} is not a registry package`);
    const bin = positional[0] || null;
    const base = (n) => n.replace(/^@[^/]+\//, '');
    const primary = (bin && specs.find((s) => s.name === bin || base(s.name) === bin)) || specs[0];
    return { ecosystem: 'npm', runner, package: primary.name, version: primary.version, spec: packages[specs.indexOf(primary)], packages: specs, bin, args: positional.slice(1), error: null };
  }
  const spec = splitNpmSpec(positional[0]);
  if (!spec) return fail(`${positional[0]} is not a registry package`);
  return { ecosystem: 'npm', runner, package: spec.name, version: spec.version, spec: positional[0], packages: [spec], bin: null, args: positional.slice(1), error: null };
}

// uvx / `uv tool run` options (https://docs.astral.sh/uv/reference/cli/#uv-tool-run).
const UVX_VALUE_FLAGS = new Set([
  '--python', '-p', '--python-preference', '--directory', '--project', '--env-file',
  '--cache-dir', '--config-file', '--color', '--python-platform',
]);
const UVX_BOOL_FLAGS = new Set([
  '-q', '--quiet', '-v', '--verbose', '--isolated', '--no-cache', '-n', '--offline',
  '--refresh', '--native-tls', '--no-progress', '--no-config', '--no-python-downloads',
  '--no-env-file', '--managed-python', '--no-managed-python',
]);
const UVX_REFUSED_FLAGS = {
  '--with':              'installs extra packages (--with) the gate does not check',
  '--with-editable':     'installs a local editable package (--with-editable)',
  '--with-requirements': 'installs extra requirements (--with-requirements) the gate does not check',
  '--index':             'installs from another index (--index), not PyPI',
  '--index-url':         'installs from another index (--index-url), not PyPI',
  '-i':                  'installs from another index (-i), not PyPI',
  '--default-index':     'installs from another index (--default-index), not PyPI',
  '--extra-index-url':   'adds another index (--extra-index-url) the gate does not check',
  '--find-links':        'installs from --find-links, not PyPI',
  '-f':                  'installs from --find-links, not PyPI',
};
// pipx run (https://pipx.pypa.io/stable/docs/#pipx-run).
const PIPX_VALUE_FLAGS = new Set(['--python']);
const PIPX_BOOL_FLAGS  = new Set(['--no-cache', '--verbose', '-v', '--quiet', '-q', '--system-site-packages', '--path']);
const PIPX_REFUSED_FLAGS = {
  '--index-url': UVX_REFUSED_FLAGS['--index-url'], '-i': UVX_REFUSED_FLAGS['-i'],
  '--pip-args':  'passes pip arguments (--pip-args) the gate cannot read',
  '--editable':  'installs a local editable package', '-e': 'installs a local editable package',
};

// PEP 508 name, optional extras, optional `==version` (or uv's `@version`).
const PYPI_SPEC = /^([A-Za-z0-9](?:[\w.-]*[A-Za-z0-9])?)(\[[\w.,\s-]+\])?(?:(==|@)([\w.!+*-]+)|((?:>=|<=|~=|!=|>|<)[\w.!+*,<>=~-]+))?$/;

function splitPypiSpec(spec) {
  const m = String(spec || '').match(PYPI_SPEC);
  if (!m) return null;
  // `@latest` is uv's spelling of "no pin"; a comparison is a range.
  const version = m[4] || m[5] || null;
  return { name: m[1], extras: m[2] || null, version };
}

/**
 * Walk uvx / pipx run arguments. `argv` excludes the runner (and `run`).
 * -> { ecosystem: 'pypi' | 'git', package, version, bin, args, from } | { error }
 */
function parsePypiArgs(argv, runner = 'uvx') {
  const pipx = runner === 'pipx';
  const valueFlags = pipx ? PIPX_VALUE_FLAGS : UVX_VALUE_FLAGS;
  const boolFlags  = pipx ? PIPX_BOOL_FLAGS : UVX_BOOL_FLAGS;
  const refused    = pipx ? PIPX_REFUSED_FLAGS : UVX_REFUSED_FLAGS;
  const fromFlag   = pipx ? '--spec' : '--from';
  let from = null;
  let i = 0;
  for (; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--') { i++; break; }
    if (!t.startsWith('-') || t === '-') break;
    const eq = t.indexOf('=');
    const flag = eq === -1 ? t : t.slice(0, eq);
    if (refused[flag]) return fail(refused[flag]);
    if (flag === fromFlag) {
      from = eq === -1 ? argv[++i] : t.slice(eq + 1);
      if (from === undefined) return fail(`${flag} has no value`);
      continue;
    }
    if (valueFlags.has(flag)) { if (eq === -1) i++; continue; }
    if (boolFlags.has(flag)) continue;
    return fail(`unknown ${runner} option ${flag} — cannot tell the package from its value`);
  }
  const positional = argv.slice(i);
  if (from !== null) {
    const spec = splitPypiSpec(from);
    // A git URL, a path or a wheel URL: source, not a PyPI release.
    if (!spec) return { ecosystem: 'git', runner, package: null, version: null, source: from, bin: positional[0] || null, args: positional.slice(1), from, error: `${fromFlag} ${from} is a source install — no released artifact to verify` };
    return { ecosystem: 'pypi', runner, package: spec.name, version: spec.version, spec: from, bin: positional[0] || null, args: positional.slice(1), from, error: null };
  }
  if (!positional.length) return fail('no package named');
  const spec = splitPypiSpec(positional[0]);
  if (!spec) return { ecosystem: 'git', runner, package: null, version: null, source: positional[0], bin: null, args: positional.slice(1), from: null, error: `${positional[0]} is not a PyPI requirement — no released artifact to verify` };
  return { ecosystem: 'pypi', runner, package: spec.name, version: spec.version, spec: positional[0], bin: null, args: positional.slice(1), from: null, error: null };
}

/**
 * Which registry launcher an argv is, and the arguments after it.
 *   npx …, npm exec …, npm x …, pnpx …, pnpm dlx …, bunx …, bun x …, yarn dlx …
 *   uvx …, uv tool run …, pipx run …
 * `command` may be a path (`/usr/local/bin/npx`, `npx.cmd`).
 * -> { family: 'npm' | 'pypi', runner, rest } | null
 */
function launcherOf(command, args = []) {
  const cmd = String(command || '').split(/[\\/]/).pop().replace(/\.(cmd|exe|bat|ps1)$/i, '');
  const a = args.map(String);
  if (cmd === 'npx') return { family: 'npm', runner: 'npx', rest: a };
  if (cmd === 'npm' && (a[0] === 'exec' || a[0] === 'x')) return { family: 'npm', runner: 'npx', rest: a.slice(1) };
  if (cmd === 'pnpx') return { family: 'npm', runner: 'pnpm', rest: a };
  if (cmd === 'pnpm' && a[0] === 'dlx') return { family: 'npm', runner: 'pnpm', rest: a.slice(1) };
  if (cmd === 'bunx') return { family: 'npm', runner: 'bun', rest: a };
  if (cmd === 'bun' && a[0] === 'x') return { family: 'npm', runner: 'bun', rest: a.slice(1) };
  if (cmd === 'yarn' && a[0] === 'dlx') return { family: 'npm', runner: 'yarn', rest: a.slice(1) };
  if (cmd === 'uvx') return { family: 'pypi', runner: 'uvx', rest: a };
  if (cmd === 'uv' && a[0] === 'tool' && a[1] === 'run') return { family: 'pypi', runner: 'uvx', rest: a.slice(2) };
  if (cmd === 'pipx' && a[0] === 'run') return { family: 'pypi', runner: 'pipx', rest: a.slice(1) };
  return null;
}

/**
 * Read a launch: what registry package it runs, at what requested version.
 * Accepts an install_cmd string or `{ command, args }` (a host config entry).
 *
 * -> null when it is not a registry launcher at all (docker, node, a binary),
 *    otherwise { ecosystem: 'npm'|'pypi'|'git'|null, runner, launcher, package,
 *    version, exact, bin, args, error }. `version` is what was asked for —
 *    `latest`, `^14.0.0` and a missing one are all "not a pin" (`exact`).
 */
function parseLaunch(input) {
  let command, args;
  if (input && typeof input === 'object') { command = input.command; args = Array.isArray(input.args) ? input.args.map(String) : []; }
  else { const parts = String(input || '').trim().split(/\s+/).filter(Boolean); command = parts[0]; args = parts.slice(1); }
  const l = launcherOf(command, args);
  if (!l) return null;
  const r = l.family === 'npm' ? parseNpmArgs(l.rest, l.runner) : parsePypiArgs(l.rest, l.runner);
  const launcher = String(command).split(/[\\/]/).pop().replace(/\.(cmd|exe|bat|ps1)$/i, '');
  const runnerForExact = l.family === 'npm' ? 'npx' : 'uvx';
  return {
    family: l.family,
    launcher,
    ...r,
    runner: l.runner,
    exact: Boolean(r.package && r.version && isExactVersion(runnerForExact, r.version)),
  };
}

/**
 * The canonical install_cmd for a parsed launch: the shape the DB stores and
 * every consumer reads (`npx -y <spec> …`, `uvx <spec> …`, `uvx --from <spec>
 * <bin> …`). Runner-specific options are dropped — none of the kept ones
 * change which artifact runs; the ones that do were refused above.
 * Returns null for a launch that could not be read.
 */
function canonicalInstallCmd(launch) {
  if (!launch || launch.error || !launch.package) return null;
  if (launch.ecosystem === 'npm') {
    const head = launch.bin
      ? [...launch.packages.map((s) => `-p ${s.name}${s.version ? `@${s.version}` : ''}`), launch.bin]
      : [launch.spec];
    return ['npx', '-y', ...head, ...launch.args].join(' ');
  }
  if (launch.ecosystem === 'pypi') {
    const spec = `${launch.package}${launch.version && !/^[<>=!~]/.test(launch.version) ? (launch.version === 'latest' ? '' : `==${launch.version}`) : ''}`;
    return launch.from
      ? ['uvx', '--from', spec, ...(launch.bin ? [launch.bin] : []), ...launch.args].join(' ')
      : ['uvx', spec, ...launch.args].join(' ');
  }
  return null;
}

// "npx -y @scope/pkg@1.2.3 args" → "@scope/pkg". Any registry runner and any
// option order (see parseLaunch); null when the package cannot be read.
// Scopes may contain dots (npm accepts `@yoda.digital/…`).
function npmPkgName(cmd) {
  const s = String(cmd || '');
  if (!/^npx\s/.test(s)) return null;
  const l = parseLaunch(s);
  return l && l.ecosystem === 'npm' && !l.error ? l.package : null;
}

// "uvx pkg-name==1.2.3 args" → "pkg-name"; also `uvx --from pkg==1 bin`.
// null for a source install (`--from git+…`): no PyPI release to verify.
function pypiPkgName(cmd) {
  const s = String(cmd || '');
  if (!/^uvx\s/.test(s)) return null;
  const l = parseLaunch(s);
  return l && l.ecosystem === 'pypi' && !l.error ? l.package : null;
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

/**
 * A docker entry carries its digest twice: `image@sha256:<hex>` inside
 * install_cmd (the registry's spelling) and `pkg_integrity` (the DB's SRI
 * spelling, `sha256-<hex>`, the same form PyPI entries use). Two spellings of
 * one fact drift apart: the drift refresher used to move pkg_integrity only
 * when it was already in the `sha256-` form, so an entry stored as
 * `sha256:<hex>` kept its old digest while install_cmd moved on.
 *
 * ociIntegrity accepts either spelling and returns the canonical one, or null
 * for anything that is not a sha256 digest.
 */
const OCI_DIGEST_RE = /^sha256[:-]([a-f0-9]{64})$/;
function ociIntegrity(digest) {
  const m = String(digest ?? '').trim().match(OCI_DIGEST_RE);
  return m ? `sha256-${m[1]}` : null;
}

/**
 * Does a docker entry's pkg_integrity say the same thing as its install_cmd?
 * Returns null when it does (or when the entry is not a digest-pinned docker
 * launch, which other checks own), otherwise a sentence saying why not.
 * Non-canonical spelling is a finding too: it is exactly the shape the
 * refresher once skipped.
 */
function dockerIntegrityMismatch(tool) {
  if (!tool || typeof tool.install_cmd !== 'string') return null;
  const ref = dockerImageRef(tool.install_cmd);
  if (!ref || !dockerDigestPinned(ref)) return null;
  const want = ociIntegrity(ref.slice(ref.lastIndexOf('@') + 1));
  const stored = tool.pkg_integrity;
  if (stored == null || stored === '') return `pkg_integrity is empty, install_cmd pins ${want}`;
  const got = ociIntegrity(stored);
  if (!got) return `pkg_integrity "${stored}" is not a sha256 digest`;
  if (got !== want) return `pkg_integrity ${got} does not match the digest install_cmd pins (${want})`;
  if (stored !== want) return `pkg_integrity "${stored}" is not in the canonical form "${want}"`;
  return null;
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
    const l = parseLaunch(raw);
    const why = l && l.error ? l.error : 'no package named';
    return {
      parts, pinned: false,
      reason: `cannot read the package from this ${runner} command (${why}) — the gate cannot check it either`,
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
  parseLaunch,
  launcherOf,
  canonicalInstallCmd,
  splitNpmSpec,
  splitPypiSpec,
  pinInstallCmd,
  isExactVersion,
  EXACT_NPM_VERSION,
  EXACT_PYPI_VERSION,
  npmPkgName,
  pypiPkgName,
  dockerImageRef,
  dockerDigestPinned,
  ociIntegrity,
  dockerIntegrityMismatch,
  DOCKER_VALUE_FLAGS,
  DOCKER_BOOL_FLAGS,
};
