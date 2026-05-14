# Security Policy

## Supported Versions

| Component | Supported |
|---|---|
| `tools_database.json` (current) | ✅ |
| `scripts/verify_integrity.cjs` (current) | ✅ |
| `scripts/orchestrate.cjs` (current) | ✅ |
| `scripts/refresh_scores.cjs` (current) | ✅ |
| `scripts/check_docker_drift.cjs` (current) | ✅ |
| Pinned `version` entries in DB | ✅ integrity-gated |

Older commits are not patched — update to `HEAD` of `master`.

## Reporting a Vulnerability

Please report privately — do **not** open a public GitHub issue for security matters.

- **Telegram:** [@froggychips](https://t.me/froggychips)
- **Email:** big@froggychips.xyz

Include: reproduction steps, what you expected vs. what happened, and the SHA of the commit you're testing against.

## Threat Model

### In scope

- A malicious or compromised entry in `tools_database.json` that causes `orchestrate.cjs --install` to write a tampered command into a project's `.mcp.json`
- A bypass or logic error in `verify_integrity.cjs` that lets a hash-mismatched package pass the gate
- A script vulnerability in `orchestrate.cjs` (e.g. shell injection via a crafted `install_cmd` field) that gains local code execution
- A compromised weekly CI PR that silently ships a poisoned hash refresh without triggering reviewer attention

### Out of scope

- Vulnerabilities in the MCP servers themselves (report to their respective maintainers)
- A locally malicious user who can already write to `tools_database.json` directly
- Supply-chain attacks on npm/PyPI after the pinned hash passes — the hash pins a specific release artifact; it does not audit the code inside
- GitHub Actions runner compromise (mitigated by `self-hosted` + human PR gate)

## Sensitive Attack Surfaces

### `tools_database.json` — the trust anchor

Every `--install` command is derived from the `install_cmd` field. A tampered entry could write an arbitrary shell command into a project's `.mcp.json`.

Mitigations in place:
- All entries carry a pinned `version` and a `pkg_integrity` hash (npm sha512 / PyPI sha256 / Docker digest)
- `verify_integrity.cjs` re-fetches the live hash from the registry and compares before writing
- The weekly CI PR is the **only** automated path to modify this file; it requires human review before merge

Residual risk: a compromised npm/PyPI release that publishes under the same version number would pass — npm and PyPI version immutability is not guaranteed for all packages.

### `verify_integrity.cjs` — the integrity gate

A logic error here is the most critical failure mode. If the gate can be bypassed, a hash-mismatched package reaches a user's `.mcp.json`.

Review checklist when modifying this file:
- Hash comparison must be constant-time or at minimum use `===` on the full string
- `--no-audit` must skip CVE checks only — the hash check must always run
- Error paths must exit non-zero; a silent failure that returns 0 is equivalent to a bypass

### `orchestrate.cjs --install` — writes `.mcp.json`

The `buildServerEntry` function parses `install_cmd` into `{command, args}`. If `install_cmd` contains shell metacharacters and is ever passed through a shell (e.g. `exec shell: true`), it could enable injection.

Current implementation: uses `spawnSync` with an explicit args array — no shell interpolation. Any future refactor that uses `shell: true` or template-string construction of the command array must be reviewed carefully.

### Weekly CI PR — the human gate

`refresh-hashes` job runs `verify_integrity.cjs --update` + `refresh_scores.cjs --write`, then opens a PR via `peter-evans/create-pull-request`. This is the **only** automated mutation of `tools_database.json`.

Risk surface: a compromised GitHub Actions token or a misconfigured workflow could auto-merge. The branch protection rule requiring human review is the control; removing it would be a security regression.

### Docker `@sha256` drift

Docker entries pin the image by digest (`image@sha256:…`). The digest is immutable in the registry, so the pin itself cannot be bypassed by an upstream rebuild. But the pin can become **stale** — the maintainer rebuilds the same tag (e.g. `:latest`) under a new digest, leaving us pointing at an older version that may be missing a security fix.

`scripts/check_docker_drift.cjs` follows the OCI Distribution Spec (anonymous bearer auth) to fetch the current digest for the tracked tag (default `latest`, overridable via `tracked_tag` in the entry) and reports drift. The weekly CI job fails on any drift so a maintainer reviews the upstream change before refreshing the DB.

Drift is not, by itself, a hijack signal — it most often means a routine rebuild. But it **could** be a hijack of the registry namespace; do not auto-refresh the pin without checking the upstream repo's release notes / commit signing.

### `--no-audit` mode

Passes `--no-audit` to skip the CVE advisory check (OSV.dev / npm advisory API). Legitimate use: offline/air-gapped environments. Misuse: masking a known-CVE package from being flagged.

The hash check still runs in `--no-audit` mode. This flag only skips the advisory API call.

### `.env` scanning — key names only

`orchestrate.cjs` reads `.env*` files to detect infrastructure signals. It reads **key names only** — values are never captured, printed, or stored. Regex: `/^([A-Z0-9_]+)=/`.

Verify this invariant if the stack-detection code is modified.

## Privacy Notes

- No telemetry is collected. All processing is local.
- `~/.claude.json` values are never read by any script in this repo. MCP config inspection uses `jq '.mcpServers | keys'` — never `cat` of the whole file.
- `.env` scanning: key names only. Value leakage would be a security regression.

## Known Limitations

- **Hash ≠ code audit.** `trust: "verified"` in the DB means the listed hash matched the registry at the time of last refresh. It does not mean the code has been reviewed for malicious behaviour.
- **Pinned version drift.** The weekly refresh updates hashes to the latest version. A new version that introduces malicious code will pass the hash check (the hash will match the new release). This is why the weekly PR requires human review of every version bump.
- **git-URL installs are not supported.** `orchestrate.cjs --install` only handles entries in `tools_database.json`. Installing from an arbitrary git URL has no integrity gate and is explicitly unsupported.

## Response SLA

| Severity | Example | Target response |
|---|---|---|
| Critical | Hash bypass / script injection → RCE | Patch within 48 h |
| High | CVE entry missing / not flagged | Patch within 7 days |
| Medium | Hash mismatch not caught in edge case | Patch within 14 days |
| Low | Docs / UX issues | Best effort |
