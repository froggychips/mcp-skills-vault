# Security Policy

## Supported Versions

| Component | Supported |
|---|---|
| `tools_database.json` (current) | ✅ |
| `scripts/verify_integrity.cjs` (current) | ✅ |
| `scripts/orchestrate.cjs` (current) | ✅ |
| `scripts/refresh_scores.cjs` (current) | ✅ |
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
- `verify_integrity.cjs` has two gates: `--offline` validates stored pins without network; default / `--no-audit` re-fetches live registry metadata before writing
- The weekly CI PR is the **only** automated path to modify this file; it requires human review before merge

Residual risk: a compromised npm/PyPI release that publishes under the same version number would pass — npm and PyPI version immutability is not guaranteed for all packages.

### `verify_integrity.cjs` — the integrity gate

A logic error here makes the entire pinning story worthless. Specifically dangerous failure modes:
- Comparing hash with `==` against a non-string (coerces away difference)
- Returning early on a parse error instead of failing
- Falling back to a "warning" when the registry is unreachable

Mitigations:
- Unit tests in `tests/verify_integrity.test.cjs` cover the parser, advisory dedup, and gate logic
- Smoke job runs on every PR (`--offline` mode), fast and network-free — would catch a regression that breaks the local gate
- `--strict` mode treats WARNs as failures and is what CI uses

### Weekly hash refresh PR

`.github/workflows/security-scan.yml`'s `refresh-hashes` job opens a PR every Monday with updated `version` + `pkg_integrity` from live registries. If an attacker can poison the registry during this window AND get the PR merged without review, they win.

Mitigations:
- PR is opened, never auto-merged
- Diff is reviewable per-entry (one JSON field per line in the formatted DB)
- The verify-integrity smoke runs on the refresh PR — it will fail if a refreshed hash diverges from what verify_integrity computes when run a second time
- Reviewer responsibility: skim the diff and look for entries where MORE than the version+hash changed (e.g., `install_cmd` shouldn't move during a refresh)

### Docker drift

`scripts/check_docker_drift.cjs` compares pinned `@sha256:` against the registry digest for `tracked_tag`. The `docker-drift` weekly job fails on any drift. A maintainer reviews the upstream change BEFORE refreshing the pin — a routine rebuild and a registry hijack look identical from here, and the human gate is the differentiator.

## What this project is NOT

- Not a sandbox. Installing an MCP server runs whatever the server's `command` does, with whatever permissions Claude Code has. The integrity gate guarantees you ran the artifact you expected; it does not guarantee the artifact is benign.
- Not a CVE database. Advisory feeds (npm bulk, OSV, GHSA, Snyk) are aggregated and surfaced, but the source of truth lives upstream.
- Not a runtime monitor. The scanner runs at install time; runtime behavior of the installed server is out of scope.
