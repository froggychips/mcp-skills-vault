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

A logic error here makes the entire pinning story worthless. The dangerous
failure mode has a shape: **a check that did not happen must never be
indistinguishable from a check that passed.** Every real instance found so far
was a variant of it — a registry timeout recorded as `SKIP` and not counted, a
wheel-only release where the comparison was skipped and the entry still read
`OK`, an advisory severity that could not be parsed and therefore was not
"hard", a feed outage coalescing into "no advisories".

What the gate does today:
- **Artifact** — the stored pin against the registry's metadata, and with
  `--deep` against the bytes themselves (npm tarball sha512, PyPI sdist sha256,
  OCI manifest sha256, hashed locally)
- **Signature** — npm signs `<name>@<version>:<integrity>` with a published
  ECDSA key; verified on every run, so a response with a swapped
  `dist.integrity` cannot pass
- **Provenance** — the attestation is read and its claimed repository compared
  with `source_url`. Reported as a *claim*: verifying the sigstore bundle
  (Fulcio chain, Rekor inclusion) is not something this tool does
- **Advisories** — four feeds merged, severity taken from the worst any of them
  reported, CVSS vectors scored rather than pattern-matched
- **Dependencies** — with `--deps`, the resolved tree's install scripts and its
  packages against OSV
- **Source binding, install hooks, licence, digest pinning** — as before

Anything the gate could not establish is `UNVERIFIED`: reported, counted, and a
hard failure under `--fail-unverified` (which `--strict` implies, and which
`install` passes). Evidence written back to the DB records *what was checked*,
per dimension, with the date — so "verified" cannot quietly mean "verified
eight months ago, by a run that skipped this part".

Mitigations:
- 535 tests, including the fail-closed paths and the CI manifests themselves
- Smoke job on every PR (`--offline`), network-free, plus a SARIF upload so a
  finding lands on the DB line that caused it
- `--strict` treats WARNs as failures; `--fail-unverified` treats "could not
  check" as one

### Weekly hash refresh PR

`.github/workflows/security-scan.yml`'s `refresh-hashes` job opens a PR every Monday with updated `version` + `pkg_integrity` from live registries. If an attacker can poison the registry during this window AND get the PR merged without review, they win.

Mitigations:
- PR is opened, never auto-merged
- Diff is reviewable per-entry (one JSON field per line in the formatted DB)
- The verify-integrity smoke runs on the refresh PR — it will fail if a refreshed hash diverges from what verify_integrity computes when run a second time
- Reviewer responsibility: skim the diff and look for entries where MORE than the version+hash changed (e.g., `install_cmd` shouldn't move during a refresh)

### Docker drift

`scripts/check_docker_drift.cjs` compares pinned `@sha256:` against the registry digest for `tracked_tag`. The `docker-drift` weekly job fails on any drift. A maintainer reviews the upstream change BEFORE refreshing the pin — a routine rebuild and a registry hijack look identical from here, and the human gate is the differentiator.

## CI isolation model

This project's own CI is part of its attack surface, and for a while it was the
weakest part of it: a supply-chain scanner whose pull-request builds ran
attacker-authored code on a persistent machine.

GitHub-hosted runners do not start on this account (billing lock, documented in
`.github/workflows/runner-health.yml`), so every job runs on one self-hosted
macOS machine. Isolation therefore happens *inside* that machine:

| Input | Where it runs |
|---|---|
| PR-authored code (tests, scripts) | container: `--network none`, repo mounted read-only, `--cap-drop ALL`, `no-new-privileges`, no docker socket |
| PR-authored data (`tools_database.json`) | evaluated by **base-commit** code; every docker launch is rebuilt from its pinned digest, so flags in an entry cannot reach the host |
| Third-party MCP servers | always `mcp_eval --sandbox`; `--unsafe` is not used in CI |
| Our own code (push, cron) | directly on the runner |

Outputs are written under `RUNNER_TEMP`, never to a path inside the checkout: a
redirect performed by the host shell follows whatever that path is, and a PR can
commit a name as a symlink. Mounting the workspace read-only does not prevent
that.

`tests/ci_manifest.test.cjs` asserts these properties against the manifests —
per step, not per job — so a later one-line edit cannot quietly remove them.

### Known limitation

For a `pull_request` event, GitHub uses the workflow file **from the pull
request**. The isolation is therefore described by the thing being isolated, and
a test that greps the manifests is a regression check, not a security boundary.

The mitigation is a repository setting rather than code: workflow runs from fork
pull requests require maintainer approval (Settings → Actions → *Require
approval for all external contributors*). Approve a run only after reading the
diff, including changes to `.github/`.

If GitHub-hosted runners become available on this account, the PR jobs should
move to a disposable VM, and the container jail becomes defence in depth rather
than the boundary.

## What this project is NOT

- Not a sandbox. Installing an MCP server runs whatever the server's `command` does, with whatever permissions Claude Code has. The integrity gate guarantees you ran the artifact you expected; it does not guarantee the artifact is benign.
- Not a CVE database. Advisory feeds (npm bulk, OSV, GHSA, Snyk) are aggregated and surfaced, but the source of truth lives upstream.
- Not a runtime monitor. The scanner runs at install time; runtime behavior of the installed server is out of scope.
