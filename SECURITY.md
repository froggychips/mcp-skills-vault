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

## What `bound` means for provenance

`verify` reports provenance as `bound` when **all** of the following hold:

1. npm's own registry signing key — the same key `dist.signatures` is checked
   against — signed a DSSE statement whose subject digest is the artifact this
   run verified. That signature is checked, not assumed.
2. A signing certificate in the bundle claims the repository the DB records, via
   the SAN identity Fulcio puts there (`https://github.com/<owner>/<repo>/<workflow>@<ref>`).
3. The builder id is a GitHub Actions runner, matched anchored rather than as a
   substring.

What `bound` does **not** mean, and the output never says otherwise:

- **The certificate chain is not validated** against Fulcio's root, and the
  Rekor inclusion proof is not checked. Anyone can mint a certificate with any
  SAN in it, so (2) is a *claim about* a repository rather than proof of one.
  That is exactly why (1) must rest on npm's key: the digest half of the binding
  has to hold even when the identity half is forgeable.
- A statement verified **only** against the bundle's own certificate reaches
  `claimed`, not `bound`, and says why. In practice npm publishes both
  attestations, so this costs nothing for real packages while refusing a forged
  document that carries only the forgeable half.
- Nothing here establishes that the code in the artifact is benign.

Validating the Fulcio chain (with a pinned root) is the obvious next step and is
not done yet.

## Our own releases

`@froggychips/mcp-vault` is published from
[.github/workflows/release.yml](.github/workflows/release.yml), which refuses to
publish without an npm provenance attestation unless the refusal is overridden
explicitly (`allow_unprovenanced`). A tool that argues for provenance should
ship with it.

**Every version published since the billing lock — 0.14.0, 0.14.1, 0.15.1 and
0.15.2 — went out with that override, and therefore has no provenance
attestation. 0.15.0 was never published at all** — its tag and GitHub Release
are public, the publish job refused, and the next release went out instead, so
the registry goes 0.14.1 → 0.15.1 with nothing between them. The reason is worth writing down because it is not a choice:

- npm accepts a provenance bundle only from a **GitHub-hosted** runner
  (`Unsupported GitHub Actions runner environment: "self-hosted"`, HTTP 422).
- Every job in this repository runs on a self-hosted runner, because
  GitHub-hosted runners do not start on this account — the account is locked
  over a failed card authorization, and a hosted job dies with zero steps and
  the annotation *"The job was not started because your account is locked due to
  a billing issue."*

So the two constraints exclude each other, and each of those versions was
published unprovenanced on purpose rather than silently. What is still true for
them: npm's **registry signature** over `name@version:integrity` is present, as
it is for every version, and `npm audit signatures` verifies it. What is absent
is `dist.attestations`, and the registry metadata says so plainly — there is no
version of this package where it is present, and nothing here claims otherwise.

The publish job now runs on `ubuntu-latest` — the fix this section has
prescribed all along, which the job itself had not taken, because a comment
sitting on it argued that a self-hosted runner works since the OIDC token comes
from GitHub. That reasoning is about where the *token* comes from and npm's
check is about where the *build* ran. It cost 0.15.0 a publish.

What that leaves: while the account is locked, the hosted job does not start,
so the job queues and npm gets nothing. That is the intended failure — a stalled
release rather than a quiet one.

**2026-09-24 is what that looks like in practice.** Merging the 0.15.1 release
PR created the tag and the GitHub Release, and the publish job died in three
seconds with no steps at all, carrying the annotation *"The job was not started
because your account is locked due to a billing issue."* 0.15.1 then went out
through the override — `workflow_dispatch` with `allow_unprovenanced=true`,
which routes to the self-hosted runner — and the sequence there is worth
recording exactly, because it is the same one that cost 0.15.0 its publish:

1. `npm publish --provenance` builds the bundle and **signs it first**. The
   statement reaches the sigstore transparency log before npm ever looks at it:
   [logIndex 2931732566](https://search.sigstore.dev/?logIndex=2931732566).
2. npm then rejects the bundle — HTTP 422, *"Unsupported GitHub Actions runner
   environment: self-hosted"*.
3. The fallback publishes the same tarball without provenance.

So there is a public, signed statement about a tarball that is on the registry
without a provenance attestation attached to it. 0.15.2 followed the same three
steps later the same day. The statements, and what each one describes:

| version | sigstore | the tarball it describes |
|---|---|---|
| 0.15.0 | [logIndex 2883447939](https://search.sigstore.dev/?logIndex=2883447939) | never published — not on the registry at all |
| 0.15.1 | [logIndex 2931732566](https://search.sigstore.dev/?logIndex=2931732566) | on the registry, no attestation attached |
| 0.15.2 | [logIndex 2932476094](https://search.sigstore.dev/?logIndex=2932476094) | on the registry, no attestation attached |

None of these is a vulnerability; all three are the kind of loose end that is
worse when it is discovered than when it is written down. Expect one more row
per release for as long as the lock holds — which is the argument for clearing
it rather than for a longer table.

Provenance returns when the billing lock is cleared: the publish job needs no
change, only a hosted runner that starts.

That override runs on the **self-hosted** runner, and has to: a dispatch saying
"publish without provenance" has given up the only thing the hosted runner was
for, and routing it to a hosted runner would mean the documented way out of a
billing lock is the one thing a billing lock stops. The refusal itself is still
npm's to make — the job attempts `--provenance` first either way and falls back
only on npm's own 422.

## Static analysis (CodeQL)

CodeQL runs as **advanced setup** on the self-hosted runner
([.github/workflows/codeql.yml](.github/workflows/codeql.yml)), analysing
`javascript-typescript` and `actions` with the `security-extended` suite on
pushes to master, on pull requests that touch code or workflows, and weekly.

The default setup was **disabled**, not abandoned. It is hard-wired to
GitHub-hosted runners, and this account's hosted minutes are blocked by a
billing lock (see [runner-health.yml](.github/workflows/runner-health.yml)), so
every "CodeQL Setup" run failed before executing a step — a red check that said
nothing about the code. In a repository about supply-chain scanning, a scanner
that cannot run is worse than one that is honestly absent.

The `actions` language is the reason this is worth a runner slot: the CI
problems fixed in this repo recently — a `pull_request_target` trust boundary, a
job running with a token scoped far wider than it needed, unpinned third-party
actions — are precisely what those queries look for, and all of them were found
by a human reading the YAML.

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

### Repository settings this relies on

Two Actions settings matter here, and one of them is a single switch doing two
jobs.

- **Default `GITHUB_TOKEN` permission: read.** Jobs that need to write a branch,
  a tag or a pull request declare it for themselves. Before this, every job in
  every workflow started with write.
- **"Allow GitHub Actions to create and approve pull requests": on.** The name
  is the problem — it is one flag for both. Turning it off to prevent
  self-approval also stops release-please, the weekly hash refresh, the
  discovery inbox, the drift refresh and the eval snapshot from opening their
  PRs, which is most of the automation. It is on, and the protection against a
  bot approving its own work is that no workflow here requests a review — not
  the flag.
- **Fork pull requests require maintainer approval for all external
  contributors.** This is the mitigation for the limitation below, and it is a
  setting rather than code.
- **SHA pinning required for actions.** Enforced by the platform as well as by
  `tests/ci_manifest.test.cjs`.

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
