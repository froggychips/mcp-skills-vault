# Contributing

Thanks for looking. The most useful contribution right now is not code.

## What helps most

mcp-vault has no users outside the project yet ([ADOPTION.md](docs/ADOPTION.md)),
so the most valuable thing is a report from a real config:

- **You ran `check` (or the Action) and it was wrong.** A false positive, a
  missed unpinned launch, a launch shape it could not read, a secret format it
  did not catch, a fix line that did not help. Paste the config line (with the
  secret removed) and the output.
- **You ran it and it was right, but noisy.** Which findings did you ignore,
  and why?
- **You stopped using it.** Why. That is the hardest answer to get and the most
  useful one.

Open an [issue](https://github.com/froggychips/mcp-skills-vault/issues). Security
problems go privately — see [SECURITY.md](SECURITY.md).

## Changing a check

The code is CommonJS on Node built-ins only, no build step. The pieces:

| Where | What |
|---|---|
| [`bin/mcp-vault.cjs`](bin/mcp-vault.cjs) | the CLI: command table, DB signature check, pass-through to a script |
| [`scripts/check_configs.cjs`](mcp-ecosystem-intelligence/scripts/check_configs.cjs) | `check` |
| [`scripts/lib/installed.cjs`](mcp-ecosystem-intelligence/scripts/lib/installed.cjs), [`lib/install_cmd.cjs`](mcp-ecosystem-intelligence/scripts/lib/install_cmd.cjs) | reading host configs and launch commands |
| [`scripts/lib/secrets.cjs`](mcp-ecosystem-intelligence/scripts/lib/secrets.cjs), [`lib/lookalike.cjs`](mcp-ecosystem-intelligence/scripts/lib/lookalike.cjs), [`lib/flows.cjs`](mcp-ecosystem-intelligence/scripts/lib/flows.cjs), [`lib/tool_scan.cjs`](mcp-ecosystem-intelligence/scripts/lib/tool_scan.cjs) | the detectors |
| [`scripts/lib/finding.cjs`](mcp-ecosystem-intelligence/scripts/lib/finding.cjs) | findings, `decide()`, the findings@1 document, SARIF |
| [`scripts/lib/policy_rules.cjs`](mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs), [`lib/policy.cjs`](mcp-ecosystem-intelligence/scripts/lib/policy.cjs), [`lib/org_policy.cjs`](mcp-ecosystem-intelligence/scripts/lib/org_policy.cjs) | the one rule table and the policy files |
| [`scripts/verify_integrity.cjs`](mcp-ecosystem-intelligence/scripts/verify_integrity.cjs) | the integrity gate over the DB or over host configs |
| [`scripts/lib/evidence.cjs`](mcp-ecosystem-intelligence/scripts/lib/evidence.cjs), [`lib/tiers.cjs`](mcp-ecosystem-intelligence/scripts/lib/tiers.cjs), [`lib/clock.cjs`](mcp-ecosystem-intelligence/scripts/lib/clock.cjs) | dated evidence, derived trust and tier, `--as-of` |
| [`action.yml`](action.yml), [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml), [`lib/job_summary.cjs`](mcp-ecosystem-intelligence/scripts/lib/job_summary.cjs) | the Action and the hook |

Rules for a change to a check:

1. **A detector produces findings; it does not decide.** Whether a finding
   blocks is a row in `lib/policy_rules.cjs`, evaluated by `decide()`
   ([ADR 0001](docs/adr/0001-findings-and-time.md)). A second place that
   computes an effect is how two commands start disagreeing.
2. **Test the failure path.** The recurring bug in this kind of tool has one
   shape: a check that did not run reported like a check that passed. A test
   that only asserts the happy path would have caught none of the past ones.
   "Could not read" is `unknown` or exit `2`, never clean.
3. **No clock below the entry point.** Time comes in as `asOf`;
   `tests/no_wall_clock.test.cjs` enforces it.
4. **Say what can no longer pass.** The PR description names what the change
   makes fail that passed before — even if the answer is "nothing, this only
   adds a check".
5. **Machine-readable changes are listed** in
   [COMPATIBILITY.md](docs/COMPATIBILITY.md); `tests/compatibility.test.cjs`
   fails when a schema id is written but not listed.
6. **No dependencies.** The supply-chain surface of this tool is Node's.

Running it:

```bash
node --test tests/*.test.cjs                 # offline; includes the docs-vs-data checks
node bin/mcp-vault.cjs check examples/insecure/.mcp.json --as-of 2026-09-30T12:00:00Z
node bin/mcp-vault.cjs verify --offline      # the DB, no network
```

If you touched `.github/`, `node --test tests/ci_manifest.test.cjs` asserts the
CI invariants: no PR code running unjailed on the runner, every action pinned
to a SHA, no `curl | sh`, every job timed out.

## Adding or correcting a DB entry

The DB is a supporting signal ([docs/DATABASE.md](docs/DATABASE.md)); a
correction to an existing entry is as welcome as a new one.

1. `mcp-vault discover --source npm --out /tmp/cands.json` and pick from the
   output (it dedupes against the DB, scores and applies the reject
   heuristics), or write the entry by hand.
2. Append it to `mcp-ecosystem-intelligence/assets/tools_database.json`. When
   editing programmatically, use `lib/db_io.cjs::writeDb()` — it keeps the
   file's `\uXXXX` escape convention (`tests/db_io.test.cjs`).
3. `mcp-vault verify --update --entry <name>` fills `version` and
   `pkg_integrity` from the registry; `mcp-vault verify --entry <name>` must
   then pass.
4. Open a PR with
   [`.github/PULL_REQUEST_TEMPLATE/new-mcp-entry.md`](.github/PULL_REQUEST_TEMPLATE/new-mcp-entry.md).

```jsonc
{
  "name":            "pkg-name",
  "category":        "database",
  "install_cmd":     "npx -y pkg-name@1.2.3",          // pinned to a version / digest
  "source_url":      "https://github.com/owner/repo",
  "version":         "1.2.3",                          // filled by --update
  "pkg_integrity":   "sha512-…",                       // filled by --update
  "license":         "MIT",                            // SPDX; "Unknown" if missing
  "health_score":    60,                               // mcp-vault health …
  "est_tools_count": 10,
  "toolsets":        "--toolsets repos,issues",        // how to reduce the tool count, or null
  "tracked_tag":     "latest",                         // docker only
  "notes":           "One line of context for the reviewer"
}
```

There is no `classification` and nothing you set makes an entry trusted:
`trust` and the tier are **derived** from dated evidence that the checks write
(`verify --record-evidence`, `availability`, `identity`, `eval`, …). An entry
starts as `candidate` and becomes `verified` when its artifact verifies and
its advisories are known and current
([`lib/evidence.cjs`](mcp-ecosystem-intelligence/scripts/lib/evidence.cjs)).

Valid categories today:

```
ai · browser · ci-cd · cms · communication · crm · database · demo · docs ·
filesystem · http · infra · maps · memory · meta · mobile · observability ·
payments · pm · reasoning · search · streaming · testing · utility · vcs ·
web-scraping
```

### What a reviewer looks for

Judgement the scripts deliberately do not make:

- `source_url` matches the registry's `repository.url`; the publisher is who
  the repository says it is; no recent silent ownership transfer.
- Reject: fewer than 10 stars, no commit in a year, archived, a fork, no
  licence or a non-OSI licence without an explanation, an `install_cmd` that
  is not pinned.
- `est_tools_count` from a real smoke (`mcp-vault eval --name <name>
  --sandbox`); `toolsets` filled in for heavy servers.

### Install-Hook Policy

An npm package with `preinstall`, `install`, `postinstall` (runs arbitrary
code during `npx -y`), `prepare`, `prepack`, `prepublish` or `prepublishOnly`
gets a human look before it is accepted: the hash covers the tarball, not what
its install script does. To accept one, read the hook in the published
package and record it in `notes` (`[VERIFIED <date>] hook reviewed: …`).
A project can set its own bar without touching the DB: `installHooks` and
`dependencyHooks` in `.mcp-vault.policy.json` (`fail` / `warn` / `allow`), with
`verify --deps` to see hooks in the dependency tree. PyPI (`uvx`) and Docker
entries have no equivalent install-time execution surface.

## Style and releases

- [Conventional Commits](https://www.conventionalcommits.org): `feat:` → minor,
  `fix:` → patch (before 1.0, `BREAKING CHANGE` bumps the minor). release-please
  reads them, opens a `chore(release)` PR with the changelog, and the merge
  tags and publishes.
- Imperative mood, about *why*; the diff says what.
- The publish job signs the DB (`sign_db.cjs --release` with the
  `MCP_VAULT_SIGNING_KEY` secret) and refuses to publish without it
  ([SECURITY.md → Signed DB](SECURITY.md#signed-db)). A clone has no `.sig` and
  does not need one.

## This repository's CI

`.github/workflows/security-scan.yml`: unit tests and the offline DB smoke
(with SARIF) on every PR and push; on Mondays the evidence refresh (versions,
hashes, `--deep --record-evidence`, availability, identity, posture,
capabilities, upgrade paths), Docker drift and licence drift, each opening a
human-reviewed PR; on Thursdays the discovery inbox; a weekly sandboxed eval of
the whole DB. `mcp-eval-pr.yml` smokes changed entries of a PR (advisory,
base-commit scripts). `action-selftest.yml` runs the Action on the fixtures
after merge. `codeql.yml` runs CodeQL. Everything runs on one self-hosted
machine; PR code runs in a jailed container — see
[SECURITY.md → CI isolation model](SECURITY.md#ci-isolation-model).
