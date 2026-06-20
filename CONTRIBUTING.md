# Contributing

Thanks for considering a contribution. This file covers the two things that come up most: **adding an entry to `tools_database.json`** and **promoting an entry from `trust: candidate` to `trust: verified`**.

For security-sensitive changes (scripts in `mcp-ecosystem-intelligence/scripts/`, anything touching the integrity gate), read [SECURITY.md](./SECURITY.md) first — that file is the source of truth for what counts as a regression.

---

## Adding a new MCP server to the database

### Quick path

1. Run `mcp-vault discover --source npm --out /tmp/cands.json` and pick from the output. The script handles dedup against the DB, health scoring, and reject heuristics.
2. Append the chosen entry to `mcp-ecosystem-intelligence/assets/tools_database.json` with `trust: "candidate"` (see schema below).
3. Run `mcp-vault verify --update` — fills `version` + `pkg_integrity` from the live registry.
4. Run `mcp-vault verify --no-audit` — must exit 0.
5. Open a PR using the template at `.github/PULL_REQUEST_TEMPLATE/new-mcp-entry.md`.

### Entry schema

```jsonc
{
  "name":            "pkg-name",                       // npm / PyPI / docker image basename
  "category":        "database",                       // see list below
  "install_cmd":     "npx -y pkg-name@1.2.3",          // ALWAYS pinned to a version / digest
  "source_url":      "https://github.com/owner/repo",  // canonical repo
  "version":         "1.2.3",                          // filled by --update
  "pkg_integrity":   "sha512-…",                       // filled by --update
  "trust":           "candidate",                      // start here; see promotion below
  "license":         "MIT",                            // SPDX identifier; "Unknown" if missing
  "health_score":    105.0,                            // from calculate_health.cjs
  "classification":  "Core",                           // Core / Recommended / Experimental / Deprecated
  "est_tools_count": 10,                               // count from server's ListToolsRequestSchema
  "toolsets":        "--toolsets repos,issues",        // how to reduce tool count, or null
  "tracked_tag":     "latest",                         // docker only; default "latest"
  "notes":           "One-line context for the reviewer"
}
```

### Valid `category` values

Current taxonomy in the DB (will grow):

```
ai · browser · ci-cd · cms · communication · crm · database · demo · docs ·
filesystem · http · infra · maps · memory · meta · mobile · observability ·
payments · pm · reasoning · search · testing · utility · vcs · web-scraping
```

`utility` is the catch-all — use a more specific category if one fits. Inventing a new category is fine if existing options genuinely don't fit; add it in the PR description so reviewers know it's intentional.

### Reject criteria (the entry will not be merged)

- `health_score < 40` (Deprecated tier) — unless there's a *very* good reason in the PR description
- `<10` GitHub stars
- `last_commit_days > 365`
- Archived or fork of another repo
- No license, or a non-OSI / source-available license, **and** the PR doesn't explain why
- Install hook (`preinstall`, `install`, `postinstall`, `prepare`, `prepack`) without justification — these run on the user's machine
- `install_cmd` not pinned to an explicit version / digest

---

## Promoting `trust: candidate` → `trust: verified`

`candidate` means: "the integrity hash matches the artifact published to the registry." That's automatic.

`verified` means: a human looked at the entry against the criteria below and signed off. It is **not** a stronger version of the integrity check — it's a separate, manual signal.

### Triage checklist

Promotion PR title format: `chore: promote <name> to trust:verified` — body must tick all of these.

#### Publisher / repo provenance
- [ ] `source_url` matches the `repository.url` from the registry (no monorepo subdirectory mismatch)
- [ ] Publisher org on npm/PyPI matches what's in `source_url` (or vendor account is well-known: `@anthropic`, `@modelcontextprotocol`, `@github`, `@microsoft`, `@cloudflare`, …)
- [ ] No recent owner transfer on the GitHub repo (check the repo's transfer log if it's a high-value entry)
- [ ] Issue tracker is open and getting responses — not a dead repo with the npm version still ticking

#### Install-time safety
- [ ] No `preinstall` / `install` / `postinstall` / `prepack` hooks; `prepare` is allowed only if it's `npm run build` (verified by reading the published `package.json`)
- [ ] No native binary downloads in install hooks
- [ ] `est_tools_count` filled in from a real smoke — `node mcp-ecosystem-intelligence/scripts/mcp_eval.cjs --name <name> --sandbox --json` reports `tool_count` (use `--unsafe` if you have no docker)

#### Operational fit
- [ ] `category` is specific (not `utility`) — or there's a note explaining why utility is right
- [ ] `toolsets` filled in if `est_tools_count >= 30` (heavy-server flag in `orchestrate.cjs`) — otherwise the entry gets shown with a `⚠` and no mitigation
- [ ] Server runs and answers a ListTools request (smoke check) — `mcp_eval.cjs --name <name> --sandbox` returns `status: pass`; a `failure_class` of `NEEDS_ENV`/`NEEDS_NET` is acceptable (couldn't boot without creds/net), but `CRASH`/`NO_TOOLS` blocks promotion

#### Advisory sweep
- [ ] `verify_integrity.cjs` (full audit, no `--no-audit`) reports no HIGH/CRITICAL CVEs for the pinned version
- [ ] Server doesn't ship known-bad transitive deps (best-effort; run `npm audit` against a fresh install if in doubt)

### When to demote `verified` → `candidate`

- Publisher org changes hands silently
- A HIGH/CRITICAL CVE is published and no fix is out within 14 days
- The repo gets archived
- `discover.cjs` health score drops below 65 (Recommended tier) on the weekly refresh

Demotion is also done via PR — same template, opposite direction. Include the trigger in the PR body.

---

## Install-Hook Policy

A `trust: "candidate"` entry stays at candidate (does **not** auto-promote to `verified`) if its upstream package ships any of these npm scripts:

- `preinstall`, `install`, `postinstall` — runs arbitrary code during `npm install` / `npx -y`
- `prepare` — runs in dev installs; harmless in most cases, but flagged for review
- `prepack`, `prepublish`, `prepublishOnly` — package-author hooks; usually fine but inspected

This is a deliberate ceiling, not a backlog. The hooks may be perfectly legitimate (build native binaries, download a CLI shim, enforce a package manager) — but `npx -y` runs them automatically, and the integrity gate's hash check covers the tarball, not the side effects of executing arbitrary install scripts. As of the last triage pass, the 18 candidate entries are all held here: `@last9/mcp-server` ships `postinstall: node bin/download-binary.js`, `@azure/mcp` ships `postinstall: node ./scripts/post-install-script.js`, `@postman/postman-mcp-server` ships `preinstall: …` that enforces pnpm, and so on.

To promote a hooked candidate to `verified`, a maintainer must:

1. Read the actual hook script in the published package — e.g. `npm view <pkg>@<ver> dist.tarball`, unpack, inspect.
2. Document in the entry's `notes` field: `[VERIFIED <date>] hook reviewed: <one-line description of what it does>`.
3. Open a PR that explains *why* this specific hook is acceptable. The promotion is opt-in per entry, not a class-wide carve-out. (Implementation detail TBD: either run `verify_integrity.cjs --strict` with a per-entry waiver, or add a `hook_review: "approved"` field that the gate reads.)

PyPI (`uvx`) and Docker (`docker run`) entries are not subject to this policy because they have no equivalent automatic-execution surface at install time — `uvx` runs the entrypoint, not arbitrary build scripts; Docker images execute only their `CMD`/`ENTRYPOINT`.

### Current hook-blocked candidates

See [`mcp-ecosystem-intelligence/assets/triage_notes.md`](./mcp-ecosystem-intelligence/assets/triage_notes.md) for the running list of why each candidate is held (created by the batch-4 triage pass).

---

## Modifying the integrity gate (`verify_integrity.cjs`)

This file is the single most security-sensitive script in the repo. Changes require:

1. Pass the existing self-checks in [SECURITY.md §`verify_integrity.cjs`](./SECURITY.md)
2. Unit-test coverage for the change (see `tests/` directory if it exists; otherwise add it)
3. CI smoke job must stay green on the same DB after the change
4. PR description must call out *what specifically can no longer pass the gate* after this change — even if the answer is "nothing, this only adds a new check"

A logic bug here is treated as Critical severity (48-hour patch SLA per SECURITY.md).

---

## Style / housekeeping

- Commit messages: [Conventional Commits](https://www.conventionalcommits.org). `feat:` → minor version bump, `fix:` → patch, `BREAKING CHANGE:` → major. PR titles are read by `release-please` to drive the next version.
- Imperative mood, focused on *why* not *what*. Reviewers will read the diff for what.
- Run `verify_integrity.cjs --no-audit` before every push if you touched `tools_database.json` or any script.
- When editing `tools_database.json` programmatically, use `mcp-ecosystem-intelligence/scripts/lib/db_io.cjs::writeDb()` — it preserves the file's `\uXXXX` escape convention for non-ASCII characters. A regression test in `tests/db_io.test.cjs` enforces this.
- Don't add dependencies to the scripts — they intentionally use only Node built-ins so the supply-chain attack surface is the same as Node itself.
- For UI / docs PRs, no need for triage checklist; just describe the change in plain English.

---

## Releasing

Two paths, both gated by human review:

**Automatic** (default). `release-please` watches `master`, parses Conventional Commit types since the last tag, opens a `chore(release): vX.Y.Z` PR with the auto-generated CHANGELOG section. Merge the PR → release-please creates the git tag and GitHub release. No manual `gh release create` needed.

**Manual** (override). For ad-hoc patches or backfilling: GitHub → Actions → `release` workflow → *Run workflow*, fill in `tag` (e.g. `v0.3.1`) and optional `notes`. The job validates the tag against semver, refuses to overwrite existing tags, and uses `gh release create --generate-notes` when notes are blank.

Both paths use the same `release` workflow; see `.github/workflows/release.yml`.

If anything here looks wrong or out of date, open a PR — the doc itself follows the same review process.
