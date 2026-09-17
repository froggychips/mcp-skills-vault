# mcp-skills-vault

[![npm version](https://img.shields.io/npm/v/@froggychips/mcp-vault.svg)](https://www.npmjs.com/package/@froggychips/mcp-vault)
[![npm downloads](https://img.shields.io/npm/dm/@froggychips/mcp-vault.svg)](https://www.npmjs.com/package/@froggychips/mcp-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Zero deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](./PHILOSOPHY.md)
[![Tests](https://img.shields.io/badge/tests-535%20pass-brightgreen.svg)](./tests)

**Homepage:** [mcp.froggychips.xyz](https://mcp.froggychips.xyz) · **npm:** [`@froggychips/mcp-vault`](https://www.npmjs.com/package/@froggychips/mcp-vault)

> **Make MCP boring.** A deterministic registry + integrity scanner for [Model Context Protocol](https://modelcontextprotocol.io) servers, so installing one stops feeling like `curl | bash`.

![demo](./docs/demo.gif)

```text
$ npx -y @froggychips/mcp-vault scan
Stack: Langs: Node | DB: postgres | Infra: aws, teamcity, atlassian
Needs: database, infra, ci-cd, pm

── Recommended ──────────────────────────────────────────────
  Core         mcp-server-neon            10 tools  score 105
  Core         mcp-server-aws             20 tools  score 105
  Core         mcp-server-filesystem      10 tools  score 105
  Core         mcp-server-memory           9 tools  score 105
  Recommended  teamcity-mcp              null tools  score  65

── Heavy — scope before global install ──────────────────────
  Experimental mcp-atlassian             72 tools ⚠  score  55
                 --toolsets jira,confluence

$ npx -y @froggychips/mcp-vault verify --offline
…
114 entries checked — 0 failure(s)
```

## Without this vault vs. with it

| | Without | With |
|---|---|---|
| **Discoverability** | search GitHub, hope the README isn't lying | curated DB of **114 entries** with health scores, license, category, est-tools-count |
| **Trust** | unknown publisher, unknown last commit | `trust: verified` per entry, **94/114 (82%)** hand-vetted against a written checklist; the remaining 20 are `trust: "candidate"` (18 held by upstream install hooks, 2 freshly promoted from discovery pending a verified smoke) (see [Install-Hook Policy](./CONTRIBUTING.md#install-hook-policy)) |
| **Integrity** | `npx -y whatever@latest` runs whatever ships today | sha512/sha256/Docker `@sha256:` pinned + re-verified against the live registry on every check |
| **Vulnerabilities** | `npm audit` after the fact, if you remember | 4 advisory feeds merged: npm bulk + OSV.dev + GHSA + Snyk† — checked *before* the install command is written |
| **Depth** | the package you asked for | `--deps` resolves the whole tree without installing it: **19,377 transitive packages** across the DB, 25 entries whose *dependencies* run install scripts, 38 with a high/critical advisory somewhere in the tree |
| **Is the hash even yours?** | trust `dist.integrity` from the host serving the tarball | `--deep` downloads and hashes the bytes; npm's registry signature is verified on every run (**100/102** npm entries today), and provenance claims are read and compared with `source_url` |
| **"Verified" as a word** | a label someone typed once | dated evidence per dimension — a hash match holds for 90 days, "no advisories" for 7 — and `trust` is computed from it, dropped when the version moves |
| **Context cost** | unknown until the window fills | `budget` totals what your configured servers inject on every request, each number stating whether it was measured or estimated |
| **Which host** | Claude Code | `install --host` writes Claude Code, Claude Desktop, Cursor, VS Code, or prints a TOML block for Codex |
| **Stack matching** | manual reading of awesome-lists | detects 40+ env-key patterns + 14 file paths + docker-compose images → suggests what to install |
| **Offline use** | doesn't | `--offline` makes no network calls and validates stored pins; `--no-audit` still checks live registries but skips advisory APIs |
| **What actually launches** | `npx -y pkg` resolves `latest` at every start — not the artifact anyone reviewed | `install` writes the version the gate hashed (`pkg@1.2.3`, `pkg==1.2.3`, `image@sha256:…`), and refuses to write an unpinned command without `--allow-unpinned` |
| **Telemetry** | varies | none. Ever. |

† Snyk requires `SNYK_TOKEN` (no public anonymous API)

## Quick start

**As a CLI** — one line, no clone, no global install:

```bash
npx -y @froggychips/mcp-vault scan --cwd ./my-project
npx -y @froggychips/mcp-vault audit --strict
npx -y @froggychips/mcp-vault verify --offline
npx -y @froggychips/mcp-vault verify --installed     # what your hosts actually launch
npx -y @froggychips/mcp-vault budget                 # what they cost in context
npx -y @froggychips/mcp-vault doctor
```

Prefer it installed? `npm i -g @froggychips/mcp-vault` then drop the `npx -y` prefix.

**As a Claude Code skill** — drop the bundled skill folder into `~/.claude/skills/` and Claude will pick it up:

```bash
git clone https://github.com/froggychips/mcp-skills-vault.git
mkdir -p ~/.claude/skills
cp -r mcp-skills-vault/mcp-ecosystem-intelligence ~/.claude/skills/
```

**Direct script invocation** — every command also runs without the CLI wrapper, e.g. `node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --cwd /path/to/project`. Flags are identical; the CLI is a thin pass-through.

Zero runtime dependencies. Node built-ins only. One JSON file is the entire database.

Ask Claude something like:

> _"Is there an MCP server for ClickHouse I should add to this project?"_
> _"Audit my MCP setup."_
> _"What MCP tools should I install for a Next.js app on Cloudflare?"_

## Five constraints that shape every decision

- **Offline-first** — the gate the user cares about runs with no network
- **Minimal** — zero runtime deps; supply-chain attack surface = Node's
- **Inspectable** — every entry carries an audit trail; every output has `--json`
- **Deterministic** — same DB, same commit → same recommendation, every time
- **Boring** — supply-chain tooling should not be exciting

Full rationale and the rules each constraint imposes: [PHILOSOPHY.md](./PHILOSOPHY.md).

## What's in here

| | Purpose | Status |
|---|---|---|
| [`mcp-ecosystem-intelligence/`](./mcp-ecosystem-intelligence) | The scanner + DB. Stack detection, integrity verification, advisory feeds, drift detection, candidate discovery, wrapper generator. | Ready |
| [`concepts/`](./concepts/) | Unfinished sketches kept for reference. Nothing here ships or runs in CI. | Not active |

---

## What works today

### Pipeline orchestrator

[`scripts/orchestrate.cjs`](./mcp-ecosystem-intelligence/scripts/orchestrate.cjs) — the single entry point. Deterministically runs steps 1, 2, 7, 8 of the pipeline so Claude only interprets results.

```bash
# Scan project, match DB, show what to install
mcp-vault scan --cwd /path/to/project

# Keyword search on top of stack detection
mcp-vault scan --query kubernetes

# Install a tool: integrity gate → writes .mcp.json
mcp-vault install github-mcp-server
mcp-vault install mcp-server-memory --global
```

Detects stack from: `package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, `Cargo.toml`, `docker-compose.yml`, `.env*` (key names only — no value leaks).

### Supply-chain security scanner

[`scripts/verify_integrity.cjs`](./mcp-ecosystem-intelligence/scripts/verify_integrity.cjs) — run before any install:

```bash
mcp-vault verify
```

| Ecosystem | Integrity | Source URL | Install hooks | CVE / advisory |
|---|---|---|---|---|
| npm (`npx -y`) | sha512 SRI from npm | `repository.url` | `pre/post/install` + `prepare` | npm bulk + OSV.dev + GHSA + Snyk† |
| PyPI (`uvx`) | sha256 of sdist tarball | `project_urls` | n/a | OSV.dev + GHSA + Snyk† |
| Docker (`docker run`) | image must be pinned by `@sha256:<digest>` | n/a | n/a | n/a |

† Snyk active only when `SNYK_TOKEN` env var is set (no public anonymous API). GHSA uses `GITHUB_TOKEN`/`GH_TOKEN` when present to raise its rate limit from 60→5000 req/hr; anonymous works at low volume. Advisories from all feeds are deduplicated by ID before flagging.

Flags:

| Flag | Effect |
|---|---|
| `--update` | Refresh `version` + `pkg_integrity` from registries |
| `--strict` | Treat WARNs (hooks, repo mismatch, unpinned docker) as hard failures |
| `--no-audit` | Skip advisory APIs; still fetch registry metadata for live hash/repo/hook checks |
| `--record-evidence` | Write what this run established back into the DB, dated per dimension (`trust_evidence`), and recompute `trust` from it |
| `--no-policy` | Ignore `.mcp-vault.policy.json` |
| `--show-policy` | Print the policy in force and the switches it implies |
| `--offline` | True offline mode; no network calls, validates stored DB pins only |
| `--fail-unverified` | Treat `UNVERIFIED` (registry unreachable, unparsable install command, wheel-only PyPI release) as a hard failure. Implied by `--strict` |
| `--entry <name>` | Check a single DB entry instead of all of them |
| `--installed` | Verify what the local hosts are configured to launch (`.mcp.json`, `~/.claude.json`, Claude Desktop, Cursor, VS Code, Codex) instead of the DB. Unpinned launch commands, servers not in the vault, and remote endpoints are each reported as what they are |
| `--deep` | Download each artifact and hash it locally, instead of comparing the DB pin against metadata from the same registry that serves the tarball. Docker digests are verified by hashing the manifest |
| `--deps` | Resolve each package's dependency tree (`npm install --package-lock-only --ignore-scripts`, nothing is installed or executed) and check it: transitive install scripts, and every package in the tree against OSV |
| `--fail-dep-advisories` | A high/critical advisory anywhere in the tree is a failure |
| `--require-signatures` | An npm release with no verifiable registry signature is a failure |
| `--require-provenance` | An npm release with no provenance attestation is a failure |

This project publishes itself with npm provenance (`npm publish --provenance`,
signed against a GitHub OIDC token — which works on a self-hosted runner, since
the token comes from GitHub rather than the runner). If provenance cannot be
produced, the publish stops rather than shipping without it.

Every npm entry's registry signature is checked on every run: npm signs
`<name>@<version>:<integrity>` with a published ECDSA key, so a response with a
swapped `dist.integrity` cannot pass. 100 of the DB's 102 npm entries verify
today; 45 also publish a provenance attestation, whose claimed source
repository is compared against `source_url`. Provenance is reported as a claim,
not a proof — verifying the sigstore bundle itself (Fulcio chain, Rekor
inclusion) is not something this tool does, and it says so rather than implying
otherwise.
| `--json` | Structured report on stdout (progress goes to stderr); exit code unchanged |
| `--sarif` | SARIF 2.1.0 for GitHub code scanning — each finding anchored to its `tools_database.json` line |

An entry the gate could not actually compare against a registry reports
`UNVERIFIED`, never `OK` — "the feed was down" is not "the pin is good". It is
advisory by default and a failure under `--fail-unverified`, which is what
`install` passes.

### Hosts

`install` writes whichever host's config you point it at, not just Claude
Code's. The vault entry is the same; only the file and (for two of them) the
shape differ.

```bash
mcp-vault install --list-hosts              # ids, scopes, formats
mcp-vault install <name>                    # Claude Code, project  (./.mcp.json)
mcp-vault install <name> --global           # Claude Code, user     (~/.claude.json)
mcp-vault install <name> --host cursor      # Cursor                (./.cursor/mcp.json)
mcp-vault install <name> --host vscode      # VS Code               (./.vscode/mcp.json, `servers` key)
mcp-vault install <name> --host claude-desktop --scope user
mcp-vault install <name> --host codex       # prints a TOML block to paste
```

An existing config is backed up before it is touched, unrelated keys are left
alone, and a config that exists but does not parse is never overwritten — it is
more likely a file worth keeping than a file worth clobbering. Codex keeps TOML;
rewriting that without a TOML parser would destroy comments and formatting, so
`mcp-vault` prints the three correct lines and lets you paste them.

### Health, trust and fit

`health_score` mixes stars, recency, registry presence and a licence penalty.
That is a fair *discovery* signal — is this project maintained — and it was
being read as a measure of trust. It is not one: a package can have 30k stars,
weekly commits, an official listing, and also a broken pin, an unsigned release
and seventy tools with filesystem access.

`scan --json` now reports three axes per entry and a verdict over them:

```json
"scores": {
  "health": 78,
  "trust": { "score": 85, "gate": "ok", "reasons": ["artifact: verified", "signature: verified"] },
  "fit":   { "score": 73, "reasons": ["maps to \"postgres\" (detected, package.json dependency, confidence 0.95)"] },
  "recommendation": { "verdict": "recommended", "reasons": ["fits this project (fit 73/100)"] }
}
```

Trust **gates**; health and fit **rank**. A blocking trust verdict (hash
mismatch, known-vulnerable version) is never outweighed by the other two, which
is precisely what adding the numbers together would do. Thin trust — nothing
recorded yet — never reads as `recommended` either. `health_score` keeps its
name and formula: it is consumed by discovery and policy, and renaming a field
to make a point is a poor trade.

Stack signals carry their own provenance, so a recommendation can be explained
rather than asserted:

```json
{ "dimension": "db", "value": "postgres", "kind": "detected", "sources": ["package.json dependency"], "confidence": 0.95 }
{ "dimension": "infra", "value": "aws",   "kind": "inferred", "sources": [".env key name"],            "confidence": 0.6 }
```

`detected` means the project declares it; `inferred` means something suggests
it. A credential in `.env` says someone has an account, not that this repo
calls that service — and the weaker signal produces a weaker fit.

### Trust as dated evidence

`trust: "verified"` collapsed several claims with different lifetimes into one
word: that a hash matched, that the repo URL agreed, that the licence was OSI,
that no advisory applied, that the server booted. Those were true on different
days, and read as one word the oldest claim inherits the confidence of the
newest. A hash match is good until the pin changes; "no advisories" is good
until the next disclosure.

`verify --record-evidence` writes each dimension with the date it was
established:

```json
"trust_evidence": {
  "artifact_id": "npm:@mapbox/mcp-server@0.11.0",
  "dimensions": {
    "artifact":       { "status": "verified", "checked_at": "2026-09-17", "method": "deep-hash" },
    "signature":      { "status": "verified", "checked_at": "2026-09-17", "keyid": "SHA256:…" },
    "source_binding": { "status": "verified", "checked_at": "2026-09-17" }
  }
}
```

`trust` becomes a derived value. Evidence is keyed to an artifact id including
the version, so it is dropped rather than inherited when the version moves —
what was learned about 1.2.3 says nothing about 1.2.4. A run records only what
it actually examined: a `--no-audit` run writes nothing about advisories rather
than writing "clean". Each dimension has its own shelf life (advisories 7 days,
a hash 90), overridable with `maxEvidenceAgeDays`; evidence past it is reported
as `UNVERIFIED` — "verified, eight months ago" is a different claim from
"verified".

The weekly refresh job records evidence as part of its run.

### Policy file

The flags above answer one question each. A project usually wants the same
answers every time, in CI and in a developer's shell — so write them down once
in `.mcp-vault.policy.json` (nearest file at or above `--cwd`; see
[`.mcp-vault.policy.example.json`](./.mcp-vault.policy.example.json)):

```json
{
  "unverified": "fail",
  "signatures": "require",
  "dependencyHooks": "warn",
  "licenses": { "deny": ["BUSL-1.1", "SSPL-1.0"] },
  "minHealthScore": 60,
  "trust": ["verified"]
}
```

A policy can only raise the bar; an explicit flag still wins. Rules that aren't
facts about the artifact — license lists, trust tiers, a health floor — appear
as ordinary findings, so JSON and SARIF carry them too. An unknown key is a
hard error rather than a no-op: a policy with a typo that silently enforces
nothing is worse than no policy, because it reads as a bar being enforced.

`mcp-vault verify --show-policy` prints what is in force and where it came from.

### Doctor

[`scripts/doctor.cjs`](./mcp-ecosystem-intelligence/scripts/doctor.cjs) — local readiness check:

```bash
mcp-vault doctor
mcp-vault doctor --json
```

Checks Node version, optional `gh` / Docker / `uvx`, project `.mcp.json`, project `.claude/settings.json`, and global `~/.claude.json` MCP server config. It never prints token values.

### What this project is NOT

- **Not a sandbox.** Installing an MCP server still runs that server with your local MCP host's permissions.
- **Not a runtime monitor.** Vault is an install-time gate; use `mcp-trace` or another monitor for runtime behaviour.
- **Not proof that a server is benign.** Hashes prove you got the artifact you expected, not that the artifact is safe.

### Docker `@sha256` drift detection

[`scripts/check_docker_drift.cjs`](./mcp-ecosystem-intelligence/scripts/check_docker_drift.cjs) — for every Docker entry, fetches the registry digest for the tracked tag (`tracked_tag` in the entry, default `latest`) via the OCI Distribution Spec and reports drift against the pinned `@sha256:` digest.

```bash
mcp-vault docker-drift           # human-readable
mcp-vault docker-drift --json    # machine-readable
mcp-vault docker-drift           # report drift
mcp-vault docker-drift --write   # move the pins, for review as a diff
mcp-vault docker-drift --strict  # exit 1 on any drift
```

Drift = upstream rebuilt the tag under a new digest. The weekly CI job (`docker-drift`) fails on any drift so a maintainer reviews the upstream change *before* refreshing the pin — a routine rebuild and a registry hijack look identical from here.

### Behavioural smoke (mcp-eval)

[`scripts/mcp_eval.cjs`](./mcp-ecosystem-intelligence/scripts/mcp_eval.cjs) — closes the "did the artifact actually start?" gap. The integrity gate verifies the *file* you downloaded; this script verifies that spawning the server produces a usable tool surface.

For each DB entry with a recognized install method (`npx -y`, `uvx`, `docker run`), the script spawns the subprocess and runs the canonical JSON-RPC handshake — `initialize` → `notifications/initialized` → `tools/list` — then lints each returned tool's `inputSchema` with a minimal validator (intentionally narrower than full JSON Schema Draft 2020-12; covers only what Claude Code actually reads: `type`, `properties`, `required`, `enum`, `description`, plus nested objects + array items).

```bash
mcp-vault eval --name memory --sandbox   # one entry, jailed in a container
mcp-vault eval --name memory --sandbox   # one entry, jailed container (preferred)
mcp-vault eval --name memory --unsafe    # one entry, on the host (no docker)
mcp-vault eval --sandbox --json --strict # whole DB, CI form
mcp-vault eval --no-spawn                # offline self-test
```

Spawn policy is **default-deny**: a live smoke runs third-party code, so it refuses to spawn unless you pass `--sandbox` (jailed ephemeral container — `--cap-drop ALL`, read-only rootfs, non-root, mem/pid caps, install hooks off) or `--unsafe` (run on the host). `--no-spawn` is exempt.

Output: `assets/eval_results.json` — `{name, status, boot_ms, list_latency_ms, tool_count, tool_count_db, tool_count_drift, schema_errors[], error_code, failure_class, sandboxed, checked_at}` per entry, sorted by name for deterministic diffs. Results never flow back into `tools_database.json` — DB stays the source of truth, eval is a separate evidence stream.

A `docker run` entry is **not** passed through as written. "Already containerized" is not the same as sandboxed: the flags come from the DB, and the DB is a file a pull request can edit — `-v /:/host`, `--privileged`, `--network host` are one diff away. Under `--sandbox` the launch is rebuilt from the pinned `image@sha256:…` under our own jail flags, and everything else in the entry is discarded. An image with no digest is refused rather than run.

Network policy: real smoke needs to fetch packages (`npx` cache miss, `uvx` wheel download, `docker pull`), so it is NOT offline (network stays on even under `--sandbox` — the jail constrains everything else). Both CI eval jobs use `--sandbox`; `--unsafe` is never used in CI, because a verified hash says which artifact ran, not that it was benign. The `--no-spawn` flag re-lints existing results without spawning anything; that path IS offline.

What it does NOT validate: behavioural correctness (we don't call any tool), business logic, or security of the server's tool implementations. This is a *smoke* check, not a fitness test.

### Discovery pipeline

[`scripts/discover.cjs`](./mcp-ecosystem-intelligence/scripts/discover.cjs) — harvest MCP server candidates from three sources, deduplicate by repo URL, annotate with health metrics from GitHub, score, and emit a candidates JSON ready for manual cherry-pick into `tools_database.json`.

```bash
# Default: all three sources, top-50 candidates, capped at 200 gh api calls
mcp-vault discover --out candidates.json

# Single source / smaller limit
mcp-vault discover --source npm --limit 20 --out candidates.json
```

Sources:

| Source | Endpoint | Notes |
|---|---|---|
| `readme` | `modelcontextprotocol/servers` README | Curated. No `gh` calls. |
| `gh`     | `gh search repos --topic mcp-server / modelcontextprotocol` | Requires `gh auth login`. Topic-tags catch non-MCP projects, filtered out by name/description heuristic. |
| `npm`    | `npm search mcp-server` | Filters to packages with a GitHub `repository` field. |

Annotation uses `gh api repos/<owner>/<repo>` for stars, last commit, license, archive/fork status. Reject heuristics: `<10 stars`, `last_commit > 365 days`, archived, fork, doesn't look like an MCP server in `name`/`description`. Surviving candidates are scored with the same formula as `calculate_health.cjs` and emitted with the same shape as `tools_database.json` entries (minus `pkg_integrity`, which `verify_integrity.cjs --update` fills after manual merge).

The weekly `discover-candidates` CI job runs this script every Thursday and opens a PR refreshing `mcp-ecosystem-intelligence/assets/discovery/candidates.json`. That file is a living *inbox* — never auto-merged into the DB; a human cherry-picks entries with `trust: "candidate"`.

### Audit installed setup

[`scripts/audit_setup.cjs`](./mcp-ecosystem-intelligence/scripts/audit_setup.cjs) — diff the user's installed MCP servers against the DB. Reads `<cwd>/.mcp.json`, the `mcpServers` key of `~/.claude.json` (and *only* that key — auth tokens live elsewhere in the file), and `<cwd>/.claude/settings.json` (`enabledMcpjsonServers`, `permissions.allow`):

```bash
mcp-vault audit            # human-readable
mcp-vault audit --json     # machine-readable findings
mcp-vault audit --strict   # exit 1 on drift/untrusted/heavy
```

| Finding | Trigger |
|---|---|
| `drift` | installed version differs from DB-pinned version |
| `untrusted` | DB `trust: "candidate"` but actively installed |
| `heavy-unbounded` | `est_tools_count > 15` (or unknown) and no `--toolsets`/`--caps`/`allowedTools`/`enabledMcpjsonServers` scoping |
| `unknown` | installed but not in DB (legitimate custom servers ok — informational) |
| `scope` | global install of a typically project-scoped category (`vcs`/`ci-cd`/`pm`/`infra`) |

Exit codes: `0` clean / info-only · `1` `--strict` triggered · `2` bad invocation. Closes the "Audit my MCP setup" use case without an LLM in the critical path.

### Public registry page

[`scripts/generate_registry_page.cjs`](./mcp-ecosystem-intelligence/scripts/generate_registry_page.cjs) renders the DB into `docs/site/registry.html` plus `docs/site/registry.json`:

```bash
mcp-vault site-registry
```

The generated page is static, searchable, and filterable by category, tier, and trust. It is meant to be published with the rest of the GitHub Pages site.

### Health scorer

[`scripts/calculate_health.cjs`](./mcp-ecosystem-intelligence/scripts/calculate_health.cjs) — score any MCP candidate:

```bash
mcp-vault health \
  <stars> <last_commit_days> <in_registry> <has_install_cmd> <critical_issues> [license]
```

```
score = min(20, 10·log10(stars+1))   # popularity, capped
      + {40|20|10|0}                  # recency: <30d / <90d / <180d / older
      + 30 if in_registry
      + 15 if install_cmd documented
      + 5  if open_issues/10 < 5
      − 10 if license is non-OSI / source-available / Unknown
```

| Score | Tier | Behaviour |
|---|---|---|
| 85+ | Core | recommend by default |
| 65–84 | Recommended | recommend with note |
| 40–64 | Experimental | mention only on ask |
| < 40 | Deprecated | hide unless asked |

### Vetted database

`mcp-ecosystem-intelligence/assets/tools_database.json` — **114 entries** across ~26 categories, all with pinned versions, integrity hashes (npm sha512 / PyPI sha256 / Docker @sha256), SPDX license, and `trust` field.

```
ai        browser   ci-cd      cms       communication   crm
database  demo      docs       filesystem http            infra
maps      memory    meta       mobile     observability   payments
pm        reasoning search     testing    utility         vcs       web-scraping
```

Distribution: **20 Core / 76 Recommended / 18 Experimental**.

**Verified hand-curated core** (the original 30): the seven official `modelcontextprotocol/servers` (filesystem, fetch, git, memory, sequentialthinking, time, everything) plus vendor-maintained servers (`github`, `microsoft/playwright`, `cloudflare`, `notion`, `sentry`, `stripe`, `neon`, `mongodb`, `redis`, `clickhouse`, `awslabs/mcp`, `context7`, …) and high-quality community entries (`mcp-atlassian`, `firecrawl`, `tavily`, `exa`, `brave`, `kubernetes`, `duckduckgo`, …).

**Candidate batch** (75, added 2026-05): vendor servers harvested via `discover.cjs` from npm + the official servers README, all with `trust: "candidate"` pending human-vetting on usage patterns. Highlights: `@mapbox/mcp-server`, `@azure-devops/mcp`, `@dynatrace-oss/dynatrace-mcp-server`, `@browserstack/mcp-server`, `@salesforce/mcp`, `@postman/postman-mcp-server`, `@eslint/mcp`, `@circleci/mcp-server-circleci`, `argocd-mcp`, …

Entry schema:

```jsonc
{
  "name": "pkg-name",
  "category": "database|search|infra|…",
  "install_cmd": "npx -y pkg@1.2.3",   // always pinned
  "source_url": "https://github.com/owner/repo",
  "version": "1.2.3",                  // pinned npm version
  "pkg_integrity": "sha512-…",         // npm dist.integrity
  "trust": "verified",                 // "verified" | "candidate"
  "license": "MIT",                    // SPDX; non-OSI triggers -10 penalty
  "health_score": 105.0,
  "classification": "Core",
  "est_tools_count": 10,               // tools injected into context (~200-500 tokens each)
  "toolsets": "--toolsets repos,issues" // how to reduce tool count; null = no native filtering
}
```

### CI

`.github/workflows/security-scan.yml` runs eight jobs across PRs, pushes and two
weekly crons.

**Isolation first.** GitHub-hosted runners do not start on this account, so
everything lands on one self-hosted machine — which means pull-request code
cannot simply be executed. PR builds run inside a container with no network, the
repo mounted read-only, no capabilities and no docker socket; `mcp-eval-pr`
additionally takes its *scripts* from the PR's base commit and only
`tools_database.json` from the PR head. If no container runtime answers, those
jobs check nothing and say so rather than falling back to the host. The rules
are asserted in [`tests/ci_manifest.test.cjs`](./tests/ci_manifest.test.cjs) —
per step, so a later edit cannot quietly add an unjailed one. See
[SECURITY.md](./SECURITY.md#ci-isolation-model).

- **unit-tests** — `node --test tests/*.test.cjs` on every PR / push. Jailed on
  PRs, direct in trusted contexts.
- **smoke** — `verify_integrity.cjs --offline` on every PR / push, plus a SARIF
  upload so each finding lands on the `tools_database.json` line that caused it
  instead of in a log.
- **refresh-hashes** — Monday cron. Refreshes `version` + `pkg_integrity` from
  live registries, re-verifies with `--deep --record-evidence`, opens a PR.
  Human-gated before merge.
- **docker-drift** — Monday cron + manual. Compares each pinned `@sha256:`
  against upstream, then **opens a PR moving the pins** with a link to the
  upstream releases page. A red job says something moved; a diff says what.
  Registry errors still fail the job — nothing was compared then.
- **license-drift** — Monday cron + manual. `--strict` fails on an OSI →
  restrictive move *and* on fetch errors: a run that read no licences is not a
  run that found no drift.
- **discover-candidates** — Thursday cron + manual. Opens a PR with a fresh
  `assets/discovery/candidates.json`. An *inbox*, never auto-merged.
- **mcp-eval-smoke** — Monday cron + manual. Smokes the whole DB under
  `--sandbox` (never `--unsafe` — a verified hash says which artifact ran, not
  that it was benign), paced so 100+ container starts don't take the daemon
  down, and opens a PR refreshing the shipped `eval_results.json`.
- **mcp-eval-pr** — on PRs touching the DB. Behavioural smoke of just the
  changed entries, advisory (never blocks merge).

---

## Roadmap

Everything in this table is scripted and tested; the column says where it lives.

| Feature | Where |
|---|---|
| Stack detection, with a source and confidence per signal | [`orchestrate.cjs detectStack()`](./mcp-ecosystem-intelligence/scripts/orchestrate.cjs) |
| Integrity gate that fails closed on anything it could not check | [`verify_integrity.cjs`](./mcp-ecosystem-intelligence/scripts/verify_integrity.cjs) |
| Artifacts hashed locally (`--deep`), npm registry signatures, provenance claims | [`lib/artifact.cjs`](./mcp-ecosystem-intelligence/scripts/lib/artifact.cjs), [`lib/npm_signatures.cjs`](./mcp-ecosystem-intelligence/scripts/lib/npm_signatures.cjs) |
| Dependency trees resolved and checked (`--deps`) | [`lib/deps.cjs`](./mcp-ecosystem-intelligence/scripts/lib/deps.cjs) |
| Trust as dated, per-dimension evidence | [`lib/evidence.cjs`](./mcp-ecosystem-intelligence/scripts/lib/evidence.cjs) |
| Health / trust / fit as separate axes | [`lib/scores.cjs`](./mcp-ecosystem-intelligence/scripts/lib/scores.cjs) |
| Policy file instead of a garland of flags | [`lib/policy.cjs`](./mcp-ecosystem-intelligence/scripts/lib/policy.cjs) |
| Install into any host's config | [`lib/hosts.cjs`](./mcp-ecosystem-intelligence/scripts/lib/hosts.cjs) |
| Verify what the hosts actually launch (`--installed`) | [`lib/installed.cjs`](./mcp-ecosystem-intelligence/scripts/lib/installed.cjs) |
| Token budget for a real config | [`token_budget.cjs`](./mcp-ecosystem-intelligence/scripts/token_budget.cjs) |
| Machine-readable report + SARIF | [`lib/report.cjs`](./mcp-ecosystem-intelligence/scripts/lib/report.cjs) |
| Behavioural smoke in a rebuilt jail | [`mcp_eval.cjs`](./mcp-ecosystem-intelligence/scripts/mcp_eval.cjs), [`lib/mcp_stdio.cjs`](./mcp-ecosystem-intelligence/scripts/lib/mcp_stdio.cjs) |
| Discovery pipeline (npm / gh / README) | [`discover.cjs`](./mcp-ecosystem-intelligence/scripts/discover.cjs) |
| Wrapper generator (CLI/API → MCP) | [`generate_wrapper.cjs`](./mcp-ecosystem-intelligence/scripts/generate_wrapper.cjs) |

Still judgement, not script — deliberately: the reject heuristics (5-Minute
Rule, Bloat, Duplication) and promoting a candidate to `trust: verified`. The
typed `artifact`/`launch` model exists in
[`lib/entry_model.cjs`](./mcp-ecosystem-intelligence/scripts/lib/entry_model.cjs)
and is asserted to reproduce every entry's `install_cmd`; consumers still read
the string, and moving them over is the next step.

---

## Token cost management

Every active MCP server injects its full tool list into Claude's system prompt (~200–500 tokens per tool). With 114 servers in the DB the spread is wide: `mcp-server-fetch` = 1 tool vs. `gitlab-mcp` = 153 tools.

**First, measure.** `mcp-vault budget` reads your host configs and totals the
surface, stating where each number came from:

```bash
mcp-vault eval --installed --unsafe --results /tmp/eval.json   # measure real tools/list payloads
mcp-vault budget --results /tmp/eval.json                      # add it up
mcp-vault budget --budget 25                                   # exit 1 over 25% of the window
```

```
server                     tools    tokens  source
hostinger                    396    87,831  measured
chrome-devtools               29     6,505  measured
github                        26     3,964  measured
teamcity                      13     2,668  measured
codex                          4     1,065  measured
TOTAL                        468   102,034  ≈51% of a 200,000-token window
```

`measured` is a real payload (bytes ÷ 4); `eval`/`db` is a tool count times the
200–500 range above; `unknown` is counted as unknown, never as zero. Where the
DB knows how to narrow a server, the report says so.

Three levers, in order of preference:

**1. Native filtering** (server flag / config key) — use the `toolsets` field in the DB:
```bash
# github-mcp: keep only what the project needs
--toolsets repos,issues,pull_requests
# playwright-mcp: drop 56 tools, keep 8
--caps core
# mongodb-mcp: exclude destructive tools
disabledTools: ["dropCollection", "dropDatabase"] in mcp_settings.json
```

**2. Project-scoped `.mcp.json`** (default install target) — server is active only in the repo where `.mcp.json` lives, invisible everywhere else:
```json
{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
               "--toolsets", "repos,issues",
               "ghcr.io/github/github-mcp-server@sha256:…"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}" }
    }
  }
}
```

Reserve `~/.claude.json` for truly cross-project servers: `mcp-server-filesystem`, `mcp-server-memory`.

**3. Wrapper (anti-bloat pattern)** — when a vendor server has no native filtering and exposes 50+ tools you don't need, wrap the 3–5 tools you do need in a thin custom MCP server using `assets/mcp-wrapper-template/`. The wrapper replaces the vendor server entirely, keeping context lean.

---

## Wrapping a CLI/API as MCP

When the vendor server has no native filtering and exposes 50+ tools you don't need, generate a thin wrapper that exposes only the 3–5 tools you actually use. Saves ~200–500 tokens per dropped tool.

```bash
# Skeleton wrapper, no tools yet
mcp-vault wrap \
  --name my-cli-mcp --tool "My CLI" --out ./my-cli-mcp

# Pre-populated with tool definitions from a JSON spec
mcp-vault wrap \
  --name warehouse-mcp --tool "Internal Warehouse" \
  --tools-file ./tools.json \
  --out ./warehouse-mcp
```

`tools.json` is an array of MCP tool defs (`name` / `description` / `inputSchema`); the generator emits `ListToolsRequestSchema` entries plus `switch`-cases with `required`-arg validation, runs Node's `--check` on the result, and writes a `.mcp.json`-ready README.

Underlying template lives in `mcp-ecosystem-intelligence/assets/mcp-wrapper-template/` if you'd rather edit by hand.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the entry schema, reject criteria, the triage checklist for promoting `trust: candidate` to `trust: verified`, and the review process for changes to the integrity gate.

Running the suite locally:

```bash
node --test tests/*.test.cjs        # unit tests (offline)
mcp-vault verify --offline          # DB smoke, no network
mcp-vault site-registry             # regenerate docs/site/registry.html
```

---

## Topics

`claude-code` · `claude-skill` · `mcp` · `model-context-protocol` · `mcp-server` · `mcp-tools` · `anthropic` · `ai-agents`

## License

[MIT](./LICENSE)
