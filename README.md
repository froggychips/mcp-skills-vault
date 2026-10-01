# mcp-skills-vault

[![npm version](https://img.shields.io/npm/v/@froggychips/mcp-vault.svg)](https://www.npmjs.com/package/@froggychips/mcp-vault)
[![npm downloads](https://img.shields.io/npm/dm/@froggychips/mcp-vault.svg)](https://www.npmjs.com/package/@froggychips/mcp-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Zero deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](./PHILOSOPHY.md)
[![Tests](https://img.shields.io/badge/tests-822%20pass-brightgreen.svg)](./tests)

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
FAIL  mcp-server-aws@1.0.27 (PyPI offline pin present for awslabs.core-mcp-server)
        [FAIL] stored evidence: availability: yanked (observed 2026-09-17)
…
112 entries checked — 1 failure(s)
```

## Without this vault vs. with it

| | Without | With |
|---|---|---|
| **Discoverability** | search GitHub, hope the README isn't lying | curated DB of **113 entries** with health scores, license, category, est-tools-count |
| **Trust** | unknown publisher, unknown last commit | `trust` is **derived from dated evidence**, not typed by hand: **107 verified / 1 candidate / 4 unverified** as of 2026-09-30 (the date of the newest evidence in the DB). The 4 are one entry with an advisory recorded against the pinned version, two whose repository disagrees with the registry's, and one yanked (see [Install-Hook Policy](./CONTRIBUTING.md#install-hook-policy)) |
| **Integrity** | `npx -y whatever@latest` runs whatever ships today | sha512/sha256/Docker `@sha256:` pinned + re-verified against the live registry on every check |
| **Vulnerabilities** | `npm audit` after the fact, if you remember | 4 advisory feeds merged: npm bulk + OSV.dev + GHSA + Snyk† — checked *before* the install command is written |
| **Depth** | the package you asked for | `--deps` resolves the whole tree without installing it: **19,377 transitive packages** across the DB, 25 entries whose *dependencies* run install scripts, 38 with a high/critical advisory somewhere in the tree |
| **Is the hash even yours?** | trust `dist.integrity` from the host serving the tarball | `--deep` downloads and hashes the bytes; npm's registry signature is verified on every run (**100/101** npm entries today), and provenance claims are read and compared with `source_url` |
| **"Verified" as a word** | a label someone typed once | dated evidence per dimension — a hash match holds for 90 days, "no advisories" for 7 — and `trust` is computed from it, dropped when the version moves |
| **Context cost** | unknown until the window fills | `budget` totals what your configured servers inject on every request, each number stating whether it was measured or estimated |
| **Which host** | Claude Code | `install --host` writes Claude Code, Claude Desktop, Cursor, VS Code, or prints a TOML block for Codex |
| **Is it still there?** | a 404 looks like a network blip | `availability` tells *gone* / *version-gone* / *yanked* / *deprecated* apart, and an unpublished name is treated as what it is: claimable by somebody else |
| **Who published it** | whatever `repository.url` says | cross-referenced with the official MCP registry, whose namespaces are **ownership-verified** at publish (`io.github.<owner>/…`) |
| **Does it run?** | find out after installing | behavioural eval, and the result caps the recommendation: **40 of 112** complete a handshake, and an entry nothing has seen start cannot read as "recommended" |
| **What can it do?** | read the source, if it isn't minified | `capabilities` records what each package is able to do with a file and a line — 38 of the 105 package versions scanned can shell out, 90 read `process.env` — and reports what a new version **gained** |
| **Did the tools change?** | invisible | every passing eval fingerprints the tool surface per tool and records what ran, so a later run can say whether a change came with a new artifact, came without one (**unexplained**), or cannot be attributed at all |
| **So what do I install instead?** | read four advisories | `upgrade` computes the shortest version that clears all of them (1 entry today, with a safe path) |
| **Why was it denied?** | read four outputs | `explain` prints the evidence with dates, the policy in force, every rule with its outcome, and the rule that decided it |
| **What runs, exactly** | `npx` re-resolves the tree at every start | `lock` freezes npm's own lockfile per server; `--vendor` installs it so nothing resolves at launch |
| **Stack matching** | manual reading of awesome-lists | detects 40+ env-key patterns + 14 file paths + docker-compose images → suggests what to install |
| **Offline use** | doesn't | `--offline` makes no network calls and validates stored pins; `--no-audit` still checks live registries but skips advisory APIs |
| **What actually launches** | `npx -y pkg` resolves `latest` at every start — not the artifact anyone reviewed | `install` writes the version the gate hashed (`pkg@1.2.3`, `pkg==1.2.3`, `image@sha256:…`), and refuses to write an unpinned command without `--allow-unpinned` |
| **Telemetry** | varies | none. Ever. |

† Snyk requires `SNYK_TOKEN` (no public anonymous API)

## Quick start

**As a CLI** — one command, no clone, no global install:

```bash
npx -y @froggychips/mcp-vault status
```

```text
mcp-vault <version> · /Users/me/repos/my-project · as of 2026-09-30T12:00:00.000Z

Environment     Node v25.9.0
Installed       7 servers · 2 matched in the vault DB · 3 on another version · 2 unvetted
                1 Deprecated · 1 Experimental
Evidence        oldest claim 2026-09-17 (stored; nothing was re-checked just now)
Context         10,500 tokens on every request · 5.3% of a 200k window · 5 not measured
Flows           claude-code: 2 toxic flows · 2 without data
This project    postgres, aws, Node → 1 matching server not installed (mcp-server-neon)

Blocking
  ✗ aws: availability: yanked (as of 2026-09-17)

Worth knowing
  ! 2 configured servers are not in the vault DB, so nothing here has checked them: my-own-server, internal-tools
  ! mcp-atlassian: the vault verified pypi:mcp-atlassian@0.22; this host launches pypi:mcp-atlassian@0.21.1
  ! filesystem: 2 claim(s) past their shelf life (availability, advisories)
  ! search: the launch command resolves at start-up (npm:exa-mcp-server), so what runs is not the npm:exa-mcp-server@3.2.1 the vault verified
  ! browser: the vault verified npm:chrome-devtools-mcp@0.26.0; this host launches npm:chrome-devtools-mcp@1.10.1
  ! claude-code: untrusted content + private data + outward sink across aws, browser, filesystem, mcp-atlassian, search — keep mcp-atlassian, search, browser and aws, filesystem in separate profiles (different project configs or hosts), or drop the outward tools of search, browser
  …and 4 more (mcp-vault audit)

Deeper:  verify --installed  re-hash what your hosts launch, live
         explain <name>      why one entry is allowed or denied
         scan                what to add for this stack
         audit --strict      every drift and scope finding in full
         secrets             plain-text credentials in host configs
```

<sub>`status --as-of 2026-09-30T12:00:00Z` over a `.mcp.json` of seven servers
(mcp-atlassian 0.21.1, awslabs.core-mcp-server 1.0.27, server-filesystem,
unpinned exa-mcp-server, chrome-devtools-mcp 1.10.1 and two local ones) and a
`package.json` using `pg` and the AWS SDK; exit `1`. The DB pins
mcp-atlassian 0.22.0 since 2026-09-30, so an old 0.21.1 launch is *version
drift* — evidence about 0.22.0 says nothing about 0.21.1 in either direction —
not an advisory finding.</sub>

Servers are matched by **artifact identity, not by the name in your config** —
and the version is compared separately, because stored evidence about `x@1.0.0`
is not a finding about `x@2.0.0` in either direction. Equality alone is not
enough: both sides must also *resolve* to one artifact, so `npx -y pkg` and
`pkg@latest` are reported as what they are rather than matched against a pin.
A server on a version nobody verified gets no tier at all.

It makes **no network calls** — every claim comes from evidence already on
disk, and says so rather than implying it was checked just now. Exit `1` means
something installed must not run: gone, yanked, wrong bytes, or a live advisory
against the pinned version, or a credential in plain text in a host config.
`--strict` also fails on drift, unvetted servers and claims past their shelf
life.

The commands it summarises are all still there, and the footer names them:

```bash
npx -y @froggychips/mcp-vault verify --installed     # re-hash what your hosts launch, live
npx -y @froggychips/mcp-vault scan --cwd ./my-project
npx -y @froggychips/mcp-vault audit --strict
npx -y @froggychips/mcp-vault verify --offline
npx -y @froggychips/mcp-vault budget
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
| `--config <path>…` | Verify exactly these config files — every later bare argument — and nothing from the home directory. Implies `--installed`; a named file that is missing is exit 2 |
| `--policy <path>` | Use this policy file instead of the nearest `.mcp-vault.policy.json` |
| `--fail-on <effect>` | Exit threshold of the decision (`fail_on`): `deny`, `unknown` (= `--fail-unverified`) or `warn` (= `--strict`). Only raises the bar |
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
swapped `dist.integrity` cannot pass. 99 of the DB's 100 npm entries verify
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

Because the answer depends on the date, the date is an input: `--as-of
2026-09-24` (or a full ISO-8601 instant) judges the same stored evidence as of
that day, on `verify`, `status`, `explain`, `audit`, `list` and `scan`, and every
`--json` document carries the `as_of` it used. The same DB and policy at the
same `--as-of` print the same bytes — which is what a test, a doc example or
"what did the gate say last Tuesday" needs. Without it, the instant is now.
`--record-evidence` and `install` refuse it: a replayed date may judge old
evidence, never date a new observation or approve an install.

The weekly refresh job records evidence as part of its run. The eight
dimensions it fills for this DB today:

```
availability   present 104, deprecated 4, yanked 1
artifact       verified 112, unverified 1
signature      verified 100, absent 1
provenance     bound 45, absent 55
source_binding verified 98, unverified 9, mismatch 2
registry       listed 11, unlisted 101
advisories     clean 107, vulnerable 1, advisories-present 1
posture        clean 1, weak 3        (Scorecard covers 4 of 113 repositories)
→ trust:       verified 108, candidate 1, unverified 4
```

### Is it still there? (`availability`)

The gate cannot answer "does this still exist": a 404 and a network failure
arrive on the same code path, so both read as "could not check". That is how
`@diskd-ai/email-mcp@0.3.8` kept `trust: verified` after npm had stopped
serving it — and an unpublished name is not a broken link, it is a name
*somebody else can register*.

```bash
mcp-vault availability            # gone / version-gone / yanked / deprecated
mcp-vault availability --repos    # also ask GitHub whether the repo moved
```

Four states, kept apart because they need different responses, plus
`relocated` for an identity change. `gone`, `version-gone` and `yanked` block
in `trustScore`, so an unavailable entry reads as `avoid`. A feed that did not
answer is never recorded — that would empty the DB the first time npm had a bad
minute.

### Who published it? (`identity`)

The [official MCP registry](https://registry.modelcontextprotocol.io) answers
the one question this DB cannot: **who published this, under a name they proved
they own.** Its namespaces are ownership-verified at publish —
`io.github.<owner>/<name>` requires authenticating as that GitHub account, a
reverse-DNS namespace requires control of the domain. Nothing else here is
proved in that sense: npm's `repository.url` is typed by the publisher, and our
`source_url` is typed by a pull request.

```bash
mcp-vault identity
```

So this repo is not a competing registry — it is a security overlay over one:

```
official registry  →  who published it, under a name they proved they own
mcp-vault          →  supply-chain evidence, policy, behaviour
```

11 entries are listed as of 2026-09-30 and all of them agree; a verified namespace under a
different owner is the finding worth having. **Being unlisted is explicitly not
a finding** — listing is opt-in and 101 entries simply are not listed.

This check replaced a field. The DB used to carry `in_registry`, a hand-set
boolean worth 30 points of health score that had never been compared with
anything; it disagreed with the live registry for 26 of 114 entries. The
boolean is gone, and whether an entry is listed is now measured here, dated,
and worth 5 points of trust.

### How is the upstream repo run? (`posture`)

OpenSSF Scorecard, read through deps.dev: branch protection, code review,
dangerous workflow triggers, token permissions, pinned actions, signed
releases. An artifact can be perfectly verified and come out of a repository
anybody can push to.

```bash
mcp-vault posture
```

The checks are recorded individually rather than as Scorecard's 0–10 average —
an average puts "there is a SECURITY.md" and "a fork can trigger the release
workflow" into one number. Scorecard's `-1` ("could not run this check") is
recorded as `unknown`, never as a failure. Coverage is stated rather than
implied: **4 of 113** entries have a report, and the other 109 read "no
report".

### What can it do, and what did it gain? (`capabilities`)

The blind spot the rest of this repo cannot see: a patch release that starts
reading `process.env` and shelling out is not a hash mismatch and does not have
a CVE yet. Between "compromised release published" and "advisory published", an
integrity scanner is blind.

```bash
mcp-vault capabilities                 # only versions not scanned before
mcp-vault capabilities --all --write   # rebuild the baseline
```

The published tarball is read in memory (nothing is unpacked to disk) and every
match is recorded with a file and a line. Across the 105 package versions
scanned so far — every npm entry's current pin, plus the six pins those entries
moved off, kept as the baseline their delta is computed against — it can read:

```
env_access  89    shell           38    dynamic_code      16
network     79    install_script  32    dynamic_require    8
fs_read     62    fs_write        41    credential_paths   5
```

31 of those packages can both run other programs and reach the network. 20 of
104 ship at least one minified file, where a pattern scan can show presence and
nothing else.

Two rules make this honest rather than theatrical:

1. **`found` is a fact; `absent` is never recorded.** Not finding a capability
   says something about the detector, not the package — minified bundles,
   dynamic requires and runtime-built strings all defeat a pattern scan. There
   is no `absent` list in the output to be mistaken for a finding, and every
   scan carries a coverage block describing what was actually read.
2. **Additions are findings; disappearances are not improvements.** A
   capability that stopped matching is as likely to mean a new bundler as a
   changed behaviour, and it is reported with exactly that wording.

History lives in `assets/capabilities.json` keyed by `npm:pkg@version`, so a
version bump in a pull request shows its capability delta *in the diff*. Scope:
the package's own files — a capability arriving through a dependency is
`verify --deps`' job, and PyPI needs a zip reader it does not have yet (those
13 entries report `unsupported`, not "nothing found").

### What do the tools tell the model? (`tool-scan`)

A tool description is an instruction the model follows on every request, and
nothing that checks the artifact reads it. `eval` already has the text in hand
when `tools/list` answers, so it runs a fixed rule table over every name,
description, parameter description and enum value: hidden Unicode (Tags
characters and variation-selector runs are *decoded*), bidi and zero-width
controls, ANSI/OSC escapes, "ignore previous instructions", "do not tell the
user", `<IMPORTANT>`, credential and MCP-config paths, references to other
tools, encoded blobs, and schemas with a catch-all `sidenote`/`notes`/`context`
parameter the description never mentions.

```bash
mcp-vault tool-scan tools.json          # a captured tools/list, offline
mcp-vault tool-scan                     # what eval stored (rule, tool, location — no text)
mcp-vault eval --installed --sandbox    # scan the servers your hosts launch
mcp-vault tool-scan --rules             # the table: id, severity, why
```

Each match is a finding `tool-scan/<rule>` on the tool it was found in, and
the verdict is the `tool-scan/*` row of the one policy table: high denies in
`tool-scan` and in `eval --fail-tool-scan`, medium warns, low is listed with
`--show-low`. `explain` shows the same outcomes as context beside the gate's
answer ("refused beside the gate"): the integrity gate does not read the scan,
and explain's exit code is the gate's. Recorded with `eval --record-evidence`
it also blocks trust through a `tool_descriptions` evidence dimension.
"Nothing was read" is never "clean": a row listed before the scan existed is
`not-run`, a `tools/list` with an unfetched next page or an empty one is
`no-data`, a scan older than 30 days is `stale` — each decides to `unknown`
(which `--strict` / `--fail-unverified` fail). `--json` is
`mcp-vault/findings@1`, `--sarif` its SARIF, `--as-of` replays a date. No
rule firing is not a clean bill either: plain polite English matches nothing
here.

### So what do I install instead? (`upgrade`)

"Affected by GHSA-2h44-8472-frjj" is correct and not actionable. OSV carries a
`fixed` version per advisory, so the target is *computed*: the highest fix
across every advisory that applies, then the smallest published version that
reaches it.

```bash
mcp-vault upgrade
mcp-vault upgrade --entry chrome-devtools-mcp --json
```

```
UPGRADE  chrome-devtools-mcp chrome-devtools-mcp@0.26.0
  MODERATE  GHSA-3pvj-jv98-qhjq — fixed in 1.1.0
            Chrome DevTools for agents: daemon.pid write follows symlinks in /tmp fallback runtime directory
  MODERATE  GHSA-8qf9-62x2-82pp — fixed in 1.1.0
            chrome-devtools-mcp: validatePath() does not canonicalize symlinks before enforcing roots
  → chrome-devtools-mcp@1.1.0 clears 2 of 2  (latest is 1.10.1)
  verify_integrity.cjs --update will re-pin and re-hash it
```

<sub>`upgrade --entry chrome-devtools-mcp` against OSV.dev on 2026-09-30
(`upgrade` asks OSV live; it has no `--as-of`).</sub>

The shortest hop, not the newest release. The candidate is queried too, because
"fixed in 2.1.30" means fixed for *that* advisory — a recommendation onto a
version with a different CVE would be worse than none. An advisory with no
published fix stays in the output rather than being dropped into a false
all-clear. On 2026-09-30 one entry in this DB is affected — chrome-devtools-mcp,
two MODERATE advisories, which do not fail `verify` — and it has a safe path;
the seven entries with high/critical advisories were moved to the version
`upgrade` computed for each that day.

### Why was it denied? (`explain`)

Everything needed to answer that existed; what did not exist was a way to ask.

```bash
mcp-vault explain mcp-server-aws
mcp-vault explain mcp-server-aws --json --record decisions.jsonl
```

```
DENIED  mcp-server-aws  pypi:awslabs.core-mcp-server@1.0.27
policy: none found — defaults in force · as of 2026-09-30T12:00:00.000Z

  ? availability    yanked (13d old, shelf life 7d)
  ✓ artifact        verified (2026-09-17)
  ✓ source_binding  verified (2026-09-17)
  ? registry        unlisted (2026-09-17)
  ✓ repository_posture clean (2026-09-17)
  ✓ advisories      clean (13d old, shelf life 7d)
  · signature       never checked
  · provenance      never checked
  · license         never checked
  · dependencies    never checked
  · smoke           never checked
  · tool_descriptions never checked

  trust 63/100 (block)   health 75   behaviour never-started
  did not complete a handshake in a clean sandbox (CRASH, exit 1)

Rules:
  ✗ trust/availability             availability is yanked (as of 2026-09-17)
  ✓ policy/unverified              artifact: verified (as of 2026-09-17) (context)
  ! behaviour/never-started        did not complete a handshake in a clean sandbox (CRASH, exit 1) (context)

Blocking: trust/availability
Decided by trust/availability
…
```

<sub>`explain mcp-server-aws --as-of 2026-09-30T12:00:00Z`, exit `1`; the trace
that follows is cut. Every release of awslabs.core-mcp-server is yanked on
PyPI ("load individual MCPs"). Rules marked `(context)` are shown and do not
decide: the exit code is the one `verify --offline --entry mcp-server-aws`
gives on the same inputs.</sub>

Each dimension with the date it was established and whether that date is inside
its shelf life; the policy in force; every rule with its outcome; the rule that
decided it. `--json` emits a decision record and `--record` appends it as one
line — "allowed on this date, under that policy, on this evidence" is what a
policy engine gets asked for six months later and otherwise cannot
reconstruct.

### What actually runs (`lock`)

The gate verifies `server@1.2.3` down to its transitive tree. Then `.mcp.json`
launches `npx -y server@1.2.3`, and npm re-resolves those dependencies at every
start: a pinned root does not pin its tree, so `server@1.2.3` depending on
`lib: ^2` runs whatever `lib` published most recently.

```bash
mcp-vault lock                  # write mcp.lock.json for this project
mcp-vault lock --check          # resolve again and diff (exit 1 on drift)
mcp-vault lock --vendor         # npm ci the locked tree; nothing resolves at launch
```

The lockfile records npm's own lockfile per server (which is what makes
`--vendor` reinstall the *locked* tree rather than a fresh resolve), the
artifact identity, and the tool-surface fingerprint. `--check` distinguishes
ordinary dependency movement from the changes an upgrade does not explain: the
same version with different bytes, a tree that gained an install script, or a
tool surface that changed while the artifact did not.

### Bill of materials (`sbom`)

```bash
mcp-vault sbom --out sbom.json              # the whole registry
mcp-vault sbom --installed --deps --out sbom.json
```

CycloneDX 1.6 (validated against the official schema), with the things this
repo knows and CycloneDX has no field for carried as `mcp-vault:` properties:
the trust tier, each evidence dimension **with the date it was established**,
which dimensions have aged out, the behavioural status, the tool-surface hash,
and for transitive packages the one property that matters most — it runs code
at install time.

### Signed DB and shared audits (`signature`, `audits`)

The DB decides what `install` writes, so the CLI checks it before any command
reads it: an Ed25519 signature over the DB's canonical JSON
(`tools_database.json.sig`, made at release), against the keys shipped in
[`assets/trusted_keys.json`](./mcp-ecosystem-intelligence/assets/trusted_keys.json).
In the installed package, a missing, tampered, unknown-key or revoked-key
signature → the command does not run. A git checkout (development, CI) needs no
`.sig`, though one that is present must verify. Offline, no dependencies. A fork
without `.git` runs on its own DB with `--allow-unsigned-db` (or
`MCP_VAULT_ALLOW_UNSIGNED_DB=1`), which warns on every run.
`mcp-vault signature --json` shows the check on its own, as `mcp-vault/findings@1`.

```bash
mcp-vault audits add <entry> --criteria safe-to-run --who "Me <me@example.org>"
mcp-vault audits export --out audits.json   # signed with $MCP_VAULT_AUDIT_KEY
mcp-vault audits fetch                      # the only network step
mcp-vault audits check                      # offline, re-verifies the lock
```

Audits follow [cargo-vet](https://mozilla.github.io/cargo-vet/importing-audits.html):
who checked which package, version **and integrity**, against which criterion.
Imports are listed in `.mcp-vault.imports.json` (URL or path, the source's
public key, the criteria you accept from it), fetched only on request, kept in
`.mcp-vault.imports.lock.json`, and not transitive. Every bundle must verify
under the key in your config. An imported audit shows in `explain`'s trace as
an observation with its source, and never changes `trust` or the decision.

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

#### Organisation policy

For a tenant-wide allowlist, an org keeps one policy and projects inherit it
with `"extends": "<path>"` (or `MCP_VAULT_ORG_POLICY` on managed machines) — see
[`.mcp-vault.org-policy.example.json`](./.mcp-vault.org-policy.example.json):

```json
{
  "allow": [{ "npmScope": "@modelcontextprotocol" }, { "githubOwner": "microsoft" },
            { "artifact": "npm:@acme/mcp@2.3.1", "integrity": "sha512-…" }],
  "deny": [{ "entry": "mcp-server-everything" }],
  "minTier": "Recommended",
  "requireEvidence": { "signature": 90, "advisories": 7 },
  "denyCapabilities": ["shell"],
  "toolApproval": "require"
}
```

An allow list means default deny, a server outside the vault DB included; a
deny rule outranks every allow. A project file can only tighten the org's: a
looser value is a policy error (exit 2). With `toolApproval: "require"` a new or
changed tool blocks until `mcp-vault approve <server> [--tool X]` records it in
`mcp.lock.json` — the output shows which tools changed, in description or schema.
An approval is for the artifact it was made on, so an upgrade needs a new one, and
a server whose tool surface nobody observed is refused rather than waved through.
The rules are the `org/*` rows of the one rule table, so `verify`, `install`,
`explain`, `lock --check` and `approve` cannot answer differently; `decided_by`
names the rule, and its detail the file and list position that matched.

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

**What the last full run found.** 40 of the 111 entries with a runnable launch command complete a handshake in a clean container; 39 of them list at least one tool, listing 1,021 tools between them, ≈294k tokens of `tools/list` payload if every one were enabled at once. The rest fail for their own reasons — 62 crash, 7 exceed a 90-second deadline, 2 want network access they are not given, 1 wants credentials, 1 needs an argument you have to supply by hand. Those results live in [`assets/eval_results.json`](./mcp-ecosystem-intelligence/assets/eval_results.json) and feed the `behaviour` axis of a recommendation: an entry nothing has ever seen start cannot read as "recommended". 8 entries report a tool count that differs from the DB's (`tool_count_drift`), which is a reviewer's decision rather than an automatic correction.

Each passing run also records a **tool-surface fingerprint** — every tool's name with its description and input schema hashed separately (hashes only: a tool description is attacker-controlled text, and it reaches the model's system prompt) — together with the **identity of what ran**: the artifact id, its integrity value, the DB version and a digest of the launch contract. `tool_count` alone never saw a rename or a rewritten description.

A later run compares both, and can give three answers rather than two:

| | |
|---|---|
| artifact changed + surface changed | an upgrade. Read the diff, then move on |
| artifact unchanged + surface changed | **unexplained**, and the one worth looking at |
| no identity recorded to compare | *not attributable* — said out loud rather than guessed |

"Unexplained" is deliberately not "impossible". An unvendored launch re-resolves
its transitive tree at every start, and feature flags, credentials and a remote
backend can each change what a server advertises. It becomes a hard finding when
the artifact bytes, the dependency closure (`mcp-vault lock`) and the launch
contract are all identical and the surface still differs.

The third answer exists because the first version of this compared `install_cmd`
*strings* and treated a missing field as a change — and the weekly job's snapshot
did not carry that field at all, so every drift read as "explained by a version
bump". A feature that looked like it worked and could not see the case it was
built for.

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
| `secret` | a credential written in plain text into a server's `env`/`args`/`headers`/`url` (see below) |

Exit codes: `0` clean / info-only · `1` a finding that refuses (a plain-text secret), or `--strict` triggered · `2` bad invocation or an unreadable config. Closes the "Audit my MCP setup" use case without an LLM in the critical path.

#### What the set can do together (toxic flows, tool shadowing)

Each server can pass every check and the combination still not be safe.
[`lib/flows.cjs`](./mcp-ecosystem-intelligence/scripts/lib/flows.cjs) labels
every configured server — and every tool, where the eval stored its surface —
`untrusted_content`, `private_data`, `public_sink` or `destructive`, each label
with its evidence (DB category, tool name, MCP annotation, code capability).
It flags a host session that holds all of the first three (the
[lethal trifecta](https://invariantlabs.ai/blog/toxic-flow-analysis)), including
one server alone — `github-mcp-server` reads public issues, private repos and
opens PRs — and untrusted content next to a destructive tool. It also flags two
servers exposing the same tool name, and a description that names another
server's tool (checked through hashed tokens; no description text is stored).
The advice is concrete where the DB knows the server's `toolsets`, and
otherwise says which servers to split into separate profiles.

It runs in `status`, `audit` and `explain <name>`, all offline, and reports
through the one findings model ([ADR 0001](./docs/adr/0001-findings-and-time.md)):
findings `flows/*` on the host's session and `shadowing/*` on the colliding tool,
judged by the policy rows of the same names. A server with no DB entry and no
stored surface is a `flows/no-data` finding (unknown, never clean), and servers
are matched to the vault by what they launch, not by their config key. A flow
that needs a code capability to close is low confidence: reported, never
enforced. `"toxicFlows"` and `"toolShadowing"` in the policy file (`fail` |
`warn` | `allow`, default `warn`) set how loud it is: `warn` fails only under
`--strict`. That is the exit code of `status` and `audit`; `explain <name>`
shows what the entry would do to your set as context, since it answers what
the install gate answers.

### Plain-text secrets in host configs (`secrets`)

`claude mcp add -e GITHUB_TOKEN=ghp_…` writes the token into `~/.claude.json`;
`.mcp.json` is a file teams commit. [`check_secrets.cjs`](./mcp-ecosystem-intelligence/scripts/check_secrets.cjs)
reads every host config the rest of the tool reads (Claude Code, Claude Desktop,
Cursor, VS Code, Codex TOML) — only the server maps, never the rest of
`~/.claude.json` — and reports credentials in `env`, `args`, `headers` and `url`:
known formats (GitHub, GitLab, AWS, Slack, OpenAI, Anthropic, Stripe, Google, JWT,
PEM keys, database URLs with a password, Bearer, tokens in a query string) and
literal high-entropy values under `*TOKEN*`/`*KEY*`/`*SECRET*`/`*PASSWORD*` names.
A `${VAR}` / `${env:VAR}` / `${input:id}` reference is not a finding.

```bash
mcp-vault secrets                 # exit 1 if anything is found
mcp-vault secrets --json          # mcp-vault/secrets@1, findings + decisions as findings@1
mcp-vault secrets --sarif         # for code scanning (rule ids secrets/<rule>)
mcp-vault secrets --fix-suggest   # a suggested edit per finding; nothing is changed
mcp-vault secrets --explain       # the decision trace, rule → finding
```

Each hit is a `secrets/<rule>` finding on a host-config subject (`path:line`),
and the verdict is the `secrets/*` row of the one rule table
([ADR 0001](./docs/adr/0001-findings-and-time.md)): a plain-text secret is
refused whether or not the file is tracked; an unreadable config is `unknown`
(exit 2), never clean.

**The value is never printed** — not in text, `--json`, findings@1, the trace or SARIF: a finding is the
type, file, path to the key, length and a masked prefix of at most four
characters (only a format's public prefix, like `ghp_`; nothing for a heuristic
match). A config tracked by git (`git ls-files`) is severity `high`: the value
is in history, so rotate it. The suggestion uses the syntax each host documents —
`${VAR}` in `.mcp.json`, `${env:NAME}` in Cursor, `inputs` + `${input:id}` in VS
Code, `env_vars` / `env_http_headers` in Codex — and says so where a host
documents none (Claude Desktop, `~/.claude.json`). `audit` reports the same
findings for Claude Code's two files; `status` shows one line. Both fail on
them, as `secrets` does: one host-config line, one answer.

### Lookalike names (typosquatting)

A typosquat passes every registry check — it is a real, signed package — it is
just not the one you meant. [`lib/lookalike.cjs`](./mcp-ecosystem-intelligence/scripts/lib/lookalike.cjs)
compares a name that is *not* in the DB against every entry's name, npm/PyPI
package and image, offline and deterministically: Damerau-Levenshtein with a
length-dependent threshold, homoglyphs (Cyrillic, `0/o`, `1/l`, `rn/m`), `-`/`_`/`.`,
PEP 503, a dropped, added, misspelled or foreign npm scope, a swapped registry,
and added affixes (`-mcp`, `-server`, `-official`, `-js`). A DB entry never flags
another; a test checks the whole DB, and with each entry left out in turn.

```text
$ mcp-vault install mcp-server-memmory
REFUSED: npm package mcp-server-memmory is not in the vault but looks like mcp-server-memory
(npm @modelcontextprotocol/server-memory) — a doubled letter. Likely an impersonation of mcp-server-memory.
```

Each hit is a `lookalike/<technique>` finding on the *name*
([`mcp-vault/findings@1`](./docs/adr/0001-findings-and-time.md)), and one row,
`lookalike/*` in [`lib/policy_rules.cjs`](./mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs),
decides it: a name you *ask for* (`install`, `explain`) is refused — `install`
exits `2` as for any unknown name, `--json` prints the findings document; a name a
host config *launches* (`audit`, `verify --installed`, including a config key that
is a vault name but launches another package) warns, which fails under `--strict`.
`--allow-lookalike <name>` is an input to that row: still reported, allowed.

### Public registry page

[`scripts/generate_registry_page.cjs`](./mcp-ecosystem-intelligence/scripts/generate_registry_page.cjs) renders the DB into `docs/site/registry.html` plus `docs/site/registry.json`:

```bash
mcp-vault site-registry
```

The generated page is static, searchable, and filterable by category, tier, and trust. It is meant to be published with the rest of the GitHub Pages site.

### Badges

The same run renders a badge per entry into `badges/` under the site root — a flat SVG drawn by [`lib/badge.cjs`](./mcp-ecosystem-intelligence/scripts/lib/badge.cjs), no external service, plus a shields.io endpoint JSON — and an evidence page per entry under `entry/` that the badge links to. It carries the derived tier and the date of the newest evidence; once a check the tier rests on is past its shelf life it says `stale` in grey, and a failed check says `blocked` in red. None of that is decided by the badge: `blocked` is the entry's Decision from `decide()` being `deny`, `stale` is an observation's state at `--as-of`, and `badge --json` carries the `findings@1` document it was read off.

```bash
mcp-vault badge <name>          # README snippet (Markdown / HTML / shields), --json, --as-of
mcp-vault site-registry --out <site root> --base-url https://mcp.froggychips.xyz
```

`--out` defaults to `docs/site` in a checkout and `--base-url` to `https://mcp.froggychips.xyz`; every link on a badge and in a snippet is built from the base URL. The public site is assembled in [froggychips/mcp-site](https://github.com/froggychips/mcp-site), which runs these generators from the npm release into its own root — the generated files are not committed here.

[`.github/scripts/finding_reports.cjs`](./.github/scripts/finding_reports.cjs) drafts a short issue text for each entry with a real finding (advisory, repository mismatch, yanked or unpublished release, install scripts in the tree, tool surface changed without a release). It writes files only; nothing is opened in anyone's repository.

### Sub-registry of the official MCP Registry (`export-registry`, `registry-ingest`)

[`scripts/export_subregistry.cjs`](./mcp-ecosystem-intelligence/scripts/export_subregistry.cjs)
writes the DB as a static [sub-registry](https://modelcontextprotocol.io/registry/registry-aggregators#acting-as-a-subregistry):
the registry's own read API (v0.1) as files under `<out>/v0.1/`, so a host
that already speaks it can point at the site's base URL — VS Code's
`McpGalleryServiceUrl`, or ToolHive via `v0.1/x/xyz.froggychips.mcp/toolhive.json`.
`site-registry` runs it too, with the same `--out` / `--base-url`, so the page
and the API describe the same DB.

The export is not committed to this repo. The site
([mcp.froggychips.xyz](https://mcp.froggychips.xyz)) lives in
`froggychips/mcp-site`, whose workflow installs a released
`@froggychips/mcp-vault` from npm and runs the generators with the site's root
as `--out`. Locally the default `--out` is `docs/site`, where `v0.1/` is
git-ignored.

```bash
mcp-vault export-registry --out <site root> --base-url https://mcp.froggychips.xyz
mcp-vault site-registry   --out <site root> --base-url https://mcp.froggychips.xyz   # page + export
mcp-vault export-registry --out <site root> --check   # exit 1 if the tree there is stale
mcp-vault registry-ingest --fetch --out snap.json      # the only networked step
mcp-vault registry-ingest --snapshot snap.json         # exit 1: a pinned/latest version deleted upstream (--strict: deprecated too)
mcp-vault discover --source registry-snapshot --snapshot snap.json
```

Each entry is a valid `server.json` (validated in the tests against the vendored
2025-12-11 schema) with a pinned package — npm/PyPI by exact version, images as
`oci` by `@sha256` digest — and our evidence under
`_meta["xyz.froggychips.mcp/vault"]`: tier and why, pinned version and
integrity, the date of each check, and how to ask `explain`. The `verdict`
there is the entry's Decision — effect, the rule that decided it, why, as of
when — made by `decide()` over the stored evidence exactly as `explain` makes
it, under the vault's own rules only — like a badge, the export is the vault's
public statement, so a `.mcp-vault.policy.json` in the directory it runs from
is not applied; `tier_holds_until` is the first
instant a piece of that evidence ages out. The name is the official one only
when `identity` recorded it; everything else is published under
`xyz.froggychips.mcp/…`, never under a namespace nobody proved. A denied entry,
a Deprecated tier, or nothing pinned is not exported — a host that ignores
`_meta` would offer it. Everything is judged as of one instant: now, or
`--as-of` (`--check` replays the instant the export on disk was made at), and
the same DB and instant give the same bytes; the manifest
(`export.json`) hashes every file, and `--json` adds the findings@1 document.

Both defaults are one constant each in
[`lib/subregistry.cjs`](./mcp-ecosystem-intelligence/scripts/lib/subregistry.cjs):
`NAMESPACE` (the `_meta` key, the names of unlisted entries and the `v0.1/x/…`
directory) and `DEFAULT_BASE_URL`. Every absolute URL the export writes — the
`explain.page` link in `_meta`, the ToolHive file's `meta.source` — is built from
`--base-url`, and the manifest records it as `base_url`.

What static hosting cannot do: `search`, `updated_since`, `version`,
`include_deleted`, `limit` and `cursor` are ignored — every list request gets
the whole list as one page with no `nextCursor`. Names are written both
`%2F`-encoded and as subdirectories, because static hosts disagree about
decoding `%2F`.

Content-Type on GitHub Pages is chosen by extension, so the API paths come back
as `text/html` (list endpoints are `index.html`, reached via a `301` from
`/v0.1/servers` to `/v0.1/servers/`) and `application/octet-stream` (single
versions have no extension). The bodies are JSON. The clients checked parse the
body and ignore the header: VS Code's gallery (`asJson` is a bare `JSON.parse`)
and ToolHive's registry client (`json.NewDecoder`, redirects followed). A client
that insists on `application/json` can use the `.json` twin every endpoint has,
same bytes:

| API path (what a client builds from the base URL) | `.json` twin (`application/json`) |
|---|---|
| `/v0.1/servers` | `/v0.1/servers.json` |
| `/v0.1/servers/<name>/versions` | `/v0.1/servers/<name>/versions.json` |
| `/v0.1/servers/<name>/versions/latest` | `…/versions/latest.json` |
| `/v0.1/servers/<name>/versions/<version>` | `…/versions/<version>.json` |
| — | `/v0.1/x/xyz.froggychips.mcp/toolhive.json` (ToolHive, one file) |

A client that needs the header on the API paths themselves needs a real server
(or a proxy in front of Pages) — a static host cannot provide it.

`registry-ingest` goes the other way. It saves a full snapshot of the official
registry (all or nothing, deleted servers included), then offline reports DB
entries whose server is `deprecated` or `deleted` — the latest version *or the
exact version pinned here* (for images: the pinned digest, or the release
version as tag) — and the listed servers the DB lacks. It never edits the DB.
Withdrawals are findings (`registry/deleted-upstream`, high;
`registry/deprecated-upstream`, medium; `registry/pinned-unseen`, not-run, when
a latest-only snapshot cannot see the pin) and the exit code is `decide()`'s:
`--strict` fails on a deprecation, `--fail-unverified` on an unseen pin, and
`--as-of` replays a saved snapshot.

### Health scorer

[`scripts/calculate_health.cjs`](./mcp-ecosystem-intelligence/scripts/calculate_health.cjs) — score any MCP candidate:

```bash
mcp-vault health \
  <stars> <last_commit_days> <has_install_cmd> <critical_issues> [license]
```

```
score = min(20, 10·log10(stars+1))   # popularity, capped
      + {40|20|10|0}                  # recency: <30d / <90d / <180d / older
      + 15 if install_cmd documented
      + 5  if open_issues/10 < 5
      − 10 if license is non-OSI / source-available / Unknown
```

It answers one question — *is this project maintained?* — and it names no tier.
Thresholds over it were measured against the real DB and abandoned: with the
registry bonus removed, scores run 40–80 with a median of 75 and **91 of 114
entries land in the top bucket**, because a curated database is popular and
recently committed by construction. A label 80% of rows share is not a label.
The tier comes from evidence instead — see the table under [Vetted
database](#vetted-database).

### Vetted database

`mcp-ecosystem-intelligence/assets/tools_database.json` — **112 entries** across ~26 categories, all with pinned versions, integrity hashes (npm sha512 / PyPI sha256 / Docker @sha256), SPDX license, and `trust` field.

```
ai        browser   ci-cd      cms       communication   crm
database  demo      docs       filesystem http            infra
maps      memory    meta       mobile     observability   payments
pm        reasoning search     testing    utility         vcs       web-scraping
```

Distribution as of 2026-09-30 (the date of the newest evidence in the DB): **0 Core / 10 Recommended / 101 Experimental / 1 Deprecated**.
On that date only the nine entries re-checked that day carry fresh evidence. The
rest hold evidence from 2026-09-17, and wherever it includes `availability` or
`advisories` (a seven-day shelf life) it has aged out, so those 101 read
Experimental until the next refresh.
That is a snapshot, not today's split: evidence has a shelf life, so an entry
whose claims have aged out reads as Experimental on a later day even though no
commit touched it. `mcp-vault list` (whole DB) and `mcp-vault status` (what you
have installed) classify against today.

The tier is derived from the evidence below, not stored in the DB and not a
threshold on `health_score`:

| Tier | What was established |
|---|---|
| Core | the artifact is verified, the evidence is about this artifact, and a run of **that pinned reference** started and listed tools |
| Recommended | the artifact is verified and current; either nothing watched it run, or what watched it cannot be tied to this artifact |
| Experimental | too little is known — a required check never happened, a claim aged out, or the stored evidence is about a different artifact than this entry now installs |
| Deprecated | do not install — and only for what the trust gate blocks on: nothing to install, bytes that are not the bytes we verified, or an advisory against this version |

**Core is empty today, and that is the tier working.** 38 entries start and
list tools — but no row in the eval snapshot records *which artifact it
launched*, and a pass for `x@1` is not a statement about `x@2`.

There was a second reason, and it was worse: the eval read that artifact id off
the DB's `version` field while launching the entry's `install_cmd` — and **80
of the 114 entries ship an unpinned command** (`npx -y pkg`; the verified
version lives in `version`, and `install` pins it on the way out). So a run of
`npx -y pkg` would have been recorded as a run of `pkg@1.0.0`. The eval now
pins before launching, and an entry it cannot pin records no artifact id at
all. The next weekly run fills the field truthfully and Core comes back on its
own; guessing in the meantime is the one thing this repository cannot do.

`Core` is deliberately narrower than "we know these bytes ran". The eval
launches `pkg@1.2.3` and does not re-hash what the registry handed it, so a
configured index could serve something else under that name — true of npm and
PyPI alike. Core says the reference was pinned, verified, and seen to run;
`artifact` is the dimension that says the bytes at that reference matched their
hash when the gate last fetched them.

Behaviour promotes but never demotes. 59 verified entries did not complete a
handshake, and the sandbox runs with an empty environment — `@azure/mcp`,
`@heroku/mcp-server` and their kind exit 1 because no API key was present.
Recording that as a fact about the server would be the same mistake as reading
a check that did not happen as a check that passed.

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

### In your repo: GitHub Action and pre-commit

```yaml
- uses: froggychips/mcp-skills-vault@<full commit SHA>   # vX.Y.Z
```

Checks the servers in the repository's `.mcp.json`, `.vscode/mcp.json` and
`.cursor/mcp.json` (`verify --offline --fail-on unknown --config …`), writes the
decisions into the job summary, and optionally uploads SARIF onto the config lines.
It runs the action's own checkout — no npm install, no token, no network — so
the SHA in `uses:` is the gate's pin. A `pre-commit` hook (`id: mcp-vault`) does
the same for staged configs. Inputs, a `pull_request` workflow to copy, and the
hook: [`docs/GITHUB_ACTION.md`](./docs/GITHUB_ACTION.md).

### CI

`.github/workflows/security-scan.yml` runs eight jobs across PRs, pushes and two
weekly crons; `.github/workflows/codeql.yml` adds static analysis.

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
- **refresh-hashes** — Monday cron. The evidence-collecting job: refreshes
  `version` + `pkg_integrity` from live registries, re-verifies with `--deep
  --record-evidence`, then runs `availability`, `identity`, `posture` and
  `capabilities` (all `--write`) and computes safe upgrade paths for anything
  with an advisory. Each one writes a table into the job summary — availability,
  registry identity, capability delta, upgrade targets — and the whole lot
  arrives as one human-gated PR. Never auto-merged: this PR is the only gate
  between a registry publishing something and this DB blessing it.
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
  changed entries, advisory (never blocks merge). In
  [its own workflow](./.github/workflows/mcp-eval-pr.yml) rather than in
  `security-scan.yml`: it checks out the PR head, and a file that cannot start
  from `schedule` or `workflow_dispatch` says so without depending on an `if:`
  that a later trigger could outlive.
- **codeql** — pushes to master, PRs touching code or workflows, and a weekly
  cron. `javascript-typescript` and `actions`, `security-extended`. Advanced
  setup on the self-hosted runner: the default setup is hard-wired to
  GitHub-hosted runners, which this account cannot start, so every "CodeQL
  Setup" run failed before executing a step. The `actions` queries are the ones
  worth a runner slot — the CI problems fixed in this repo lately (a
  `pull_request_target` boundary, a token scoped wider than its job, unpinned
  third-party actions) are exactly what they look for, and a human found all of
  them.

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
| Typosquat / lookalike names refused at install, flagged in audit | [`lib/lookalike.cjs`](./mcp-ecosystem-intelligence/scripts/lib/lookalike.cjs) |
| One-line GitHub Action and pre-commit hook over a repo's MCP configs | [`action.yml`](./action.yml), [`.pre-commit-hooks.yaml`](./.pre-commit-hooks.yaml) |
| Token budget for a real config | [`token_budget.cjs`](./mcp-ecosystem-intelligence/scripts/token_budget.cjs) |
| Machine-readable report + SARIF | [`lib/report.cjs`](./mcp-ecosystem-intelligence/scripts/lib/report.cjs) |
| Behavioural smoke in a rebuilt jail | [`mcp_eval.cjs`](./mcp-ecosystem-intelligence/scripts/mcp_eval.cjs), [`lib/mcp_stdio.cjs`](./mcp-ecosystem-intelligence/scripts/lib/mcp_stdio.cjs) |
| Discovery pipeline (npm / gh / README) | [`discover.cjs`](./mcp-ecosystem-intelligence/scripts/discover.cjs) |
| Static sub-registry export (MCP Registry API v0.1) + official-registry ingest | [`lib/subregistry.cjs`](./mcp-ecosystem-intelligence/scripts/lib/subregistry.cjs), [`lib/registry_snapshot.cjs`](./mcp-ecosystem-intelligence/scripts/lib/registry_snapshot.cjs) |
| Wrapper generator (CLI/API → MCP) | [`generate_wrapper.cjs`](./mcp-ecosystem-intelligence/scripts/generate_wrapper.cjs) |
| Provenance bound to the artifact digest, not just read | [`lib/npm_signatures.cjs`](./mcp-ecosystem-intelligence/scripts/lib/npm_signatures.cjs) |
| Behaviour capping the recommendation | [`lib/scores.cjs`](./mcp-ecosystem-intelligence/scripts/lib/scores.cjs) |
| Gone / yanked / deprecated / relocated packages | [`check_availability.cjs`](./mcp-ecosystem-intelligence/scripts/check_availability.cjs) |
| Ownership-verified identity from the official registry | [`lib/mcp_registry.cjs`](./mcp-ecosystem-intelligence/scripts/lib/mcp_registry.cjs) |
| Upstream repository posture (OpenSSF Scorecard) | [`lib/scorecard.cjs`](./mcp-ecosystem-intelligence/scripts/lib/scorecard.cjs) |
| Capability presence with evidence, and the version-to-version delta | [`lib/capabilities.cjs`](./mcp-ecosystem-intelligence/scripts/lib/capabilities.cjs), [`lib/tarball.cjs`](./mcp-ecosystem-intelligence/scripts/lib/tarball.cjs) |
| Tool-surface fingerprint, for the rug-pull case | [`lib/surface.cjs`](./mcp-ecosystem-intelligence/scripts/lib/surface.cjs) |
| Tool poisoning in descriptions and schemas, by rule | [`lib/tool_scan.cjs`](./mcp-ecosystem-intelligence/scripts/lib/tool_scan.cjs), [`check_tool_descriptions.cjs`](./mcp-ecosystem-intelligence/scripts/check_tool_descriptions.cjs) |
| Lockfile + vendored tree, so nothing re-resolves at launch | [`lib/lockfile.cjs`](./mcp-ecosystem-intelligence/scripts/lib/lockfile.cjs), [`lock.cjs`](./mcp-ecosystem-intelligence/scripts/lock.cjs) |
| Org allowlist / denylist, inherited and only tightened; tools approved one by one | [`lib/org_policy.cjs`](./mcp-ecosystem-intelligence/scripts/lib/org_policy.cjs), [`approve.cjs`](./mcp-ecosystem-intelligence/scripts/approve.cjs) |
| Shortest safe upgrade for anything with an advisory | [`suggest_upgrade.cjs`](./mcp-ecosystem-intelligence/scripts/suggest_upgrade.cjs), [`lib/versions.cjs`](./mcp-ecosystem-intelligence/scripts/lib/versions.cjs) |
| A decision, with the rule that made it, as an audit record | [`explain.cjs`](./mcp-ecosystem-intelligence/scripts/explain.cjs) |
| CycloneDX SBOM | [`sbom.cjs`](./mcp-ecosystem-intelligence/scripts/sbom.cjs) |
| Signed DB checked before use; signed, non-transitive audit imports | [`lib/signing.cjs`](./mcp-ecosystem-intelligence/scripts/lib/signing.cjs), [`lib/audits.cjs`](./mcp-ecosystem-intelligence/scripts/lib/audits.cjs) |
| Context ceiling enforced where the set changes | [`lib/budget.cjs`](./mcp-ecosystem-intelligence/scripts/lib/budget.cjs) |
| Toxic flows and tool shadowing across the configured set | [`lib/flows.cjs`](./mcp-ecosystem-intelligence/scripts/lib/flows.cjs) |
| Tier derived from evidence, not from a score | [`lib/tiers.cjs`](./mcp-ecosystem-intelligence/scripts/lib/tiers.cjs) |
| One command instead of six | [`status.cjs`](./mcp-ecosystem-intelligence/scripts/status.cjs) |
| Plain-text secrets in host configs, never printed | [`lib/secrets.cjs`](./mcp-ecosystem-intelligence/scripts/lib/secrets.cjs), [`check_secrets.cjs`](./mcp-ecosystem-intelligence/scripts/check_secrets.cjs) |
| Badges that go grey when the evidence ages | [`lib/badge.cjs`](./mcp-ecosystem-intelligence/scripts/lib/badge.cjs), [`badge.cjs`](./mcp-ecosystem-intelligence/scripts/badge.cjs) |
| The documented numbers checked against the data | [`tests/docs_numbers.test.cjs`](./tests/docs_numbers.test.cjs) |
| What will not change without a major bump | [`docs/COMPATIBILITY.md`](./docs/COMPATIBILITY.md) |
| One findings model and one place that decides; time as an explicit input (`--as-of`) | [`docs/adr/0001`](./docs/adr/0001-findings-and-time.md), [`lib/finding.cjs`](./mcp-ecosystem-intelligence/scripts/lib/finding.cjs), [`lib/policy_rules.cjs`](./mcp-ecosystem-intelligence/scripts/lib/policy_rules.cjs), [`lib/clock.cjs`](./mcp-ecosystem-intelligence/scripts/lib/clock.cjs) |

**Not shipping the next feature until three people have used this and said
something about it.** 33 npm downloads a month, 0 stars, 0 referrers, 41 clones
against 7 views — the honest reading is that no human has used it yet, and with
no telemetry (by promise) the only instrument left is somebody saying so. The
reasoning, what counts as a user, and what to ask them:
[`docs/ADOPTION.md`](./docs/ADOPTION.md); re-measure with
`node .github/scripts/adoption.cjs`.

Still judgement, not script — deliberately: the reject heuristics (5-Minute
Rule, Bloat, Duplication) and promoting a candidate to `trust: verified`. And
still open: PyPI capability scanning (sdists and wheels need a zip reader), a
capability delta across the *dependency* tree rather than the top-level package,
and Scorecard's coverage, which is 4 of 113 repositories and not something this
repo can fix. The
typed `artifact`/`launch` model exists in
[`lib/entry_model.cjs`](./mcp-ecosystem-intelligence/scripts/lib/entry_model.cjs)
and is asserted to reproduce every entry's `install_cmd`; consumers still read
the string, and moving them over is the next step.

---

## Token cost management

Every active MCP server injects its full tool list into Claude's system prompt (~200–500 tokens per tool). With 112 servers in the DB the spread is wide: `mcp-server-fetch` = 1 tool vs. `gitlab-mcp` = 153 tools.

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
mcp-vault site-registry             # regenerate docs/site/registry.html (+ git-ignored v0.1/)
```

---

## Topics

`claude-code` · `claude-skill` · `mcp` · `model-context-protocol` · `mcp-server` · `mcp-tools` · `anthropic` · `ai-agents`

## License

[MIT](./LICENSE)
