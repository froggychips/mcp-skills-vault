# mcp-vault

[![npm](https://img.shields.io/npm/v/@froggychips/mcp-vault.svg)](https://www.npmjs.com/package/@froggychips/mcp-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0-brightgreen.svg)](./package.json)
[![tests: 1230 passing](https://img.shields.io/badge/tests-1230%20passing-brightgreen.svg)](./tests)

**Offline security check for MCP configs in CI.**

A GitHub Action, pre-commit hook and CLI that flag unpinned MCP servers, plaintext secrets, typosquats, tool poisoning and toxic tool flows — offline, zero dependencies, no telemetry.

It reads the MCP configs committed to a repository (`.mcp.json`,
`.vscode/mcp.json`, `.cursor/mcp.json`) and fails the build before anyone's
editor launches something it should not.

## Add to CI in one line

```yaml
# .github/workflows/mcp-vault.yml
name: mcp-vault
on:
  pull_request:
    paths: ['**/.mcp.json', '**/.vscode/mcp.json', '**/.cursor/mcp.json', '.mcp-vault.policy.json']
permissions:
  contents: read
jobs:
  mcp-vault:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1   # v7.0.1
        with:
          persist-credentials: false
      - uses: froggychips/mcp-skills-vault@<sha>   # v0.16.0 — the full 40-character commit SHA
        with:
          paths: '**/.mcp.json **/.vscode/mcp.json **/.cursor/mcp.json'
```

Replace `<sha>` with the full commit SHA of a release tag (`git ls-remote
https://github.com/froggychips/mcp-skills-vault refs/tags/v0.16.0`). The action
runs its own checkout — no `npm install`, no token, no network — so the SHA
pins both the checker and the data it checks against; a tag or branch would let
both change under you, and the action warns when it is not given a SHA. The
job summary lists every decision; `sarif: true` puts findings on the config
lines in code scanning. All inputs, outputs and the pre-commit hook:
[docs/GITHUB_ACTION.md](./docs/GITHUB_ACTION.md).

## What it prints

On [`examples/insecure/.mcp.json`](./examples/insecure/.mcp.json):

```text
$ npx -y @froggychips/mcp-vault check examples/insecure/.mcp.json --as-of 2026-09-30T12:00:00Z
examples/insecure/.mcp.json
  (the config as a whole)
    ! browser alone reads untrusted content and can run destructive actions [flows/untrusted-destructive: warn]
      fix: require approval for browser's destructive tools (browser_drop, browser_evaluate, browser_run_code_unsafe), or scope them out (DB hint: --caps core)
  :3 browser
    ! this config launches @playwright/mcp@latest, a tag rather than a version: whatever is latest at each start runs [config/unpinned-launch: warn; so pin/missing: unknown]
      fix: pin it to the version the vault verified (playwright-mcp): "args": ["-y","@playwright/mcp@0.0.75"]
  :7 memory
    ! this config launches mcp-server-memmory without a version: whatever is latest at each start runs [config/unpinned-launch: warn; so pin/missing: unknown]
      fix: pin to an exact version (mcp-server-memmory@<x.y.z>)
    ! npm package mcp-server-memmory is not in the vault but looks like mcp-server-memory (npm @modelcontextprotocol/server-memory) — a doubled letter: mcp-server-memmory vs mcp-server-memory. Likely an impersonation of mcp-server-memory. [lookalike/doubled-letter: warn]
      fix: if you meant the vetted server: mcp-vault install mcp-server-memory; if this one is yours: --allow-lookalike mcp-server-memmory
  :11 postgres
    ! this config launches @modelcontextprotocol/server-postgres from a source other than the public registry: installs from another registry (--registry). [config/launch-source-override: unknown; so verify/unverified: unknown]
      fix: launch it from the public registry, or verify that source yourself
  :14 postgres
    ✗ postgres connection string with a password in plain text at mcpServers.postgres.env.DATABASE_URL (15 chars, …) [secrets/connection-string: deny, fails]
      fix: replace it with mcpServers.postgres.env.DATABASE_URL: "postgres://app:${DATABASE_URL}@db.internal:5432/app" and set the value in the environment

FAIL — 1 failing, 5 to look at · 3 servers in 1 config · fail on deny · offline
```

Exit `1`. The password is never printed — only its type, location and length.
With `--strict`, or `--fail-on unknown` as the Action uses by default, the
other five fail too.

## What it catches

| Check | Example finding | How to fix |
|---|---|---|
| Unpinned launch | `npx -y @playwright/mcp@latest`, a range like `^1.2`, no version at all | pin the exact version; for a known server the fix line gives the verified one |
| Plaintext secret | a token, API key, `Bearer …` or database password in `env`, `args`, `headers` or `url` | move it to the environment and reference it (`${VAR}`, `${env:VAR}`, `${input:id}` — the syntax your host documents) |
| Typosquat / lookalike | `mcp-server-memmory`, a homoglyph, a swapped or dropped npm scope, an added `-official` | use the real package, or `--allow-lookalike <name>` if it is yours |
| Package source override | `--registry`, `--userconfig`, a uv index, `npm_config_registry` in the server's env | launch from the public registry, or verify that source yourself |
| Known server, other version | a server the vault knows, launched on a version the vault never verified; with `--online`, a hash that differs from the registry's or a live advisory | move to the version the vault verified (`mcp-vault upgrade` computes the shortest safe one when an advisory applies) |
| Tool poisoning | a tool description with hidden Unicode, ANSI escapes, "ignore previous instructions", credential paths — via `mcp-vault tool-scan` on a captured `tools/list`, or `eval --installed --sandbox` for your own servers. `check` applies stored scans; the eval snapshot shipped today carries none yet | drop or replace the server; report it upstream |
| Toxic flows, shadowing | one config that reads untrusted content, reaches private data and can send outward; two servers exposing the same tool name | split servers into separate configs, or scope out the tools (the fix line names them) |
| Organisation policy | a server outside your allowlist, a denied licence or capability, an unapproved tool change | add it to the allowlist, or `mcp-vault approve <server>` |

Every finding has a rule id (`config/unpinned-launch`, `secrets/connection-string`,
…) and lands on the config line it is about, in text, JSON and SARIF.

## Run it locally

```bash
npx -y @froggychips/mcp-vault check                      # .mcp.json, .vscode/mcp.json, .cursor/mcp.json here
npx -y @froggychips/mcp-vault check path/to/.mcp.json --strict
```

`check` reads exactly those files and nothing from your home directory, so the
answer is the same on every machine. Offline by default; `--online` adds the
live registries and advisory feeds. As a pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/froggychips/mcp-skills-vault
    rev: <sha>   # v0.16.0 — `pre-commit autoupdate --freeze` writes it
    hooks:
      - id: mcp-vault
```

## Your own machine: `status`

```bash
npx -y @froggychips/mcp-vault status
```

One screen over every MCP host config on this machine — Claude Code (project
and user), Claude Desktop, Cursor, VS Code, Codex: what is installed, which
servers launch a version nobody verified, plaintext secrets, context cost,
toxic flows. No network calls. `mcp-vault secrets` lists the plaintext
credentials alone; `mcp-vault audit` is the long form.
[All commands](./docs/REFERENCE.md).

## Policy for organisations

A `.mcp-vault.policy.json` in the repository sets the bar once for CI and for
everyone's shell (`"unpinnedLaunch": "fail"`, `"signatures": "require"`, licence
deny lists, …). An organisation can keep one policy with an allowlist —
default deny, by npm scope, GitHub owner, registry namespace, entry or pinned
artifact — that projects inherit with `"extends"` and can only tighten, plus
per-tool approval recorded in `mcp.lock.json`. An unknown key is an error, not
a no-op. [Policy and org policy](./docs/HOW-IT-DECIDES.md#policy).

## How it decides

Every check produces **findings** with a state — `observed`, or `not-run`,
`no-data`, `stale` — and one function, `decide()`, turns findings and the
policy into a **decision** per subject: `allow`, `warn`, `unknown` or `deny`,
with the rule that decided it. "Nobody looked" is `unknown`, never clean.

- **Exit codes:** `0` nothing fails, `1` something fails, `2` could not answer
  (unreadable config or policy, bad arguments). `2` never means clean.
- **Threshold:** `check` fails on `deny` by default; `--fail-on unknown` also
  fails what could not be checked; `--strict` (= `--fail-on warn`) fails
  warnings too.
- **Time is an input:** stored evidence has a shelf life, so `--as-of <date>`
  replays a decision at a fixed instant. Same DB, policy, `--as-of` and
  version → same bytes:
  `result = f(db, evidence, policy, asOf, rules_version)`.

[How it decides](./docs/HOW-IT-DECIDES.md) · [ADR 0001](./docs/adr/0001-findings-and-time.md)

## The vault DB: extra signal for known servers

The checks above work on any config. For servers the vault knows — a curated DB of 112 known servers — it adds a reference point: the verified version
and hash (npm sha512, PyPI sha256, Docker `@sha256`), recorded advisories,
availability (yanked, unpublished), the npm registry signature, provenance
bound to the artifact digest, and a behavioural smoke run. Each claim is dated
and expires. `check` compares a launched version with that pin (and with
`--online` re-checks hash and advisories live); `status` and `explain` also
apply the stored evidence. A server the DB does not know is reported as *not
in the vault* — `unknown`, not clean. The DB ships signed (Ed25519) in the npm
package. [What is in it](./docs/DATABASE.md).

## What it is not

- **Not a sandbox and not a runtime monitor.** It reads configs before
  anything runs; it does not watch what a server does. ([mcp-trace](https://github.com/froggychips/mcp-trace)
  is an experimental sister project for that.)
- **Weak on remote servers.** An HTTP/SSE server ships no artifact, so there is
  nothing to pin or hash: it is checked for secrets in its URL and headers and
  for flows, and is otherwise reported as `unknown`.
- **Not proof a server is benign.** A matching hash says you got the bytes
  that were reviewed, not that they are safe.
- **Not a catalogue of MCP servers.** The DB is a supporting signal, not a
  directory to browse.

## Status: 0.16, looking for first users

0.16.0 is the first release built around `check`, the Action and the
pre-commit hook. The JSON schemas and the policy format may still change
before 1.0 — [COMPATIBILITY.md](./docs/COMPATIBILITY.md) says what is stable
and what is not.

An honest note on how it got here. The previous README said no new feature
would ship until three people had used the tool. That did not hold: between
0.15.2 and 0.16.0, 31 feature commits landed — `check`, the Action, plaintext
secrets, lookalikes, tool poisoning, toxic flows, org policy, the signed DB,
one `decide()` — all before anyone outside the project had used it. The
numbers do not show users yet: 698 npm downloads from 31 Aug to 29 Sep, about
80% of them on three release days and split almost evenly between 0.15.1 and
0.15.2 (mirrors and scanners, not people), and 5–10 a day in between; on
GitHub over 14 days, 4 views, 0 stars, 0 issues from outside. The goal from
here is first users, not features. If you run it on a real config, an issue
saying what it found — or why you stopped — is the most useful thing you can
send. [docs/ADOPTION.md](./docs/ADOPTION.md)

## Docs

- [GitHub Action and pre-commit](./docs/GITHUB_ACTION.md)
- [Command reference](./docs/REFERENCE.md)
- [How it decides](./docs/HOW-IT-DECIDES.md)
- [The vault DB](./docs/DATABASE.md)
- [Compatibility](./docs/COMPATIBILITY.md) · [Security](./SECURITY.md) · [Philosophy](./PHILOSOPHY.md)
- [FAQ](./docs/FAQ.md) · [FAQ (русский)](./docs/FAQ.ru.md)
- [Contributing](./CONTRIBUTING.md) · [Architecture decisions](./docs/adr/README.md) · [Changelog](./CHANGELOG.md)

## License

[MIT](./LICENSE)
