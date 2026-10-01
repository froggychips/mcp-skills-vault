# mcp-vault in CI and pre-commit

One line in your repository: every MCP server its committed configs launch is
checked before a pull request merges, or before a commit is made. Both run
`mcp-vault check` ([reference](REFERENCE.md#checking-a-repository-check)).

## GitHub Action

```yaml
# .github/workflows/mcp-vault.yml
name: mcp-vault

on:
  pull_request:
    paths:
      - '**/.mcp.json'
      - '**/.vscode/mcp.json'
      - '**/.cursor/mcp.json'
      - '.mcp-vault.policy.json'

permissions:
  contents: read

jobs:
  mcp-vault:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1   # v7.0.1
        with:
          persist-credentials: false
      - uses: froggychips/mcp-skills-vault@<sha>                        # v0.16.0
        with:
          # The same globs as the trigger above: a nested config that starts
          # the workflow must also be one the action checks, or the run is a
          # green "no MCP config found" over the file that changed.
          paths: '**/.mcp.json **/.vscode/mcp.json **/.cursor/mcp.json'
```

With SARIF, so each finding lands on the config line it is about:

```yaml
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1   # v7.0.1
        with:
          persist-credentials: false
      - uses: froggychips/mcp-skills-vault@<sha>                        # v0.16.0
        with:
          paths: '**/.mcp.json **/.vscode/mcp.json **/.cursor/mcp.json'
          sarif: true
```

### Pin by SHA

`<sha>` is the full 40-character commit SHA of a release tag:

```sh
git ls-remote https://github.com/froggychips/mcp-skills-vault refs/tags/v0.16.0
```

By default the action runs **its own checkout** — the code at the commit the
`uses:` line names. The CLI has no dependencies, so nothing is installed from
npm and no install script exists to run. The vault DB is part of that same
commit, so the SHA pins both the checker and the data it checks against; that
pin is the DB's integrity in this mode (a git checkout carries no release
signature). Given a tag or branch instead, the action still runs and prints a
warning: the gate and its DB can then change under you. The job summary
records which of the two it was (`DB integrity: pinned by action SHA …`).

### What it does

`mcp-vault check` over the configs: launches with no exact version, package
sources overridden away from the public registry, plaintext secrets (the value
is never printed), lookalike names, what the servers of one config can do
together, versions of known servers the vault never verified, and your policy
— one decision per finding, one exit code. The job summary is a table of every
decision: its effect, the rule that decided it (`decided_by`), the config line
and why. It is rendered from the report's `mcp-vault/findings@1` decisions;
the summary and the SARIF judge nothing themselves.

Offline by default: no network call, no token read, and the same commit gives
the same answer on every run.

**Remote servers.** An HTTP/SSE server (`"url": …`) ships no artifact, so
there is nothing to pin or hash. It is checked for secrets in its URL and
headers and for flows, and is otherwise `unknown`. Under the default
`fail-on: unverified` that fails the job; if your configs use remote servers
on purpose, use `fail-on: error`.

## Inputs

| Input | Default | |
|---|---|---|
| `paths` | `.mcp.json .vscode/mcp.json .cursor/mcp.json` | Config files, space- or newline-separated; globs expand (`**/mcp.json`). Missing files are skipped; none found = pass with a note |
| `policy` | nearest `.mcp-vault.policy.json` | Path to a policy file. A named one that does not exist fails the job |
| `fail-on` | `unverified` | The decision's exit threshold, passed as `check --fail-on`. `error` (or `deny`): a plaintext secret, a policy violation, a recorded problem. `unverified` (or `unknown`): also anything that could not be checked — unpinned, not in the vault, a remote server, an overridden source. `warning` (or `warn`): also warnings — a lookalike name, a risky combination of servers (same as `--strict`). A policy file can raise it, never lower it |
| `sarif` | `false` | Upload to code scanning (the job needs `security-events: write`) |
| `offline` | `true` | `false` adds live registry and advisory checks (network; pass `GITHUB_TOKEN` in `env` for the GHSA feed) |
| `version` | — | Run the published npm package at this exact version instead of the action's checkout: **0.16.0 or later** (the first with `check`; an older one fails the job with exit 2). Ranges, tags and `latest` are refused. The tarball is fetched with `npm pack --ignore-scripts`, hashed, compared with `integrity`, and unpacked with tar — never `npm install`ed, never run through npx. In this mode the CLI checks the DB's Ed25519 release signature strictly |
| `integrity` | — | sha512 SRI of that tarball (`npm view @froggychips/mcp-vault@X dist.integrity`). Strongly recommended with `version` |
| `node-version` | `22` | For `actions/setup-node` |

## Outputs

| Output | |
|---|---|
| `exit-code` | `0` clean, `1` failures, `2` a config or policy could not be read |
| `report` | path to `check --json`: an `mcp-vault/findings@1` document — findings, decisions, and the policy and facts they were decided on. Unset when no config was found |
| `sarif-file` | path to the SARIF file, when `sarif` is true |

The job fails last, after the summary and the SARIF upload, so a red job
always comes with its explanation.

## The same check by hand

```sh
npx -y @froggychips/mcp-vault check --fail-on unknown .mcp.json .vscode/mcp.json
```

With no paths, `check` reads the project-scoped configs in the current
directory. It reads exactly those files and nothing from the home directory —
unlike `status` and `audit`, whose answer depends on whose machine runs them.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/froggychips/mcp-skills-vault
    rev: <sha>   # v0.16.0 — `pre-commit autoupdate --freeze` writes it
    hooks:
      - id: mcp-vault
      # - id: mcp-vault
      #   args: [--strict]
```

Runs `mcp-vault check --fail-on unknown` on staged `.mcp.json`,
`.vscode/mcp.json` and `.cursor/mcp.json`, offline. The package has no
dependencies and no install scripts, so pre-commit's `npm install` of it runs
nothing but a copy.
