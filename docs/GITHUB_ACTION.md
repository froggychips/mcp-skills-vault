# mcp-vault in CI and pre-commit

One line in someone else's repository: every MCP server its committed configs
launch is checked before a pull request merges, or before a commit is made.

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
      - uses: froggychips/mcp-skills-vault@<full commit SHA>             # vX.Y.Z
        with:
          # The same globs as the trigger above: a nested config that starts
          # the workflow must also be one the action checks, or the run is a
          # green "no MCP config found" over the file that changed.
          paths: '**/.mcp.json **/.vscode/mcp.json **/.cursor/mcp.json'
```

With SARIF, so each finding lands on the config line that launches the server:

```yaml
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1   # v7.0.1
        with:
          persist-credentials: false
      - uses: froggychips/mcp-skills-vault@<full commit SHA>             # vX.Y.Z
        with:
          paths: '**/.mcp.json **/.vscode/mcp.json **/.cursor/mcp.json'
          sarif: true
```

What it runs is the action's own checkout — the code at the commit the `uses:`
line names. The CLI has no dependencies, so nothing is installed from npm and
no install script exists to run; pinning the action by SHA pins the gate by
SHA. It runs `mcp-vault check` over the configs: pins and hashes of known
packages, stored advisories, launches with no exact version, overridden
package sources, lookalike names, plain-text secrets (the value is never
printed) and what the servers of one config do together — one decision, one
exit code. The job summary gets a table of every server's decision — its effect,
the rule that decided it (`decided_by`), the config line it came from, and why.
It is rendered from the report's `mcp-vault/findings@1` decisions; the summary
and the SARIF judge nothing themselves. In SARIF each finding sits on the
config line that launches the server (the finding's host-config subject,
`path:line`), and a policy outcome with no finding of its own — a licence
deny, a required signature — sits there too, under its rule id.

Offline by default: no network call, no token read. The configs are checked
against the pins and hashes in the vault DB shipped with that version, so the
same commit gives the same answer on every run.

| Input | Default | |
|---|---|---|
| `paths` | `.mcp.json .vscode/mcp.json .cursor/mcp.json` | Config files, space- or newline-separated; globs expand (`**/mcp.json`). Missing files are skipped; none found = pass with a note |
| `policy` | nearest `.mcp-vault.policy.json` | Path to a policy file. A named one that does not exist fails the job |
| `fail-on` | `unverified` | The decision's exit threshold, passed as `check --fail-on` (`fail_on`). `error`/`deny`: integrity mismatch, advisory, policy violation. `unverified`/`unknown`: also anything that could not be checked — unpinned, not in the vault, a local command. `warning`/`warn`: also an unpinned launch, a lookalike name, a risky combination of servers (`--strict`). A policy file can raise it, never lower it |
| `sarif` | `false` | Upload to code scanning (`security-events: write`) |
| `offline` | `true` | `false` adds live registry and advisory checks (network; pass `GITHUB_TOKEN` in `env` for the GHSA feed) |
| `version` | — | Run the published npm package at this exact version instead, 0.16.0 or later (the first with `check`; an older one fails the job with exit 2). Ranges and `latest` are refused. The tarball is fetched with `npm pack --ignore-scripts`, hashed, compared with `integrity`, and unpacked with tar — never `npm install`ed, never run through npx |
| `integrity` | — | sha512 SRI of that tarball (`npm view @froggychips/mcp-vault@X dist.integrity`) |
| `node-version` | `22` | For `actions/setup-node` |

Outputs: `exit-code` (0 clean, 1 failures, 2 a config or policy could not be
read — the decisions' exit code), `report` (`check --json`: an `mcp-vault/findings@1`
document — findings, decisions, and the policy and facts they were decided on;
unset when no config was found), `sarif-file`.

The same check by hand:

```sh
npx -y @froggychips/mcp-vault check --fail-on unknown .mcp.json .vscode/mcp.json
```

With no paths, `check` reads the project-scoped configs in the current
directory. It reads exactly those files and nothing from the home directory —
unlike `status` and `audit`, whose answer depends on whose machine runs them.
Offline by default; `--online` adds the registry and advisory checks.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/froggychips/mcp-skills-vault
    rev: <full commit SHA>   # vX.Y.Z — `pre-commit autoupdate --freeze` writes it
    hooks:
      - id: mcp-vault
      # - id: mcp-vault
      #   args: [--strict]
```

Runs `mcp-vault check --fail-on unknown` on staged `.mcp.json`,
`.vscode/mcp.json` and `.cursor/mcp.json`, offline.
