# FAQ

## What is this?

An offline security check for MCP configs in CI: a GitHub Action, a
pre-commit hook and a CLI (`mcp-vault check`) that read the MCP configs
committed to a repository — `.mcp.json`, `.vscode/mcp.json`,
`.cursor/mcp.json` — and fail the build on unpinned servers, plaintext
secrets, typosquats, overridden package sources, risky combinations of
servers and violations of your policy.

## How do I add it?

One step in a workflow, pinned by SHA:

```yaml
- uses: froggychips/mcp-skills-vault@<sha>   # v0.16.0
```

The full workflow and every input: [GITHUB_ACTION.md](GITHUB_ACTION.md).
Locally: `npx -y @froggychips/mcp-vault check`.

## Does it need network access or a token?

No. By default it makes no network call and reads no token: the configs are
compared with the pins in the vault DB shipped with that version.
`--online` (`offline: false` in the Action) adds live registry and advisory
checks.

## What does it check?

Per server in each config: launches without an exact version (`@latest`, a
range, nothing); package sources overridden away from the public registry
(`--registry`, a uv index, `npm_config_registry` in the server's env);
plaintext credentials in `env`, `args`, `headers` or `url`; names that look
like a known server's (typo, homoglyph, scope swap, added `-official`);
versions of known servers the vault never verified; and, across the config,
servers that together read untrusted content, reach private data and can send
data out, or expose the same tool name. Plus your policy, if you have one.
[Full list](REFERENCE.md#checking-a-repository-check).

## Does it only work for servers in its database?

No. Every check except the version comparison works on any server. A server
the vault DB does not know is reported as *not in the vault* — `unknown`,
which fails under `--fail-on unknown` (the Action's default) and passes with
a note under `--fail-on deny`. It is never reported as clean.

## What about remote (HTTP/SSE) servers?

Checked weakly, and the output says so. A remote server ships no artifact,
so there is nothing to pin or hash. It is checked for secrets in its URL and
headers and for flows, and is otherwise `unknown`. If you use remote servers
on purpose, run the Action with `fail-on: error`.

## Will it print my secrets?

No. A secret finding is the type, file, key path, length and at most a
four-character public prefix (`ghp_`), in every output format. A `${VAR}`
reference is not a finding.

## Why did it fail on something it "could not check"?

Because "could not check" is not "fine". The Action and the pre-commit hook
use `--fail-on unknown`: a server not in the vault, a remote server or an
overridden source fails until you decide otherwise — with a policy, with
`fail-on: error`, or by pinning the server to a version the vault knows.
[How it decides](HOW-IT-DECIDES.md).

## What do the exit codes mean?

`0` nothing fails, `1` something fails, `2` could not answer (unreadable
config or policy, bad arguments). `2` never means clean.

## Is it a sandbox or a runtime monitor?

Neither. It reads configs and metadata before anything runs; it does not
watch what a server does. A matching hash says you got the bytes that were
reviewed, not that they are safe. (mcp-trace, an experimental sister project,
looks at runtime.)

## What is the database for, then?

Extra signal for servers it knows: the version and hash the vault verified,
recorded advisories, whether the release was yanked, the npm registry
signature, provenance, whether it starts in a sandbox. `status` and `explain`
use all of it; `check` compares the launched version with the pin, and with
`--online` re-checks hash and advisories. It is not a catalogue to browse.
[What is in it](DATABASE.md).

## How is the database kept current, and can I trust the copy I have?

A weekly job refreshes versions, hashes and evidence and opens a PR that a
person reviews; nothing is auto-merged. The DB in the npm package is signed
(Ed25519) and the CLI refuses to read it if the signature does not verify; in
the Action's default mode the SHA pin of `uses:` is the integrity.
[SECURITY.md](../SECURITY.md#signed-db).

## Can my organisation enforce an allowlist?

Yes: an organisation policy with `"default": "deny"` and allow rules by npm
scope, GitHub owner, registry namespace, entry or pinned artifact; projects
inherit it and can only tighten it. [Policy](HOW-IT-DECIDES.md#policy).

## Does it send any data anywhere?

No telemetry. Offline mode makes no network call. `--online` calls public
APIs (npm registry, PyPI, OSV.dev, GitHub's advisory database), which reveals
the package names and versions being checked — the same as installing them.

## Why 0.16 and not 1.0?

Because nobody outside the project has used it yet. The JSON schemas, rule
names and defaults may still change after feedback from the first users;
[COMPATIBILITY.md](COMPATIBILITY.md) says what is stable already.

## What about my own machine, not the repository?

`npx -y @froggychips/mcp-vault status` reads every MCP host config on the
machine (Claude Code, Claude Desktop, Cursor, VS Code, Codex) and prints one
screen: what is installed, what is wrong, what is missing. No network calls.

## Where do I report a bug?

[GitHub Issues](https://github.com/froggychips/mcp-skills-vault/issues).
Security issues privately: [SECURITY.md](../SECURITY.md#reporting-a-vulnerability).
