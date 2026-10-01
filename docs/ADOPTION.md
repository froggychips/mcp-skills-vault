# First users

mcp-vault has no telemetry and never will, so the only way to know whether it
helps anyone is a person saying so. This page records what the numbers say,
what happened to the rule this project set itself, and what comes next.
Re-measure with `node .github/scripts/adoption.cjs`.

## What the data says

Measured 2026-10-01:

| Signal | Value |
|---|---|
| npm downloads, 2026-08-31 … 2026-09-29 | **698**, on 20 of 30 days |
| …on the three release days (17, 18 and 24 Sep) | 563 — about **80%** |
| …on the other 27 days | 135: 5–10 a day after the first release in the window, 0–5 before it |
| downloads by version, last 7 days | 0.15.1: 159 · 0.15.2: 156 · 0.14.1: 21 · older: 8 |
| GitHub, 14 days | **4 views** (4 unique), 826 clones (273 unique), no referrers |
| stars / forks / watchers | 0 / 0 / 0 |
| issues or PRs from anyone but the owner | **0** (35 from this repository's own bots) |

How to read it:

- **The downloads are mostly not people.** Four fifths of the month landed on
  the days a version was published, and two versions published hours apart
  were fetched almost equally — the pattern of mirrors and registry scanners
  pulling every new version. A person installs the latest one.
- **The clones are not people either.** 826 clones against 4 views: a person
  looks at a repository before cloning it. Likely sources: this repository's
  own CI (every job checks it out) and crawlers.
- **The background is small and real-looking:** 5–10 downloads a day since
  mid-September. Whether any of them ran `check` on a config of their own is
  exactly what the data cannot say.

## What happened to the rule

The previous version of this page set a rule: *no new feature until three
real people have used this and said something about it.* It was not kept.
Between 0.15.2 (2026-09-24) and 0.16.0, 31 feature commits landed: `check`
and the GitHub Action, the pre-commit hook, plaintext secrets, lookalike
names, tool-description scanning, toxic flows and tool shadowing, organisation
policy and per-tool approval, the signed DB, signed audit imports, badges, the
sub-registry export, and one `decide()` under all of it. All of it was built
before anyone outside the project had used the tool.

Some of that work changed what the product is — it is now a check for MCP
configs in CI rather than a registry of servers, and that is the version worth
putting in front of people. But it was still built on the maintainer's guesses,
and the schemas, defaults and rule names in 0.16 are those guesses
([COMPATIBILITY.md](COMPATIBILITY.md) says they may still change).

## What comes next

The goal for 0.16.x is **first users, not features.** Work is limited to:
fixing what is wrong, making `check` and the Action easier to adopt, and
asking. 1.0 — the point where the compatibility promise starts to bind — comes
after feedback from those users, not on a date.

## What counts as a user

Not a download, a star or a clone. A user is a person who

1. ran `check` (or the Action, or `status`) on a config that is theirs, and
2. told us something specific that came out of it — a finding they acted on, a
   false positive, a launch shape it could not read, or a reason they stopped.

**A reason they stopped counts**, and is the most useful answer.

## What to ask

Short, answerable without homework, not a feature survey:

> Would you run one command on your repo's MCP config and tell me what it said?
>
> `npx -y @froggychips/mcp-vault check`
>
> Offline, no telemetry, nothing installed or written; it reads `.mcp.json`,
> `.vscode/mcp.json` and `.cursor/mcp.json` in the current directory. Two
> questions: was anything it flagged news to you, and was anything wrong?

## Who, and where

1. **Teams that commit MCP configs** (`.mcp.json`, `.vscode/mcp.json`,
   `.cursor/mcp.json`) to shared repositories — they are who the Action is for.
2. **Maintainers of MCP servers** — they care whether their server is
   recognised correctly, and their corrections improve the DB directly.
3. **People who review supply-chain and security tooling** — they will say
   which claims are overstated.

Candidate places, each a decision before it happens: MCP community discussions,
lists of MCP tooling (this is a checker, not a server, so not the official
registry), a Show HN, and direct messages to maintainers of servers in the DB,
opening with *their* entry. Wherever it is posted, the numbers above go with
it.
