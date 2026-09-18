# Three users

A rule for this repository: **no new feature until three real people have used
this and said something about it.** Everything below is the reasoning and the
plan; re-run the numbers with `node .github/scripts/adoption.cjs`.

## What the data says

Measured 2026-09-18:

| Signal | Value |
|---|---|
| npm downloads, 30 days | 33, spread over 15 days, peak 5 |
| stars / forks / watchers | 0 / 0 / 0 |
| traffic, 14 days | 7 views (6 unique), **41 clones (29 unique)** |
| referrers | none |
| issues or PRs from a person other than the owner | **0** (31 from this repo's own bots) |

The clone-to-view ratio is the part that matters. A person views a repository
before cloning it; six viewers did not produce twenty-nine cloners. Forty-one
clones against seven views is the signature of mirrors and crawlers. Combined
with zero referrers and zero outside issues, the honest reading is that **there
is no evidence of a single human user yet** — and a few of those 33 downloads
were this project's own release testing.

This is not a quality problem, and it is not fixed by shipping more. Zero
referrers means nobody has a path to the thing. Twenty-four checks do not beat
one user who can say which of them they actually ran.

## Why features cannot substitute

This tool has no telemetry and never will — that is a promise in
[COMPATIBILITY.md](./COMPATIBILITY.md), not a gap. Which means:

- we cannot tell which command anyone runs;
- we cannot tell whether a check ever fired on real input;
- we cannot tell whether a finding changed anybody's decision.

The only instrument available is a person saying so. Building a twenty-fifth
check adds a thing nobody asked for to a pile nobody has been through; the next
useful piece of information is not in the code.

## What counts as one of the three

Not a download, not a star, not a clone. One of the three is a person who:

1. ran it on a config or project that is theirs, and
2. told us something specific that came out of it — a finding they acted on, a
   number that surprised them, a command that did the wrong thing, or a reason
   they stopped using it.

A "this looks cool" is not one. A "I ran `status`, my `hostinger` server was
44% of my context window and I had no idea" is — even though it is not a bug
report, and even though they may never run it again. **A reason they stopped
counts.** That is the most useful of the three answers and the hardest to get.

## What to ask them

Short, answerable without homework, and not a feature survey:

> Would you run one command against your MCP setup and tell me what it said?
>
> `npx -y @froggychips/mcp-vault status`
>
> No network calls, no telemetry, nothing installed or written. It reads your
> host configs and prints about fifteen lines. Two things I want to know: was
> anything on that screen news to you, and was anything on it wrong?

Three sentences, one command, two questions. Not "what features would you
like" — nobody knows, including us, which is the whole point.

## Who

Three groups, roughly in order of how likely the answer is to be useful:

1. **People who already run several MCP servers.** They have the problem this
   addresses and a config big enough for `status` to say something surprising.
   The context-budget number lands hardest here.
2. **People who maintain an MCP server.** They care about a different half —
   whether their own entry is right, what `capabilities` says about their
   package, whether the eval could start it. Their corrections improve the DB
   directly, which no amount of our own work does.
3. **People who review supply-chain tooling.** They will tell us which claims
   are overstated. That is worth more than praise and is the group most likely
   to reply.

## Where — each of these needs a decision before it happens

Nothing outward has been done. These are candidates, not a checklist:

- the MCP community Discord / the `modelcontextprotocol` GitHub discussions
- `awesome-mcp-servers`-style lists (this is a scanner, not a server — it fits
  the "tooling" sections, where those exist)
- a Show HN, or r/ClaudeAI / r/LocalLLaMA
- direct messages to maintainers of servers already in the DB, opening with
  *their* entry rather than with the tool
- the Anthropic Discord's Claude Code channels

The direct-message route to DB maintainers is the one with the best ratio: the
opening line is about something of theirs, and every reply corrects real data.

Two notes on doing it honestly. This project does not belong in the official
MCP registry — that registry lists MCP *servers*, and this is a CLI. And
anywhere it gets posted, the download number goes with it: 33 downloads and no
users is the true state, and pretending otherwise would be the one thing this
repository cannot afford to do.

## The rule, stated plainly

Until three of the above exist, work here is limited to: fixing what is wrong,
making the existing surface easier to reach, and asking. `mcp-vault status`
was the last feature — one command instead of six, because the reason to
build it did not require a user to confirm: nobody has six commands' worth of
patience for a tool they have not decided to trust yet.
