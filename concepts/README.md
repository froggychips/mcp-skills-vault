# Concepts

Sketches and unfinished skills kept around for reference. Nothing in this directory ships, runs in CI, or is loaded as a Claude Code skill from `~/.claude/skills/`. The main project is `../mcp-ecosystem-intelligence/`.

| File | What it is |
|---|---|
| `mcp-swift-synthesizer.skill` | Concept-level packed skill. Idea: translate Node MCP servers to native Swift binaries to cut RAM (Node 150–300 MB → Swift 1–10 MB per server). No implementation; the .skill file is the original write-up only. Pursuing this would require deep familiarity with both `@modelcontextprotocol/sdk` (Node) and Swift's MCP SDK plus a cross-compile pipeline. |

Promote a concept to the main project by giving it scripts + tests + docs and moving it into the appropriate place; archive a concept by deleting it from this directory and noting it in a release.
