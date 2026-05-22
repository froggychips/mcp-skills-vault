# Triage notes

Append-only log of MCP servers investigated but **not** added to `tools_database.json`, with the reason. Lets future contributors see which gaps were considered and why they were left open.

Format: `YYYY-MM-DD: <ecosystem-or-name> — <one-line reason>`.

---

2026-05-22: seq — no viable upstream MCP server found (searched npm/gh). Candidate gap; could be wrapper target. npm `mcp-seq@1.0.2` (ahmad2x4/mcp-server-seq) has only 8 GitHub stars — below the CONTRIBUTING.md ≥10 floor. The healthier candidate `willibrandon/seq-mcp-server` (15 stars, MIT, recent commits) ships as a .NET tool on NuGet (`dotnet tool install -g SeqMcpServer`); the DB only supports npx/uvx/docker install_cmd patterns today, so it can't be added without extending `verify_integrity.cjs` to handle the dotnet ecosystem.
