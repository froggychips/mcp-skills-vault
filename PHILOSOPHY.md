# Philosophy

Five constraints that shape every decision in this repo. They're not aspirations — they're rules. If a PR breaks one, that's grounds to reject it independent of how useful the feature is.

## 1. Offline-first

Every gate the user cares about must run with no network. `verify_integrity.cjs --no-audit` is the canonical example: hash check + repo check + hook check, all from cached data, exit 0 means safe-to-install. The advisory feed calls (npm bulk, OSV, GHSA, Snyk) are an *additive* layer that runs when network is available — they make the gate stricter, never looser.

Concretely: the CI `smoke` job is offline. Air-gapped environments install with the same exit code as networked ones.

## 2. Minimal

Zero runtime dependencies for the scripts. Node built-ins only (`fs`, `https`, `child_process`, `path`, `crypto`). The supply-chain attack surface for *this* repo is exactly Node's, no more.

The DB is a single JSON file. The orchestrator is one `.cjs` file. The integrity scanner is one `.cjs` file. No build step, no transpilation, no bundler. `npx -y @froggychips/mcp-vault scan` works on day one — and so does `git clone` + `node scripts/orchestrate.cjs` for users who prefer to inspect first.

## 3. Inspectable

Every output is machine-readable (`--json`) and human-readable (default). Every entry in the DB carries its full audit trail in `notes`: `[VERIFIED YYYY-MM-DD]` and `[TRIAGE YYYY-MM-DD]` prefixes are greppable. Every promotion / demotion is a git commit with the reasoning in the message.

You can audit this project by reading the JSON, the four scripts, and the CHANGELOG. No telemetry, no remote-fetched code, no plugins. What's in the repo is what runs.

## 4. Deterministic

The same DB at the same commit produces the same recommendations. `orchestrate.cjs --json` against a fixed `cwd` is reproducible. `verify_integrity.cjs --no-audit` against a fixed DB returns the same exit code every run.

No randomness, no time-dependent behavior, no LLM in the critical path. The Claude skill is a *consumer* of this project's output — Claude reads what `orchestrate.cjs` prints, doesn't replace it.

## 5. Boring

The most explicit goal. MCP supply-chain tooling should not be exciting. It should be the kind of thing you forget exists between releases. New features earn their place by reducing what users have to think about, not by adding capability for its own sake. `--strict` mode is a feature; `--ai-suggest-fixes` would not be.

If a change makes a maintainer's life harder (more configs, more steps, more decisions per PR), it pays a cost. The triage workflow in CONTRIBUTING.md exists because *not* having it forced thinking every time.

---

These five constraints are what differentiate this project from "another curated list" or "another security scanner." Anything competing on **excitement** is a different product.
