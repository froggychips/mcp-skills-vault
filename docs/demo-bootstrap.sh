#!/usr/bin/env bash
# Prep work for docs/demo.tape — VHS Type-strings can't carry
# nested quotes / braces cleanly, so we create the demo fixture
# project + a shell function that maps `mcp-vault <cmd>` to a
# pre-captured output (deterministic, fast, no network).
set -euo pipefail
DEMO_DIR="${DEMO_DIR:-/tmp/msv-demo-proj}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cat > "$DEMO_DIR/package.json" <<'JSON'
{
  "name": "demo-app",
  "dependencies": {
    "pg": "^8.11.0",
    "@aws-sdk/client-s3": "^3.500.0"
  }
}
JSON
cat > "$DEMO_DIR/.env.example" <<'ENV'
TEAMCITY_URL=
ATLASSIAN_URL=
ENV

# Demo helper sourced by docs/demo.tape so the cast shows
# `mcp-vault scan` / `mcp-vault verify` while we actually
# stream pre-captured fixtures — keeps the GIF deterministic.
cat > "$DEMO_DIR/.demo-aliases.sh" <<EOF
mcp-vault() {
  case "\$1" in
    scan)   cat "${REPO_DIR}/docs/demo-out-orchestrate.txt" ;;
    verify) cat "${REPO_DIR}/docs/demo-out-verify.txt" ;;
    *)      echo "mcp-vault: demo only stubs scan/verify" >&2; return 2 ;;
  esac
}
EOF

echo "Demo project ready at $DEMO_DIR"
