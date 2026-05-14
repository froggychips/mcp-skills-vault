#!/usr/bin/env bash
# Prep work for docs/demo.tape — VHS Type-strings can't carry
# nested quotes / braces cleanly, so we create the demo fixture
# project here and have the tape `cd` into it.
set -euo pipefail
DEMO_DIR="${DEMO_DIR:-/tmp/msv-demo-proj}"
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
echo "Demo project ready at $DEMO_DIR"
