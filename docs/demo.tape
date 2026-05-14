## VHS tape for the README demo GIF.
## Regenerate locally:
##   bash docs/demo-bootstrap.sh && vhs docs/demo.tape
## Output: docs/demo.gif
##
## To keep the recording fast and deterministic the demo `cat`s
## pre-captured outputs. Refresh them with:
##   bash docs/demo-bootstrap.sh
##   node mcp-ecosystem-intelligence/scripts/orchestrate.cjs --cwd /tmp/msv-demo-proj > docs/demo-out-orchestrate.txt
##   node mcp-ecosystem-intelligence/scripts/verify_integrity.cjs --no-audit 2>&1 | tail -3 > docs/demo-out-verify.txt

Output docs/demo.gif

Set FontSize       16
Set Width          1200
Set Height         700
Set Padding        16
Set TypingSpeed    40ms

Type "cd /tmp/msv-demo-proj && clear"
Enter
Sleep 600

Type "# Typical infra project: pg + AWS + TeamCity + Atlassian"
Sleep 1200
Enter
Type "ls -1 && cat .env.example"
Enter
Sleep 1800

Type "# Scan it:"
Sleep 800
Enter
Type "cat ~/repos/mcp-skills-vault/docs/demo-out-orchestrate.txt"
Enter
Sleep 5500

Type "# Verify the whole 112-entry DB, offline:"
Sleep 800
Enter
Type "cat ~/repos/mcp-skills-vault/docs/demo-out-verify.txt"
Enter
Sleep 3500

Type "# 0 failures. 84% verified. Offline. Boring."
Sleep 2500
