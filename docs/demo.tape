## VHS tape for the README demo GIF.
## Regenerate locally:
##   bash docs/demo-bootstrap.sh && vhs docs/demo.tape
## Output: docs/demo.gif
##
## The demo `cat`s pre-captured outputs through a shell function
## defined by docs/demo-bootstrap.sh — viewer sees `mcp-vault scan`,
## runner sees `cat docs/demo-out-*.txt`. Refresh the fixtures with:
##   bash docs/demo-bootstrap.sh
##   node bin/mcp-vault.cjs scan   --cwd /tmp/msv-demo-proj > docs/demo-out-orchestrate.txt
##   node bin/mcp-vault.cjs verify --no-audit 2>&1 | tail -3 > docs/demo-out-verify.txt

Output docs/demo.gif

Set FontSize 14
Set Width    1100
Set Height   620
Set Padding  12
Set TypingSpeed 30ms

Hide
Type "cd /tmp/msv-demo-proj && source .demo-aliases.sh && clear"
Enter
Sleep 200ms
Show

Type "# Typical infra project: pg + AWS + TeamCity + Atlassian"
Enter
Sleep 700ms

Type "mcp-vault scan --cwd ."
Enter
Sleep 3500ms

Type "mcp-vault verify --no-audit"
Enter
Sleep 2500ms
