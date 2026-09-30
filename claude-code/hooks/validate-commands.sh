#!/usr/bin/env bash
# PreToolUse hook for the Bash tool.
# Blocks recursive deletes, pipe-to-shell, destructive SQL, permission bypass,
# world-writable chmod, reads/writes of .env through the shell, and network
# commands that mention a secret. Exit code 2 blocks the action and sends the
# message on stderr back to Claude. Requires jq.
#
# These are pattern matches on command text: guardrails, not walls. Keep the
# sandbox on underneath them.
#
# It fails closed: if jq is missing or the input can't be parsed, the command
# is blocked rather than allowed.

block() {
  echo "Blocked: $1. Ask the user to run this by hand if it is really needed." >&2
  exit 2
}

command -v jq >/dev/null 2>&1 || block "jq is not installed, so this hook can't check the command"
input=$(cat)
cmd=$(printf '%s' "$input" | jq -er '.tool_input.command | strings' 2>/dev/null) || block "the hook could not read a command from the tool input"

grep -Eq 'rm +-[a-zA-Z]*r[a-zA-Z]*f|rm +-[a-zA-Z]*f[a-zA-Z]*r' <<<"$cmd" && block "recursive delete"
grep -Eq '(curl|wget)[^|]*\|[[:space:]]*(ba|z)?sh'              <<<"$cmd" && block "pipe to shell"
grep -Eiq 'drop +table|drop +database|delete +from|truncate +table' <<<"$cmd" && block "destructive SQL"
grep -Eq -- '--dangerously-skip-permissions'                    <<<"$cmd" && block "permission bypass"
grep -Eq 'chmod +(-R +)?777'                                    <<<"$cmd" && block "world-writable chmod"
grep -Eq '(>|>>|cat|less|more|head|tail|cp|mv)[^;|&]*\.env'     <<<"$cmd" && block "reading or writing .env"
if grep -Eq '(curl|wget|nc)\b' <<<"$cmd" && grep -Eiq 'key|token|secret|password' <<<"$cmd"; then
  block "network command that mentions a secret"
fi

exit 0
