#!/usr/bin/env bash
# PreToolUse hook for the Edit and Write tools.
# Blocks edits to secrets, agent configuration, CI definitions, lockfiles and
# shell startup files. Exit code 2 blocks the action and sends the message on
# stderr back to Claude. Requires jq.
#
# Symlinks are resolved first, so a harmless-looking name that points at your
# agent config or dotfiles is judged by its real target (the "SymJack" attack).
# When CLAUDE_PROJECT_DIR is set (it is, inside Claude Code), writes that
# resolve outside the project are blocked too.
#
# It fails closed: if jq is missing, the input can't be parsed, or no file
# path can be found, the edit is blocked rather than allowed.

block() {
  echo "Blocked: $1. Ask the user to change it by hand." >&2
  exit 2
}

command -v jq >/dev/null 2>&1 || block "jq is not installed, so this hook can't check the edit"
input=$(cat)
path=$(printf '%s' "$input" | jq -er '.tool_input.file_path // .tool_input.notebook_path // empty' 2>/dev/null) || block "the hook could not read a file path from the tool input"

# resolve <path>: follow symlinks to the real location, even when the file
# (or some of its parent directories) doesn't exist yet. Plain POSIX tools
# only, so it behaves the same on Linux, macOS, WSL2 and BusyBox.
resolve() {
  local p="$1" target dir base rest="" i=0
  while [ -L "$p" ] && [ "$i" -lt 40 ]; do           # follow links on the final component
    target=$(readlink "$p")
    case "$target" in /*) p="$target" ;; *) p="$(dirname "$p")/$target" ;; esac
    i=$((i + 1))
  done
  dir=$(dirname "$p"); base=$(basename "$p")
  while [ ! -d "$dir" ] && [ "$dir" != "/" ] && [ "$dir" != "." ]; do   # walk up to an existing directory
    rest="/$(basename "$dir")$rest"; dir=$(dirname "$dir")
  done
  dir=$(cd -P "$dir" 2>/dev/null && pwd) || { printf '%s\n' "$1"; return; }
  printf '%s%s/%s\n' "${dir%/}" "$rest" "$base"
}

protected() {
  case "$1" in
    *.env|*.env.*|*/secrets/*|*.pem|*.key|\
    */.claude/*|*/.mcp.json|*/.claude.json|\
    */.github/workflows/*|*/.gitlab-ci.yml|\
    *lock.json|*.lock|*/go.sum|\
    */.bashrc|*/.zshrc|*/.profile|*/.bash_profile|*/.zprofile|*/.ssh/*|*/.aws/*)
      return 0 ;;
  esac
  return 1
}

real=$(resolve "$path")

protected "$path" && block "$path is a protected file"
[ "$real" != "$path" ] && protected "$real" && block "$path resolves to protected file $real"

if [ -n "${CLAUDE_PROJECT_DIR:-}" ]; then
  project=$(resolve "$CLAUDE_PROJECT_DIR")
  case "$real" in
    "$project"|"$project"/*) ;;
    *) block "$path resolves to $real, outside the project" ;;
  esac
fi

exit 0
