#!/usr/bin/env bash
# Run the Gemini CLI and Code Assist security audit in a throwaway, offline container.
#
# Usage (from the project you want to audit):
#   bash /path/to/coding-agent-security/gemini/audit/run.sh [options]
#
# Options:
#   --report html|txt|csv|json   also save a report with how-to-fix steps
#   --report-dir DIR             where to save it (default ~/gemini-audit-reports)
#   --no-report                  don't ask about saving a report
#   --json                       print JSON on screen instead of the summary
#
# Without --report or --no-report, you are asked at the end whether to save one.
#
# Requires Docker or Podman. The container:
#   - has no network access          (--network none)
#   - sees your files read-only      (:ro mounts, only the files listed below)
#   - cannot write to its own image  (--read-only)
#   - runs as you, not root, with every Linux capability dropped
#   - is deleted when it exits       (--rm)
# Reports are printed by the container and saved by this script on your machine;
# the container itself is never given write access to anything.

set -eu

IMAGE="${AUDIT_IMAGE:-gemini-audit}"
ENGINE="${CONTAINER_ENGINE:-$(command -v docker || command -v podman || true)}"
[ -n "$ENGINE" ] || { echo "Docker or Podman is required." >&2; exit 2; }

screen_format=text
report=""
report_dir="$HOME/gemini-audit-reports"
ask=1
while [ $# -gt 0 ]; do
  case "$1" in
    --json) screen_format=json ;;
    --report) report="${2:-}"; shift ;;
    --report=*) report="${1#--report=}" ;;
    --report-dir) report_dir="${2:-}"; shift ;;
    --no-report) ask=0 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

# The container runs with your user ID, so never start it as root.
if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as your normal user, not as root or with sudo." >&2
  exit 2
fi

here="$(cd "$(dirname "$0")" && pwd)"
export DOCKER_CLI_HINTS=false

# Build the image locally from the open Dockerfile. The image is labelled with
# a fingerprint of its source files, so it is rebuilt whenever they change.
if [ -z "${AUDIT_IMAGE:-}" ]; then
  sum() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
  src_hash=$(cat "$here/Dockerfile" "$here/audit.sh" "$here/mappings.json" "$here/../../common/audit-lib.sh" "$here/../../common/jsonc.awk" "$here/../../common/gitignore.sh" | tr -d '\r' | sum | cut -c1-16)
  have_hash=$("$ENGINE" image inspect "$IMAGE" --format '{{ index .Config.Labels "org.aisecuritylabs.src-hash" }}' 2>/dev/null || true)
  if [ "$have_hash" != "$src_hash" ]; then
    old_id=$("$ENGINE" image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null || true)
    echo "Building $IMAGE from $here/Dockerfile ..." >&2
    "$ENGINE" build -q --label "org.aisecuritylabs.src-hash=$src_hash" \
      -f "$here/Dockerfile" -t "$IMAGE" "$here/../.." >/dev/null
    [ -n "$old_id" ] && "$ENGINE" image rm "$old_id" >/dev/null 2>&1 || true
  fi
fi

mounts=()
add() { [ -e "$1" ] && mounts+=(-v "$1:$2:ro"); return 0; }

# Only these files, plus the project folder below, are shared with the container:
# never oauth_creds.json, google_accounts.json, chat history or anything else in ~/.gemini.
gemini_home="$HOME/.gemini"
add "$gemini_home/settings.json" /audit/gemini-home/settings.json
for f in "$gemini_home"/policies/*.toml; do
  [ -f "$f" ] && add "$f" "/audit/gemini-home/policies/$(basename "$f")"
done
# Only each extension's manifest, never its code.
for d in "$gemini_home"/extensions/*/; do
  n="$(basename "$d")"
  case "$n" in *:*|*,*) continue ;; esac
  add "$d/gemini-extension.json" "/audit/gemini-home/extensions/$n/gemini-extension.json"
done
# VS Code user settings, for the Gemini Code Assist agent setting.
case "$(uname -s)" in
  Darwin) vscode_user="$HOME/Library/Application Support/Code/User" ;;
  *)      vscode_user="${XDG_CONFIG_HOME:-$HOME/.config}/Code/User" ;;
esac
add "$vscode_user/settings.json" /audit/vscode-user/settings.json
# Machine-wide files every Gemini CLI user on this computer loads.
case "$(uname -s)" in
  Darwin)
    add "/Library/Application Support/GeminiCli/settings.json" /audit/system/settings.json
    add "/Library/Application Support/GeminiCli/system-defaults.json" /audit/system/system-defaults.json ;;
  *)
    add "/etc/gemini-cli/settings.json" /audit/system/settings.json
    add "/etc/gemini-cli/system-defaults.json" /audit/system/system-defaults.json ;;
esac
for rc in .bashrc .zshrc .profile .bash_profile .bash_aliases .zprofile; do
  add "$HOME/$rc" "/audit/rc/$rc"
done
# The current directory is audited as the project, but never your whole home.
project_name=""
if [ "$PWD" = "$HOME" ] || [ "$PWD" = "/" ]; then
  echo "Not mounting $PWD as the project. Run this from a project directory." >&2
else
  add "$PWD" /audit/project
  project_name="$(basename "$PWD")"
fi
gemini_version="$(gemini --version 2>/dev/null | head -n1 || true)"

audit() {
  "$ENGINE" run --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 256 \
    --memory 256m \
    --user "$(id -u):$(id -g)" \
    -e GEMINI_VERSION="$gemini_version" \
    -e PROJECT_NAME="$project_name" \
    "${mounts[@]}" \
    "$IMAGE" --format "$1"
}

set +e
audit "$screen_format"
status=$?
set -e

if [ -z "$report" ] && [ "$ask" -eq 1 ] && [ -t 0 ] && [ -t 1 ]; then
  echo
  printf 'Save a report with how-to-fix steps? [h]tml, [t]ext, [c]sv, [j]son, [n]o (default n): '
  read -r answer || answer=n
  case "$answer" in
    h|H|html) report=html ;;
    t|T|txt|text) report=txt ;;
    c|C|csv) report=csv ;;
    j|J|json) report=json ;;
  esac
fi

if [ -n "$report" ]; then
  case "$report" in
    html) fmt=html ;;
    txt|text) fmt=report; report=txt ;;
    csv) fmt=csv ;;
    json) fmt=json ;;
    *) echo "Unknown report format '$report' (use html, txt, csv or json)." >&2; exit 2 ;;
  esac
  mkdir -p "$report_dir"
  file="$report_dir/gemini-audit-${project_name:-home}-$(date '+%Y%m%d-%H%M%S').$report"
  audit "$fmt" > "$file" || true
  echo "Report saved: $file"
fi

exit "$status"
