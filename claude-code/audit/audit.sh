#!/usr/bin/env bash
# Claude Code security audit — read-only, offline.
#
# Checks a developer's Claude Code configuration against the checklist in
# claude-code/07-checklist.md and prints PASS / WARN / FAIL / INFO results.
# It never modifies anything and needs no network access.
#
# Inputs (all optional, mounted read-only by run.sh / run.ps1):
#   /audit/home-claude   the user's ~/.claude directory
#   /audit/claude.json   the user's ~/.claude.json (MCP server list)
#   /audit/project       a project directory to inspect
#   /audit/rc/*          shell startup files (.bashrc, .zshrc, ...)
#   CLAUDE_VERSION       output of `claude --version`, passed as an env var
#   HOST_OS              "windows" when launched from run.ps1
#   PROJECT_NAME         the audited project's folder name, for report headers
#
# Usage: audit.sh [--format text|report|json|csv|html]   (--json = --format json)
#   text    on-screen summary (default)
#   report  plain-text report with how-to-fix steps for every WARN / FAIL
#   csv     one row per check, with fix and guide link (opens in Excel)
#   html    self-contained HTML report with fixes (no external resources)
#   json    machine-readable, including fixes
# Reports are written to standard output; run.sh / run.ps1 save them to a file.
# Exit code: 0 = no FAIL results, 1 = at least one FAIL, 2 = usage error.

set -u

AUDIT_VERSION="1.3.0"
MIN_STRICT_VERSION="2.1.219"   # sandbox.network.strictAllowlist requires this
GUIDE_URL="https://github.com/aisecuritylabs-org/coding-agent-security/blob/main/claude-code"

HOME_CLAUDE="${HOME_CLAUDE:-/audit/home-claude}"
CLAUDE_JSON="${CLAUDE_JSON:-/audit/claude.json}"
PROJECT="${PROJECT:-/audit/project}"
RC_DIR="${RC_DIR:-/audit/rc}"
TESTS="${TESTS:-/opt/audit/tests/test-hooks.sh}"
MAPPINGS="${MAPPINGS:-/opt/audit/mappings.json}"   # why each check matters + framework mappings

# MCP servers whose name, command, args or URL suggest they read content other
# people can write (error trackers, tickets, chat, email, forges). Agentjacking.
THIRD_PARTY_FILTER='.mcpServers // {} | to_entries[]
  | select(([.key, (.value.command // ""), ((.value.args // []) | join(" ")), (.value.url // "")] | join(" "))
           | test("sentry|jira|atlassian|confluence|linear|slack|discord|teams|gmail|outlook|imap|e-?mail|zendesk|intercom|pagerduty|datadog|github|gitlab|notion|hubspot"; "i"))
  | .key'

# Plugin marketplaces fetched from git hosts other than GitHub. Plugin4Shell
# (fixed in Claude Code 2.1.179) relied on hosts that accept 40-hex branch names.
MARKETPLACE_FILTER='.extraKnownMarketplaces // {} | to_entries[]
  | select(((.value.source.source // "") | IN("git", "url"))
           and ((.value.source.url // "") | test("github\\.com") | not))
  | "\(.key): \(.value.source.url // "?")"'

FORMAT=text
while [ $# -gt 0 ]; do
  case "$1" in
    --json) FORMAT=json ;;
    --format) FORMAT="${2:-}"; shift ;;
    --format=*) FORMAT="${1#--format=}" ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "usage: audit.sh [--format text|report|json|csv|html]" >&2; exit 2 ;;
  esac
  shift
done
case "$FORMAT" in
  text|report|json|csv|html) ;;
  *) echo "unknown format '$FORMAT' (use text, report, json, csv or html)" >&2; exit 2 ;;
esac

# guide_page <step> — the guide page that explains a step
guide_page() {
  case "$1" in
    1) echo "01-before-you-start.md" ;;
    2) echo "02-sandbox-and-permissions.md" ;;
    3) echo "03-hooks.md" ;;
    4) echo "04-mcp-plugins-and-repos.md" ;;
    5) echo "05-working-habits.md" ;;
    6) echo "06-self-test.md" ;;
    *) echo "07-checklist.md" ;;
  esac
}

# fix_for <id> — how to fix a WARN / FAIL result, as concrete as possible.
# JSON snippets go in ~/.claude/settings.json unless stated otherwise.
fix_for() {
  case "$1" in
    I01) echo 'Update Claude Code: `claude update` (native installer), `sudo apt update && sudo apt upgrade claude-code` (apt), or `winget upgrade Anthropic.ClaudeCode` (WinGet).' ;;
    U00) echo 'Run the audit with run.sh or run.ps1, which share ~/.claude/settings.json with the container automatically.' ;;
    U01) echo 'Copy claude-code/config/settings.json from this repository to ~/.claude/settings.json, adapt it to your stack, then run `claude doctor` to validate it.' ;;
    U02) if [ "${HOST_OS:-}" = "windows" ]; then
           echo 'Install Claude Code inside WSL2 (Ubuntu) and use it from there for sensitive work; then set in ~/.claude/settings.json inside WSL2: { "sandbox": { "enabled": true } }. On Linux/WSL2 also install: sudo apt-get install bubblewrap socat'
         else
           echo 'Add to ~/.claude/settings.json: { "sandbox": { "enabled": true } }. On Linux/WSL2 first install: sudo apt-get install bubblewrap socat. Check with /sandbox.'
         fi ;;
    U03) echo 'Add to ~/.claude/settings.json: { "sandbox": { "allowUnsandboxedCommands": false } }' ;;
    U04) echo 'Add to ~/.claude/settings.json: { "sandbox": { "network": { "strictAllowlist": true } } } (needs Claude Code 2.1.219 or later).' ;;
    U05) echo 'Edit sandbox.network.allowedDomains: remove wildcards, github.com, paste sites and webhook services. List only the package registries and APIs your build needs, e.g. ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"].' ;;
    U06) echo 'Add to ~/.claude/settings.json: { "sandbox": { "credentials": { "files": [ { "path": "~/.ssh", "mode": "deny" }, { "path": "~/.aws/credentials", "mode": "deny" } ] } } }' ;;
    U07) echo 'Add to ~/.claude/settings.json: { "permissions": { "deny": [ "Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)" ] } }' ;;
    U08) echo 'Add to ~/.claude/settings.json: { "permissions": { "deny": [ "Bash(curl *)", "Bash(wget *)" ] } }' ;;
    U09) echo 'Remove the listed rules from "permissions.allow". Check ~/.claude/settings.json and the project'"'"'s .claude/settings.local.json — answering "always allow" in a session saves rules there. Move push, publish and deploy commands to "permissions.ask" instead.' ;;
    U10) echo 'Add to ~/.claude/settings.json: { "permissions": { "ask": [ "Bash(git push *)" ] } }' ;;
    U11) echo 'Delete "enableAllProjectMcpServers". Enable servers you trust by name instead: { "enabledMcpjsonServers": ["server-name"] }' ;;
    U12) echo 'Remove "permissions.additionalDirectories", or limit it to folders this project genuinely needs. Never add your home directory.' ;;
    U13) echo 'Remove "defaultMode": "bypassPermissions" from "permissions". Use the default (manual), plan, or auto mode with the sandbox on.' ;;
    U14) echo 'Add to ~/.claude/settings.json: { "cleanupPeriodDays": 14 }' ;;
    U15) echo 'Remove the listed variables from the "env" block. Keep secrets out of the agent'"'"'s environment; load them per command from a secret manager when you run things yourself.' ;;
    U16) echo 'Remove "/var/run/docker.sock" from "sandbox.network.allowUnixSockets".' ;;
    H01|H02) echo 'Copy claude-code/hooks/protect-files.sh and validate-commands.sh into your project'"'"'s .claude/hooks/ (chmod +x), add the contents of claude-code/config/hooks.json to .claude/settings.json, then run claude-code/tests/test-hooks.sh. Needs jq.' ;;
    H03) echo 'Compare your hooks with claude-code/hooks/ in this repository, make them executable (chmod +x), make sure jq is installed and the files use LF line endings, then re-run claude-code/tests/test-hooks.sh until it reports 0 failed.' ;;
    P01) echo 'Fix the JSON syntax in the listed file; check it with `jq . <file>` or `claude doctor`.' ;;
    P02) echo 'Remove "enableAllProjectMcpServers" from the project settings file.' ;;
    P03) echo 'Read every listed hook command and the scripts it runs. Remove any you did not write or review. Never keep a hook that downloads or pipes remote code into a shell.' ;;
    P05) echo 'Pin every MCP server to an exact version in .mcp.json, e.g. "some-server@1.4.2" instead of "some-server" or "@latest".' ;;
    P06) echo 'Read CLAUDE.md before trusting this repository. Remove fetch/install instructions you did not add, or open the repository only in a dev container or VM.' ;;
    P07) echo 'Copy claude-code/config/CLAUDE.md.example from this repository to CLAUDE.md in your project root and adapt it.' ;;
    P08) echo 'Add these lines to the project'"'"'s .gitignore: .env and .env.*' ;;
    R01) echo 'Remove the alias or function that adds --dangerously-skip-permissions from the listed shell startup file, then open a new terminal.' ;;
    P09) echo 'Read the hook command and every script it runs before starting Claude Code in this repository. If you did not write it, remove it or open the repository only in a dev container or VM with no credentials. Organisations can enforce "allowManagedHooksOnly": true in managed settings so only company-approved hooks run.' ;;
    P10) echo 'Before accepting the folder-trust prompt, read .mcp.json and every command it starts. Remove servers you do not recognise. Keep "enableAllProjectMcpServers" off and approve servers by name; organisations can enforce "allowManagedMcpServersOnly": true. Never run Claude Code headless (claude -p, CI) on untrusted branches with production credentials.' ;;
    P11) echo 'Do not start Claude Code here until you have checked each listed link: ls -la <link>. Delete links you did not create. A link named like an ordinary file that points at .claude/, .mcp.json or a dotfile is an attack. Install the updated protect-files.sh hook, which resolves symlinks and blocks writes outside the project.' ;;
    P12|M02) echo 'Treat everything these servers return as untrusted input: give them read-only credentials, keep approvals on for any command that follows a read from them, and never let the agent run commands copied from tickets, errors or messages without reading them yourself.' ;;
    P13|U17) echo 'Use marketplaces hosted on GitHub or on infrastructure you control, keep Claude Code at 2.1.179 or later (fixes Plugin4Shell), and review plugin updates before they install.' ;;
    *) echo '' ;;
  esac
}

USER_SETTINGS="$HOME_CLAUDE/settings.json"
PROJ_SETTINGS="$PROJECT/.claude/settings.json"
PROJ_LOCAL="$PROJECT/.claude/settings.local.json"

results=()   # one JSON object per check
n_pass=0 n_warn=0 n_fail=0 n_info=0

# record <STATUS> <id> <guide-step> <title> [detail]
record() {
  local status="$1" id="$2" step="$3" title="$4" detail="${5:-}"
  case "$status" in
    PASS) n_pass=$((n_pass + 1)) ;;
    WARN) n_warn=$((n_warn + 1)) ;;
    FAIL) n_fail=$((n_fail + 1)) ;;
    INFO) n_info=$((n_info + 1)) ;;
  esac
  local fix="" url
  case "$status" in WARN|FAIL) fix="$(fix_for "$id")" ;; esac
  url="$GUIDE_URL/$(guide_page "$step")"
  results+=("$(jq -cn --arg s "$status" --arg i "$id" --arg g "$step" --arg t "$title" --arg d "$detail" \
    --arg f "$fix" --arg u "$url" \
    '{status:$s, id:$i, guide_step:$g, title:$t, detail:$d, fix:$f, guide_url:$u}')")
}

# q <file> <jq-filter> — run a jq filter, empty output on any error
q() { [ -f "$1" ] && jq -r "$2" "$1" 2>/dev/null; }

valid_json() { [ -f "$1" ] && jq empty "$1" >/dev/null 2>&1; }

# All settings files that apply to a session in the audited project.
settings_files() {
  local f
  for f in "$USER_SETTINGS" "$PROJ_SETTINGS" "$PROJ_LOCAL"; do
    valid_json "$f" && echo "$f"
  done
}

# Collect a permissions list (allow / ask / deny) across all settings files.
rules() {
  local kind="$1" f
  while IFS= read -r f; do
    q "$f" ".permissions.$kind // [] | .[]"
  done < <(settings_files)
}

version_ge() { # version_ge A B  -> true if A >= B
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# ------------------------------------------------------------ install ----

if [ -n "${CLAUDE_VERSION:-}" ]; then
  v=$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' <<<"$CLAUDE_VERSION" | head -n1)
  if [ -z "$v" ]; then
    record INFO I01 1 "Claude Code version not recognised" "$CLAUDE_VERSION"
  elif version_ge "$v" "$MIN_STRICT_VERSION"; then
    record PASS I01 1 "Claude Code version $v supports every setting in the baseline"
  else
    record WARN I01 1 "Claude Code $v is older than $MIN_STRICT_VERSION" "Run 'claude update'. strictAllowlist needs $MIN_STRICT_VERSION or later."
  fi
else
  record INFO I01 1 "Claude Code version not provided" "Pass -e CLAUDE_VERSION=\"\$(claude --version)\" to check it."
fi

# ------------------------------------------------------ user settings ----

if [ ! -d "$HOME_CLAUDE" ]; then
  record WARN U00 2 "~/.claude was not mounted" "User settings could not be checked."
elif [ ! -f "$USER_SETTINGS" ]; then
  record FAIL U01 2 "No ~/.claude/settings.json" "Claude Code is running on defaults: no sandbox, no deny rules."
elif ! valid_json "$USER_SETTINGS"; then
  record FAIL U01 2 "~/.claude/settings.json is not valid JSON" "Claude Code will not load it. Check it with: jq . ~/.claude/settings.json"
else
  record PASS U01 2 "~/.claude/settings.json exists and is valid JSON"
  S="$USER_SETTINGS"

  # Sandbox
  if [ "$(q "$S" '.sandbox.enabled // false')" = "true" ]; then
    record PASS U02 2 "Sandbox is enabled"
    [ "${HOST_OS:-}" = "windows" ] && \
      record WARN U02 2 "Sandbox setting has no effect on native Windows" "Run Claude Code inside WSL2 for the sandbox to apply."
  elif [ "${HOST_OS:-}" = "windows" ]; then
    record FAIL U02 2 "No sandbox: native Windows is not supported" "Run Claude Code inside WSL2 and enable sandbox.enabled there (guide step 1.5)."
  else
    record FAIL U02 2 "Sandbox is not enabled" "Set sandbox.enabled: true."
  fi

  case "$(q "$S" '.sandbox.allowUnsandboxedCommands | tostring')" in
    false) record PASS U03 2 "Strict sandbox mode is on (allowUnsandboxedCommands: false)" ;;
    true)  record FAIL U03 2 "Commands may escape the sandbox (allowUnsandboxedCommands: true)" "Set it to false." ;;
    *)     record WARN U03 2 "Strict sandbox mode is not set" "Add sandbox.allowUnsandboxedCommands: false." ;;
  esac

  if [ "$(q "$S" '.sandbox.network.strictAllowlist // false')" = "true" ]; then
    record PASS U04 2 "Network strict allowlist is on"
  else
    record WARN U04 2 "Network strict allowlist is off" "Set sandbox.network.strictAllowlist: true so unknown hosts are denied, not prompted."
  fi

  risky_domains=$(q "$S" '.sandbox.network.allowedDomains // [] | .[]' \
    | grep -Eix '\*|\*\..*|github\.com|gist\.github\.com|.*pastebin.*|.*webhook.*|.*requestbin.*|.*ngrok.*|.*pipedream.*|raw\.githubusercontent\.com|discord\.com|hooks\.slack\.com' || true)
  if [ -z "$(q "$S" '.sandbox.network.allowedDomains // [] | .[]')" ]; then
    record INFO U05 2 "No network allowlist entries" "Sandboxed commands can reach no hosts until you add some."
  elif [ -n "$risky_domains" ]; then
    record WARN U05 2 "Network allowlist contains exfiltration-prone domains" "$(echo $risky_domains)"
  else
    record PASS U05 2 "Network allowlist looks narrow"
  fi

  cred_files=$(q "$S" '[(.sandbox.credentials.files // [])[] | select(.mode=="deny" or .mode=="mask") | .path] + (.sandbox.filesystem.denyRead // []) | .[]')
  for p in "~/.ssh" "~/.aws"; do
    if grep -Fq "$p" <<<"$cred_files"; then
      record PASS U06 2 "Sandbox blocks reads of $p"
    else
      record WARN U06 2 "Sandbox does not block $p" "The default read policy allows it. Add it under sandbox.credentials.files with mode deny."
    fi
  done

  if [ "$(q "$S" '.enableAllProjectMcpServers // false')" = "true" ]; then
    record FAIL U11 2 "enableAllProjectMcpServers is true" "Every MCP server a repository declares is auto-enabled. Remove it."
  fi

  if [ "$(q "$S" '.permissions.defaultMode // ""')" = "bypassPermissions" ]; then
    record FAIL U13 2 "Default permission mode is bypassPermissions" "No permission checks run at all. Change defaultMode."
  fi

  days=$(q "$S" '.cleanupPeriodDays // empty')
  if [ -z "$days" ]; then
    record WARN U14 2 "cleanupPeriodDays is not set" "Transcripts keep code and secrets. Set 7–14 days."
  elif [ "$days" -gt 30 ] 2>/dev/null; then
    record WARN U14 2 "Transcripts are kept for $days days" "Set cleanupPeriodDays to 7–14."
  else
    record PASS U14 2 "Transcripts are cleaned up after $days days"
  fi

  secret_env=$(q "$S" '.env // {} | keys[]' | grep -Ei 'key|token|secret|password|credential' || true)
  if [ -n "$secret_env" ]; then
    record FAIL U15 2 "Secrets set in the settings env block" "$(echo $secret_env) — every session and subprocess receives these."
  fi

  if q "$S" '.sandbox.network.allowUnixSockets // [] | .[]' | grep -q 'docker.sock'; then
    record FAIL U16 2 "Docker socket allowed into the sandbox" "Access to docker.sock is equivalent to root on the host."
  fi

  mk=$(q "$S" "$MARKETPLACE_FILTER")
  [ -n "$mk" ] && record WARN U17 4 "Plugin marketplaces hosted outside GitHub" "$mk"
fi

# ------------------------------------------- permission rules (merged) ----

if [ -n "$(settings_files)" ]; then
  deny=$(rules deny); ask=$(rules ask); allow=$(rules allow)

  if grep -Eq 'Read\([^)]*\.env' <<<"$deny"; then
    record PASS U07 2 "Reads of .env files are denied"
  else
    record WARN U07 2 "No deny rule for .env files" "Add Read(./.env) and Read(./.env.*) to permissions.deny."
  fi

  if grep -Eq 'Bash\((curl|wget)' <<<"$deny$ask"; then
    record PASS U08 2 "curl / wget are denied or require approval"
  else
    record WARN U08 2 "curl / wget are not restricted" "Add Bash(curl *) and Bash(wget *) to permissions.deny."
  fi

  if grep -Eq 'Bash\(git push' <<<"$deny$ask"; then
    record PASS U10 2 "git push requires approval"
  else
    record WARN U10 2 "git push is not in ask or deny" "Add Bash(git push *) to permissions.ask."
  fi

  broad=$(grep -E '^Bash$|^Bash\(\*\)$|Bash\((git push|docker|curl|wget|rm |sudo|npm publish|terraform|kubectl|ssh|scp)' <<<"$allow" || true)
  if [ -n "$broad" ]; then
    record FAIL U09 2 "Dangerous commands are auto-allowed" "$broad"
  else
    record PASS U09 2 "Allow list contains no dangerous commands"
  fi

  extra_dirs=$(while IFS= read -r f; do q "$f" '.permissions.additionalDirectories // [] | .[]'; done < <(settings_files))
  if [ -n "$extra_dirs" ]; then
    record WARN U12 2 "additionalDirectories widens the write boundary" "$(echo $extra_dirs)"
  fi
fi

# ---------------------------------------------------------------- hooks ----

hook_cmds() { # hook_cmds <matcher-regex>
  local f
  while IFS= read -r f; do
    q "$f" '.hooks.PreToolUse // [] | .[] | select((.matcher // "") | test("'"$1"'")) | .hooks[]?.command'
  done < <(settings_files)
}

if [ -n "$(settings_files)" ]; then
  if [ -n "$(hook_cmds 'Bash')" ]; then
    record PASS H01 3 "A PreToolUse hook guards the Bash tool"
  else
    record WARN H01 3 "No PreToolUse hook on the Bash tool" "Add validate-commands.sh (guide step 3)."
  fi
  if [ -n "$(hook_cmds 'Edit|Write')" ]; then
    record PASS H02 3 "A PreToolUse hook guards Edit / Write"
  else
    record WARN H02 3 "No PreToolUse hook on Edit / Write" "Add protect-files.sh (guide step 3)."
  fi
fi

# Run the hook test suite against the project's installed hooks, if present.
for dir in "$PROJECT/.claude/hooks" "$HOME_CLAUDE/hooks"; do
  if [ -f "$dir/protect-files.sh" ] && [ -f "$dir/validate-commands.sh" ]; then
    out=$(HOOKS_DIR="$dir" bash "$TESTS" 2>&1 | tail -n 5)
    if HOOKS_DIR="$dir" bash "$TESTS" >/dev/null 2>&1; then
      record PASS H03 3 "Installed hooks pass the test suite ($dir)" "$(tail -n1 <<<"$out")"
    else
      record FAIL H03 3 "Installed hooks fail the test suite ($dir)" "$out"
    fi
  fi
done

# ------------------------------------------------------ project config ----

if [ -d "$PROJECT" ] && [ -n "$(ls -A "$PROJECT" 2>/dev/null)" ]; then
  for f in "$PROJ_SETTINGS" "$PROJ_LOCAL"; do
    [ -f "$f" ] || continue
    rel="${f#$PROJECT/}"
    if ! valid_json "$f"; then
      record WARN P01 4 "$rel is not valid JSON"
      continue
    fi
    [ "$(q "$f" '.enableAllProjectMcpServers // false')" = "true" ] && \
      record FAIL P02 4 "$rel auto-enables every MCP server"
    cmds=$(q "$f" '.hooks // {} | to_entries[] | .value[]? | .hooks[]?.command')
    remote=$(grep -Ei 'curl|wget|https?://|\| *(ba|z)?sh|base64|eval' <<<"$cmds" || true)
    known=$(grep -E '/\.claude/hooks/(protect-files|validate-commands)\.sh$' <<<"$cmds" || true)
    other=$(grep -Ev '/\.claude/hooks/(protect-files|validate-commands)\.sh$' <<<"$cmds" | grep -v '^$' || true)
    [ -n "$remote" ] && record FAIL P03 4 "$rel has a hook that downloads or runs remote code" "$remote"
    [ -n "$known" ]  && record INFO P03 4 "$rel registers this guide's hooks" "$known"
    [ -n "$remote" ] && other=$(grep -Fvx -f <(printf '%s\n' "$remote") <<<"$other" || true)
    [ -n "$other" ]  && record WARN P03 4 "$rel runs hook commands — confirm you wrote or reviewed each one" "$other"

    # Hooks that fire on their own when a session starts: the Miasma worm's trigger.
    auto=$(q "$f" '[(.hooks.SessionStart // []), (.hooks.Setup // [])] | add | .[]? | .hooks[]?.command')
    [ -n "$auto" ] && record WARN P09 4 "$rel runs a hook automatically when a session starts" "$auto"

    # Plugin marketplaces outside GitHub (Plugin4Shell exposure).
    mk=$(q "$f" "$MARKETPLACE_FILTER")
    [ -n "$mk" ] && record WARN P13 4 "$rel registers plugin marketplaces hosted outside GitHub" "$mk"
  done

  if valid_json "$PROJECT/.mcp.json"; then
    servers=$(q "$PROJECT/.mcp.json" '.mcpServers // {} | keys[]')
    [ -n "$servers" ] && record INFO P04 4 "Project declares MCP servers" "$(echo $servers)"
    unpinned=$(q "$PROJECT/.mcp.json" '.mcpServers // {} | to_entries[] | select(((.value.args // []) | map(select(test("^@?[a-z0-9._-]+(/[a-z0-9._-]+)?(@latest)?$"; "i"))) | length) > 0 and (.value.command // "" | test("npx|uvx|bunx"))) | .key')
    [ -n "$unpinned" ] && record WARN P05 4 "MCP servers run without a pinned version" "$(echo $unpinned)"

    # Local (stdio) servers start as native processes once the folder is trusted (TrustFall).
    local_srv=$(q "$PROJECT/.mcp.json" '.mcpServers // {} | to_entries[] | select(.value.command) | "\(.key): \(.value.command) \((.value.args // []) | join(" "))"')
    [ -n "$local_srv" ] && record WARN P10 4 "Trusting this folder starts MCP servers as local processes outside the sandbox" "$local_srv"

    # Servers that read content other people can write (Agentjacking).
    tp=$(q "$PROJECT/.mcp.json" "$THIRD_PARTY_FILTER")
    [ -n "$tp" ] && record WARN P12 4 "Project MCP servers read content that outsiders can write" "$tp"
  fi

  # Symlinks that point at agent config, dotfiles, or out of the project (SymJack).
  sensitive_links="" outside_links=""
  while IFS= read -r link; do
    [ -z "$link" ] && continue
    rel="${link#$PROJECT/}"; target=$(readlink "$link")
    if grep -Eq '(^|/)(\.claude|\.claude\.json|\.mcp\.json|\.ssh|\.aws|\.gnupg|\.config|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|\.gitconfig|\.npmrc|\.netrc)(/|$)' <<<"$target"; then
      sensitive_links+="$rel -> $target"$'\n'
    else
      case "$target" in
        /*) outside_links+="$rel -> $target"$'\n' ;;
        *)  # relative: does it climb above the project root?
            depth=$(awk -F/ -v p="$(dirname "$rel")/$target" 'BEGIN{n=split(p,a,"/"); d=0; for(i=1;i<=n;i++){ if(a[i]==".."){d--; if(d<0){print "out"; exit}} else if(a[i]!="." && a[i]!=""){d++} } print "in"}')
            [ "$depth" = "out" ] && outside_links+="$rel -> $target"$'\n' ;;
      esac
    fi
  done < <(find "$PROJECT" \( -name .git -o -name node_modules -o -name .venv -o -name vendor \) -prune -o -type l -print 2>/dev/null | head -n 500)
  [ -n "$sensitive_links" ] && record FAIL P11 4 "Symlinks point at agent configuration or dotfiles" "$(head -n 20 <<<"$sensitive_links")"
  [ -n "$outside_links" ]   && record WARN P11 4 "Symlinks point outside the project" "$(head -n 20 <<<"$outside_links")"

  if [ -f "$PROJECT/CLAUDE.md" ]; then
    if grep -Eiq 'curl |wget |\| *(ba)?sh|npm install -g|pip install|https?://[^ )]*\.(sh|ps1)' "$PROJECT/CLAUDE.md"; then
      record WARN P06 4 "CLAUDE.md tells the agent to fetch or install something" "Read it before trusting this repository."
    fi
    if grep -Eiq 'environment variable|secret|credential' "$PROJECT/CLAUDE.md"; then
      record PASS P07 5 "CLAUDE.md contains security rules"
    else
      record WARN P07 5 "CLAUDE.md has no security rules" "See claude-code/config/CLAUDE.md.example."
    fi
  else
    record WARN P07 5 "No CLAUDE.md in the project" "See claude-code/config/CLAUDE.md.example."
  fi

  if ls -a "$PROJECT" 2>/dev/null | grep -Eq '^\.env(\..*)?$'; then
    if [ -f "$PROJECT/.gitignore" ] && grep -Eq '^\.env' "$PROJECT/.gitignore"; then
      record PASS P08 5 ".env files are gitignored"
    else
      record WARN P08 5 ".env file present but not in .gitignore" "It can be committed by accident."
    fi
  fi
else
  record INFO P00 4 "No project mounted" "Run from a project directory to check its .claude/, .mcp.json and CLAUDE.md."
fi

# ------------------------------------------------ user MCP servers ----

if valid_json "$CLAUDE_JSON"; then
  servers=$(q "$CLAUDE_JSON" '[(.mcpServers // {} | keys[]), (.projects // {} | .[] | .mcpServers // {} | keys[])] | unique | .[]')
  if [ -n "$servers" ]; then
    record INFO M01 4 "MCP servers configured for your user" "$(echo $servers) — confirm each is approved and pinned."
  else
    record PASS M01 4 "No user-level MCP servers configured"
  fi
  tp=$(jq -r '[.mcpServers // {}, (.projects // {} | .[] | .mcpServers // {})] | add | {mcpServers: .}' "$CLAUDE_JSON" 2>/dev/null | jq -r "$THIRD_PARTY_FILTER" 2>/dev/null | sort -u)
  [ -n "$tp" ] && record WARN M02 4 "Your MCP servers read content that outsiders can write" "$tp"
fi

# ------------------------------------------------------ shell startup ----

if [ -d "$RC_DIR" ]; then
  hits=$(grep -l -- '--dangerously-skip-permissions' "$RC_DIR"/.[a-z]* "$RC_DIR"/* 2>/dev/null | xargs -r -n1 basename | sort -u)
  if [ -n "$hits" ]; then
    record FAIL R01 7 "Shell startup files use --dangerously-skip-permissions" "$(echo $hits)"
  elif [ -n "$(ls -A "$RC_DIR" 2>/dev/null)" ]; then
    record PASS R01 7 "No permission-bypass aliases in shell startup files"
  fi
fi

# --------------------------------------------------------------- report ----

generated="$(date -u '+%Y-%m-%d %H:%M UTC')"
project_label="${PROJECT_NAME:-}"
[ -z "$project_label" ] && [ -d "$PROJECT" ] && project_label="(mounted project)"
[ -z "$project_label" ] && project_label="(none)"

# One JSON document holding everything; every format below renders from it.
doc=$(printf '%s\n' "${results[@]}" | jq -s \
  --arg v "$AUDIT_VERSION" --arg gen "$generated" --arg proj "$project_label" \
  --arg os "${HOST_OS:-linux/macos}" --arg cv "${CLAUDE_VERSION:-unknown}" \
  --argjson p "$n_pass" --argjson w "$n_warn" --argjson f "$n_fail" --argjson i "$n_info" \
  '{tool:"claude-code-audit", version:$v, generated:$gen, project:$proj, host_os:$os,
    claude_version:$cv, summary:{pass:$p, warn:$w, fail:$f, info:$i},
    checks: (map(. + {order: {FAIL:0, WARN:1, INFO:2, PASS:3}[.status]}) | sort_by(.order) | map(del(.order)))}')

# Add why-it-matters, framework mappings, and framework coverage of the findings.
if [ -f "$MAPPINGS" ]; then
  doc=$(jq --slurpfile map "$MAPPINGS" '
    $map[0] as $m
    | def fw($id; $k): [($m.checks[$id][$k] // [])[] | {id: ., title: $m.frameworks[$k].items[.]}];
      def keys4: ["owasp_llm", "owasp_agentic", "mitre_atlas", "nist_ai_rmf"];
    .checks |= map(. as $c | . + {
        why: ($m.checks[$c.id].why // ""),
        sources: ($m.checks[$c.id].sources // []),
        frameworks: (reduce keys4[] as $k ({}; .[$k] = fw($c.id; $k)))
      })
    | .frameworks = (reduce keys4[] as $k ({}; .[$k] = ($m.frameworks[$k] | {name, version, url})))
    | ([.checks[] | select(.status == "FAIL" or .status == "WARN")]) as $todo
    | .coverage = (reduce keys4[] as $k ({};
        .[$k] = ([ $todo[] | . as $c | .frameworks[$k][] | {id, title, check: $c.id, status: $c.status} ]
                 | group_by(.id)
                 | map({id: .[0].id, title: .[0].title,
                        fail: (map(select(.status == "FAIL")) | length),
                        warn: (map(select(.status == "WARN")) | length),
                        checks: (map(.check) | unique)})
                 | sort_by(-.fail, -.warn, .id))))
  ' <<<"$doc")
fi

case "$FORMAT" in
  json)
    jq . <<<"$doc"
    ;;

  text)
    echo "Claude Code security audit v$AUDIT_VERSION (read-only, offline)"
    echo "Guide: claude-code/README.md — step numbers shown in [brackets]"
    echo
    for r in "${results[@]}"; do
      # Multi-line details (lists of rules, hooks, ...) print one item per line.
      jq -r '"\(.status | . + "    " | .[0:5]) [\(.guide_step)] \(.title)" + (.detail | split("\n") | map(select(. != "") | "\n              " + .) | join(""))' <<<"$r"
    done
    echo
    echo "Summary: $n_pass pass, $n_warn warn, $n_fail fail, $n_info info"
    ;;

  report)
    jq -r '
      "CLAUDE CODE SECURITY AUDIT REPORT",
      "=================================",
      "Generated:      \(.generated)",
      "Project:        \(.project)",
      "Host:           \(.host_os)",
      "Claude Code:    \(.claude_version)",
      "Audit version:  \(.version)",
      "",
      "Summary: \(.summary.fail) FAIL, \(.summary.warn) WARN, \(.summary.pass) PASS, \(.summary.info) INFO",
      "",
      ( .checks | map(select(.status == "FAIL" or .status == "WARN")) as $todo
        | if ($todo | length) == 0 then "Nothing to fix. Re-run after every Claude Code upgrade." else
          "WHAT TO FIX (most serious first)",
          "--------------------------------",
          ( $todo | to_entries[] |
            "",
            "\(.key + 1). [\(.value.status)] \(.value.title)   (\(.value.id), guide step \(.value.guide_step))",
            ( if (.value.why // "") != "" then "     Why:     \(.value.why)" else empty end ),
            ( .value.detail | split("\n") | map(select(. != ""))[] | "     Details: \(.)" ),
            "     Fix:     \(.value.fix)",
            ( .value.frameworks // {} | to_entries[] | select(.value | length > 0)
              | "     \({owasp_llm: "OWASP LLM:", owasp_agentic: "OWASP Agentic:", mitre_atlas: "MITRE ATLAS:", nist_ai_rmf: "NIST AI RMF:"}[.key] | . + "       " | .[0:15]) \(.value | map("\(.id) \(if (.id | startswith("GOVERN") or startswith("MAP") or startswith("MEASURE") or startswith("MANAGE")) then "" else .title end)" | rtrimstr(" ")) | join("; "))" ),
            "     Guide:   \(.value.guide_url)",
            ( (.value.sources // [])[] | "     Source:  \(.title) — \(.url)" ) )
          end ),
      ( if (.coverage // null) != null then
          "",
          "FRAMEWORK COVERAGE OF FINDINGS",
          "------------------------------",
          "Which framework risks your FAIL / WARN findings relate to (fails, warns, check IDs).",
          ( .frameworks as $fw | .coverage | to_entries[] |
            "",
            "\($fw[.key].name) (\($fw[.key].version))",
            ( if (.value | length) == 0 then "  none" else
              ( .value[] | "  \(.id) \(.title | if length > 70 then .[0:67] + "..." else . end)  —  \(.fail) FAIL, \(.warn) WARN  [\(.checks | join(", "))]" ) end ) )
        else empty end ),
      "",
      "PASSED AND INFORMATIONAL",
      "------------------------",
      ( .checks[] | select(.status == "PASS" or .status == "INFO") | "[\(.status)] \(.title)" ),
      "",
      "Framework mappings are AISecurityLabs.org'"'"'s interpretation, verified against",
      "OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026, MITRE ATLAS 2026.09 and",
      "NIST AI RMF 1.0. They are not endorsed by the framework owners.",
      "",
      "This audit reads configuration only. To prove the controls work in a live",
      "session, run the self-test: \(.checks[0].guide_url | sub("/[^/]*$"; "/06-self-test.md"))"
    ' <<<"$doc"
    ;;

  csv)
    jq -r '
      def ids($k): (.frameworks[$k] // []) | map(.id + (if $k == "nist_ai_rmf" then "" else " " + .title end)) | join("; ");
      ["status","id","guide_step","title","why","details","fix","owasp_llm_2025","owasp_agentic_2026","mitre_atlas_2026_09","nist_ai_rmf_1_0","guide_url","sources"],
      (.checks[] | [.status, .id, .guide_step, .title, (.why // ""), (.detail | gsub("\n"; "; ")), .fix,
                    ids("owasp_llm"), ids("owasp_agentic"), ids("mitre_atlas"), ids("nist_ai_rmf"), .guide_url,
                    ((.sources // []) | map("\(.title) <\(.url)>") | join("; "))])
      | @csv
    ' <<<"$doc"
    ;;

  html)
    jq -r '
      def badge: "<span class=\"b \(. | ascii_downcase)\">\(.)</span>";
      "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
      "<title>Claude Code security audit — \(.project | @html)</title>",
      "<style>",
      "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#0d0d0d;background:#faf7f0;line-height:1.55}",
      "h1{margin:0 0 .25rem}h2{margin-top:2.5rem;border-bottom:1px solid #d9d0c0;padding-bottom:.3rem}",
      ".meta{color:#57544d;font-size:.9rem}.sum{display:flex;gap:.75rem;flex-wrap:wrap;margin:1.25rem 0}",
      ".sum div{background:#fff;border:1px solid #e6e0d4;border-radius:8px;padding:.6rem 1rem;min-width:6rem}",
      ".sum strong{display:block;font-size:1.6rem}",
      ".card{background:#fff;border:1px solid #e6e0d4;border-left:5px solid #999;border-radius:8px;padding:1rem 1.25rem;margin:1rem 0}",
      ".card.fail{border-left-color:#c53030}.card.warn{border-left-color:#d4a72c}",
      ".card h3{margin:.2rem 0 .5rem;font-size:1.05rem}.id{color:#57544d;font-weight:400;font-size:.85rem}",
      ".b{display:inline-block;font-size:.72rem;font-weight:700;padding:.1rem .5rem;border-radius:999px;color:#fff;letter-spacing:.04em}",
      ".b.fail{background:#c53030}.b.warn{background:#a8801a}.b.pass{background:#1f5fa8}.b.info{background:#4a5568}",
      "pre{background:#f3f1ea;border:1px solid #e6e0d4;border-radius:6px;padding:.6rem .8rem;white-space:pre-wrap;word-break:break-word;margin:.25rem 0 .75rem;font-size:.85rem}",
      ".label{font-weight:600;font-size:.85rem;margin-top:.5rem}a{color:#1f5fa8}",
      "table{border-collapse:collapse;width:100%;background:#fff}td{border-bottom:1px solid #e6e0d4;padding:.45rem .6rem;vertical-align:top}",
      ".foot{margin-top:2.5rem;font-size:.85rem;color:#57544d}",
      ".why{margin:.25rem 0 .5rem}.map{width:100%;margin:.5rem 0 .75rem;font-size:.82rem}.map td{border:none;border-top:1px solid #efeae0;padding:.3rem .5rem}",
      ".map td:first-child{white-space:nowrap;font-weight:600;color:#57544d;width:9rem}",
      ".chip{display:inline-block;background:#f3f1ea;border:1px solid #e6e0d4;border-radius:4px;padding:.05rem .4rem;margin:.1rem .25rem .1rem 0}",
      ".chip b{font-weight:600}.cov td{font-size:.85rem}.cov th{text-align:left;font-size:.8rem;color:#57544d;padding:.4rem .6rem;border-bottom:2px solid #d9d0c0}",
      ".n{text-align:right;white-space:nowrap}.small{font-size:.8rem;color:#57544d}",
      ".src{margin:.2rem 0 .75rem 1.1rem;padding:0;font-size:.82rem}.src li{margin:.1rem 0}",
      "</style></head><body>",
      "<h1>Claude Code security audit</h1>",
      "<p class=\"meta\">Project: <strong>\(.project | @html)</strong> · Generated \(.generated | @html) · Host: \(.host_os | @html) · Claude Code: \(.claude_version | @html) · Audit v\(.version | @html)</p>",
      "<div class=\"sum\"><div><strong>\(.summary.fail)</strong>FAIL</div><div><strong>\(.summary.warn)</strong>WARN</div><div><strong>\(.summary.pass)</strong>PASS</div><div><strong>\(.summary.info)</strong>INFO</div></div>",
      ( .checks | map(select(.status == "FAIL" or .status == "WARN")) as $todo
        | "<h2>What to fix</h2>",
          ( if ($todo | length) == 0 then "<p>Nothing to fix. Re-run after every Claude Code upgrade.</p>" else
            ( $todo[] |
              "<div class=\"card \(.status | ascii_downcase)\">",
              "<h3>\(.status | badge) \(.title | @html) <span class=\"id\">\(.id) · guide step \(.guide_step)</span></h3>",
              ( if (.why // "") != "" then "<div class=\"label\">Why it matters</div><p class=\"why\">\(.why | @html)</p>" else empty end ),
              ( if .detail != "" then "<div class=\"label\">Details</div><pre>\(.detail | @html)</pre>" else empty end ),
              "<div class=\"label\">How to fix</div><pre>\(.fix | @html)</pre>",
              ( if (.frameworks // {} | [.[]] | add // [] | length) > 0 then
                  "<div class=\"label\">Risk mapping</div><table class=\"map\">",
                  ( .frameworks | to_entries[] | select(.value | length > 0)
                    | "<tr><td>\({owasp_llm: "OWASP LLM Top 10", owasp_agentic: "OWASP Agentic Top 10", mitre_atlas: "MITRE ATLAS", nist_ai_rmf: "NIST AI RMF"}[.key])</td><td>\(.key as $k | .value | map("<span class=\"chip\"\(if $k == "nist_ai_rmf" then " title=\"" + (.title | @html) + "\"" else "" end)><b>\(.id | @html)</b>\(if $k == "nist_ai_rmf" then "" else " " + (.title | @html) end)</span>") | join(""))</td></tr>" ),
                  "</table>"
                else empty end ),
              ( if (.sources // [] | length) > 0 then
                  "<div class=\"label\">Sources</div><ul class=\"src\">",
                  ( .sources[] | "<li><a href=\"\(.url | @html)\">\(.title | @html)</a></li>" ),
                  "</ul>"
                else empty end ),
              "<a href=\"\(.guide_url | @html)\">Read guide step \(.guide_step) →</a>",
              "</div>" )
            end ) ),
      ( if (.coverage // null) != null then
          "<h2>Framework coverage</h2>",
          "<p class=\"small\">Which framework risks your FAIL and WARN findings relate to. Use this to report against your organisation'"'"'s AI risk framework.</p>",
          ( .frameworks as $fw | .coverage | to_entries[] |
            "<h3>\($fw[.key].name | @html) <span class=\"id\">\($fw[.key].version | @html)</span></h3>",
            ( if (.value | length) == 0 then "<p class=\"small\">No findings relate to this framework.</p>" else
                "<table class=\"cov\"><tr><th>ID</th><th>\(if .key == "nist_ai_rmf" then "Subcategory" else "Risk / technique" end)</th><th class=\"n\">FAIL</th><th class=\"n\">WARN</th><th>Checks</th></tr>",
                ( .value[] | "<tr><td><b>\(.id | @html)</b></td><td>\(.title | @html)</td><td class=\"n\">\(.fail)</td><td class=\"n\">\(.warn)</td><td class=\"small\">\(.checks | join(", ") | @html)</td></tr>" ),
                "</table>"
              end ),
            "<p class=\"small\"><a href=\"\($fw[.key].url | @html)\">About \($fw[.key].name | @html)</a></p>" )
        else empty end ),
      "<h2>Passed and informational</h2><table>",
      ( .checks[] | select(.status == "PASS" or .status == "INFO")
        | "<tr><td>\(.status | badge)</td><td>\(.title | @html)\(if .detail != "" then "<br><small>\(.detail | @html)</small>" else "" end)</td><td class=\"id\">\(.id)</td></tr>" ),
      "</table>",
      "<p class=\"foot\">Framework mappings are AISecurityLabs.org'"'"'s interpretation, verified against OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS 2026.09 and NIST AI RMF 1.0; they are not endorsed by the framework owners.</p>",
      "<p class=\"foot\">This audit reads configuration only. To prove the controls work in a live session, run the <a href=\"\(.checks[0].guide_url | sub("/[^/]*$"; "/06-self-test.md") | @html)\">self-test</a>. Generated offline by claude-code-audit; this file loads no external resources.</p>",
      "</body></html>"
    ' <<<"$doc"
    ;;
esac

[ "$n_fail" -eq 0 ]
