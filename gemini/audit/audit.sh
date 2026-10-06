#!/usr/bin/env bash
# Gemini CLI and Gemini Code Assist security audit: read-only, offline.
#
# Checks Gemini CLI settings, policies, MCP servers, hooks and extensions, the
# Gemini Code Assist agent setting in VS Code, and a project against the
# AISecurityLabs.org Gemini hardening guide (gemini/README.md). Code Assist
# agent mode reads the same ~/.gemini/settings.json as the CLI. It never
# modifies anything and needs no network access.
#
# Inputs (all optional, mounted read-only by run.sh / run.ps1):
#   /audit/gemini-home/settings.json            ~/.gemini/settings.json
#   /audit/gemini-home/policies/*.toml          ~/.gemini/policies
#   /audit/gemini-home/extensions/*/gemini-extension.json
#   /audit/system/{settings,system-defaults}.json   machine-wide settings
#   /audit/vscode-user/settings.json            VS Code user settings (Code Assist)
#   /audit/project                              a project directory to inspect
#   /audit/rc/*                                 shell startup files
#   GEMINI_VERSION, HOST_OS ("windows" from run.ps1), PROJECT_NAME
#   PROGRAMDATA_STATE                           Windows only: missing | admin-only | user-writable | unknown
#
# Usage: audit.sh [--format text|report|json|csv|html]   (--json = --format json)
# Exit code: 0 = no FAIL results, 1 = at least one FAIL, 2 = usage error.

PRODUCT="Gemini CLI and Code Assist"
TOOL="gemini-audit"
VERSION_LABEL="Gemini CLI"
AUDIT_VERSION="1.0.0"
GUIDE_URL="https://github.com/aisecuritylabs-org/coding-agent-security/blob/main/gemini/README.md"
GUIDE_NAME="gemini/README.md"
MIN_GEMINI="0.39.1"          # fixes CVE-2026-12537 (headless runs trusted the workspace)
MIN_ACTION="0.1.22"          # run-gemini-cli release with the same fix

GEMINI_HOME_DIR="${GEMINI_HOME_DIR:-/audit/gemini-home}"
SYSTEM_DIR="${SYSTEM_DIR:-/audit/system}"
VSCODE_DIR="${VSCODE_DIR:-/audit/vscode-user}"
PROJECT="${PROJECT:-/audit/project}"
RC_DIR="${RC_DIR:-/audit/rc}"
MAPPINGS="${MAPPINGS:-/opt/audit/mappings.json}"
TMP="${TMPDIR:-/tmp}"
PRODUCT_VERSION="${GEMINI_VERSION:-unknown}"

guide_page() {
  case "$1" in
    1) echo "#1-before-you-start" ;;
    2) echo "#2-baseline-settings" ;;
    3) echo "#3-policies-and-hooks" ;;
    4) echo "#4-repositories-and-extensions" ;;
    5) echo "#5-working-habits" ;;
    6) echo "#6-self-test" ;;
    *) echo "#7-checklist" ;;
  esac
}

fix_for() {
  case "$1" in
    I01) echo 'Update Gemini CLI to 0.39.1 or later: npm install -g @google/gemini-cli@latest' ;;
    G00) echo 'Copy gemini/config/settings.json from this repository to ~/.gemini/settings.json and adapt it.' ;;
    G01) echo 'Fix the syntax error in ~/.gemini/settings.json, then re-run the audit.' ;;
    G02) echo 'Turn on sandboxing: set "tools": { "sandbox": true } (or "docker" / "podman") or "security": { "toolSandboxing": true } in ~/.gemini/settings.json.' ;;
    G03) echo 'Remove "security": { "folderTrust": { "enabled": false } } from ~/.gemini/settings.json. Folder trust keeps an untrusted project'"'"'s settings, .env and MCP servers from loading.' ;;
    G04) echo 'Add "security": { "disableYoloMode": true } to ~/.gemini/settings.json so --yolo is ignored.' ;;
    G05) echo 'Set "general": { "defaultApprovalMode": "default" } so edits ask first; use auto_edit only for a session that needs it.' ;;
    G06) echo 'Remove the listed entries from tools.allowed. Allow only read-only commands, e.g. "run_shell_command(git status)", never the bare run_shell_command or a shell, interpreter, delete or network tool.' ;;
    G07) echo 'Set "tools": { "sandboxNetworkAccess": false }, the default, unless a task needs the network.' ;;
    G08) echo 'Remove "security": { "enablePermanentToolApproval": true } so approvals don'"'"'t outlive the session.' ;;
    G09) echo 'Set "security": { "blockGitExtensions": true }, or list allowed extensions in security.allowedExtensions.' ;;
    M02|P03) echo 'Treat everything these servers return as untrusted input: give them read-only credentials, keep confirmations on for their tools, and never let the agent run commands copied from tickets, errors or messages.' ;;
    M03|P04) echo 'Pin every MCP server to an exact version, e.g. "some-server@1.4.2" instead of "some-server" or "@latest".' ;;
    M04|P05) echo 'Remove "trust": true from the listed MCP servers. It bypasses every tool call confirmation for that server.' ;;
    M05) echo 'Move the listed secrets out of settings.json and reference environment variables instead, e.g. "$MY_TOKEN".' ;;
    H01|P07) echo 'Read every listed hook command and the scripts it runs. Remove any you did not write; never keep a hook that downloads or pipes remote code into a shell.' ;;
    E01) echo 'Review each extension and what it adds. Uninstall extensions you no longer use: gemini extensions uninstall <name>.' ;;
    E02) echo 'Read the listed extension manifests. Remove extensions that add trusted MCP servers or hooks you did not expect.' ;;
    R01) echo 'Change the listed allow rules to decision = "ask_user", or narrow them with commandPrefix to read-only commands.' ;;
    C01) echo 'Set "geminicodeassist.agentYoloMode": false in your VS Code user settings, so Code Assist agent mode asks before it acts.' ;;
    P01) echo 'Do not trust this folder until you have removed the listed settings from .gemini/settings.json. A repository should never lower your sandbox or approvals.' ;;
    P02) echo 'Read every MCP server in .gemini/settings.json before trusting the folder. Remove servers you do not recognise, or open the repository in a container with no credentials.' ;;
    P06) echo 'Read the project'"'"'s hooks before trusting the folder: they run commands on agent events. Remove hooks you did not write.' ;;
    P08) echo 'Remove the listed GEMINI_* variables from the project .env. A trusted folder'"'"'s .env can turn the sandbox off.' ;;
    P09) echo 'Read the listed context files before trusting this repository. Remove fetch or install instructions you did not add.' ;;
    P10) echo 'Open the listed files in an editor that shows invisible characters (or run: grep -nP "[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]" <file>) and remove the hidden characters.' ;;
    P11) echo 'Update google-github-actions/run-gemini-cli to v0.1.22 or later, pin it by commit SHA, never run it with --yolo on issue or pull request text from outsiders, and give it only the permissions and secrets it needs.' ;;
    P12) echo 'Add these lines to the project'"'"'s .gitignore: .env and .env.* (and remove any !.env exception). If a .env file is already committed, remove it with git rm --cached <file> and rotate the secrets it held.' ;;
    P13) echo 'Do not open this folder with Gemini until you have checked each listed link: ls -la <link>. Delete links you did not create.' ;;
    P14) echo 'This repository came with a .git/config that runs programs. Remove the listed keys, or re-clone it: a normal git clone never copies .git/config.' ;;
    W01) echo 'In PowerShell opened with Run as administrator, run gemini/config/lock-programdata.ps1 from this repository. It creates C:\ProgramData\gemini-cli if needed, makes Administrators the owner, gives only Administrators and SYSTEM write access and Users read access, and applies the same to everything inside. If the folder already existed, first remove any settings.json or system-defaults.json your administrators did not put there.' ;;
    W02) echo 'Find out who created the machine-wide settings file and remove anything your administrators did not put there; on Windows, lock the folder as in W01.' ;;
    S01) echo 'Remove the alias or export that adds --yolo, --approval-mode yolo, --skip-trust, GEMINI_SANDBOX=false or GEMINI_CLI_TRUST_WORKSPACE=true from the listed shell startup file, then open a new terminal.' ;;
    *) echo '' ;;
  esac
}

# shellcheck source=../../common/audit-lib.sh
. "${AUDIT_LIB:-/opt/audit/audit-lib.sh}"

REMOTE_CODE='curl|wget|\| *(ba|z)?sh|iex|Invoke-WebRequest|Invoke-Expression|nc |base64 -d'
RISKY_CMD='^(bash|sh|zsh|fish|pwsh|powershell|cmd|python[0-9.]*|node|ruby|perl|eval|exec|sudo|su|rm|rmdir|del|dd|chmod|chown|curl|wget|nc|ssh|scp|rsync|docker|kubectl|terraform|aws|gcloud|az)( |$)|^git (push|reset|clean)|^npm (publish|exec)|^npx( |$)'

# hook_cmds <json>: every hook command in a settings or manifest file.
hook_cmds() { q "$1" '[.hooks // {} | .. | objects | select(.command? != null) | .command] | .[]'; }
# risky_allowed <json>: tools.allowed entries that let the agent run anything risky.
risky_allowed() {
  q "$1" '.tools.allowed // [] | .[]' | while IFS= read -r t; do
    case "$t" in
      run_shell_command|ShellTool|"run_shell_command()") echo "$t" ;;
      run_shell_command\(*\)|ShellTool\(*\))
        c="${t#*(}"; c="${c%)}"
        grep -Eq "$RISKY_CMD" <<<"$c" && echo "$t" ;;
    esac
  done
}
# loosened <json>: settings in a project or system file that weaken protections.
# sandbox_value: tools.sandbox, or the legacy top-level sandbox, keeping an explicit
# false (jq's // would treat false as missing and fall through).
SANDBOX_DEF='def sandbox_value: if ((.tools // {}) | has("sandbox")) then .tools.sandbox elif has("sandbox") then .sandbox else null end;'
loosened() {
  q "$1" "$SANDBOX_DEF"'[
    (if sandbox_value == false then "tools.sandbox = false" else empty end),
    (if .security.folderTrust.enabled == false then "security.folderTrust.enabled = false" else empty end),
    (if .general.defaultApprovalMode == "auto_edit" then "general.defaultApprovalMode = auto_edit" else empty end),
    (if .tools.sandboxNetworkAccess == true then "tools.sandboxNetworkAccess = true" else empty end),
    (if .security.enablePermanentToolApproval == true then "security.enablePermanentToolApproval = true" else empty end),
    ((.tools.allowed // [])[] | "tools.allowed: \(.)") ] | .[]'
}

# ------------------------------------------------------------ versions ----

if [ -n "${GEMINI_VERSION:-}" ]; then
  # Keep the prerelease part: the advisory lists 0.40.0-preview.2 as affected and
  # 0.40.0-preview.3 as fixed, and a prerelease comes before its release.
  full=$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?' <<<"$GEMINI_VERSION" | head -n1)
  v="${full%%-*}"; pre=""; [ "$full" != "$v" ] && pre="${full#*-}"
  pn=$(grep -Eo '^preview\.[0-9]+$' <<<"$pre" | cut -d. -f2)
  if [ -z "$v" ]; then record INFO I01 1 "Gemini CLI version not recognised" "$GEMINI_VERSION"
  elif ! version_ge "$v" "$MIN_GEMINI" || { [ "$v" = "$MIN_GEMINI" ] && [ -n "$pre" ]; }; then
    record WARN I01 1 "Gemini CLI $full is older than $MIN_GEMINI" "Older versions trusted the workspace in headless runs (CVE-2026-12537)."
  elif [ "$v" = "0.40.0" ] && [ -n "$pre" ] && { [ -z "$pn" ] || [ "$pn" -lt 3 ]; }; then
    record WARN I01 1 "Gemini CLI $full is a prerelease without the CVE-2026-12537 fix" "The fix reached the 0.40.0 previews in 0.40.0-preview.3."
  else record PASS I01 1 "Gemini CLI $full is current"; fi
else
  record INFO I01 1 "Gemini CLI version not provided" "Pass -e GEMINI_VERSION=\"\$(gemini --version)\" to check it."
fi

# ------------------------------------------------------ ~/.gemini/settings ----

G=""
if [ ! -f "$GEMINI_HOME_DIR/settings.json" ]; then
  record INFO G00 2 "No ~/.gemini/settings.json" "Gemini CLI runs on its defaults: folder trust on, sandboxing off."
elif ! jsonc "$GEMINI_HOME_DIR/settings.json" gsettings; then
  record FAIL G01 2 "~/.gemini/settings.json could not be read" "Gemini CLI may be ignoring it. Check it for syntax errors."
else
  G="$TMP/gsettings.json"
  record PASS G01 2 "~/.gemini/settings.json is readable"
fi

if [ -n "$G" ]; then
  sb=$(q "$G" "$SANDBOX_DEF"' sandbox_value | if . == null then empty else tostring end')
  if { [ -n "$sb" ] && [ "$sb" != "false" ]; } || [ "$(q "$G" '.security.toolSandboxing // false')" = "true" ]; then
    record PASS G02 2 "Sandboxing is on"
  else
    record WARN G02 2 "Sandboxing is off (the default)" "Shell commands and file edits run with your full user permissions."
  fi
fi
if [ -n "$G" ] && [ "$(q "$G" '.security.folderTrust.enabled')" = "false" ]; then
  record FAIL G03 2 "Folder trust is turned off" "Every folder's .gemini/settings.json, .env and MCP servers load without asking."
elif [ -n "$G" ]; then
  record PASS G03 2 "Folder trust is on"
fi
if [ -n "$G" ]; then
  if [ "$(q "$G" '.security.disableYoloMode // false')" = "true" ] || [ "$(q "$G" '.admin.secureModeEnabled // false')" = "true" ]; then
    record PASS G04 3 "YOLO mode is disabled"
  else
    record INFO G04 3 "YOLO mode can be turned on with --yolo" "security.disableYoloMode is not set."
  fi
  [ "$(q "$G" '.general.defaultApprovalMode // empty')" = "auto_edit" ] && \
    record WARN G05 2 "File edits are approved automatically by default" "general.defaultApprovalMode is auto_edit."
  risky=$(risky_allowed "$G")
  if [ -n "$risky" ]; then
    record FAIL G06 2 "Risky tools bypass confirmation" "$risky"
  else
    record PASS G06 2 "No allowed tool matches the audit's risky list"
  fi
  [ "$(q "$G" '.tools.sandboxNetworkAccess // false')" = "true" ] && \
    record WARN G07 2 "The sandbox allows network access" "tools.sandboxNetworkAccess is true."
  [ "$(q "$G" '.security.enablePermanentToolApproval // false')" = "true" ] && \
    record WARN G08 2 "Tool approvals can last across sessions" "security.enablePermanentToolApproval is true."
  if [ "$(q "$G" '.security.blockGitExtensions // false')" = "true" ] || [ "$(q "$G" '.security.allowedExtensions // [] | length')" -gt 0 ] 2>/dev/null; then
    record PASS G09 4 "Extensions are restricted"
  else
    record INFO G09 4 "Any extension can be installed from Git" "security.blockGitExtensions and security.allowedExtensions are not set."
  fi

  servers=$(q "$G" '.mcpServers // {} | keys[]')
  if [ -n "$servers" ]; then
    record INFO M01 4 "MCP servers configured for Gemini" "$(echo $servers): confirm each is approved and pinned."
    tp=$(mcp_third_party "$G" '.mcpServers'); [ -n "$tp" ] && record WARN M02 4 "Your MCP servers read content that outsiders can write" "$tp"
    un=$(mcp_unpinned "$G" '.mcpServers');    [ -n "$un" ] && record WARN M03 4 "MCP servers run without a pinned version" "$(echo $un)"
    tr=$(q "$G" '.mcpServers // {} | to_entries[] | select(.value.trust == true) | .key')
    [ -n "$tr" ] && record FAIL M04 4 "MCP servers bypass every confirmation" "$(echo $tr)"
    lit=$(q "$G" '.mcpServers // {} | to_entries[] | .key as $s
      | (((.value.env // {}) + (.value.headers // {})) | to_entries[]
         | select((.key | test("key|token|secret|password|credential|authorization"; "i")) and ((.value | tostring) | test("\\$") | not))
         | "\($s): \(.key)")')
    [ -n "$lit" ] && record WARN M05 4 "Secrets stored in settings.json" "$lit"
  fi

  cmds=$(hook_cmds "$G")
  remote=$(grep -Ei "$REMOTE_CODE" <<<"$cmds" || true)
  [ -n "$remote" ] && record FAIL H01 3 "A user hook downloads or runs remote code" "$remote"
fi

# Policy files: allow rules that let risky shell commands run without asking.
if [ -d "$GEMINI_HOME_DIR/policies" ]; then
  allow=""
  for f in "$GEMINI_HOME_DIR"/policies/*.toml; do
    [ -f "$f" ] || continue
    toml "$f" pol || { allow+="$(basename "$f"): could not be read"$'\n'; continue; }
    hits=$(jq -r --arg f "$(basename "$f")" '(.rule // [])[] | select(.decision == "allow")
      | select(([.toolName] | flatten | map(. == "run_shell_command" or . == "*") | any))
      | select(.commandPrefix == null and .commandRegex == null and .argsPattern == null
               or (([.commandPrefix] | flatten | map(select(. != null) | test("^(bash|sh|rm|sudo|curl|wget|python|node|ssh|docker|kubectl|git push)"; "i")) | length) > 0))
      | "\($f): allow \([.toolName] | flatten | join(",")) \(.commandPrefix // .commandRegex // "(any command)")"' "$TMP/pol.json" 2>/dev/null)
    [ -n "$hits" ] && allow+="$hits"$'\n'
  done
  allow=$(grep -v '^$' <<<"$allow" || true)
  if [ -n "$allow" ]; then
    record FAIL R01 3 "Policy rules let risky shell commands run without asking" "$allow"
  elif ls "$GEMINI_HOME_DIR"/policies/*.toml >/dev/null 2>&1; then
    record PASS R01 3 "Policy rules don't allow risky shell commands"
  fi
fi

# Installed extensions.
if [ -d "$GEMINI_HOME_DIR/extensions" ]; then
  inv=""; risky_ext=""
  for m in "$GEMINI_HOME_DIR"/extensions/*/gemini-extension.json; do
    [ -f "$m" ] || continue
    jsonc "$m" ext || continue
    name=$(basename "$(dirname "$m")")
    adds=$(q "$TMP/ext.json" '[ (if (.mcpServers // {}) != {} then "MCP: \(.mcpServers | keys | join(", "))" else empty end),
      (if (.hooks // {}) != {} then "hooks" else empty end),
      (if .contextFileName then "context: \(.contextFileName)" else empty end) ] | join("; ")')
    inv+="$name${adds:+ ($adds)}"$'\n'
    t=$(q "$TMP/ext.json" '.mcpServers // {} | to_entries[] | select(.value.trust == true) | .key')
    h=$(hook_cmds "$TMP/ext.json" | grep -Ei "$REMOTE_CODE" || true)
    [ -n "$t$h" ] && risky_ext+="$name: ${t:+trusted MCP server $t }${h:+hook runs remote code}"$'\n'
  done
  [ -n "$inv" ] && record INFO E01 4 "Installed Gemini CLI extensions" "$inv"
  [ -n "$risky_ext" ] && record WARN E02 4 "Extensions add trusted MCP servers or remote-code hooks" "$risky_ext"
fi

# ---------------------------------------------------------- Code Assist ----

if jsonc "$VSCODE_DIR/settings.json" vscode; then
  if [ "$(q "$TMP/vscode.json" '.["geminicodeassist.agentYoloMode"] // false')" = "true" ]; then
    record FAIL C01 2 "Gemini Code Assist agent mode runs without asking" "geminicodeassist.agentYoloMode is true."
  else
    record PASS C01 2 "Gemini Code Assist agent mode asks before it acts"
  fi
fi

# --------------------------------------------------------------- project ----

if project_mounted; then
  if jsonc "$PROJECT/.gemini/settings.json" psettings; then
    PS="$TMP/psettings.json"
    loose=$(loosened "$PS")
    [ -n "$loose" ] && record WARN P01 4 "The project's .gemini/settings.json changes your protections" "$loose"
    list=$(mcp_list "$PS" '.mcpServers')
    [ -n "$list" ] && record WARN P02 4 ".gemini/settings.json declares MCP servers" "$list"
    tp=$(mcp_third_party "$PS" '.mcpServers'); [ -n "$tp" ] && record WARN P03 4 ".gemini/settings.json adds MCP servers that read outsider-written content" "$tp"
    un=$(mcp_unpinned "$PS" '.mcpServers');    [ -n "$un" ] && record WARN P04 4 ".gemini/settings.json runs MCP servers without a pinned version" "$(echo $un)"
    tr=$(q "$PS" '.mcpServers // {} | to_entries[] | select(.value.trust == true) | .key')
    [ -n "$tr" ] && record FAIL P05 4 "The project trusts MCP servers, bypassing every confirmation" "$(echo $tr)"
    cmds=$(hook_cmds "$PS")
    if [ -n "$cmds" ]; then
      record WARN P06 4 "The project ships hooks" "$cmds"
      remote=$(grep -Ei "$REMOTE_CODE" <<<"$cmds" || true)
      [ -n "$remote" ] && record FAIL P07 4 "A project hook downloads or runs remote code" "$remote"
    fi
  fi

  if [ -f "$PROJECT/.env" ]; then
    genv=$(grep -Eo '^[[:space:]]*(export[[:space:]]+)?GEMINI_[A-Z0-9_]+' "$PROJECT/.env" | sed -E 's/^[[:space:]]*(export[[:space:]]+)?//' | grep -Ev '^GEMINI_(API_KEY|MODEL)$' | sort -u || true)
    [ -n "$genv" ] && record FAIL P08 4 "The project .env sets Gemini CLI variables" "$(echo $genv)"
  fi

  mapfile -t instr < <(cd "$PROJECT" && find . -maxdepth 3 \( -name .git -o -name node_modules \) -prune -o -type f \( -name GEMINI.md -o -name AGENTS.md \) -print 2>/dev/null | sed 's#^\./##' | head -n 100)
  fetch=""
  for f in "${instr[@]}"; do grep -Eiq "$FETCH_PATTERN" "$PROJECT/$f" && fetch+="$f"$'\n'; done
  [ -n "$fetch" ] && record WARN P09 4 "Context files tell the agent to fetch or install something" "$fetch"
  hidden=$(hidden_unicode "${instr[@]/#/$PROJECT/}")
  [ -n "$hidden" ] && record FAIL P10 4 "Context files contain hidden Unicode characters" "$hidden"

  # GitHub workflows that run Gemini.
  wf=""
  for f in "$PROJECT"/.github/workflows/*.yml "$PROJECT"/.github/workflows/*.yaml; do
    [ -f "$f" ] || continue
    grep -q 'run-gemini-cli' "$f" || continue
    rel="${f#$PROJECT/}"
    ref=$(grep -Eo 'run-gemini-cli@[^[:space:]#]+' "$f" | head -n1 | cut -d@ -f2)
    rv=$(grep -Eo '^v?[0-9]+\.[0-9]+\.[0-9]+$' <<<"$ref" | tr -d v)
    if [ -n "$rv" ] && ! version_ge "$rv" "$MIN_ACTION"; then wf+="$rel: run-gemini-cli $ref is older than $MIN_ACTION"$'\n'; fi
    if grep -Eq '^[[:space:]]*(issues|issue_comment|pull_request_target|pull_request_review_comment|discussion_comment):' "$f" || grep -Eq 'on:.*(issues|issue_comment|pull_request_target)' "$f"; then
      grep -Eq -- '--yolo|approval-mode[^a-z]*yolo|GEMINI_CLI_TRUST_WORKSPACE|"?yolo"?:[[:space:]]*true' "$f" && \
        wf+="$rel: runs Gemini without confirmations on issue or pull request text"$'\n'
    fi
  done
  wf=$(grep -v '^$' <<<"$wf" || true)
  [ -n "$wf" ] && record WARN P11 4 "GitHub workflows run Gemini on untrusted input" "$wf"

  check_env_gitignored P12 5
  check_symlinks P13 4 '(^|/)(\.gemini|GEMINI\.md|AGENTS\.md|\.github|\.vscode|\.ssh|\.aws|\.gnupg|\.config|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|\.gitconfig|\.npmrc|\.netrc)(/|$)'
  check_gitconfig P14 4
else
  record INFO P00 4 "No project mounted" "Run from a project directory to check its .gemini/ folder, context files and workflows."
fi

# ---------------------------------------------------- machine-wide files ----

if [ "${HOST_OS:-}" = "windows" ]; then
  case "${PROGRAMDATA_STATE:-}" in
    admin-only)    record PASS W01 1 'C:\ProgramData\gemini-cli is writable by administrators only' ;;
    user-writable) record FAIL W01 1 'Someone other than administrators can change C:\ProgramData\gemini-cli' "An account other than Administrators, SYSTEM or TrustedInstaller owns the folder or a file in it, or can write there, so it can plant settings every Gemini CLI user on this machine loads." ;;
    missing)       record WARN W01 1 'C:\ProgramData\gemini-cli does not exist yet' "Windows does not restrict new folders under ProgramData, so a standard user could create it and plant a system-defaults.json with a session-start hook for every user (reported by Cymulate)." ;;
    unknown)       record WARN W01 1 'Could not read the permissions of C:\ProgramData\gemini-cli' "Check them by hand: the folder and everything in it should be owned by Administrators and writable only by Administrators and SYSTEM." ;;
    *)             record INFO W01 1 'ProgramData folder permissions not checked' "Run the audit with run.ps1 to check them." ;;
  esac
fi
sysbad=""; sysinfo=""
for f in settings.json system-defaults.json; do
  jsonc "$SYSTEM_DIR/$f" "sys$f" || continue
  S_="$TMP/sys$f.json"
  cmds=$(hook_cmds "$S_")
  remote=$(grep -Ei "$REMOTE_CODE" <<<"$cmds" || true)
  loose=$(loosened "$S_")
  [ -n "$remote" ] && sysbad+="$f hook: $remote"$'\n'
  [ -n "$loose" ] && sysbad+="$(sed "s#^#$f: #" <<<"$loose")"$'\n'
  [ -n "$cmds$(q "$S_" '.mcpServers // {} | keys[]')" ] && sysinfo+="$f: hooks or MCP servers present"$'\n'
done
if [ -n "$sysbad" ]; then
  record FAIL W02 1 "Machine-wide settings weaken Gemini CLI for every user" "$sysbad"
elif [ -n "$sysinfo" ]; then
  record INFO W02 1 "Machine-wide settings add hooks or MCP servers for every user" "$sysinfo""Confirm your administrators created them."
fi

check_rc_flags S01 3 'gemini[^#]*(--yolo|--approval-mode[= ]yolo|--skip-trust)|GEMINI_SANDBOX=["'"'"']?false|GEMINI_CLI_TRUST_WORKSPACE=["'"'"']?true' "Shell startup files turn off Gemini CLI protections"

render_report
