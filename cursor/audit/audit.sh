#!/usr/bin/env bash
# Cursor security audit: read-only, offline.
#
# Checks Cursor's sandbox, allowlist, MCP, hook and CLI configuration and a
# project against the AISecurityLabs.org Cursor hardening guide
# (cursor/README.md). It never modifies anything and needs no network access.
# Run modes are chosen in the Cursor app and aren't stored in these files, so
# they are covered by the guide's checklist rather than by this audit.
#
# Inputs (all optional, mounted read-only by run.sh / run.ps1):
#   /audit/cursor-home/{sandbox,permissions,mcp,hooks,cli-config}.json   ~/.cursor
#   /audit/cursor-user/settings.json   Cursor user settings (Workspace Trust)
#   /audit/system/hooks.json           machine-wide hooks (ProgramData, /etc/cursor, /Library)
#   /audit/project                     a project directory to inspect
#   /audit/rc/*                        shell startup files
#   CURSOR_VERSION, HOST_OS ("windows" from run.ps1), PROJECT_NAME
#   PROGRAMDATA_STATE                  Windows only: missing | admin-only | user-writable | unknown
#
# Usage: audit.sh [--format text|report|json|csv|html]   (--json = --format json)
# Exit code: 0 = no FAIL results, 1 = at least one FAIL, 2 = usage error.

PRODUCT="Cursor"
TOOL="cursor-audit"
VERSION_LABEL="Cursor"
AUDIT_VERSION="1.0.0"
GUIDE_URL="https://github.com/aisecuritylabs-org/coding-agent-security/blob/main/cursor/README.md"
GUIDE_NAME="cursor/README.md"
MIN_CURSOR="3.1.2"          # fixes CVE-2026-73217 (sandbox escape through a Python virtual environment)

CURSOR_HOME_DIR="${CURSOR_HOME_DIR:-/audit/cursor-home}"
CURSOR_USER_DIR="${CURSOR_USER_DIR:-/audit/cursor-user}"
SYSTEM_DIR="${SYSTEM_DIR:-/audit/system}"
PROJECT="${PROJECT:-/audit/project}"
RC_DIR="${RC_DIR:-/audit/rc}"
MAPPINGS="${MAPPINGS:-/opt/audit/mappings.json}"
TMP="${TMPDIR:-/tmp}"
PRODUCT_VERSION="${CURSOR_VERSION:-unknown}"

guide_page() {
  case "$1" in
    1) echo "#1-before-you-start" ;;
    2) echo "#2-sandbox-and-run-mode" ;;
    3) echo "#3-allowlists-hooks-and-the-cli" ;;
    4) echo "#4-repositories-and-extensions" ;;
    5) echo "#5-working-habits" ;;
    6) echo "#6-self-test" ;;
    *) echo "#7-checklist" ;;
  esac
}

fix_for() {
  case "$1" in
    I01) echo 'Update Cursor (Cursor > Check for Updates, or download the current release from cursor.com) to 3.1.2 or later.' ;;
    V00) echo 'Run the audit with run.sh or run.ps1, which share your Cursor user settings with the container automatically.' ;;
    V01) echo 'Fix the syntax error in your Cursor settings.json, then re-run the audit.' ;;
    V02) echo 'Add "security.workspace.trust.enabled": true to your Cursor user settings (Command Palette: "Preferences: Open User Settings (JSON)"), then open folders you did not create in restricted mode. Organisations can enforce it with the WorkspaceTrustEnabled policy.' ;;
    B01|P01) echo 'Remove "type": "insecure_none" from the listed sandbox.json. Use "workspace_readwrite" (the default) or "workspace_readonly".' ;;
    B02) echo 'Set "networkPolicy": { "default": "deny" } in ~/.cursor/sandbox.json and list only the registries you use under "allow".' ;;
    B03) echo 'Remove the listed wildcard entries from networkPolicy.allow in ~/.cursor/sandbox.json; list exact domains instead.' ;;
    B04) echo 'Remove the listed paths from additionalReadwritePaths and additionalReadonlyPaths. Never give the sandbox your home folder or credential folders.' ;;
    A01) echo 'Remove the listed entries from terminalAllowlist in ~/.cursor/permissions.json (or Settings > Agents > Approvals & Execution). Allowlisted commands run outside the sandbox without asking, so list only read-only commands such as "git status" and "git diff".' ;;
    A02) echo 'Replace "*:*" and whole-server entries in mcpAllowlist with the specific read-only tools you need, e.g. "github:get_issue".' ;;
    A03) echo 'Add autoRun.block_instructions to ~/.cursor/permissions.json describing calls Auto-review should send to you: credential files, deletes, pushes, publishing and outbound data (see cursor/config/permissions.json). Remove allow_instructions you did not write.' ;;
    M02|P04) echo 'Treat everything these servers return as untrusted input: give them read-only credentials, keep their tools out of mcpAllowlist, and never let the agent run commands copied from tickets, errors or messages.' ;;
    M03|P05) echo 'Pin every MCP server to an exact version, e.g. "some-server@1.4.2" instead of "some-server" or "@latest".' ;;
    M04) echo 'Move the listed secrets out of mcp.json and reference them as "${env:NAME}", so the value is never stored in the file.' ;;
    H01|P07) echo 'Read every listed hook command and the scripts it runs. Remove any you did not write; never keep a hook that downloads or pipes remote code into a shell.' ;;
    H02) echo 'Add "failClosed": true to the listed security hooks, so a crash or timeout blocks the action instead of allowing it.' ;;
    L01) echo 'Remove "approvalMode": "unrestricted" from ~/.cursor/cli-config.json and use "allowlist" or "auto-review".' ;;
    L02) echo 'Turn the CLI sandbox back on: run agent sandbox enable, or remove "sandbox": { "mode": "disabled" } from ~/.cursor/cli-config.json.' ;;
    L03) echo 'Remove the listed entries from permissions.allow in ~/.cursor/cli-config.json; allow only specific read-only commands and named domains.' ;;
    L04) echo 'Add "Read(**/.env*)" and "Write(**/.env*)" to permissions.deny in ~/.cursor/cli-config.json (see cursor/config/cli-config.json).' ;;
    P02) echo 'Do not trust this project until you have removed the listed entries from .cursor/permissions.json. A repository adds to your allowlists, so it can make commands run without asking.' ;;
    P03) echo 'Read every MCP server the project declares in .cursor/mcp.json before trusting the folder. Remove servers you do not recognise, or open the repository in a container with no credentials.' ;;
    P06) echo 'Read the project'"'"'s .cursor/hooks.json before trusting the folder: project hooks run in every trusted workspace. Remove hooks you did not write.' ;;
    P08) echo 'Remove the listed allow entries from the project'"'"'s .cursor/cli.json, or don'"'"'t run the Cursor CLI in this repository until you have.' ;;
    P09) echo 'Read the listed rules and instruction files before trusting this repository. Remove fetch or install instructions you did not add.' ;;
    P10) echo 'Open the listed files in an editor that shows invisible characters (or run: grep -nP "[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]" <file>) and remove the hidden characters. Add a pre-commit check for them.' ;;
    P11) echo 'Review the listed install and setup commands; pin what they install and never pipe downloads into a shell. Cloud agents and worktree setup run them for you.' ;;
    P12) echo 'Add these lines to the project'"'"'s .gitignore: .env and .env.* (and remove any !.env exception). If a .env file is already committed, remove it with git rm --cached <file> and rotate the secrets it held.' ;;
    P13) echo 'Do not open this folder with Cursor until you have checked each listed link: ls -la <link>. Delete links you did not create.' ;;
    P14) echo 'This repository came with a .git/config that runs programs. Remove the listed keys, or re-clone it: a normal git clone never copies .git/config.' ;;
    W01) echo 'In PowerShell opened with Run as administrator, run cursor/config/lock-programdata.ps1 from this repository. It creates C:\ProgramData\Cursor if needed, makes Administrators the owner, gives only Administrators and SYSTEM write access and Users read access, and applies the same to everything inside. If the folder already existed, first remove any hooks.json your administrators did not put there.' ;;
    W02) echo 'Find out who created the machine-wide hooks.json and remove any hook your administrators did not put there; on Windows, lock the folder as in W01.' ;;
    S01) echo 'Remove the alias or function that adds --yolo, --force, --sandbox disabled or --approve-mcps to the Cursor CLI from the listed shell startup file, then open a new terminal.' ;;
    *) echo '' ;;
  esac
}

# shellcheck source=../../common/audit-lib.sh
. "${AUDIT_LIB:-/opt/audit/audit-lib.sh}"

# Commands that download or run remote code.
REMOTE_CODE='curl|wget|\| *(ba|z)?sh|iex|Invoke-WebRequest|Invoke-Expression|nc |base64 -d'
# Terminal allowlist entries that let the agent run anything, delete, escalate or reach the network.
RISKY_CMD='^(\*|bash|sh|zsh|fish|pwsh|powershell|cmd|python[0-9.]*|node|ruby|perl|eval|exec|sudo|su|rm|rmdir|del|dd|chmod|chown|curl|wget|nc|ssh|scp|rsync|docker|kubectl|terraform|aws|gcloud|az)( |:|$)|^git (push|reset|clean)|^npm (publish|exec)|^npx( |$)|^git$|^npm$'
# Paths that should never be given to the sandbox.
SENSITIVE_PATH='^(~|/|/home/[^/]+|/Users/[^/]+|[A-Za-z]:\\Users\\[^\\]+)/?$|\.ssh|\.aws|\.gnupg|\.kube|\.config/gcloud|\.azure|\.docker/config|\.npmrc|\.netrc'

# hook_cmds <json>: every command in a hooks.json file.
hook_cmds() { q "$1" '.hooks // {} | to_entries[] | .value[]? | select(.command != null) | .command'; }

# ------------------------------------------------------------ versions ----

if [ -n "${CURSOR_VERSION:-}" ]; then
  v=$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' <<<"$CURSOR_VERSION" | head -n1)
  if [ -z "$v" ]; then record INFO I01 1 "Cursor version not recognised" "$CURSOR_VERSION"
  elif ! version_ge "$v" "$MIN_CURSOR"; then
    record WARN I01 1 "Cursor $v is older than $MIN_CURSOR" "Older versions are exposed to sandbox escapes fixed since, including CVE-2026-73217 and the DuneSlide CVEs."
  else record PASS I01 1 "Cursor $v is current"; fi
else
  record INFO I01 1 "Cursor version not provided" "Pass -e CURSOR_VERSION=\"\$(cursor --version | head -n1)\" to check it."
fi

# ------------------------------------------------------- user settings ----

if [ ! -d "$CURSOR_USER_DIR" ]; then
  record WARN V00 1 "Cursor user settings were not mounted" "Workspace Trust could not be checked."
elif [ ! -f "$CURSOR_USER_DIR/settings.json" ]; then
  record WARN V02 1 "Workspace Trust is off (the default)" "There is no Cursor user settings.json, and Cursor ships with Workspace Trust disabled."
elif ! jsonc "$CURSOR_USER_DIR/settings.json" usettings; then
  record FAIL V01 1 "Cursor settings.json could not be read" "Cursor may be ignoring it. Check it for syntax errors."
else
  if [ "$(q "$TMP/usettings.json" '.["security.workspace.trust.enabled"] // false')" = "true" ]; then
    record PASS V02 1 "Workspace Trust is on"
  else
    record WARN V02 1 "Workspace Trust is off (the default)" "Every folder you open is trusted, so its project hooks, MCP servers and allowlists apply at once."
  fi
fi

# ---------------------------------------------------------- ~/.cursor ----

S=""
if jsonc "$CURSOR_HOME_DIR/sandbox.json" usandbox; then
  S="$TMP/usandbox.json"
  if [ "$(q "$S" '.type // "workspace_readwrite"')" = "insecure_none" ]; then
    record FAIL B01 2 "~/.cursor/sandbox.json turns the sandbox off" "type is insecure_none."
  else
    record PASS B01 2 "The sandbox is on ($(q "$S" '.type // "workspace_readwrite"'))"
  fi
  [ "$(q "$S" '.networkPolicy.default // "deny"')" = "allow" ] && \
    record WARN B02 2 "Sandboxed commands can reach any host" "networkPolicy.default is allow."
  wild=$(q "$S" '.networkPolicy.allow // [] | .[] | select(. == "*" or test("^\\*\\.[^.]+$") or . == "0.0.0.0/0")')
  [ -n "$wild" ] && record WARN B03 2 "The sandbox network allow list has wildcards" "$wild"
  paths=$(q "$S" '((.additionalReadwritePaths // []) + (.additionalReadonlyPaths // []))[]' | grep -E "$SENSITIVE_PATH" || true)
  [ -n "$paths" ] && record WARN B04 2 "The sandbox can reach your home or credential folders" "$paths"
elif [ -f "$CURSOR_HOME_DIR/sandbox.json" ]; then
  record WARN B01 2 "~/.cursor/sandbox.json could not be read" "Cursor may be ignoring it. Check it for syntax errors."
elif [ -d "$CURSOR_HOME_DIR" ] && [ -n "$(ls -A "$CURSOR_HOME_DIR" 2>/dev/null)" ]; then
  record INFO B05 2 "No ~/.cursor/sandbox.json" "The sandbox uses its defaults: workspace read and write, network denied apart from Cursor's package-registry defaults. ~/.ssh stays readable."
fi

if jsonc "$CURSOR_HOME_DIR/permissions.json" uperms; then
  P_="$TMP/uperms.json"
  risky=$(q "$P_" '.terminalAllowlist // [] | .[]' | grep -E "$RISKY_CMD" || true)
  if [ -n "$risky" ]; then
    record FAIL A01 3 "Risky commands are allowlisted" "$risky"
  else
    record PASS A01 3 "No allowlisted command matches the audit's risky list"
  fi
  wide=$(q "$P_" '.mcpAllowlist // [] | .[] | select(test("^\\*:") or test(":\\*$"))')
  [ -n "$wide" ] && record WARN A02 3 "Whole MCP servers are allowlisted" "$wide"
  # Block instructions steer Auto-review toward asking you; they aren't enforcement.
  # The audit can see that they exist, not whether they cover what matters, so it
  # lists them for a person to read rather than passing them.
  allow_i=$(q "$P_" '.autoRun.allow_instructions // [] | .[] | "allow: \(.)"')
  block_i=$(q "$P_" '.autoRun.block_instructions // [] | .[] | "block: \(.)"')
  if [ -n "$block_i" ]; then
    record INFO A03 3 "Auto-review has block instructions: review what they cover" "$block_i${allow_i:+$'\n'$allow_i}"$'\n'"Check by hand that they cover credential files, deletes, pushes and outbound data."
  else
    record INFO A03 3 "Auto-review has no block instructions" "${allow_i:-Add block_instructions for credentials, deletes, pushes and outbound data.}"
  fi
fi

if jsonc "$CURSOR_HOME_DIR/mcp.json" umcp; then
  U="$TMP/umcp.json"
  servers=$(q "$U" '.mcpServers // {} | keys[]')
  if [ -n "$servers" ]; then
    record INFO M01 4 "MCP servers configured in Cursor" "$(echo $servers): confirm each is approved and pinned."
    tp=$(mcp_third_party "$U" '.mcpServers'); [ -n "$tp" ] && record WARN M02 4 "Your MCP servers read content that outsiders can write" "$tp"
    un=$(mcp_unpinned "$U" '.mcpServers');    [ -n "$un" ] && record WARN M03 4 "MCP servers run without a pinned version" "$(echo $un)"
    lit=$(q "$U" '.mcpServers // {} | to_entries[] | .key as $s
      | (((.value.env // {}) + (.value.headers // {})) | to_entries[]
         | select((.key | test("key|token|secret|password|credential|authorization"; "i")) and ((.value | tostring) | test("\\$\\{env:") | not))
         | "\($s): \(.key)")')
    [ -n "$lit" ] && record WARN M04 4 "Secrets stored in mcp.json" "$lit"
  fi
fi

if [ -f "$CURSOR_HOME_DIR/hooks.json" ] && jsonc "$CURSOR_HOME_DIR/hooks.json" uhooks; then
  cmds=$(hook_cmds "$TMP/uhooks.json")
  remote=$(grep -Ei "$REMOTE_CODE" <<<"$cmds" || true)
  [ -n "$remote" ] && record FAIL H01 3 "A user hook downloads or runs remote code" "$remote"
  open=$(q "$TMP/uhooks.json" '.hooks // {} | to_entries[] | select(.key | test("^(beforeShellExecution|beforeMCPExecution|beforeReadFile|preToolUse)$")) | .key as $e | .value[]? | select(.failClosed != true and (.type // "command") == "command") | "\($e): \(.command)"')
  [ -n "$open" ] && record INFO H02 3 "Security hooks fail open" "$open"
fi

if [ -f "$CURSOR_HOME_DIR/cli-config.json" ] && jq empty "$CURSOR_HOME_DIR/cli-config.json" 2>/dev/null; then
  L="$CURSOR_HOME_DIR/cli-config.json"
  if [ "$(q "$L" '.approvalMode // empty')" = "unrestricted" ]; then
    record FAIL L01 3 "The Cursor CLI runs every command without asking" "approvalMode is unrestricted."
  else
    record PASS L01 3 "The Cursor CLI keeps approvals on"
  fi
  [ "$(q "$L" '(.sandbox.mode // .["sandbox.mode"]) // empty')" = "disabled" ] && \
    record WARN L02 3 "The Cursor CLI sandbox is off" "sandbox.mode is disabled."
  lallow=$(q "$L" '.permissions.allow // [] | .[] | select(test("^Shell\\((\\*|bash|sh|zsh|pwsh|powershell|python[0-9.]*|node|rm|sudo|curl|wget|ssh|docker|kubectl|terraform)(:.*)?\\)$") or . == "Mcp(*:*)" or . == "WebFetch(*)" or test("^Write\\(\\*\\*\\)$") or test("^Read\\((~|/)"))')
  [ -n "$lallow" ] && record WARN L03 3 "The Cursor CLI allows broad commands, tools or paths" "$lallow"
  # Only a pattern that covers every .env file anywhere counts; Read(.env.example)
  # or Read(.env*) at the root alone doesn't.
  denies=$(q "$L" '.permissions.deny // [] | .[]')
  if grep -Eqx 'Read\(\*\*/\.env\*?\)|Read\(\*\*/\*\.env\*\)|Read\(\*\*/\.env\*\*\)' <<<"$denies"; then
    record PASS L04 3 "The Cursor CLI denies reading .env files in every folder"
  elif grep -Eqx 'Read\(\.env\*?\)' <<<"$denies"; then
    record WARN L04 3 "The Cursor CLI denies .env reads only at the workspace root" "Relative patterns are scoped to the workspace; use Read(**/.env*) to cover subfolders."
  else
    record WARN L04 3 "The Cursor CLI doesn't deny reading .env files" "Add Read(**/.env*) to permissions.deny."
  fi
fi

# --------------------------------------------------------------- project ----

if project_mounted; then
  C="$PROJECT/.cursor"

  if jsonc "$C/sandbox.json" psandbox; then
    loose=$(q "$TMP/psandbox.json" '[
      (if .type == "insecure_none" then "type = insecure_none" else empty end),
      (if .networkPolicy.default == "allow" then "networkPolicy.default = allow" else empty end),
      ((.networkPolicy.allow // [])[] | "network allow: \(.)"),
      ((.additionalReadwritePaths // [])[] | "read/write path: \(.)"),
      ((.additionalReadonlyPaths // [])[] | "read-only path: \(.)") ] | .[]')
    if grep -q 'insecure_none' <<<"$loose"; then
      record FAIL P01 4 "The project's .cursor/sandbox.json turns the sandbox off" "$loose"
    elif [ -n "$loose" ]; then
      record WARN P01 4 "The project's .cursor/sandbox.json widens the sandbox" "$loose"
    fi
  fi

  if jsonc "$C/permissions.json" pperms; then
    added=$(q "$TMP/pperms.json" '((.terminalAllowlist // [])[] | "terminal: \(.)"), ((.mcpAllowlist // [])[] | "mcp: \(.)"), ((.autoRun.allow_instructions // [])[] | "auto-review allow: \(.)")')
    prisky=$(q "$TMP/pperms.json" '.terminalAllowlist // [] | .[]' | grep -E "$RISKY_CMD" || true)
    pwide=$(q "$TMP/pperms.json" '.mcpAllowlist // [] | .[] | select(. == "*:*")')
    if [ -n "$prisky$pwide" ]; then
      record FAIL P02 4 "The project's .cursor/permissions.json allowlists risky commands or every MCP tool" "$added"
    elif [ -n "$added" ]; then
      record WARN P02 4 "The project's .cursor/permissions.json adds to your allowlists" "$added"
    fi
  fi

  if jsonc "$C/mcp.json" pmcp; then
    list=$(mcp_list "$TMP/pmcp.json" '.mcpServers')
    [ -n "$list" ] && record WARN P03 4 ".cursor/mcp.json declares MCP servers" "$list"
    tp=$(mcp_third_party "$TMP/pmcp.json" '.mcpServers'); [ -n "$tp" ] && record WARN P04 4 ".cursor/mcp.json adds MCP servers that read outsider-written content" "$tp"
    un=$(mcp_unpinned "$TMP/pmcp.json" '.mcpServers');    [ -n "$un" ] && record WARN P05 4 ".cursor/mcp.json runs MCP servers without a pinned version" "$(echo $un)"
  fi

  if jsonc "$C/hooks.json" phooks; then
    cmds=$(hook_cmds "$TMP/phooks.json")
    if [ -n "$cmds" ]; then
      record WARN P06 4 "The project ships hooks that run in every trusted workspace" "$cmds"
      remote=$(grep -Ei "$REMOTE_CODE" <<<"$cmds" || true)
      [ -n "$remote" ] && record FAIL P07 4 "A project hook downloads or runs remote code" "$remote"
    fi
  fi

  if [ -f "$C/cli.json" ] && jq empty "$C/cli.json" 2>/dev/null; then
    pallow=$(q "$C/cli.json" '.permissions.allow // [] | .[]')
    [ -n "$pallow" ] && record WARN P08 4 "The project's .cursor/cli.json allows commands for the Cursor CLI" "$pallow"
  fi

  # Rules and instruction files.
  mapfile -t instr < <(cd "$PROJECT" && { find .cursor/rules -type f \( -name '*.mdc' -o -name '*.md' \) 2>/dev/null
    for f in .cursorrules AGENTS.md CLAUDE.md; do [ -f "$f" ] && echo "$f"; done; } | sed 's#^\./##' | head -n 200)
  fetch=""
  for f in "${instr[@]}"; do grep -Eiq "$FETCH_PATTERN" "$PROJECT/$f" && fetch+="$f"$'\n'; done
  [ -n "$fetch" ] && record WARN P09 4 "Rules files tell the agent to fetch or install something" "$fetch"
  hidden=$(hidden_unicode "${instr[@]/#/$PROJECT/}")
  [ -n "$hidden" ] && record FAIL P10 4 "Rules files contain hidden Unicode characters" "$hidden"

  setup=""
  for f in environment.json worktrees.json; do
    jsonc "$C/$f" "p$f" || continue
    s=$(q "$TMP/p$f.json" '[.. | strings] | .[]' | grep -Ei "$REMOTE_CODE" || true)
    [ -n "$s" ] && setup+=".cursor/$f: $s"$'\n'
  done
  [ -n "$setup" ] && record WARN P11 4 "Setup commands download or run remote code" "$setup"

  check_env_gitignored P12 5
  check_symlinks P13 4 '(^|/)(\.cursor|\.cursorrules|\.cursorignore|\.vscode|\.claude|AGENTS\.md|CLAUDE\.md|\.ssh|\.aws|\.gnupg|\.config|\.bashrc|\.zshrc|\.zshenv|\.profile|\.bash_profile|\.zprofile|\.gitconfig|\.npmrc|\.netrc)(/|$)'
  check_gitconfig P14 4
else
  record INFO P00 4 "No project mounted" "Run from a project directory to check its .cursor/ folder, rules and MCP servers."
fi

# ---------------------------------------------------- machine-wide files ----

if [ "${HOST_OS:-}" = "windows" ]; then
  case "${PROGRAMDATA_STATE:-}" in
    admin-only)    record PASS W01 1 'C:\ProgramData\Cursor is writable by administrators only' ;;
    user-writable) record FAIL W01 1 'Someone other than administrators can change C:\ProgramData\Cursor' "An account other than Administrators, SYSTEM or TrustedInstaller owns the folder or a file in it, or can write there, so it can plant a hooks.json every Cursor user on this machine loads." ;;
    missing)       record WARN W01 1 'C:\ProgramData\Cursor does not exist yet' "Windows does not restrict new folders under ProgramData, so a standard user could create it and plant a hooks.json for every user (reported by Cymulate, unresolved)." ;;
    unknown)       record WARN W01 1 'Could not read the permissions of C:\ProgramData\Cursor' "Check them by hand: the folder and everything in it should be owned by Administrators and writable only by Administrators and SYSTEM." ;;
    *)             record INFO W01 1 'ProgramData folder permissions not checked' "Run the audit with run.ps1 to check them." ;;
  esac
fi
if jsonc "$SYSTEM_DIR/hooks.json" shooks; then
  cmds=$(hook_cmds "$TMP/shooks.json")
  if grep -Eiq "$REMOTE_CODE" <<<"$cmds"; then
    record FAIL W02 1 'Machine-wide hooks download or run remote code' "$cmds"
  elif [ -n "$cmds" ]; then
    record INFO W02 1 'Machine-wide hooks run for every Cursor user' "$cmds"$'\n'"Confirm your administrators created them."
  fi
fi

check_rc_flags S01 3 '(cursor-agent|cursor agent|[^a-z-]agent)[^#]*(--yolo|--force|[[:space:]]-f([[:space:]]|$)|--sandbox[= ]disabled|--approve-mcps)' "Shell startup files turn off Cursor CLI approvals"

render_report
