#!/usr/bin/env bash
# GitHub Copilot security audit: read-only, offline.
#
# Checks VS Code agent mode settings, the Copilot CLI configuration and a
# project against the AISecurityLabs.org Copilot hardening guide
# (copilot/README.md). It never modifies anything and needs no network access.
# VS Code settings are JSON with comments; jsonc.awk converts them for jq.
#
# Inputs (all optional, mounted read-only by run.sh / run.ps1):
#   /audit/vscode-user/settings.json   VS Code user settings
#   /audit/vscode-user/mcp.json        VS Code user MCP servers
#   /audit/copilot-home/settings.json  Copilot CLI settings (~/.copilot)
#   /audit/copilot-home/permissions-config.json
#   /audit/copilot-home/mcp-config.json
#   /audit/project                     a project directory to inspect
#   /audit/rc/*                        shell startup files
#   VSCODE_VERSION, COPILOT_CHAT_VERSION
#   HOST_OS ("windows" from run.ps1), PROJECT_NAME
#
# Usage: audit.sh [--format text|report|json|csv|html]   (--json = --format json)
# Exit code: 0 = no FAIL results, 1 = at least one FAIL, 2 = usage error.

PRODUCT="GitHub Copilot"
TOOL="copilot-audit"
VERSION_LABEL="VS Code"
AUDIT_VERSION="1.0.0"
GUIDE_URL="https://github.com/aisecuritylabs-org/coding-agent-security/blob/main/copilot/README.md"
GUIDE_NAME="copilot/README.md"
MIN_VSCODE="1.132.1"        # fixes CVE-2026-70335 (agent ran commands without confirmation)
MIN_CHAT_EXT="1.123.2"      # Copilot Chat extension, fixes CVE-2026-45482

VSCODE_DIR="${VSCODE_DIR:-/audit/vscode-user}"
COPILOT_HOME_DIR="${COPILOT_HOME_DIR:-/audit/copilot-home}"
PROJECT="${PROJECT:-/audit/project}"
RC_DIR="${RC_DIR:-/audit/rc}"
MAPPINGS="${MAPPINGS:-/opt/audit/mappings.json}"
TMP="${TMPDIR:-/tmp}"
PRODUCT_VERSION="${VSCODE_VERSION:-unknown}"

guide_page() {
  case "$1" in
    1) echo "#1-before-you-start" ;;
    2) echo "#2-baseline-vs-code-settings" ;;
    3) echo "#3-copilot-cli" ;;
    4) echo "#4-repositories-and-extensions" ;;
    5) echo "#5-working-habits" ;;
    6) echo "#6-self-test" ;;
    *) echo "#7-checklist" ;;
  esac
}

fix_for() {
  case "$1" in
    I01) echo 'Update VS Code (Help > Check for Updates, or your package manager) to the current release.' ;;
    I02) echo 'Update the GitHub Copilot Chat extension from the Extensions view, or run: code --install-extension GitHub.copilot-chat --force' ;;
    V00) echo 'Run the audit with run.sh or run.ps1, which share your VS Code user settings with the container automatically.' ;;
    V01) echo 'Fix the syntax error in your VS Code settings.json (VS Code shows it in the Problems view), then re-run the audit.' ;;
    V02) echo 'Remove "chat.tools.global.autoApprove": true (and the old "chat.tools.autoApprove") from your user settings. Organisations can enforce it off with the ChatToolsAutoApprove policy.' ;;
    V03) echo 'Set "chat.permissions.default" back to its default so new chat sessions start with Default Permissions, and switch to Bypass Approvals or Autopilot only for a session that needs it.' ;;
    V04) echo 'Remove the listed entries from "chat.tools.terminal.autoApprove", or set them to false. Auto-approve only read-only commands such as "git status" and "git diff", and never a regular expression that matches everything.' ;;
    V05) echo 'Remove the listed entries from "chat.tools.edits.autoApprove". Never auto-approve "**/*" or edits to .vscode/, .github/, .env or lockfiles.' ;;
    V06) echo 'Set "security.workspace.trust.enabled": true. Agents are disabled in folders you have not trusted.' ;;
    V07) echo 'Turn on the agent terminal sandbox: "chat.agent.sandbox.enabled": "on" (macOS, Linux, WSL2; on Linux install bubblewrap and socat; native Windows uses the experimental chat.agent.sandbox.enabledWindows). Also set "chat.agent.sandbox.allowNetwork": false unless a task needs the network.' ;;
    V09) echo 'Set "chat.mcp.discovery.enabled": false so VS Code does not pick up MCP servers configured for other tools.' ;;
    V10) echo 'Remove wildcard entries from "chat.tools.urls.autoApprove"; list exact URLs or domains you trust.' ;;
    M02|P03) echo 'Treat everything these servers return as untrusted input: give them read-only credentials, keep approvals on for any command that follows a read from them, and never let the agent run commands copied from tickets, errors or messages.' ;;
    M03|P04) echo 'Pin every MCP server to an exact version, e.g. "some-server@1.4.2" instead of "some-server" or "@latest".' ;;
    L01) echo 'Turn on the Copilot CLI sandbox: add "sandbox": { "enabled": true } to ~/.copilot/settings.json (see copilot/config/copilot-cli-settings.json).' ;;
    L02) echo 'Edit ~/.copilot/permissions-config.json (with no CLI session running) and remove the listed saved approvals, or delete the file to be prompted again.' ;;
    L03) echo 'Remove wildcard entries from "allowedUrls" in ~/.copilot/settings.json.' ;;
    L04) echo 'Add "permissions": { "disableBypassPermissionsMode": "disable" } to ~/.copilot/settings.json so the allow-all flags are ignored.' ;;
    P01) echo 'Remove the listed keys from the project'"'"'s .vscode/settings.json. A repository should never change your agent approval, trust or sandbox settings.' ;;
    P02) echo 'Read every MCP server the project declares before trusting the folder. Remove servers you do not recognise, or open the repository in a container or Codespace with no credentials.' ;;
    P05) echo 'Read the listed instruction files before trusting this repository. Remove fetch or install instructions you did not add.' ;;
    P06) echo 'Open the listed files in an editor that shows invisible characters (or run: grep -nP "[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]" <file>) and remove the hidden characters. Add a pre-commit check for them.' ;;
    P07) echo 'Review copilot-setup-steps.yml: pin every action by SHA and never download and run scripts there. Setup steps run outside the cloud agent firewall.' ;;
    P08) echo 'Read every hook file in .github/hooks/ before trusting this repository; hooks run commands on agent events.' ;;
    P09) echo 'Add these lines to the project'"'"'s .gitignore: .env and .env.* (and remove any !.env exception). If a .env file is already committed, remove it with git rm --cached <file> and rotate the secrets it held.' ;;
    P10) echo 'Do not open this folder with Copilot until you have checked each listed link: ls -la <link>. Delete links you did not create.' ;;
    P11) echo 'This repository came with a .git/config that runs programs. Remove the listed keys, or re-clone it: a normal git clone never copies .git/config.' ;;
    P12) echo 'Read the hooks, plugins and marketplaces in .github/copilot/settings.json before running the Copilot CLI in this repository. Remove entries you do not recognise.' ;;
    S01) echo 'Remove the alias, function or export that adds --allow-all, --yolo, --allow-all-tools or COPILOT_ALLOW_ALL from the listed shell startup file, then open a new terminal.' ;;
    *) echo '' ;;
  esac
}

# shellcheck source=../../common/audit-lib.sh
. "${AUDIT_LIB:-/opt/audit/audit-lib.sh}"

# Commands that let the agent run anything, delete, escalate or reach the network.
# A heuristic: a command not on this list isn't proven safe. Read by jq as $ENV.RISKY_JQ.
export RISKY_JQ='^(\*|rm|rmdir|del|kill|dd|curl|wget|nc|eval|exec|chmod|chown|sudo|su|bash|sh|zsh|fish|pwsh|powershell|cmd|python[0-9.]*|node|deno|bun|ruby|perl|php|npx|bunx|pnpx|uvx|ssh|scp|rsync|docker|podman|kubectl|terraform|aws|gcloud|az)( |$)|^npm (publish|exec)|^pnpm (dlx|exec)|^git (push|reset|clean)|Remove-Item|Invoke-Expression'

# vs <key>: a top-level VS Code setting (keys are literal dotted names).
# A key set to false must read as "false", so test for the key rather than use //.
vs() { q "$V" "if has(\"$1\") and .[\"$1\"] != null then .[\"$1\"] | if type == \"object\" or type == \"array\" then tojson else tostring end else empty end"; }

# ------------------------------------------------------------ versions ----

if [ -n "${VSCODE_VERSION:-}" ]; then
  v=$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' <<<"$VSCODE_VERSION" | head -n1)
  if [ -z "$v" ]; then record INFO I01 1 "VS Code version not recognised" "$VSCODE_VERSION"
  elif version_ge "$v" "$MIN_VSCODE"; then record PASS I01 1 "VS Code $v includes the known Copilot security fixes"
  else record WARN I01 1 "VS Code $v is older than $MIN_VSCODE" "Versions before $MIN_VSCODE are exposed to CVE-2026-70335, where the agent could run commands without asking."
  fi
else
  record INFO I01 1 "VS Code version not provided" "Pass -e VSCODE_VERSION=\"\$(code --version | head -n1)\" to check it."
fi
if [ -n "${COPILOT_CHAT_VERSION:-}" ]; then
  v=$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' <<<"$COPILOT_CHAT_VERSION" | head -n1)
  if [ -n "$v" ] && ! version_ge "$v" "$MIN_CHAT_EXT"; then
    record WARN I02 1 "Copilot Chat extension $v is older than $MIN_CHAT_EXT" "Older versions are exposed to CVE-2026-45482 (security feature bypass)."
  elif [ -n "$v" ]; then
    record PASS I02 1 "Copilot Chat extension $v is current"
  fi
fi

# ------------------------------------------------- VS Code user settings ----

V=""
if [ ! -d "$VSCODE_DIR" ]; then
  record WARN V00 2 "VS Code user settings were not mounted" "Agent mode settings could not be checked."
elif [ ! -f "$VSCODE_DIR/settings.json" ]; then
  record INFO V01 2 "No VS Code user settings.json" "VS Code runs on its defaults: auto-approve off, Workspace Trust on, terminal sandbox off."
elif ! jsonc "$VSCODE_DIR/settings.json" vscode; then
  record FAIL V01 2 "VS Code settings.json could not be read" "VS Code may be ignoring it. Check it for syntax errors."
else
  V="$TMP/vscode.json"
  record PASS V01 2 "VS Code user settings.json is readable"

  if [ "$(vs chat.tools.global.autoApprove)" = "true" ] || [ "$(vs chat.tools.autoApprove)" = "true" ]; then
    record FAIL V02 2 "Every agent tool call is auto-approved" "chat.tools.global.autoApprove is true: VS Code calls this setting one that \"disables critical security protections\"."
  else
    record PASS V02 2 "Global auto-approve is off"
  fi

  perm=$(vs chat.permissions.default)
  if [ -n "$perm" ] && [ "$perm" != "default" ]; then
    record WARN V03 2 "New chat sessions skip approvals by default" "chat.permissions.default is \"$perm\"."
  else
    record PASS V03 2 "New chat sessions start with Default Permissions"
  fi

  approved='.["chat.tools.terminal.autoApprove"] // {} | to_entries[]
    | select(.value == true or (.value | type == "object" and .approve == true)) | .key'
  risky_cmd=$(q "$V" "$approved"' | select(test("^/\\.[*+]/|^/\\^?\\.[*+]\\$?/"; "i") or test($ENV.RISKY_JQ; "i"))')
  regexes=$(q "$V" "$approved"' | select(startswith("/"))' | grep -Fxv -f <(printf '%s\n' "$risky_cmd") || true)
  if [ -n "$risky_cmd" ]; then
    record FAIL V04 2 "Risky terminal commands are auto-approved" "$risky_cmd"
  elif [ -n "$regexes" ]; then
    record WARN V04 2 "Auto-approved regular expressions need a manual review" "$regexes"$'\n'"The audit can't tell everything these match."
  else
    record PASS V04 2 "No auto-approved terminal command matches the audit's risky list"
  fi

  risky_edit=$(q "$V" '.["chat.tools.edits.autoApprove"] // {} | to_entries[] | select(.value == true)
    | select(.key | test("^\\*\\*/\\*$|\\.vscode|\\.github|\\.env|\\.git/|lock|\\.npmrc|mcp\\.json|copilot-instructions|AGENTS\\.md"; "i")) | .key')
  [ -n "$risky_edit" ] && record WARN V05 2 "Edits to sensitive files are auto-approved" "$risky_edit"

  if [ "$(vs security.workspace.trust.enabled)" = "false" ]; then
    record FAIL V06 2 "Workspace Trust is turned off" "Agents normally stay disabled in folders you have not trusted; with trust off, every folder is trusted."
  else
    record PASS V06 2 "Workspace Trust is on"
  fi

  # Documented values are "on" and "off"; anything else isn't treated as on.
  skey=chat.agent.sandbox.enabled
  [ "${HOST_OS:-}" = "windows" ] && skey=chat.agent.sandbox.enabledWindows
  sandbox=$(vs "$skey")
  if [ "$sandbox" = "on" ]; then
    if [ "$(vs chat.agent.sandbox.allowNetwork)" = "false" ]; then
      domains=$(q "$V" '.["chat.agent.allowedNetworkDomains"] // [] | join(", ")')
      record PASS V07 2 "The agent terminal sandbox is on, with network restricted" "${domains:+Allowed domains (local sessions on macOS and Linux): $domains}"
    else
      record WARN V07 2 "The agent terminal sandbox is on, but network is allowed (the default)" "chat.agent.sandbox.allowNetwork defaults to true."
    fi
  elif [ -n "$sandbox" ] && [ "$sandbox" != "off" ]; then
    record WARN V07 2 "The agent terminal sandbox setting has an undocumented value" "$skey is $sandbox; the documented values are \"on\" and \"off\"."
  else
    record WARN V07 2 "The agent terminal sandbox is off (the default)" "Terminal commands run with your full user permissions and network access."
  fi

  access=$(vs chat.mcp.access); access="${access:-all}"
  record INFO V08 4 "MCP server access: $access" "Organisations can limit MCP to a registry or an allowlist with the ChatMCP and ChatAllowedMcpServers policies."

  [ "$(vs chat.mcp.discovery.enabled)" = "true" ] && \
    record WARN V09 4 "VS Code picks up MCP servers configured for other tools" "chat.mcp.discovery.enabled is true."

  wide_urls=$(q "$V" '.["chat.tools.urls.autoApprove"] // {} | to_entries[] | select(.value != false) | select(.key | test("^\\*$|^https?://\\*|^\\*\\.[^.]+$")) | .key')
  [ -n "$wide_urls" ] && record WARN V10 2 "Wildcard URLs are auto-approved" "$wide_urls"
fi

# VS Code user MCP servers ("servers")
if jsonc "$VSCODE_DIR/mcp.json" vscmcp; then
  U="$TMP/vscmcp.json"
  servers=$(q "$U" '.servers // {} | keys[]')
  if [ -n "$servers" ]; then
    record INFO M01 4 "MCP servers configured in VS Code" "$(echo $servers): confirm each is approved and pinned."
    tp=$(mcp_third_party "$U" '.servers'); [ -n "$tp" ] && record WARN M02 4 "Your MCP servers read content that outsiders can write" "$tp"
    un=$(mcp_unpinned "$U" '.servers');    [ -n "$un" ] && record WARN M03 4 "MCP servers run without a pinned version" "$(echo $un)"
  fi
fi

# ----------------------------------------------------------- Copilot CLI ----

if [ -d "$COPILOT_HOME_DIR" ] && [ -n "$(ls -A "$COPILOT_HOME_DIR" 2>/dev/null)" ]; then
  C=""
  if jsonc "$COPILOT_HOME_DIR/settings.json" cli; then C="$TMP/cli.json"; fi
  # The reference lists dotted names; accept them nested or as literal keys.
  if [ -n "$C" ] && [ "$(q "$C" '(.sandbox.enabled // .["sandbox.enabled"]) // false')" = "true" ]; then
    record PASS L01 3 "The Copilot CLI sandbox is on"
  else
    record WARN L01 3 "The Copilot CLI sandbox is off (the default)" "Shell commands the CLI runs have your full user permissions and network access."
  fi
  if [ -n "$C" ]; then
    wide=$(q "$C" '.allowedUrls // [] | .[] | select(test("^\\*$|^https?://\\*|^\\*\\.[^.]+$"))')
    [ -n "$wide" ] && record WARN L03 3 "The Copilot CLI auto-approves wildcard URLs" "$wide"
  fi
  bypass=""
  [ -n "$C" ] && bypass=$(q "$C" '(.permissions.disableBypassPermissionsMode // .["permissions.disableBypassPermissionsMode"]) // empty')
  if [ "$bypass" = "disable" ]; then
    record PASS L04 3 "The Copilot CLI ignores --allow-all and --yolo"
  else
    record INFO L04 3 "The Copilot CLI accepts --allow-all and --yolo" "permissions.disableBypassPermissionsMode is ${bypass:-not set}."
  fi
  if jsonc "$COPILOT_HOME_DIR/permissions-config.json" perms; then
    P_="$TMP/perms.json"
    risky=$(q "$P_" '.locations // {} | to_entries[] | .key as $loc | (.value.tool_approvals // [])[]
      | select(.kind == "commands") | (.commandIdentifiers // [])[]
      | select(test($ENV.RISKY_JQ; "i"))
      | "\($loc): \(.)"')
    allmcp=$(q "$P_" '.locations // {} | to_entries[] | .key as $loc | (.value.tool_approvals // [])[]
      | select(.kind == "mcp" and .toolName == null) | "\($loc): every tool on \(.serverName)"')
    detail=$(printf '%s\n%s' "$risky" "$allmcp" | grep -v '^$' || true)
    if [ -n "$risky" ]; then
      record FAIL L02 3 "The Copilot CLI has saved approvals for risky commands" "$detail"
    elif [ -n "$allmcp" ]; then
      record WARN L02 3 "The Copilot CLI has approved every tool of some MCP servers" "$detail"
    else
      record PASS L02 3 "No saved approval matches the audit's risky list"
    fi
  fi
  if jsonc "$COPILOT_HOME_DIR/mcp-config.json" climcp; then
    M="$TMP/climcp.json"
    s=$(q "$M" '.mcpServers // {} | keys[]')
    [ -n "$s" ] && record INFO M01 4 "MCP servers configured for the Copilot CLI" "$(echo $s): confirm each is approved and pinned."
    tp=$(mcp_third_party "$M" '.mcpServers'); [ -n "$tp" ] && record WARN M02 4 "Copilot CLI MCP servers read content that outsiders can write" "$tp"
    un=$(mcp_unpinned "$M" '.mcpServers');    [ -n "$un" ] && record WARN M03 4 "Copilot CLI MCP servers run without a pinned version" "$(echo $un)"
  fi
fi

# --------------------------------------------------------------- project ----

if project_mounted; then
  # Workspace settings that try to change agent safety settings.
  if jsonc "$PROJECT/.vscode/settings.json" wsettings; then
    W="$TMP/wsettings.json"
    keys=$(q "$W" 'to_entries[] | select(.key | test("^chat\\.tools\\..*[aA]utoApprove|^chat\\.permissions\\.|^security\\.workspace\\.trust|^chat\\.agent\\.sandbox|^chat\\.mcp\\.")) | "\(.key) = \(.value | tojson)"')
    [ -n "$keys" ] && record WARN P01 4 "The project's .vscode/settings.json changes agent safety settings" "$keys"
  fi

  # Project MCP servers in any of the three formats.
  for spec in ".vscode/mcp.json|.servers" ".mcp.json|.mcpServers" ".github/mcp.json|.mcpServers"; do
    file="${spec%%|*}"; path="${spec#*|}"
    jsonc "$PROJECT/$file" pmcp || continue
    list=$(mcp_list "$TMP/pmcp.json" "$path")
    [ -n "$list" ] && record WARN P02 4 "$file declares MCP servers" "$list"
    tp=$(mcp_third_party "$TMP/pmcp.json" "$path"); [ -n "$tp" ] && record WARN P03 4 "$file adds MCP servers that read outsider-written content" "$tp"
    un=$(mcp_unpinned "$TMP/pmcp.json" "$path");    [ -n "$un" ] && record WARN P04 4 "$file runs MCP servers without a pinned version" "$(echo $un)"
  done

  # Instruction files: fetch instructions and hidden characters.
  mapfile -t instr < <(cd "$PROJECT" && find .github/copilot-instructions.md .github/instructions .github/agents .github/prompts AGENTS.md CLAUDE.md \
    -maxdepth 3 -type f \( -name '*.md' \) 2>/dev/null | sed 's#^\./##')
  fetch=""
  for f in "${instr[@]}"; do grep -Eiq "$FETCH_PATTERN" "$PROJECT/$f" && fetch+="$f"$'\n'; done
  [ -n "$fetch" ] && record WARN P05 4 "Instruction files tell the agent to fetch or install something" "$fetch"
  hidden=$(hidden_unicode "${instr[@]/#/$PROJECT/}")
  [ -n "$hidden" ] && record FAIL P06 4 "Instruction files contain hidden Unicode characters" "$hidden"

  steps="$PROJECT/.github/workflows/copilot-setup-steps.yml"
  if [ -f "$steps" ]; then
    remote=$(grep -Ein 'curl|wget|\| *(ba|z)?sh|iex|Invoke-WebRequest' "$steps" || true)
    if [ -n "$remote" ]; then
      record WARN P07 4 "copilot-setup-steps.yml downloads or runs remote code" "$remote"
    else
      record INFO P07 4 "The project customises the Copilot cloud agent environment" "Setup steps run outside the agent firewall."
    fi
  fi

  hookfiles=$(cd "$PROJECT" && find .github/hooks -type f 2>/dev/null)
  [ -n "$hookfiles" ] && record WARN P08 4 "The project ships agent hooks" "$hookfiles"

  # Repository settings for the Copilot CLI, shared with every collaborator.
  if jsonc "$PROJECT/.github/copilot/settings.json" rsettings; then
    rs=$(q "$TMP/rsettings.json" '[ (if (.hooks // {}) != {} then "hooks: \(.hooks | keys | join(", "))" else empty end),
      (if (.enabledPlugins // {}) != {} then "enabledPlugins: \(.enabledPlugins | keys | join(", "))" else empty end),
      (if (.extraKnownMarketplaces // {}) != {} then "extraKnownMarketplaces: \(.extraKnownMarketplaces | keys | join(", "))" else empty end) ] | .[]')
    [ -n "$rs" ] && record WARN P12 4 ".github/copilot/settings.json adds hooks or plugins for everyone" "$rs"
  fi

  check_env_gitignored P09 5
  check_symlinks P10 4 '(^|/)(\.vscode|\.github|\.copilot|\.mcp\.json|AGENTS\.md|\.ssh|\.aws|\.gnupg|\.config|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|\.gitconfig|\.npmrc|\.netrc)(/|$)'
  check_gitconfig P11 4
else
  record INFO P00 4 "No project mounted" "Run from a project directory to check its .vscode/, MCP configs and instruction files."
fi

check_rc_flags S01 7 'copilot[^#]*(--allow-all|--yolo|--allow-all-tools)|COPILOT_ALLOW_ALL' "Shell startup files turn off Copilot CLI approvals"

render_report
