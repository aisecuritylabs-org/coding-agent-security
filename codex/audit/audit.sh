#!/usr/bin/env bash
# OpenAI Codex security audit: read-only, offline.
#
# Checks a developer's Codex configuration and a project against the
# AISecurityLabs.org Codex hardening guide (codex/README.md) and prints
# PASS / WARN / FAIL / INFO results. It never modifies anything and needs no
# network access. Codex config is TOML; yq converts it to JSON for jq.
#
# Inputs (all optional, mounted read-only by run.sh / run.ps1):
#   /audit/codex-home/config.toml   the user's ~/.codex/config.toml
#   /audit/codex-home/hooks.json    the user's ~/.codex/hooks.json
#   /audit/codex-home/rules/        the user's ~/.codex/rules/
#   /audit/codex-home/AGENTS.md     the user's global ~/.codex/AGENTS.md
#   /audit/requirements.toml        managed requirements (/etc/codex/requirements.toml)
#   /audit/system-config.toml       Windows %ProgramData%\OpenAI\Codex\config.toml
#   /audit/project                  a project directory to inspect
#   /audit/rc/*                     shell startup files (.bashrc, .zshrc, PowerShell profile, ...)
#   CODEX_VERSION        output of `codex --version`
#   HOST_OS              "windows" when launched from run.ps1
#   PROGRAMDATA_STATE    Windows only: missing | admin-only | user-writable
#   PROJECT_NAME         the audited project's folder name, for report headers
#
# Usage: audit.sh [--format text|report|json|csv|html]   (--json = --format json)
# Exit code: 0 = no FAIL results, 1 = at least one FAIL, 2 = usage error.

set -u

AUDIT_VERSION="1.0.0"
MIN_VERSION="0.146.0"   # fixes Plugin4Shell; also includes the CVE-2026-19591 fix (0.131.0)
GUIDE_URL="https://github.com/aisecuritylabs-org/coding-agent-security/blob/main/codex/README.md"

CODEX_HOME_DIR="${CODEX_HOME_DIR:-/audit/codex-home}"
REQUIREMENTS="${REQUIREMENTS:-/audit/requirements.toml}"
SYSTEM_CONFIG="${SYSTEM_CONFIG:-/audit/system-config.toml}"
PROJECT="${PROJECT:-/audit/project}"
RC_DIR="${RC_DIR:-/audit/rc}"
MAPPINGS="${MAPPINGS:-/opt/audit/mappings.json}"
TMP="${TMPDIR:-/tmp}"

# MCP servers whose name, command, args or URL suggest they read content other
# people can write (error trackers, tickets, chat, email, forges). Agentjacking.
THIRD_PARTY_FILTER='.mcp_servers // {} | to_entries[]
  | select(([.key, (.value.command // ""), ((.value.args // []) | join(" ")), (.value.url // "")] | join(" "))
           | test("sentry|jira|atlassian|confluence|linear|slack|discord|teams|gmail|outlook|imap|e-?mail|zendesk|intercom|pagerduty|datadog|github|gitlab|notion|hubspot"; "i"))
  | .key'

# Hosts that make good exfiltration channels when they are on a network allowlist.
RISKY_HOSTS='^(\*|\*\..*|github\.com|gist\.github\.com|raw\.githubusercontent\.com|.*pastebin.*|.*webhook.*|.*requestbin.*|.*ngrok.*|.*pipedream.*|discord\.com|hooks\.slack\.com)$'

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

# guide_page <step>: the section of codex/README.md that explains a step
guide_page() {
  case "$1" in
    1) echo "#1-before-you-start" ;;
    2) echo "#2-baseline-configtoml" ;;
    3) echo "#3-command-rules-and-hooks" ;;
    4) echo "#4-repositories-and-extensions" ;;
    5) echo "#5-working-habits" ;;
    6) echo "#6-self-test" ;;
    *) echo "#7-checklist" ;;
  esac
}

# fix_for <id>: how to fix a WARN / FAIL result, as concrete as possible.
fix_for() {
  case "$1" in
    I01) echo 'Update Codex: `npm install -g @openai/codex@latest` or `brew upgrade codex`, and update the desktop app and IDE extension too.' ;;
    C00) echo 'Run the audit with run.sh or run.ps1, which share ~/.codex/config.toml with the container automatically.' ;;
    C01) echo 'Copy codex/config/config.toml from this repository to ~/.codex/config.toml and adapt the domains and paths to your stack. Check the syntax with: yq -p toml . ~/.codex/config.toml' ;;
    C02) echo 'Remove sandbox_mode = "danger-full-access" / default_permissions = ":danger-full-access". Use the permission profile in codex/config/config.toml (extends ":workspace"). Keep full access for disposable containers only.' ;;
    C03) echo 'Set approval_policy = "on-request". "untrusted" was retired in Codex 0.149.0 and can stop Codex starting; "on-failure" is deprecated; "never" removes every approval.' ;;
    C04) echo 'Keep command network access off. When a task needs it, enable it in the permission profile with [features] network_proxy = true and an allow list under [permissions.<name>.network.domains], e.g. "registry.npmjs.org" = "allow".' ;;
    C05) if [ "${HOST_OS:-}" = "windows" ]; then
           echo 'Set web_search = "disabled" on native Windows (Cymulate showed web content plus PATH hijacking reaching code execution there), or run Codex in WSL or a container. Never use "live" or --search for routine work.'
         else
           echo 'Set web_search = "cached" (the default) or "disabled". Avoid "live" and --search for routine work: live pages are an injection carrier.'
         fi ;;
    C06) echo 'Deny secrets in your permission profile: under [permissions.<name>.filesystem] add "~/.ssh" = "deny" and "~/.aws" = "deny"; under [permissions.<name>.filesystem.":workspace_roots"] add "**/.env*" = "deny". The legacy sandbox_mode settings have no user-level deny-read, so switch to default_permissions (see codex/config/config.toml).' ;;
    C07) echo 'Add to ~/.codex/config.toml: cli_auth_credentials_store = "keyring" and mcp_oauth_credentials_store = "keyring"' ;;
    C08) echo 'Add to ~/.codex/config.toml: allow_login_shell = false, so commands don'"'"'t load ~/.bashrc, ~/.zprofile and the secrets they often export.' ;;
    C10) echo 'Add to ~/.codex/config.toml under [features]: skill_mcp_dependency_install = false, and install MCP servers a skill needs yourself after reviewing them.' ;;
    C11) echo 'Add to ~/.codex/config.toml: [memories] disable_on_external_context = true, so content from web search or MCP tools can'"'"'t become a lasting memory.' ;;
    C12|C13|P05) echo 'Read every listed command and the scripts it runs. Remove any you did not write or review; never keep a hook or notify command that downloads or pipes remote code into a shell. Organisations can set allow_managed_hooks_only in requirements.toml.' ;;
    C14) echo 'Move secret values out of mcp_servers.<name>.env. Use env_vars to pass a variable through from your shell, or bearer_token_env_var for HTTP servers, so the secret is never stored in config.toml.' ;;
    M02|P08) echo 'Treat everything these servers return as untrusted input: give them read-only credentials, set default_tools_approval_mode = "prompt" for them, and never let the agent run commands copied from tickets, errors or messages without reading them yourself.' ;;
    M03) echo 'Pin every MCP server to an exact version, e.g. "some-server@1.4.2" instead of "some-server" or "@latest", and use enabled_tools to expose only the tools you need.' ;;
    R01) echo 'Copy codex/config/default.rules from this repository to ~/.codex/rules/default.rules and restart Codex. Test it with: codex execpolicy check --pretty --rules ~/.codex/rules/default.rules -- git push' ;;
    R02) echo 'Remove the listed allow rules, or change them to decision = "prompt". Remember that a prefix_rule with no decision is an allow rule.' ;;
    S01) echo 'Remove the alias or function that adds --yolo, --dangerously-bypass-approvals-and-sandbox, --dangerously-bypass-hook-trust or danger-full-access from the listed shell startup file, then open a new terminal.' ;;
    W01) echo 'In PowerShell opened with Run as administrator, run codex/config/lock-programdata.ps1 from this repository. It creates C:\ProgramData\OpenAI\Codex if needed, makes Administrators the owner, gives only Administrators and SYSTEM write access and Users read access, and applies the same to everything inside. If the folder already existed, first remove any config.toml or requirements.toml your administrators did not put there. Alert on changes to files in it.' ;;
    W02) echo 'Remove the listed settings from C:\ProgramData\OpenAI\Codex\config.toml, find out who created them, and lock the folder as in W01.' ;;
    P01) echo 'Fix the TOML syntax in the listed file; check it with: yq -p toml . <file>' ;;
    P02) echo 'Do not trust this project until you have removed the listed settings from .codex/config.toml. A repository should never lower the sandbox, approvals or web search for you.' ;;
    P03) echo 'Read every MCP server in .codex/config.toml before you trust the project: once trusted, Codex starts them. Remove servers you do not recognise, or open the repository in a container or Codex cloud.' ;;
    P04) echo 'Remove the CODEX_* lines from the project .env and never run an old Codex version in this repository (CVE-2025-61260 used a project .env to point CODEX_HOME at attacker config).' ;;
    P06) echo 'Remove the listed allow rules from .codex/rules/ before trusting the project, or change them to decision = "prompt".' ;;
    P07) echo 'Read AGENTS.md before trusting this repository. Remove fetch or install instructions you did not add, or open the repository only in a container or Codex cloud.' ;;
    P09) echo 'Copy codex/config/AGENTS.md.example from this repository to AGENTS.md in your project root and adapt it.' ;;
    P10) echo 'Add these lines to the project'"'"'s .gitignore: .env and .env.*' ;;
    P11) echo 'Do not start Codex here until you have checked each listed link: ls -la <link>. Delete links you did not create. A link named like an ordinary file that points at .codex/, AGENTS.md or a dotfile is an attack.' ;;
    P12) echo 'This repository came with a .git/config that runs programs. Remove the listed keys (git config --unset <key>), or better, re-clone it: a normal git clone never copies .git/config. Update Codex (CVE-2026-19590, -19592, -19593).' ;;
    *) echo '' ;;
  esac
}

USER_CONFIG="$CODEX_HOME_DIR/config.toml"
PROJ_CONFIG="$PROJECT/.codex/config.toml"

results=()
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
  url="$GUIDE_URL$(guide_page "$step")"
  results+=("$(jq -cn --arg s "$status" --arg i "$id" --arg g "$step" --arg t "$title" --arg d "$detail" \
    --arg f "$fix" --arg u "$url" \
    '{status:$s, id:$i, guide_step:$g, title:$t, detail:$d, fix:$f, guide_url:$u}')")
}

# toml <file> <cache-name>: convert a TOML file to JSON in $TMP; fails on invalid TOML.
toml() { [ -f "$1" ] && yq -p toml -o json . "$1" > "$TMP/$2.json" 2>/dev/null; }

# q <json-file> <jq-filter>: run a jq filter, empty output on any error
q() { [ -f "$1" ] && jq -r "$2" "$1" 2>/dev/null; }

version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# rule_blocks <file>: one line per prefix_rule(...) call, whitespace collapsed.
rule_blocks() {
  sed 's/^[[:space:]]*#.*$//; s/[[:space:]]#[^"]*$//' "$1" | tr '\n' ' ' | grep -o 'prefix_rule([^)]*)' 2>/dev/null
}
# allow_rules <file>: prefix_rule calls that allow (decision omitted means allow).
allow_rules() {
  rule_blocks "$1" | grep -Ev 'decision *= *"(prompt|forbidden)"' || true
}

# hook_cmds <json-file>: every hook command in a hooks.json or config [hooks] table.
hook_cmds() { q "$1" '(.hooks // {}) | to_entries[] | .value[]? | .hooks[]? | .command // empty'; }
session_hooks() { q "$1" '[(.hooks.SessionStart // []), (.hooks.UserPromptSubmit // [])] | add | .[]? | .hooks[]? | .command // empty'; }
REMOTE_CODE='curl|wget|https?://|\| *(ba|z)?sh|base64|eval|iex|Invoke-WebRequest|DownloadString'

# ------------------------------------------------------------ install ----

if [ -n "${CODEX_VERSION:-}" ]; then
  v=$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' <<<"$CODEX_VERSION" | head -n1)
  if [ -z "$v" ]; then
    record INFO I01 1 "Codex version not recognised" "$CODEX_VERSION"
  elif version_ge "$v" "$MIN_VERSION"; then
    record PASS I01 1 "Codex CLI $v includes the known security fixes"
  else
    record WARN I01 1 "Codex CLI $v is older than $MIN_VERSION" "Versions before $MIN_VERSION are exposed to Plugin4Shell (fixed in 0.146.0) and older issues such as CVE-2026-19591."
  fi
else
  record INFO I01 1 "Codex version not provided" "Pass -e CODEX_VERSION=\"\$(codex --version)\" to check it."
fi

# ---------------------------------------------------------- user config ----

U=""   # JSON form of ~/.codex/config.toml when present and valid
if [ ! -d "$CODEX_HOME_DIR" ]; then
  record WARN C00 2 "~/.codex was not mounted" "User configuration could not be checked."
elif [ ! -f "$USER_CONFIG" ]; then
  record WARN C01 2 "No ~/.codex/config.toml" "Codex runs on its defaults: workspace-write, no network, cached web search, but nothing keeps secrets unreadable."
elif ! toml "$USER_CONFIG" user; then
  record FAIL C01 2 "~/.codex/config.toml is not valid TOML" "Codex will not load it. Check it with: yq -p toml . ~/.codex/config.toml"
else
  U="$TMP/user.json"
  record PASS C01 2 "~/.codex/config.toml exists and is valid TOML"

  mode=$(q "$U" '.sandbox_mode // ""')
  perm=$(q "$U" '.default_permissions // ""')
  if [ "$mode" = "danger-full-access" ] || [ "$perm" = ":danger-full-access" ]; then
    record FAIL C02 2 "Full access is the default: no sandbox" "sandbox_mode / default_permissions removes filesystem and network boundaries for every session."
  elif [ -n "$mode" ]; then
    record PASS C02 2 "Sandbox mode is $mode"
  elif [ -n "$perm" ]; then
    record PASS C02 2 "A permission profile is the default ($perm)"
  else
    record PASS C02 2 "Sandbox is on its default (workspace-write)"
  fi
  prof_full=$(q "$U" '.profiles // {} | to_entries[] | select(.value.sandbox_mode == "danger-full-access") | .key')
  [ -n "$prof_full" ] && record WARN C02 2 "Legacy [profiles] entries use danger-full-access" "$(echo $prof_full): Codex 0.134.0 and later ignore [profiles], but remove them anyway."

  case "$(q "$U" '.approval_policy | if type == "object" then "granular" else (. // "") end')" in
    untrusted) record FAIL C03 2 'approval_policy = "untrusted" is retired' "Codex 0.149.0 and later reject it, and the setting can stop Codex starting." ;;
    on-failure) record WARN C03 2 'approval_policy = "on-failure" is deprecated' "Use on-request." ;;
    never) record WARN C03 2 'approval_policy = "never": no approvals at all' "Every command inside the sandbox runs unattended; with network or full access, nothing stops a hijacked session." ;;
    *) record PASS C03 2 "Approval policy keeps approvals on" ;;
  esac

  net_legacy=$(q "$U" '.sandbox_workspace_write.network_access // false')
  net_prof=$(q "$U" '.permissions // {} | to_entries[] | select(.value.network.enabled == true) | .key')
  proxy=$(q "$U" '(.features.network_proxy | if type == "object" then .enabled else . end) // false')
  if [ "$net_legacy" = "true" ] || [ -n "$net_prof" ]; then
    if [ "$proxy" = "true" ]; then
      domains=$(q "$U" '[(.features.network_proxy.domains // {}), (.permissions // {} | .[] | .network.domains // {})] | add | to_entries[] | select(.value == "allow") | .key')
      risky=$(grep -Eix "$RISKY_HOSTS" <<<"$domains" || true)
      if [ -n "$risky" ]; then
        record WARN C04 2 "Network allow list contains exfiltration-prone domains" "$(echo $risky)"
      else
        record PASS C04 2 "Command network access goes through the proxy allow list"
      fi
    else
      record WARN C04 2 "Command network access is on with no proxy allow list" "Every command and subprocess can reach any host. Turn on [features] network_proxy with allowed domains."
    fi
  else
    record PASS C04 2 "Command network access is off"
  fi

  ws=$(q "$U" '.web_search // "cached"')
  if [ "$ws" = "live" ]; then
    record WARN C05 2 'web_search = "live"' "Live pages reach the model unfiltered; they are the carrier in documented Codex injection chains."
  elif [ "${HOST_OS:-}" = "windows" ] && [ "$ws" != "disabled" ]; then
    record WARN C05 2 "Web search is on ($ws) on native Windows" "Cymulate's unfixed chain combined web content with Windows PATH hijacking to run code outside the sandbox."
  else
    record PASS C05 2 "Web search is $ws"
  fi

  # Deny rules that actually apply: only the active profile and the profiles it
  # extends. Codex ignores permission profiles whenever legacy sandbox_mode or
  # [sandbox_workspace_write] settings are present.
  legacy=$(q "$U" 'if has("sandbox_mode") or has("sandbox_workspace_write") then "yes" else "" end')
  denies=$(jq -r --arg p "$perm" '
    . as $c
    | def chain($n; $d):
        if $d > 10 or ($n | startswith(":")) or (($c.permissions // {})[$n] == null) then []
        else [$n] + chain(($c.permissions[$n].extends // ":"); $d + 1) end;
    chain($p; 0)[] as $n
    | ($c.permissions[$n].filesystem // {})
    | [paths(scalars) as $x | {k: ($x | map(tostring) | join("/")), v: getpath($x)}]
    | .[] | select(.v == "deny") | .k' "$U" 2>/dev/null)
  if [ -n "$legacy" ]; then
    record WARN C06 2 "Legacy sandbox settings are active, so no deny rules apply" "sandbox_mode or [sandbox_workspace_write] makes Codex ignore permission profiles, and the legacy sandbox limits writes, not reads."
  elif [ -z "$perm" ]; then
    record WARN C06 2 "Nothing keeps secrets unreadable" "The sandbox limits writes, not reads. Use a permission profile with deny rules for .env files, ~/.ssh and ~/.aws."
  elif [[ "$perm" == :* ]]; then
    record WARN C06 2 "The default is the built-in $perm profile, which denies no secrets" "Define your own profile that extends $perm and add deny rules."
  else
    missing=""
    if grep -Eq '\.env\*$' <<<"$denies"; then :
    elif grep -Eq '\.env$' <<<"$denies" && grep -Eq '\.env\.\*$' <<<"$denies"; then :
    elif grep -Eq '\.env$' <<<"$denies"; then missing+=".env.* variants such as .env.local "
    else missing+=".env files "
    fi
    grep -Eq '\.ssh' <<<"$denies" || missing+="~/.ssh "
    grep -Eq '\.aws' <<<"$denies" || missing+="~/.aws "
    if [ -n "$missing" ]; then
      record WARN C06 2 "The active profile ($perm) does not deny some secrets" "Not denied: $missing"
    else
      record PASS C06 2 "The active profile ($perm) denies .env files, ~/.ssh and ~/.aws"
    fi
  fi

  if [ "$(q "$U" '.cli_auth_credentials_store // ""')" = "keyring" ]; then
    record PASS C07 2 "Codex credentials are stored in the OS keyring"
  else
    record WARN C07 2 "Codex credentials are not pinned to the OS keyring" "cli_auth_credentials_store is \"$(q "$U" '.cli_auth_credentials_store // "unset"')\"."
  fi

  if [ "$(q "$U" '.allow_login_shell | tostring')" = "false" ]; then
    record PASS C08 2 "Commands can't start login shells"
  else
    record WARN C08 2 "Login shells are allowed (the default)" "Login shells load ~/.bashrc and ~/.zprofile, including any secrets exported there."
  fi

  [ "$(q "$U" '.approvals_reviewer // "user"')" = "auto_review" ] && \
    record INFO C09 2 "Approvals go to the auto-review agent" "OpenAI: it \"can still make mistakes\"; PromptArmor showed it approving a malicious npm install. Keep a person on sensitive work."

  if [ "$(q "$U" '.features.skill_mcp_dependency_install | tostring')" = "false" ]; then
    record PASS C10 2 "Skills can't install their MCP dependencies automatically"
  else
    record WARN C10 2 "Skills install their MCP dependencies automatically (the default)" "A skill can pull in and start an MCP server you never reviewed."
  fi

  if [ "$(q "$U" '.memories.disable_on_external_context // .memories.no_memories_if_mcp_or_web_search // false')" = "true" ]; then
    record PASS C11 2 "Web and MCP content can't become memories"
  else
    record WARN C11 2 "Memories can be created from web search and MCP content" "Injected text can persist into later sessions."
  fi

  n=$(q "$U" '.notify // [] | join(" ")')
  if [ -n "$n" ]; then
    if grep -Eiq "$REMOTE_CODE" <<<"$n"; then
      record FAIL C12 2 "notify runs a command that downloads or runs remote code" "$n"
    else
      record INFO C12 2 "notify runs a command after every turn" "$n"
    fi
  fi

  secret_env=$(q "$U" '.mcp_servers // {} | to_entries[] | .key as $s | (.value.env // {}) | keys[] | select(test("key|token|secret|password|credential"; "i")) | "\($s): \(.)"')
  [ -n "$secret_env" ] && record WARN C14 2 "Secrets stored in MCP server env blocks" "$secret_env"
fi

# User hooks (hooks.json and [hooks] in config.toml)
user_hook_files=()
[ -f "$CODEX_HOME_DIR/hooks.json" ] && jq empty "$CODEX_HOME_DIR/hooks.json" 2>/dev/null && user_hook_files+=("$CODEX_HOME_DIR/hooks.json")
[ -n "$U" ] && user_hook_files+=("$U")
for f in "${user_hook_files[@]}"; do
  cmds=$(hook_cmds "$f")
  [ -z "$cmds" ] && continue
  remote=$(grep -Ei "$REMOTE_CODE" <<<"$cmds" || true)
  if [ -n "$remote" ]; then
    record FAIL C13 3 "A user hook downloads or runs remote code" "$remote"
  else
    record INFO C13 3 "User hooks are configured: Codex runs them only after you trust each one" "$cmds"
  fi
done

# ---------------------------------------------------------- user MCP ----

if [ -n "$U" ]; then
  servers=$(q "$U" '.mcp_servers // {} | to_entries[] | select(.value.enabled != false) | .key')
  if [ -n "$servers" ]; then
    record INFO M01 4 "MCP servers configured for your user" "$(echo $servers): confirm each is approved and pinned."
    tp=$(q "$U" "$THIRD_PARTY_FILTER")
    [ -n "$tp" ] && record WARN M02 4 "Your MCP servers read content that outsiders can write" "$tp"
    unpinned=$(q "$U" '.mcp_servers // {} | to_entries[] | select((.value.command // "" | test("npx|uvx|bunx|pnpm")) and (((.value.args // []) | map(select(test("^@?[a-z0-9._-]+(/[a-z0-9._-]+)?(@latest)?$"; "i"))) | length) > 0)) | .key')
    [ -n "$unpinned" ] && record WARN M03 4 "MCP servers run without a pinned version" "$(echo $unpinned)"
  else
    record PASS M01 4 "No user-level MCP servers configured"
  fi
fi

# ---------------------------------------------------------- command rules ----

if [ -d "$CODEX_HOME_DIR" ]; then
  rules_files=$(find "$CODEX_HOME_DIR/rules" -name '*.rules' 2>/dev/null)
  if [ -z "$rules_files" ]; then
    record WARN R01 3 "No command rules in ~/.codex/rules/" "Nothing makes Codex ask before git push or refuse destructive commands."
  else
    all=$(for f in $rules_files; do rule_blocks "$f"; done)
    guarded=$(grep -E 'decision *= *"(prompt|forbidden)"' <<<"$all" || true)
    missing=""
    grep -Eq '"git", *"push"' <<<"$guarded" || missing+="git push "
    grep -Eq '"rm"' <<<"$guarded" || missing+="rm "
    if [ -n "$missing" ]; then
      record WARN R01 3 "Command rules don't cover some risky commands" "No prompt or forbidden rule for: $missing"
    else
      record PASS R01 3 "Command rules ask before git push and guard rm"
    fi
    allowed=$(for f in $rules_files; do allow_rules "$f"; done \
      | grep -E '\[ *(\[[^]]*\] *,? *)?"(bash|sh|zsh|pwsh|powershell|rm|sudo|curl|wget|ssh|scp|docker|kubectl|terraform)"' || true)
    [ -n "$allowed" ] && record FAIL R02 3 "Command rules auto-allow risky commands" "$(head -n 10 <<<"$allowed")"
  fi
fi

# ------------------------------------------------------ managed config ----

if toml "$REQUIREMENTS" req; then
  keys=$(q "$TMP/req.json" 'keys | join(", ")')
  record INFO Q01 7 "Managed requirements.toml is present" "Enforced keys: $keys"
fi

# --------------------------------------------------------------- Windows ----

if [ "${HOST_OS:-}" = "windows" ]; then
  case "${PROGRAMDATA_STATE:-}" in
    admin-only)    record PASS W01 1 'C:\ProgramData\OpenAI\Codex is writable by administrators only' ;;
    user-writable) record FAIL W01 1 'Someone other than administrators can change C:\ProgramData\OpenAI\Codex' "An account other than Administrators, SYSTEM or TrustedInstaller owns the folder or a file in it, or can write or delete there, so it can plant or remove settings every Codex user on this machine loads." ;;
    missing)       record WARN W01 1 'C:\ProgramData\OpenAI\Codex does not exist yet' "Windows does not restrict new folders under ProgramData, so a standard user could create it and plant a config.toml (reported by Cymulate, unresolved)." ;;
    unknown)       record WARN W01 1 'Could not read the permissions of C:\ProgramData\OpenAI\Codex' "Check them by hand: the folder and everything in it should be owned by Administrators and writable only by Administrators and SYSTEM." ;;
    *)             record INFO W01 1 'ProgramData folder permissions not checked' "Run the audit with run.ps1 to check them." ;;
  esac
  if toml "$SYSTEM_CONFIG" sys; then
    bad=$(q "$TMP/sys.json" '[
      (if .notify then "notify = \(.notify | join(" "))" else empty end),
      (if .sandbox_mode == "danger-full-access" then "sandbox_mode = danger-full-access" else empty end),
      (if .approval_policy == "never" then "approval_policy = never" else empty end),
      (if .sandbox_workspace_write.network_access == true then "network_access = true" else empty end),
      (if .web_search == "live" then "web_search = live" else empty end),
      (if (.mcp_servers // {} | length) > 0 then "mcp_servers: \(.mcp_servers | keys | join(", "))" else empty end)
    ] | .[]')
    if [ -n "$bad" ]; then
      record FAIL W02 1 'The machine-wide config.toml weakens Codex for every user' "$bad"
    else
      record INFO W02 1 'A machine-wide config.toml is present' "Confirm your administrators created it."
    fi
  fi
fi

# ---------------------------------------------------------- project ----

if [ -d "$PROJECT" ] && [ -n "$(ls -A "$PROJECT" 2>/dev/null)" ]; then
  if [ -f "$PROJ_CONFIG" ]; then
    if ! toml "$PROJ_CONFIG" proj; then
      record WARN P01 4 ".codex/config.toml is not valid TOML"
    else
      P="$TMP/proj.json"
      record INFO P01 4 "The project ships .codex/config.toml" "Codex loads it only after you trust the project."
      weak=$(q "$P" '[
        (if .sandbox_mode == "danger-full-access" or .default_permissions == ":danger-full-access" then "full access" else empty end),
        (if .approval_policy == "never" then "approval_policy = never" else empty end),
        (if .sandbox_workspace_write.network_access == true then "network_access = true" else empty end),
        (if (.permissions // {} | [.[] | .network.enabled == true] | any) then "a permission profile with network on" else empty end),
        (if .web_search == "live" then "web_search = live" else empty end),
        (if .approvals_reviewer == "auto_review" then "approvals_reviewer = auto_review" else empty end)
      ] | .[]')
      [ -n "$weak" ] && record FAIL P02 4 ".codex/config.toml lowers your protections" "$weak"
      srv=$(q "$P" '.mcp_servers // {} | to_entries[] | "\(.key): \(.value.command // .value.url // "?") \((.value.args // []) | join(" "))"')
      [ -n "$srv" ] && record WARN P03 4 "Trusting this project starts its MCP servers" "$srv"
      tp=$(q "$P" "$THIRD_PARTY_FILTER")
      [ -n "$tp" ] && record WARN P08 4 "Project MCP servers read content that outsiders can write" "$tp"
    fi
  fi

  # Project hooks: .codex/hooks.json and [hooks] in .codex/config.toml
  for f in "$PROJECT/.codex/hooks.json" "${P:-}"; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    [ "$f" = "$PROJECT/.codex/hooks.json" ] && ! jq empty "$f" 2>/dev/null && continue
    cmds=$(hook_cmds "$f")
    [ -z "$cmds" ] && continue
    remote=$(grep -Ei "$REMOTE_CODE" <<<"$cmds" || true)
    [ -n "$remote" ] && record FAIL P05 4 "A project hook downloads or runs remote code" "$remote"
    auto=$(session_hooks "$f")
    [ -n "$auto" ] && record WARN P05 4 "A project hook runs when a session starts or a prompt is sent" "$auto"
    [ -z "$remote" ] && [ -z "$auto" ] && record WARN P05 4 "The project defines hooks: review each before trusting it" "$cmds"
  done

  if [ -d "$PROJECT/.codex/rules" ]; then
    pallow=$(find "$PROJECT/.codex/rules" -name '*.rules' 2>/dev/null | while read -r f; do allow_rules "$f"; done)
    [ -n "$pallow" ] && record WARN P06 4 "The project's command rules allow commands" "$(head -n 10 <<<"$pallow")"
  fi

  # A project .env that sets CODEX_* variables: the CVE-2025-61260 pattern.
  for envf in "$PROJECT/.env" "$PROJECT/.codex/.env"; do
    [ -f "$envf" ] || continue
    cv=$(grep -Eo '^[[:space:]]*(export[[:space:]]+)?CODEX_[A-Z_]+' "$envf" | sed 's/.*\(CODEX_[A-Z_]*\)/\1/' | sort -u)
    [ -n "$cv" ] && record FAIL P04 4 "${envf#$PROJECT/} sets Codex variables" "$(echo $cv)"
  done

  if [ -f "$PROJECT/AGENTS.md" ]; then
    if grep -Eiq 'curl |wget |\| *(ba)?sh|npm install -g|pip install|iex|Invoke-WebRequest|https?://[^ )]*\.(sh|ps1)' "$PROJECT/AGENTS.md"; then
      record WARN P07 4 "AGENTS.md tells the agent to fetch or install something" "Read it before trusting this repository."
    fi
    if grep -Eiq 'environment variable|secret|credential' "$PROJECT/AGENTS.md"; then
      record PASS P09 5 "AGENTS.md contains security rules"
    else
      record WARN P09 5 "AGENTS.md has no security rules" "See codex/config/AGENTS.md.example."
    fi
  else
    record WARN P09 5 "No AGENTS.md in the project" "See codex/config/AGENTS.md.example."
  fi

  if ls -a "$PROJECT" 2>/dev/null | grep -Eq '^\.env(\..*)?$'; then
    if [ -f "$PROJECT/.gitignore" ] && grep -Eq '^\.env' "$PROJECT/.gitignore"; then
      record PASS P10 5 ".env files are gitignored"
    else
      record WARN P10 5 ".env file present but not in .gitignore" "It can be committed by accident."
    fi
  fi

  # Symlinks that point at agent config, dotfiles, or out of the project (SymJack).
  sensitive_links="" outside_links=""
  while IFS= read -r link; do
    [ -z "$link" ] && continue
    rel="${link#$PROJECT/}"; target=$(readlink "$link")
    if grep -Eq '(^|/)(\.codex|AGENTS\.md|\.ssh|\.aws|\.gnupg|\.config|\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile|\.gitconfig|\.npmrc|\.netrc)(/|$)' <<<"$target"; then
      sensitive_links+="$rel -> $target"$'\n'
    else
      case "$target" in
        /*) outside_links+="$rel -> $target"$'\n' ;;
        *)  depth=$(awk -F/ -v p="$(dirname "$rel")/$target" 'BEGIN{n=split(p,a,"/"); d=0; for(i=1;i<=n;i++){ if(a[i]==".."){d--; if(d<0){print "out"; exit}} else if(a[i]!="." && a[i]!=""){d++} } print "in"}')
            [ "$depth" = "out" ] && outside_links+="$rel -> $target"$'\n' ;;
      esac
    fi
  done < <(find "$PROJECT" \( -name .git -o -name node_modules -o -name .venv -o -name vendor \) -prune -o -type l -print 2>/dev/null | head -n 500)
  [ -n "$sensitive_links" ] && record FAIL P11 4 "Symlinks point at agent configuration or dotfiles" "$(head -n 20 <<<"$sensitive_links")"
  [ -n "$outside_links" ]   && record WARN P11 4 "Symlinks point outside the project" "$(head -n 20 <<<"$outside_links")"

  # .git/config keys that make git run programs (CVE-2026-19590, -19592, -19593).
  if [ -f "$PROJECT/.git/config" ]; then
    gitexec=$(grep -Ei '^[[:space:]]*(hookspath|fsmonitor|sshcommand|pager|editor|askpass|process|clean|smudge|textconv|tree)[[:space:]]*=' "$PROJECT/.git/config" | sed 's/^[[:space:]]*//' || true)
    [ -n "$gitexec" ] && record WARN P12 4 ".git/config makes git run programs" "$gitexec"
  fi
else
  record INFO P00 4 "No project mounted" "Run from a project directory to check its .codex/, AGENTS.md and .env."
fi

# ------------------------------------------------------ shell startup ----

if [ -d "$RC_DIR" ]; then
  hits=$(grep -l -E -- '--yolo|--dangerously-bypass-approvals-and-sandbox|--dangerously-bypass-hook-trust|danger-full-access' "$RC_DIR"/.[a-zA-Z]* "$RC_DIR"/* 2>/dev/null | xargs -r -n1 basename | sort -u)
  if [ -n "$hits" ]; then
    record FAIL S01 7 "Shell startup files turn off the sandbox or approvals" "$(echo $hits)"
  elif [ -n "$(ls -A "$RC_DIR" 2>/dev/null)" ]; then
    record PASS S01 7 "No sandbox-bypass aliases in shell startup files"
  fi
fi

# --------------------------------------------------------------- report ----

generated="$(date -u '+%Y-%m-%d %H:%M UTC')"
project_label="${PROJECT_NAME:-}"
[ -z "$project_label" ] && [ -d "$PROJECT" ] && project_label="(mounted project)"
[ -z "$project_label" ] && project_label="(none)"

doc=$(printf '%s\n' "${results[@]}" | jq -s \
  --arg v "$AUDIT_VERSION" --arg gen "$generated" --arg proj "$project_label" \
  --arg os "${HOST_OS:-linux/macos}" --arg cv "${CODEX_VERSION:-unknown}" \
  --argjson p "$n_pass" --argjson w "$n_warn" --argjson f "$n_fail" --argjson i "$n_info" \
  '{tool:"codex-audit", version:$v, generated:$gen, project:$proj, host_os:$os,
    codex_version:$cv, summary:{pass:$p, warn:$w, fail:$f, info:$i},
    checks: (map(. + {order: {FAIL:0, WARN:1, INFO:2, PASS:3}[.status]}) | sort_by(.order) | map(del(.order)))}')

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

SELF_TEST="$GUIDE_URL#6-self-test"

case "$FORMAT" in
  json)
    jq . <<<"$doc"
    ;;

  text)
    echo "OpenAI Codex security audit v$AUDIT_VERSION (read-only, offline)"
    echo "Guide: codex/README.md, step numbers shown in [brackets]"
    echo
    for r in "${results[@]}"; do
      jq -r '"\(.status | . + "    " | .[0:5]) [\(.guide_step)] \(.title)" + (.detail | split("\n") | map(select(. != "") | "\n              " + .) | join(""))' <<<"$r"
    done
    echo
    echo "Summary: $n_pass pass, $n_warn warn, $n_fail fail, $n_info info"
    ;;

  report)
    jq -r --arg selftest "$SELF_TEST" '
      "OPENAI CODEX SECURITY AUDIT REPORT",
      "==================================",
      "Generated:      \(.generated)",
      "Project:        \(.project)",
      "Host:           \(.host_os)",
      "Codex:          \(.codex_version)",
      "Audit version:  \(.version)",
      "",
      "Summary: \(.summary.fail) FAIL, \(.summary.warn) WARN, \(.summary.pass) PASS, \(.summary.info) INFO",
      "",
      ( .checks | map(select(.status == "FAIL" or .status == "WARN")) as $todo
        | if ($todo | length) == 0 then "Nothing to fix. Re-run after every Codex upgrade." else
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
            ( (.value.sources // [])[] | "     Source:  \(.title): \(.url)" ) )
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
              ( .value[] | "  \(.id) \(.title | if length > 70 then .[0:67] + "..." else . end): \(.fail) FAIL, \(.warn) WARN  [\(.checks | join(", "))]" ) end ) )
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
      "session, run the self-test: \($selftest)"
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
    jq -r --arg selftest "$SELF_TEST" '
      def badge: "<span class=\"b \(. | ascii_downcase)\">\(.)</span>";
      "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
      "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
      "<title>OpenAI Codex security audit: \(.project | @html)</title>",
      "<style>",
      "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1f2937;background:#fff;line-height:1.55}",
      "h1{margin:0 0 .25rem;color:#0d0d0d}h2{margin-top:2.5rem;border-bottom:1px solid #d1d9e0;padding-bottom:.3rem;color:#0d0d0d}",
      ".meta{color:#59636e;font-size:.9rem}.sum{display:flex;gap:.75rem;flex-wrap:wrap;margin:1.25rem 0}",
      ".sum div{background:#f6f8fa;border:1px solid #d1d9e0;border-radius:6px;padding:.6rem 1rem;min-width:6rem}",
      ".sum strong{display:block;font-size:1.6rem}",
      ".card{background:#fff;border:1px solid #d1d9e0;border-left:5px solid #999;border-radius:6px;padding:1rem 1.25rem;margin:1rem 0}",
      ".card.fail{border-left-color:#b42318}.card.warn{border-left-color:#d4a72c}",
      ".card h3{margin:.2rem 0 .5rem;font-size:1.05rem}.id{color:#59636e;font-weight:400;font-size:.85rem}",
      ".b{display:inline-block;font-size:.72rem;font-weight:700;padding:.1rem .5rem;border-radius:999px;color:#fff;letter-spacing:.04em}",
      ".b.fail{background:#b42318}.b.warn{background:#a8801a}.b.pass{background:#1f5fa8}.b.info{background:#4a5568}",
      "pre{background:#f6f8fa;border:1px solid #d1d9e0;border-radius:6px;padding:.6rem .8rem;white-space:pre-wrap;word-break:break-word;margin:.25rem 0 .75rem;font-size:.85rem}",
      ".label{font-weight:600;font-size:.85rem;margin-top:.5rem}a{color:#1e3a8a}",
      "table{border-collapse:collapse;width:100%;background:#fff}td{border-bottom:1px solid #d1d9e0;padding:.45rem .6rem;vertical-align:top}",
      ".foot{margin-top:2.5rem;font-size:.85rem;color:#59636e}",
      ".why{margin:.25rem 0 .5rem}.map{width:100%;margin:.5rem 0 .75rem;font-size:.82rem}.map td{border:none;border-top:1px solid #eaeef2;padding:.3rem .5rem}",
      ".map td:first-child{white-space:nowrap;font-weight:600;color:#59636e;width:9rem}",
      ".chip{display:inline-block;background:#f6f8fa;border:1px solid #d1d9e0;border-radius:4px;padding:.05rem .4rem;margin:.1rem .25rem .1rem 0}",
      ".chip b{font-weight:600}.cov td{font-size:.85rem}.cov th{text-align:left;font-size:.8rem;color:#59636e;padding:.4rem .6rem;border-bottom:2px solid #d1d9e0}",
      ".n{text-align:right;white-space:nowrap}.small{font-size:.8rem;color:#59636e}",
      ".src{margin:.2rem 0 .75rem 1.1rem;padding:0;font-size:.82rem}.src li{margin:.1rem 0}",
      "</style></head><body>",
      "<h1>OpenAI Codex security audit</h1>",
      "<p class=\"meta\">Project: <strong>\(.project | @html)</strong> · Generated \(.generated | @html) · Host: \(.host_os | @html) · Codex: \(.codex_version | @html) · Audit v\(.version | @html)</p>",
      "<div class=\"sum\"><div><strong>\(.summary.fail)</strong>FAIL</div><div><strong>\(.summary.warn)</strong>WARN</div><div><strong>\(.summary.pass)</strong>PASS</div><div><strong>\(.summary.info)</strong>INFO</div></div>",
      ( .checks | map(select(.status == "FAIL" or .status == "WARN")) as $todo
        | "<h2>What to fix</h2>",
          ( if ($todo | length) == 0 then "<p>Nothing to fix. Re-run after every Codex upgrade.</p>" else
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
              "<a href=\"\(.guide_url | @html)\">Read guide step \(.guide_step)</a>",
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
      "<p class=\"foot\">This audit reads configuration only. To prove the controls work in a live session, run the <a href=\"\($selftest | @html)\">self-test</a>. Generated offline by codex-audit; this file loads no external resources.</p>",
      "</body></html>"
    ' <<<"$doc"
    ;;
esac

[ "$n_fail" -eq 0 ]
