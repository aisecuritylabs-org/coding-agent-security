# OpenAI Codex security audit

Audit your Codex setup in about a minute with a throwaway container that is offline, read-only, and deleted when it's done.

```text
$ bash ~/coding-agent-security/codex/audit/run.sh
OpenAI Codex security audit v1.0.0 (read-only, offline)

PASS  [2] A permission profile is the default (dev)
PASS  [2] Command network access is off
WARN  [2] Login shells are allowed (the default)
FAIL  [4] .codex/config.toml lowers your protections
              approval_policy = never
...
Summary: 13 pass, 3 warn, 1 fail, 1 info
```

Every finding shows, in brackets, the section of the [Codex guide](../README.md) that explains the fix.

## Run it

You need Docker Desktop, Docker Engine or Podman. Nothing else is installed on your machine.

**macOS, Linux and WSL2:**

```bash
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git ~/coding-agent-security
cd ~/code/my-app            # the project you want to audit
bash ~/coding-agent-security/codex/audit/run.sh
```

**Windows, Command Prompt:**

```bat
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "%USERPROFILE%\coding-agent-security"
cd /d C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\coding-agent-security\codex\audit\run.ps1"
```

**Windows, PowerShell:**

```powershell
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "$HOME\coding-agent-security"
Set-Location C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "$HOME\coding-agent-security\codex\audit\run.ps1"
```

On Windows the launcher also checks who can write `C:\ProgramData\OpenAI\Codex`, which the container can't see.

After the summary you're asked whether to save a report (HTML, text, CSV or JSON) with why each finding matters, the exact fix, OWASP, MITRE ATLAS and NIST AI RMF mappings, and sources. Reports go to `codex-audit-reports` in your home folder. Reports mask values that look like secrets, such as tokens, passwords and credentials in URLs, but review a report before you share it. Options: `--report html|txt|csv|json`, `--report-dir DIR`, `--no-report`, `--json` (`-Report`, `-ReportDir`, `-NoReport`, `-Json` on Windows).

## Why you can trust it

| | |
| --- | --- |
| **Small and known** | Official Alpine Linux 3.24.2 pinned by digest, plus only `bash`, `jq` and `yq` (to read TOML) from Alpine's repositories, pinned to exact versions. |
| **Open** | Everything that runs is the [`Dockerfile`](Dockerfile), [`audit.sh`](audit.sh) and [`mappings.json`](mappings.json). You build it yourself. |
| **Offline** | `--network none`: it cannot send anything anywhere. |
| **Read-only** | Your files are mounted read-only and the container's filesystem is read-only. |
| **What it can read** | `~/.codex/config.toml`, `hooks.json`, `rules/` and `AGENTS.md`, your shell startup files, and the whole project folder you run it from, including any secrets kept in that project. Never `auth.json`, transcripts, history or logs. It prints variable names, never secret values. |
| **Unprivileged** | Runs as you, with every Linux capability dropped, and is removed when it exits. |

## What it checks

| ID | Check |
| --- | --- |
| I01 | Codex CLI is at least 0.146.0 (fixes Plugin4Shell, and includes the CVE-2026-19591 fix) |
| C01 | `~/.codex/config.toml` exists and is valid TOML |
| C02 | No full access (`danger-full-access`, `:danger-full-access`) as the default |
| C03 | Approvals stay on: not `never`, not the retired `untrusted`, not the deprecated `on-failure` |
| C04 | Command network is off, or goes through the proxy with no exfiltration-prone domains |
| C05 | Web search isn't `live` (and is `disabled` on native Windows) |
| C06 | A permission profile denies `.env` files, `~/.ssh` and `~/.aws` |
| C07 | Credentials are stored in the OS keyring |
| C08 | `allow_login_shell = false` |
| C09 | Auto-review is on (information) |
| C10 | Skills can't install MCP dependencies automatically |
| C11 | Web and MCP content can't become memories |
| C12 | `notify` doesn't download or run remote code |
| C13 | User hooks don't download or run remote code |
| C14 | No secrets in MCP server `env` blocks |
| M01 to M03 | User MCP servers: inventory, servers that read outsider-written content (Agentjacking), unpinned versions |
| R01, R02 | Command rules ask before `git push` and guard `rm`; no allow rules for shells, deletes, network or infrastructure tools |
| Q01 | Managed `requirements.toml` present (information) |
| W01, W02 | Windows: `C:\ProgramData\OpenAI\Codex` writable by administrators only; no machine-wide settings that weaken Codex |
| P01 to P03, P08 | Project `.codex/config.toml`: doesn't lower protections; MCP servers it starts once trusted |
| P04 | Project `.env` doesn't set `CODEX_*` variables (the CVE-2025-61260 pattern) |
| P05, P06 | Project hooks and rules: no remote code, no session-start hooks, no allow rules |
| P07, P09 | `AGENTS.md`: no fetch or install instructions; contains security rules |
| P10 | `.env` files are gitignored |
| P11 | No symlinks disguised as ordinary files pointing at agent config or dotfiles (SymJack) |
| P12 | `.git/config` doesn't make git run programs (CVE-2026-19590, -19592, -19593) |
| S01 | No `--yolo`, bypass or full-access aliases in shell startup files |

The exit code is `0` with no FAIL results and `1` otherwise, so the audit also works in scripts and CI.

## Test it

```bash
bash codex/audit/tests/test-audit.sh
```

The suite builds the image and runs it against the published baseline (expect no FAIL) and a deliberately insecure setup (expect every result it lists).

## Delete it when you are done

```bash
docker image rm codex-audit
```
