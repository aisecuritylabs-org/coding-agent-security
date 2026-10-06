# Gemini CLI and Code Assist security audit

Audit your Gemini CLI and Gemini Code Assist setup in about a minute with a throwaway container that is offline, read-only, and deleted when it's done.

```text
$ bash ~/coding-agent-security/gemini/audit/run.sh
Gemini CLI and Code Assist security audit v1.0.0 (read-only, offline)

PASS  [2] Sandboxing is on
PASS  [2] Folder trust is on
FAIL  [4] The project trusts MCP servers, bypassing every confirmation
              tickets
WARN  [4] GitHub workflows run Gemini on untrusted input
              .github/workflows/gemini.yml: run-gemini-cli v0.1.20 is older than 0.1.22
...
Summary: 8 pass, 1 warn, 1 fail, 2 info
```

Every finding shows, in brackets, the section of the [Gemini guide](../README.md) that explains the fix.

## Run it

You need Docker Desktop, Docker Engine or Podman. Nothing else is installed on your machine.

**macOS, Linux and WSL2:**

```bash
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git ~/coding-agent-security
cd ~/code/my-app            # the project you want to audit
bash ~/coding-agent-security/gemini/audit/run.sh
```

**Windows, Command Prompt:**

```bat
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "%USERPROFILE%\coding-agent-security"
cd /d C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\coding-agent-security\gemini\audit\run.ps1"
```

**Windows, PowerShell:**

```powershell
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "$HOME\coding-agent-security"
Set-Location C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "$HOME\coding-agent-security\gemini\audit\run.ps1"
```

The launcher reads your Gemini CLI version with `gemini --version` when `gemini` is on your PATH. On Windows it also checks who can write `C:\ProgramData\gemini-cli`, which the container can't see.

After the summary you're asked whether to save a report (HTML, text, CSV or JSON) with why each finding matters, the exact fix, OWASP, MITRE ATLAS and NIST AI RMF mappings, and sources. Reports go to `gemini-audit-reports` in your home folder. Reports mask values that look like secrets, such as tokens, passwords and credentials in URLs, but review a report before you share it. Options: `--report html|txt|csv|json`, `--report-dir DIR`, `--no-report`, `--json` (`-Report`, `-ReportDir`, `-NoReport`, `-Json` on Windows).

## Why you can trust it

| | |
| --- | --- |
| **Small and known** | Official Alpine Linux 3.24.2 pinned by digest, plus only `bash`, `jq` and `yq` (to read TOML policy files) from Alpine's repositories, pinned to exact versions. |
| **Open** | Everything that runs is the [`Dockerfile`](Dockerfile), [`audit.sh`](audit.sh), [`mappings.json`](mappings.json) and the shared [`audit-lib.sh`](../../common/audit-lib.sh) and [`jsonc.awk`](../../common/jsonc.awk). You build it yourself. |
| **Offline** | `--network none`: it cannot send anything anywhere. |
| **Read-only** | Your files are mounted read-only and the container's filesystem is read-only. |
| **What it can read** | `~/.gemini/settings.json`, your policy files and each extension's `gemini-extension.json` manifest; the machine-wide `settings.json` and `system-defaults.json`; your VS Code user `settings.json`; your shell startup files; and the whole project folder you run it from, including any secrets kept in that project. Never `oauth_creds.json`, `google_accounts.json`, chat history or extension code. |
| **Unprivileged** | Runs as you, with every Linux capability dropped, and is removed when it exits. |

## What it checks

| ID | Check |
| --- | --- |
| I01 | Gemini CLI is at least 0.39.1 (CVE-2026-12537) |
| G00, G01 | `~/.gemini/settings.json` exists and is readable |
| G02, G03 | Sandboxing is on; folder trust is on |
| G04, G05 | YOLO mode disabled (information); `auto_edit` isn't the default |
| G06 to G08 | No risky tools in `tools.allowed`; no sandbox network access; no approvals that last across sessions |
| G09 | Extensions restricted to an allowlist or blocked from Git (information) |
| M01 to M05 | MCP servers: inventory, servers that read outsider-written content (Agentjacking), unpinned versions, `"trust": true`, secrets stored in the file |
| H01 | User hooks don't run remote code |
| R01 | Policy rules don't allow risky shell commands without asking |
| E01, E02 | Installed extensions, and extensions that add trusted MCP servers or remote-code hooks |
| C01 | Gemini Code Assist agent YOLO mode is off |
| P01 to P07 | The project's `.gemini/settings.json`: protections, MCP servers, trusted servers and hooks |
| P08 | The project `.env` doesn't set `GEMINI_*` variables such as `GEMINI_SANDBOX` |
| P09, P10 | `GEMINI.md` and `AGENTS.md`: no fetch or install instructions, no hidden Unicode |
| P11 | GitHub workflows use `run-gemini-cli` 0.1.22 or later and don't run it without confirmations on issues or pull requests |
| P12 | `.env` files are gitignored |
| P13 | No symlinks disguised as ordinary files pointing at agent config or dotfiles (SymJack) |
| P14 | `.git/config` doesn't make git run programs |
| W01, W02 | Windows: `C:\ProgramData\gemini-cli` writable by administrators only; machine-wide settings don't weaken Gemini or run remote code |
| S01 | No `--yolo`, `--skip-trust`, `GEMINI_SANDBOX=false` or `GEMINI_CLI_TRUST_WORKSPACE=true` in shell startup files |

The exit code is `0` with no FAIL results and `1` otherwise, so the audit also works in scripts and CI. Admin controls for Code Assist Standard and Enterprise live in the Google Cloud console, which this offline audit can't see; check them against the checklist in the guide.

## Test it

```bash
bash gemini/audit/tests/test-audit.sh
```

The suite builds the image and runs it against the published baseline (expect no FAIL) and a deliberately insecure setup (expect every result it lists).

## Delete it when you are done

```bash
docker image rm gemini-audit
```
