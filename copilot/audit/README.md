# GitHub Copilot security audit

Audit your Copilot setup in about a minute with a throwaway container that is offline, read-only, and deleted when it's done.

```text
$ bash ~/coding-agent-security/copilot/audit/run.sh
GitHub Copilot security audit v1.0.0 (read-only, offline)

PASS  [2] Global auto-approve is off
PASS  [2] Workspace Trust is on
WARN  [2] The agent terminal sandbox is off (the default)
WARN  [4] .vscode/mcp.json declares MCP servers
              helper: node ./tools/helper.js
...
Summary: 12 pass, 2 warn, 0 fail, 2 info
```

Every finding shows, in brackets, the section of the [Copilot guide](../README.md) that explains the fix.

## Run it

You need Docker Desktop, Docker Engine or Podman. Nothing else is installed on your machine.

**macOS, Linux and WSL2:**

```bash
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git ~/coding-agent-security
cd ~/code/my-app            # the project you want to audit
bash ~/coding-agent-security/copilot/audit/run.sh
```

**Windows, Command Prompt:**

```bat
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "%USERPROFILE%\coding-agent-security"
cd /d C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\coding-agent-security\copilot\audit\run.ps1"
```

**Windows, PowerShell:**

```powershell
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "$HOME\coding-agent-security"
Set-Location C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "$HOME\coding-agent-security\copilot\audit\run.ps1"
```

The launcher reads your VS Code and Copilot Chat versions with `code --version` and `code --list-extensions --show-versions` when `code` is on your PATH.

After the summary you're asked whether to save a report (HTML, text, CSV or JSON) with why each finding matters, the exact fix, OWASP, MITRE ATLAS and NIST AI RMF mappings, and sources. Reports go to `copilot-audit-reports` in your home folder. Reports mask values that look like secrets, such as tokens, passwords and credentials in URLs, but review a report before you share it. Options: `--report html|txt|csv|json`, `--report-dir DIR`, `--no-report`, `--json` (`-Report`, `-ReportDir`, `-NoReport`, `-Json` on Windows).

## Why you can trust it

| | |
| --- | --- |
| **Small and known** | Official Alpine Linux 3.24.2 pinned by digest, plus only `bash` and `jq` from Alpine's repositories, pinned to exact versions. |
| **Open** | Everything that runs is the [`Dockerfile`](Dockerfile), [`audit.sh`](audit.sh), [`mappings.json`](mappings.json) and the shared [`audit-lib.sh`](../../common/audit-lib.sh) and [`jsonc.awk`](../../common/jsonc.awk). You build it yourself. |
| **Offline** | `--network none`: it cannot send anything anywhere. |
| **Read-only** | Your files are mounted read-only and the container's filesystem is read-only. |
| **What it can read** | Your VS Code user `settings.json` and `mcp.json`; `~/.copilot/settings.json`, `permissions-config.json` and `mcp-config.json`; your shell startup files; and the whole project folder you run it from, including any secrets kept in that project. Never the Copilot CLI's `config.json`, session history or logs. |
| **Unprivileged** | Runs as you, with every Linux capability dropped, and is removed when it exits. |

## What it checks

| ID | Check |
| --- | --- |
| I01, I02 | VS Code is at least 1.132.1 (CVE-2026-70335) and Copilot Chat at least 1.123.2 (CVE-2026-45482) |
| V00, V01 | VS Code user settings were shared and are readable (JSON with comments) |
| V02 | Global auto-approve is off (`chat.tools.global.autoApprove`, and the old `chat.tools.autoApprove`) |
| V03 | New chat sessions start with Default Permissions |
| V04, V05 | No risky terminal commands or sensitive file edits are auto-approved |
| V06 | Workspace Trust is on |
| V07 | The agent terminal sandbox is on, with network off |
| V08 to V10 | MCP access (information), MCP discovery off, no wildcard URL approvals |
| M01 to M03 | User MCP servers in VS Code and the CLI: inventory, servers that read outsider-written content (Agentjacking), unpinned versions |
| L01 to L04 | Copilot CLI: sandbox on, no risky saved approvals, no wildcard URLs, allow-all flags disabled |
| P01 | The project's `.vscode/settings.json` doesn't change agent safety settings |
| P02 to P04 | Project MCP servers in `.vscode/mcp.json`, `.mcp.json` and `.github/mcp.json` |
| P05, P06 | Instruction files: no fetch or install instructions, no hidden Unicode |
| P07, P08 | Cloud agent setup steps and repository hooks |
| P09 | `.env` files are gitignored |
| P10 | No symlinks disguised as ordinary files pointing at agent config or dotfiles (SymJack) |
| P11 | `.git/config` doesn't make git run programs |
| P12 | `.github/copilot/settings.json` doesn't add hooks or plugins for every collaborator |
| S01 | No `--yolo`, `--allow-all` or `COPILOT_ALLOW_ALL` in shell startup files |

The exit code is `0` with no FAIL results and `1` otherwise, so the audit also works in scripts and CI. Copilot cloud agent and organisation policies live on GitHub, which this offline audit can't see; check them against section 4 of the guide.

## Test it

```bash
bash copilot/audit/tests/test-audit.sh
```

The suite builds the image and runs it against the published baseline (expect no FAIL) and a deliberately insecure setup (expect every result it lists).

## Delete it when you are done

```bash
docker image rm copilot-audit
```
