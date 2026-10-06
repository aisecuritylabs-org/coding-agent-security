# Cursor security audit

Audit your Cursor setup in about a minute with a throwaway container that is offline, read-only, and deleted when it's done.

```text
$ bash ~/coding-agent-security/cursor/audit/run.sh
Cursor security audit v1.0.0 (read-only, offline)

PASS  [2] The sandbox is on (workspace_readwrite)
PASS  [3] No risky commands in the terminal allowlist
WARN  [1] Workspace Trust is off (the default)
WARN  [4] The project's .cursor/permissions.json adds to your allowlists
              terminal: python
...
Summary: 9 pass, 2 warn, 0 fail, 2 info
```

Every finding shows, in brackets, the section of the [Cursor guide](../README.md) that explains the fix.

## Run it

You need Docker Desktop, Docker Engine or Podman. Nothing else is installed on your machine.

**macOS, Linux and WSL2:**

```bash
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git ~/coding-agent-security
cd ~/code/my-app            # the project you want to audit
bash ~/coding-agent-security/cursor/audit/run.sh
```

**Windows, Command Prompt:**

```bat
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "%USERPROFILE%\coding-agent-security"
cd /d C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\coding-agent-security\cursor\audit\run.ps1"
```

**Windows, PowerShell:**

```powershell
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "$HOME\coding-agent-security"
Set-Location C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "$HOME\coding-agent-security\cursor\audit\run.ps1"
```

The launcher reads your Cursor version with `cursor --version` when `cursor` is on your PATH. On Windows it also checks who can write `C:\ProgramData\Cursor`, which the container can't see.

After the summary you're asked whether to save a report (HTML, text, CSV or JSON) with why each finding matters, the exact fix, OWASP, MITRE ATLAS and NIST AI RMF mappings, and sources. Reports go to `cursor-audit-reports` in your home folder. Reports mask values that look like secrets, such as tokens, passwords and credentials in URLs, but review a report before you share it. Options: `--report html|txt|csv|json`, `--report-dir DIR`, `--no-report`, `--json` (`-Report`, `-ReportDir`, `-NoReport`, `-Json` on Windows).

## Why you can trust it

| | |
| --- | --- |
| **Small and known** | Official Alpine Linux 3.24.2 pinned by digest, plus only `bash` and `jq` from Alpine's repositories, pinned to exact versions. |
| **Open** | Everything that runs is the [`Dockerfile`](Dockerfile), [`audit.sh`](audit.sh), [`mappings.json`](mappings.json) and the shared [`audit-lib.sh`](../../common/audit-lib.sh) and [`jsonc.awk`](../../common/jsonc.awk). You build it yourself. |
| **Offline** | `--network none`: it cannot send anything anywhere. |
| **Read-only** | Your files are mounted read-only and the container's filesystem is read-only. |
| **What it can read** | `~/.cursor/sandbox.json`, `permissions.json`, `mcp.json`, `hooks.json` and `cli-config.json`; your Cursor user `settings.json`; the machine-wide `hooks.json`; your shell startup files; and the whole project folder you run it from, including any secrets kept in that project. Never the rest of `~/.cursor` (extensions, chats, project data) or Cursor's app state. |
| **Unprivileged** | Runs as you, with every Linux capability dropped, and is removed when it exits. |

## What it checks

| ID | Check |
| --- | --- |
| I01 | Cursor is at least 3.1.2 (CVE-2026-73217) |
| V00 to V02 | Cursor user settings were shared and are readable, and Workspace Trust is on |
| B01 to B05 | `~/.cursor/sandbox.json`: sandbox on, network denied by default, no wildcard domains, no home or credential paths |
| A01 to A03 | `~/.cursor/permissions.json`: no allowlisted command on the risky list, no whole-server MCP entries, and the Auto-review block instructions listed for you to review (information) |
| M01 to M04 | User MCP servers: inventory, servers that read outsider-written content (Agentjacking), unpinned versions, secrets stored in the file |
| H01, H02 | User hooks: no remote code; security hooks set to fail closed (information) |
| L01 to L04 | Cursor CLI: approvals on, sandbox on, no broad allow entries, `.env` reads denied |
| P01, P02 | The project's `.cursor/sandbox.json` and `permissions.json` don't widen the sandbox or your allowlists |
| P03 to P05 | Project MCP servers in `.cursor/mcp.json` |
| P06 to P08 | Project hooks and CLI permissions |
| P09, P10 | Rules files: no fetch or install instructions, no hidden Unicode |
| P11 | Cloud agent and worktree setup commands don't run remote code |
| P12 | `.env` files are gitignored |
| P13 | No symlinks disguised as ordinary files pointing at agent config or dotfiles (SymJack) |
| P14 | `.git/config` doesn't make git run programs |
| W01, W02 | Windows: `C:\ProgramData\Cursor` writable by administrators only; machine-wide hooks don't run remote code |
| S01 | No `--yolo`, `--force`, `--sandbox disabled` or `--approve-mcps` aliases in shell startup files |

The exit code is `0` with no FAIL results and `1` otherwise, so the audit also works in scripts and CI. Your run mode is chosen in the Cursor app and team policies live in the Cursor dashboard, which this offline audit can't see; check them against sections 2 and 7 of the guide.

## Test it

```bash
bash cursor/audit/tests/test-audit.sh
```

The suite builds the image and runs it against the published baseline (expect no FAIL) and a deliberately insecure setup (expect every result it lists).

## Delete it when you are done

```bash
docker image rm cursor-audit
```
