# Claude Code security audit (container)

A throwaway container that checks your Claude Code setup against [this guide's checklist](../07-checklist.md) and prints PASS / WARN / FAIL for each item. Run it, read the report, delete it.

```text
PASS  [2] Sandbox is enabled
PASS  [2] Strict sandbox mode is on (allowUnsandboxedCommands: false)
WARN  [2] Sandbox does not block ~/.ssh
              The default read policy allows it. Add it under sandbox.credentials.files with mode deny.
FAIL  [2] Dangerous commands are auto-allowed
              Bash(*) Bash(git push *)
...
Summary: 14 pass, 3 warn, 1 fail, 1 info
```

The number in brackets is the guide step that explains the fix.

## Why you can trust it

| Property | How |
| --- | --- |
| **Small and known** | Official Alpine Linux 3.24.2 pinned by digest, plus only `bash` and `jq` from Alpine's official repository, pinned to exact versions. About 18 MB. |
| **Open** | Everything that runs is in this folder: [`Dockerfile`](Dockerfile) and [`audit.sh`](audit.sh). Read them before running. |
| **Offline** | Runs with `--network none`. It cannot send anything anywhere. |
| **Read-only** | Your files are mounted `:ro`, and the container's own filesystem is `--read-only`. It cannot change anything. |
| **What it can read** | Only the files listed below, plus the whole project folder you run it from, including any secrets kept in that project. It doesn't mount `~/.ssh`, cloud credential folders, transcripts or the rest of your home folder, and it never prints the contents of `.env` or credential files. |
| **Unprivileged** | Runs as your user (or `nobody`), with every Linux capability dropped and `no-new-privileges`. |
| **Leaves nothing behind** | `--rm` deletes the container when it exits. One command removes the image. |
| **Verifiable** | Published images are built by [GitHub Actions](../../.github/workflows/audit-image.yml) with an SBOM, build provenance and a signed attestation. |

### Exactly what it can see

| Your file | Why |
| --- | --- |
| `~/.claude/settings.json` | Sandbox, permissions, hooks, MCP and retention settings |
| `~/.claude/hooks/` | Runs the hook test suite against your installed hooks |
| `~/.claude.json` | Lists MCP server *names* (nothing else is reported) |
| `~/.bashrc`, `~/.zshrc`, `~/.profile`, … | Looks for `--dangerously-skip-permissions` aliases (macOS / Linux only) |
| The current directory | The project's `.claude/`, `.mcp.json`, `CLAUDE.md` and `.gitignore`. Refused if the current directory is your home directory. |

## Requirements

Docker Desktop, Docker Engine or Podman. Nothing else: no new software on your machine.

## Run it

### Option A: build it yourself from source (recommended)

Building from this repository means you run exactly the code you can read.

macOS / Linux / WSL2:

```bash
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git ~/coding-agent-security
cd ~/code/my-app
bash ~/coding-agent-security/claude-code/audit/run.sh
```

Windows (Docker Desktop), which works in both Command Prompt and PowerShell:

```bat
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "%USERPROFILE%\coding-agent-security"
cd /d C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\coding-agent-security\claude-code\audit\run.ps1"
```

Replace `~/code/my-app` / `C:\Projects\my-app` with the project you want to audit. In PowerShell, write `$env:USERPROFILE` instead of `%USERPROFILE%`. `-ExecutionPolicy Bypass` applies to this one command only; Windows blocks downloaded `.ps1` scripts by default.

The first run builds the image locally from the `Dockerfile` (a few seconds). The image is rebuilt automatically whenever you update the repository.

### Save a report with how-to-fix steps

After the on-screen summary you're asked:

```text
Save a report with how-to-fix steps? [h]tml, [t]ext, [c]sv, [j]son, [n]o (default n):
```

| Format | Best for |
| --- | --- |
| **HTML** | Reading and sharing: every finding as a card with *Why it matters*, *Details*, *How to fix* (the exact setting to add), its *Risk mapping* and a link to the guide, plus a *Framework coverage* summary. Self-contained: no scripts, no external resources. |
| **Text** | Email, tickets, or reading in any editor. Same content, most serious first. |
| **CSV** | Tracking fixes across a team in Excel or Google Sheets: one row per check with why, fix, framework columns and guide link. |
| **JSON** | Scripts and CI. |

Reports are saved to a `claude-code-audit-reports` folder in your home directory, never inside the project, so they can't be committed by accident. Reports mask values that look like secrets, such as tokens, passwords and credentials in URLs, but review a report before you share it. The file name includes the project and a timestamp.

To skip the question:

```bash
bash .../run.sh --report html          # save an HTML report without asking
bash .../run.sh --no-report            # never ask
bash .../run.sh --report csv --report-dir ./audit-out
```

On Windows: `-Report html`, `-NoReport`, `-ReportDir <folder>`.

The container only prints the report; the launcher script saves it on your machine. The container is never given write access to anything.

### Option B: use the published image

```bash
# Verify it was built by this repository's workflow before running it
gh attestation verify oci://ghcr.io/aisecuritylabs-org/claude-code-audit:1.0.0 --owner aisecuritylabs-org

AUDIT_IMAGE=ghcr.io/aisecuritylabs-org/claude-code-audit:1.0.0 \
  bash /path/to/coding-agent-security/claude-code/audit/run.sh
```

### Run it by hand

`run.sh` is a convenience. The equivalent command, so you can see every flag:

```bash
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
  -e CLAUDE_VERSION="$(claude --version)" \
  -v ~/.claude/settings.json:/audit/home-claude/settings.json:ro \
  -v ~/.claude/hooks:/audit/home-claude/hooks:ro \
  -v ~/.claude.json:/audit/claude.json:ro \
  -v ~/.zshrc:/audit/rc/.zshrc:ro \
  -v "$PWD":/audit/project:ro \
  claude-code-audit
```

## Read the result

| Status | Meaning |
| --- | --- |
| **FAIL** | A setting that removes a protection or grants dangerous access. Fix before your next session. |
| **WARN** | A recommended control is missing, or something needs your review. |
| **PASS** | The control is in place. |
| **INFO** | Context only; nothing to fix. |

The exit code is `0` when there are no FAIL results and `1` otherwise, so you can use it in a script or CI job.

The audit reads configuration. It does not prove the controls work in a live session; for that, run the [self-test](../06-self-test.md).

## Why it matters, and framework mapping

Every WARN and FAIL in a saved report explains **why it matters** (the risk the control protects against) and maps the finding to four AI security frameworks:

| Framework | Version | What the mapping tells you |
| --- | --- | --- |
| [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) | 2025 | Which LLM application risk the gap exposes (e.g. LLM06 Excessive Agency) |
| [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | 2026 | Which agent-specific risk it exposes (e.g. ASI05 Unexpected Code Execution) |
| [MITRE ATLAS](https://atlas.mitre.org/) | 2026.09 | Which adversary technique the gap enables (e.g. AML.T0086 Exfiltration via AI Agent Tool Invocation) |
| [NIST AI RMF](https://airc.nist.gov/airmf-resources/playbook/) | 1.0 | Which risk-management outcome the control supports (e.g. MEASURE 2.7) |

Reports end with a **framework coverage** summary: every OWASP risk, ATLAS technique and NIST subcategory your findings relate to, with FAIL / WARN counts, ready to paste into a risk register.

The full table for all checks is in **[FRAMEWORK-MAPPING.md](FRAMEWORK-MAPPING.md)**. The mappings live in [`mappings.json`](mappings.json); every ATLAS ID and name was verified against MITRE's ATLAS 2026.09 data, and the NIST statements are quoted from the AI RMF Playbook. They are AISecurityLabs.org's interpretation and are not endorsed by the framework owners.

## Check reference

Each check has a stable ID (shown in `--json` output). The step column links to the guide section that explains the fix. See [FRAMEWORK-MAPPING.md](FRAMEWORK-MAPPING.md) for why each one matters and its framework mapping.

| ID | Checks | Can report | Step |
| --- | --- | --- | --- |
| I01 | Claude Code version supports every baseline setting (v2.1.219+) | PASS · WARN · INFO | [1](../01-before-you-start.md) |
| U00 | `~/.claude` was available to the audit | WARN | [2](../02-sandbox-and-permissions.md) |
| U01 | `~/.claude/settings.json` exists and is valid JSON | PASS · FAIL | [2](../02-sandbox-and-permissions.md) |
| U02 | Sandbox enabled (and supported: native Windows has none) | PASS · WARN · FAIL | [2](../02-sandbox-and-permissions.md) |
| U03 | Strict sandbox mode: `allowUnsandboxedCommands: false` | PASS · WARN · FAIL | [2](../02-sandbox-and-permissions.md) |
| U04 | `sandbox.network.strictAllowlist: true` | PASS · WARN | [2](../02-sandbox-and-permissions.md) |
| U05 | Network allowlist has no wildcard or exfiltration-prone domains | PASS · WARN · INFO | [2](../02-sandbox-and-permissions.md) |
| U06 | Sandbox blocks reads of `~/.ssh` and `~/.aws` | PASS · WARN | [2](../02-sandbox-and-permissions.md) |
| U07 | A deny rule covers `.env` files | PASS · WARN | [2](../02-sandbox-and-permissions.md) |
| U08 | `curl` / `wget` denied or require approval | PASS · WARN | [2](../02-sandbox-and-permissions.md) |
| U09 | Allow list has no dangerous commands (`Bash(*)`, `git push`, `docker`, `rm`, `sudo`, …) | PASS · FAIL | [2](../02-sandbox-and-permissions.md) |
| U10 | `git push` requires approval | PASS · WARN | [2](../02-sandbox-and-permissions.md) |
| U11 | `enableAllProjectMcpServers` is not `true` | FAIL | [2](../02-sandbox-and-permissions.md) |
| U12 | `additionalDirectories` does not widen the write boundary | WARN | [2](../02-sandbox-and-permissions.md) |
| U13 | Default permission mode is not `bypassPermissions` | FAIL | [2](../02-sandbox-and-permissions.md) |
| U14 | Transcripts cleaned up within 30 days (7 to 14 recommended) | PASS · WARN | [2](../02-sandbox-and-permissions.md) |
| U15 | No secrets in the settings `env` block | FAIL | [2](../02-sandbox-and-permissions.md) |
| U16 | Docker socket not allowed into the sandbox | FAIL | [2](../02-sandbox-and-permissions.md) |
| U17 | Plugin marketplaces are not fetched from git hosts outside GitHub (Plugin4Shell) | WARN | [4](../04-mcp-plugins-and-repos.md) |
| H01 | A `PreToolUse` hook guards the Bash tool | PASS · WARN | [3](../03-hooks.md) |
| H02 | A `PreToolUse` hook guards Edit / Write | PASS · WARN | [3](../03-hooks.md) |
| H03 | Installed hooks pass the 41-case test suite | PASS · FAIL | [3](../03-hooks.md) |
| P00 | A project directory was available to the audit | INFO | [4](../04-mcp-plugins-and-repos.md) |
| P01 | Project settings are valid JSON | WARN | [4](../04-mcp-plugins-and-repos.md) |
| P02 | Project does not auto-enable every MCP server | FAIL | [4](../04-mcp-plugins-and-repos.md) |
| P03 | Project hooks: none download or run remote code; others listed for review | FAIL · WARN · INFO | [4](../04-mcp-plugins-and-repos.md) |
| P04 | MCP servers the project declares | INFO | [4](../04-mcp-plugins-and-repos.md) |
| P05 | Project MCP servers are version-pinned | WARN | [4](../04-mcp-plugins-and-repos.md) |
| P06 | `CLAUDE.md` does not tell the agent to fetch or install things | WARN | [4](../04-mcp-plugins-and-repos.md) |
| P07 | `CLAUDE.md` exists and contains security rules | PASS · WARN | [5](../05-working-habits.md) |
| P08 | `.env` files are gitignored | PASS · WARN | [5](../05-working-habits.md) |
| P09 | Project hooks that run automatically when a session starts (the Miasma worm's trigger) | WARN | [4](../04-mcp-plugins-and-repos.md) |
| P10 | Project MCP servers that start as local processes once the folder is trusted (TrustFall) | WARN | [4](../04-mcp-plugins-and-repos.md) |
| P11 | Symlinks pointing at agent config or dotfiles (FAIL) or out of the project (WARN) (SymJack) | FAIL · WARN | [4](../04-mcp-plugins-and-repos.md) |
| P12 | Project MCP servers that read content outsiders can write, such as errors, tickets, chat and email (Agentjacking) | WARN | [4](../04-mcp-plugins-and-repos.md) |
| P13 | Project plugin marketplaces fetched from git hosts outside GitHub (Plugin4Shell) | WARN | [4](../04-mcp-plugins-and-repos.md) |
| M01 | MCP servers configured for your user | PASS · INFO | [4](../04-mcp-plugins-and-repos.md) |
| M02 | Your MCP servers that read content outsiders can write (Agentjacking) | WARN | [4](../04-mcp-plugins-and-repos.md) |
| R01 | No `--dangerously-skip-permissions` aliases in shell startup files | PASS · FAIL | [7](../07-checklist.md) |

## Delete it when you're done

The container is already gone (`--rm`). Any reports you saved stay in `~/claude-code-audit-reports` until you delete that folder. Remove the image:

```bash
docker image rm claude-code-audit
# or, for the published image:
docker image rm ghcr.io/aisecuritylabs-org/claude-code-audit:1.0.0
```

## Build and test it yourself

```bash
docker build -f claude-code/audit/Dockerfile -t claude-code-audit .
bash claude-code/audit/tests/test-audit.sh
```

The test suite runs the audit against a hardened setup (expects no FAIL and no WARN) and a deliberately insecure one (expects every FAIL and WARN it should catch).
