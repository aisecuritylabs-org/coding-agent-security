# Coding Agent Security

**Audit your AI coding agent setup in about a minute, with a throwaway container that is offline, read-only, and deleted when it's done.**

Published by [AISecurityLabs.org](https://aisecuritylabs.org).

```text
$ bash claude-code/audit/run.sh
Claude Code security audit v1.0.0 (read-only, offline)

PASS  [2] Sandbox is enabled
PASS  [2] Strict sandbox mode is on (allowUnsandboxedCommands: false)
WARN  [2] Sandbox does not block ~/.ssh
              The default read policy allows it. Add it under sandbox.credentials.files with mode deny.
FAIL  [2] Dangerous commands are auto-allowed
              Bash(*) Bash(git push *)
...
Summary: 14 pass, 3 warn, 1 fail, 1 info
```

Every finding points to the step of the guide that explains the fix.

## Coding agents covered

| Agent | Guide | Audit |
| --- | --- | --- |
| Claude Code | [claude-code/](claude-code/README.md) | `bash claude-code/audit/run.sh` |
| OpenAI Codex | [codex/](codex/README.md) | `bash codex/audit/run.sh` ([details](codex/audit/README.md)) |
| GitHub Copilot | [copilot/](copilot/README.md) | `bash copilot/audit/run.sh` ([details](copilot/audit/README.md)) |
| Cursor | [cursor/](cursor/README.md) | `bash cursor/audit/run.sh` ([details](cursor/audit/README.md)) |
| Gemini CLI and Code Assist | [gemini/](gemini/README.md) | `bash gemini/audit/run.sh` ([details](gemini/audit/README.md)) |

The quick start below uses the Claude Code audit; the other audits run the same way from their own `audit/` folders.

## Quick start

You need Docker Desktop, Docker Engine or Podman; nothing else is installed on your machine.

**macOS / Linux / WSL2:**

```bash
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git ~/coding-agent-security
cd ~/code/my-app
bash ~/coding-agent-security/claude-code/audit/run.sh
```

Replace `~/code/my-app` with the folder of the project you want to audit.

**Windows** (Docker Desktop): these commands work in both Command Prompt and PowerShell:

```bat
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git "%USERPROFILE%\coding-agent-security"
cd /d C:\Projects\my-app
powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\coding-agent-security\claude-code\audit\run.ps1"
```

Replace `C:\Projects\my-app` with the folder of the project you want to audit. In PowerShell, write `$env:USERPROFILE` instead of `%USERPROFILE%`. `-ExecutionPolicy Bypass` applies to this one command only; it's needed because Windows blocks downloaded `.ps1` scripts by default.

The first run builds the image locally from the open [`Dockerfile`](claude-code/audit/Dockerfile) in a few seconds.

After the on-screen summary, you're asked whether to **save a report with how-to-fix steps**, as **HTML**, **text**, **CSV** or **JSON**. Each finding explains **why it matters**, gives the exact setting to add, links to the guide, and is **mapped to OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS and NIST AI RMF** ([full mapping](claude-code/audit/FRAMEWORK-MAPPING.md)). Reports go to `claude-code-audit-reports` in your home folder, never into the project. ([Report options](claude-code/audit/README.md#save-a-report-with-how-to-fix-steps))

When you're finished:

```bash
docker image rm claude-code-audit
```

## Why you can trust it

| | |
| --- | --- |
| **Small and known** | Official Alpine Linux 3.24.2 pinned by digest, plus only `bash` and `jq` from Alpine's official repository, pinned to exact versions. About 18 MB. |
| **Open** | Everything that runs is two short files: [`Dockerfile`](claude-code/audit/Dockerfile) and [`audit.sh`](claude-code/audit/audit.sh). You build it yourself from source. |
| **Offline** | Runs with `--network none`: it cannot send anything anywhere. |
| **Read-only** | Your files are mounted read-only and the container filesystem is read-only. It changes nothing. |
| **What it can read** | Your Claude Code settings, hooks and MCP server list, your shell startup files, and the whole project folder you run it from, including any secrets kept in that project. It doesn't mount `~/.ssh`, cloud credential folders, transcripts or the rest of your home folder, and it never prints the contents of `.env` or credential files. |
| **Unprivileged** | Runs as you, with every Linux capability dropped. |
| **Leaves nothing behind** | The container is removed on exit; one command removes the image. |
| **Verifiable releases** | The [GitHub Actions workflow](.github/workflows/audit-image.yml) builds release images with an SBOM, provenance and a signed attestation. No images are published yet; build it yourself from source until then. |

Full details, including exactly which files it reads: [claude-code/audit/README.md](claude-code/audit/README.md).

## What it checks

About 40 checks across the whole setup, including the attack patterns behind the Miasma worm, TrustFall, SymJack, Agentjacking and Plugin4Shell:

| Area | Examples |
| --- | --- |
| **Sandbox** | Enabled; strict mode; strict network allowlist; no exfiltration-prone domains; `~/.ssh` and `~/.aws` blocked; no Docker socket |
| **Permissions** | `.env` reads denied; `curl`/`wget` restricted; `git push` needs approval; no `Bash(*)` or other dangerous allow rules; no bypass mode; no widened directories |
| **Hooks** | Guards on Bash and on Edit/Write; installed hooks pass a 41-case test suite; no hook that downloads or runs remote code |
| **Repositories** | Hooks that run the moment a session starts (Miasma); MCP servers that launch on folder trust (TrustFall); symlinks disguised as ordinary files (SymJack); servers that read outsider-written content (Agentjacking); non-GitHub plugin marketplaces (Plugin4Shell); auto-enabled or unpinned MCP servers; a `CLAUDE.md` that tells the agent to fetch or install things; `.env` files not gitignored |
| **Hygiene** | Secrets in the settings `env` block; transcript retention; `--dangerously-skip-permissions` aliases; Claude Code version |

The exit code is `0` with no FAIL results and `1` otherwise, so it also works in scripts and CI.

## Fix what it finds: the guide

Each finding's `[step]` links to a section of the step-by-step hardening guide:

| Step | Covers |
| --- | --- |
| [1. Before you start](claude-code/01-before-you-start.md) | Version, account, OS user, sandbox dependencies |
| [2. Sandbox and permissions](claude-code/02-sandbox-and-permissions.md) | The baseline `settings.json`, explained setting by setting |
| [3. Hooks](claude-code/03-hooks.md) | Two `PreToolUse` hooks that block dangerous actions deterministically |
| [4. MCP servers, plugins and repositories](claude-code/04-mcp-plugins-and-repos.md) | Vetting extensions; inspecting a cloned repository before trusting it |
| [5. Working habits](claude-code/05-working-habits.md) | `CLAUDE.md` rules and the habits settings can't enforce |
| [6. Self-test](claude-code/06-self-test.md) | Proving the controls work in a live session |
| [7. Checklist](claude-code/07-checklist.md) | One-page summary |

**The attacks behind the checks:** [THREATS.md](claude-code/THREATS.md) summarises the real incidents and research (the Miasma worm, TrustFall, SymJack, GhostApproval, Plugin4Shell, Agentjacking and more), with a source for every claim.

Ready-to-copy files: [baseline settings](claude-code/config/settings.json), [hook registration](claude-code/config/hooks.json), [`CLAUDE.md` template](claude-code/config/CLAUDE.md.example), and the [hook scripts](claude-code/hooks/).

**Configuration vs. behaviour.** The audit reads configuration. To prove the controls actually block things in a live session, run the [self-test](claude-code/06-self-test.md) as well.

## Supported agents

| Agent | Audit container | Guide |
| --- | --- | --- |
| Claude Code | ✅ | ✅ |

More agents will be added one at a time.

## Repository layout

```
claude-code/
├── audit/               ← the audit container: start here
│   ├── Dockerfile
│   ├── audit.sh
│   ├── run.sh           ← macOS / Linux / WSL2
│   ├── run.ps1          ← Windows
│   ├── mappings.json    ← why each check matters + OWASP / ATLAS / NIST mapping
│   ├── FRAMEWORK-MAPPING.md  ← the mapping as a readable table (generated)
│   └── tests/           ← fixture-based tests for the audit
├── 01-before-you-start.md … 07-checklist.md   ← the guide
├── config/              ← baseline settings, hook registration, CLAUDE.md template
├── hooks/               ← protect-files.sh, validate-commands.sh
└── tests/
    └── test-hooks.sh    ← 41-case test suite for the hooks
.github/workflows/
└── audit-image.yml      ← open build: test every change, publish signed releases
scripts/
├── gen-mapping-doc.js   ← regenerates FRAMEWORK-MAPPING.md
└── prepublish-check.sh  ← maintainers: run before every push
```

## Disclaimer

This material is informational only. It is not legal advice and comes with no guarantee of a vulnerability-free system. The audit reads configuration and cannot detect every weakness. Coding agents change weekly: verify every setting against the vendor's current documentation and test every configuration in your own environment before relying on it.

AISecurityLabs.org is independent and is not affiliated with, sponsored by or endorsed by any vendor named here. Product names are trademarks of their respective owners, used only to identify the products discussed.

## License

- Guides and other documentation: [CC BY 4.0](LICENSE-docs.md)
- Scripts, container and configuration files: [MIT](LICENSE)

## Contributing

Corrections are welcome. Please open an issue with what you observed, the tool version and your operating system. For audit findings, include the check ID (for example `U09`) from `--json` output.

## Contact

For any questions, contact us at [info@aisecuritylabs.org](mailto:info@aisecuritylabs.org).
