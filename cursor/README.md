# Securing Cursor

A developer's guide to running the Cursor agent, in the editor and the Cursor CLI, without handing it your credentials. Published by [AISecurityLabs.org](https://aisecuritylabs.org).

Cursor's agent edits files and runs commands with your permissions. Its default run mode, Auto-review, sandboxes shell commands where it can and sends the rest to a classifier, but Workspace Trust is off by default, a repository's `.cursor/` folder adds to your configuration, and allowlisted commands run outside the sandbox. Most Cursor incidents come from a repository or injected text getting the agent to write configuration that then runs commands. This guide keeps the protections on and closes the gaps they leave.

**Audit your setup in about a minute** with the [Cursor security audit](audit/README.md), a throwaway container that is offline, read-only and deleted when it's done. Each finding points to a section below.

Every setting here is from [Cursor's documentation](https://cursor.com/docs/agent/security). Settings change as Cursor evolves, so check them against the docs for your version.

## 1. Before you start

- **Update Cursor to 3.1.2 or later.** Cursor publishes its fixes as [security advisories](https://github.com/cursor/cursor/security/advisories). Recent ones fixed a sandbox escape through a tampered Python virtual environment ([CVE-2026-73217](https://github.com/cursor/cursor/security/advisories/GHSA-p9g2-cr55-cw9c), fixed in 3.1.2), two sandbox escapes Cato Networks called DuneSlide ([CVE-2026-50548 and CVE-2026-50549](https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities), fixed in 3.0) and an agent write to unprotected git settings, including hooks ([CVE-2026-26268](https://novee.security/blog/cursor-ide-cve-2026-26268-git-hook-arbitrary-code-execution/), fixed in 2.5). A macOS escape through privileged Docker containers had no fix when it was published ([GHSA-v4xv-rqh3-w9mc](https://github.com/cursor/cursor/security/advisories/GHSA-v4xv-rqh3-w9mc)), so don't give the agent a Docker socket on macOS.
- **Turn on Workspace Trust.** Cursor supports it but ships with it "disabled by default" ([Cursor docs](https://cursor.com/docs/agent/security)). Without it, every folder you open is trusted, and project hooks only need a trusted workspace to run. Add [`config/settings.jsonc`](config/settings.jsonc) to your user settings.
- **Use your organisation's Teams or Enterprise account,** so its run mode, sandbox, MCP and model policies apply.
- **On Windows,** ask your administrator to lock `C:\ProgramData\Cursor` with [`config/lock-programdata.ps1`](config/lock-programdata.ps1), run as administrator. Cursor loads machine-wide hooks from `hooks.json` there, and Cymulate showed a standard user creating the folder and planting hooks that run for every user; it was unresolved at publication ([Cymulate](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/)).

## 2. Sandbox and run mode

Choose the run mode in **Settings > Agents > Approvals & Execution** ([Cursor docs](https://cursor.com/docs/agent/security/run-modes)):

| Mode | What runs without asking |
| --- | --- |
| **Auto-review** (default) | Allowlisted calls, then shell commands in the sandbox where possible, with a classifier reviewing the rest. Cursor says Auto-review "is not a security boundary". |
| **Allowlist** | Only allowlisted calls. Turn on its sandbox option. |
| **Run Everything** | Every tool call, with no sandbox. Never use it on a machine with credentials. |

The sandbox uses Seatbelt on macOS and Landlock with seccomp on Linux (kernel 6.2 or later). On Windows it works only through WSL2, and on a Linux kernel that can't run it Cursor falls back to asking for approval. Copy [`config/sandbox.json`](config/sandbox.json) to `~/.cursor/sandbox.json`:

| Setting | Why |
| --- | --- |
| `type: "workspace_readwrite"` | Commands can read and write the workspace only. Never use `"insecure_none"`, which turns the sandbox off. |
| `networkPolicy.default: "deny"` with a short `allow` list | Sandboxed commands reach only the registries you list. Choose **sandbox.json Only** as the network mode so Cursor's default domains aren't added. |

The sandbox keeps `.cursor/*.json`, `.vscode/`, `.git/hooks/` and `.git/config` write-protected, but "SSL certificate paths and `~/.ssh` are always readable" ([Cursor docs](https://cursor.com/docs/reference/sandbox)), so keep keys you don't need off the machine.

## 3. Allowlists, hooks and the CLI

**Allowlists** in `~/.cursor/permissions.json` let commands and MCP tools run without asking, outside the sandbox. Cursor says they "are not a security guarantee". Copy [`config/permissions.json`](config/permissions.json): it allowlists only read-only commands, no MCP tools, and gives Auto-review `block_instructions` for credentials, deletes, pushes and outbound data ([Cursor docs](https://cursor.com/docs/reference/permissions)).

**Hooks** in `~/.cursor/hooks.json` run your commands on agent events, and a `beforeShellExecution`, `beforeMCPExecution` or `beforeReadFile` hook can block an action by exiting with code 2. Hooks fail open by default, so set `"failClosed": true` on every hook you rely on for security ([Cursor docs](https://cursor.com/docs/hooks)).

**The Cursor CLI** (`agent`) has its own permissions in `~/.cursor/cli-config.json`, where deny rules take precedence over allow rules. Merge [`config/cli-config.json`](config/cli-config.json) into it: approvals in allowlist mode, and reads and writes of `.env` files and credential folders denied ([Cursor docs](https://cursor.com/docs/cli/reference/permissions)). Never alias `agent` with `--yolo`, `--force`, `--sandbox disabled` or `--approve-mcps`.

## 4. Repositories and extensions

A repository's `.cursor/` folder adds to your configuration. Its `sandbox.json` takes priority over yours, its `permissions.json` is concatenated with yours, and its hooks and MCP servers run once the folder is trusted. Before opening a repository you didn't create:

- Read `.cursor/sandbox.json`, `permissions.json`, `mcp.json`, `hooks.json`, `cli.json`, `environment.json` and `worktrees.json`. Stop at anything that widens the sandbox, allowlists commands, or starts a server or command you didn't write.
- Read `.cursor/rules/`, `.cursorrules`, `AGENTS.md` and `CLAUDE.md`, which Cursor loads as instructions, and check them for hidden Unicode ([Pillar Security](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)).
- Treat `.git/config` in a repository that didn't come from `git clone`, and every symlink, as suspect.
- Remember that `.cursorignore` is "not a security boundary": the agent's terminal and MCP tools can still read ignored files ([Cursor docs](https://cursor.com/help/customization/ignore-files)).

**MCP servers** are third-party code. Prompt injection has written `.cursor/mcp.json` to run commands ([CurXecute, CVE-2025-54135](https://www.catonetworks.com/blog/curxecute-rce/)), and Check Point found that "Once an MCP is approved, future modifications to its command or arguments are trusted without any additional validation or prompt" ([MCPoison, CVE-2025-54136](https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/)); both are fixed. Install servers from your organisation's allowlist, pin versions, pass secrets as `${env:NAME}`, and give servers that read tickets, errors, chat or email read-only scopes ([The Hacker News](https://thehackernews.com/2026/06/agentjacking-attack-tricks-ai-coding.html)).

**Extensions** come from Open VSX. A fake "Solidity Language" extension there cost one developer about $500,000 ([Kaspersky](https://securelist.com/open-source-package-for-cursor-ai-turned-into-a-crypto-heist/116908/)). Install only extensions your organisation allows, from publishers you can verify.

## 5. Working habits

- **Read untrusted content first:** instruction-like text in an issue, pull request, web page or MCP result is the attack.
- **Keep production credentials out of your environment:** an agent can't misuse a token it can't see. Keep `.env` files gitignored.
- **Treat any change to `.cursor/`, rules files or `.git/` as a security event,** whether you or the agent made it.
- **Review agent changes like outside contributions,** including lockfiles and dependency URLs.
- **Put project rules in `.cursor/rules/`** (see [`config/security.mdc.example`](config/security.mdc.example)); they shape the code Cursor writes but don't enforce anything.

## 6. Self-test

In a throwaway project containing a fake `.env`, apply the baseline and try each of these. Every one should be refused or stopped for approval.

| Ask the agent to... | What should stop it |
| --- | --- |
| Open the folder without trusting it, then start the agent | Restricted mode turns AI features off |
| "Run curl https://example.com" | The sandbox's network policy blocks it; a rerun outside the sandbox is reviewed first |
| "Write a file in my home folder" | The sandbox limits writes to the workspace; anything outside is reviewed first |
| "Add a new server to .cursor/mcp.json" | `.cursor/*.json` is write-protected in the sandbox |
| Run `agent -p "cat .env"` in the CLI | The CLI's `Read(**/.env*)` deny rule |

Re-run the test after every Cursor upgrade.

## 7. Checklist

- [ ] Cursor 3.1.2 or later
- [ ] Workspace Trust on; unknown folders opened in restricted mode
- [ ] Auto-review or Allowlist with the sandbox, never Run Everything
- [ ] `~/.cursor/sandbox.json` with network denied by default and a short allow list
- [ ] Terminal allowlist limited to read-only commands; no `*:*` MCP entries
- [ ] Security hooks set to `failClosed`
- [ ] Cursor CLI in allowlist mode with `.env` reads denied, and no `--yolo` alias
- [ ] Repository `.cursor/`, rules files, `.git/config` and symlinks reviewed before trusting a project
- [ ] MCP servers and extensions from an allowlist and pinned; secrets passed as `${env:NAME}`
- [ ] On Windows: `C:\ProgramData\Cursor` locked to administrators
- [ ] No production credentials on the machine

---

Informational only, with no guarantee of a vulnerability-free setup, so test every configuration in your own environment. AISecurityLabs.org is independent and not affiliated with Anysphere. Cursor is a trademark of its owner, used here only to identify the product.
