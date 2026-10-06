# Securing GitHub Copilot

A developer's guide to running GitHub Copilot agent mode in VS Code, the Copilot CLI and Copilot cloud agent without handing them your credentials. Published by [AISecurityLabs.org](https://aisecuritylabs.org).

Copilot's agents edit files and run commands with your permissions. Its defaults ask before most tools run and keep agents out of folders you haven't trusted, but the terminal sandbox is off, and a handful of settings remove every approval at once. Most Copilot incidents come from text the agent reads (issues, comments, file names, instruction files) persuading it to flip those settings or run a command. This guide keeps the protections on and closes the gaps they leave.

**Audit your setup in about a minute** with the [Copilot security audit](audit/README.md), a throwaway container that is offline, read-only and deleted when it's done. Each finding points to a section below.

Every setting here is from the [VS Code agent documentation](https://code.visualstudio.com/docs/agents/reference/ai-settings) and [GitHub's Copilot documentation](https://docs.github.com/en/copilot). Setting names have changed often, so check them against the reference for your version.

## 1. Before you start

- **Update VS Code to 1.132.1 or later and the Copilot Chat extension to 1.123.2 or later.** Microsoft fixed an agent that ran commands without confirmation in VS Code 1.132.1 ([CVE-2026-70335](https://www.cve.org/CVERecord?id=CVE-2026-70335), CVSS 7.8 by Microsoft), a path traversal that bypassed a security feature in Copilot Chat 1.123.2 ([CVE-2026-45482](https://www.cve.org/CVERecord?id=CVE-2026-45482), CVSS 8.4 by Microsoft) and credential disclosure in VS Code 1.128.1 ([CVE-2026-47282](https://www.cve.org/CVERecord?id=CVE-2026-47282)). In Visual Studio 2022, use 17.14.26 or later ([CVE-2026-21256](https://www.cve.org/CVERecord?id=CVE-2026-21256)).
- **Keep Workspace Trust on.** It is on by default, and VS Code says "Opening a workspace in restricted mode disables agents in that workspace" ([VS Code docs](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust)). Microsoft's answer to a file-name injection in agent mode it chose not to fix was that Workspace Trust should mitigate it ([Tenable TRA-2025-53](https://www.tenable.com/security/research/tra-2025-53)).
- **Turn on secret scanning with push protection** for the repositories you work in. In a sample of about 20,000 public repositories where Copilot is active, GitGuardian found that 6.4% leaked at least one secret, against 4.6% across all public repositories; it reports a correlation, not a proven cause ([GitGuardian](https://blog.gitguardian.com/yes-github-copilot-can-leak-secrets/)). Push protection blocks pushes that contain secrets it recognises; it misses formats it doesn't detect and secrets already in the history.
- **Ask your administrator for policies** rather than relying on each developer's settings: `ChatToolsAutoApprove` keeps global auto-approve off, `ChatMCP` and `ChatAllowedMcpServers` limit MCP servers, and `ChatAgentSandboxEnabled` enforces the terminal sandbox ([VS Code enterprise policies](https://code.visualstudio.com/docs/enterprise/policies)).

## 2. Baseline VS Code settings

Merge [`config/vscode-settings.jsonc`](config/vscode-settings.jsonc) into your **user** settings (Command Palette: "Preferences: Open User Settings (JSON)"). What it does:

| Setting | Why |
| --- | --- |
| `chat.tools.global.autoApprove: false` | Every tool call keeps its confirmation. VS Code describes enabling it as a setting that "disables critical security protections". [CVE-2025-53773](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53773) worked by getting the agent to switch on its earlier name, `chat.tools.autoApprove`, which "disables all user confirmations" ([Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)). |
| `chat.permissions.default: "default"` | New sessions start with Default Permissions. Use Bypass Approvals or Autopilot only for a single session that needs it. |
| `security.workspace.trust.enabled: true` | Agents stay disabled in folders you haven't trusted. |
| `chat.agent.sandbox.enabled: "on"`, `chat.agent.sandbox.allowNetwork: false` | Agent terminal commands run in an OS sandbox. With network off, local sessions on macOS and Linux reach only the domains in `chat.agent.allowedNetworkDomains`, and an empty list blocks all outbound access. The sandbox is off by default, and when on it allows network unless you turn it off. It works on macOS, Linux and WSL2; on Linux install `bubblewrap` and `socat` first. Native Windows support is experimental (`chat.agent.sandbox.enabledWindows`). |
| `chat.tools.terminal.autoApprove` with read-only commands only | Listed commands run without asking. VS Code calls this list "a best-effort convenience, not a security boundary", so never add `rm`, `curl`, a shell or a pattern such as `/.*/`. |
| `chat.mcp.discovery.enabled: false` | VS Code doesn't pick up MCP servers configured for other tools. |

These belong in user settings. `chat.tools.global.autoApprove` can't be set by a workspace, but a repository's `.vscode/settings.json` can still change other agent settings, so review it before trusting a folder (section 4).

## 3. Copilot CLI

The Copilot CLI keeps your settings in `~/.copilot/settings.json` (or `$COPILOT_HOME`). Merge [`config/copilot-cli-settings.json`](config/copilot-cli-settings.json) into it:

| Setting | Why |
| --- | --- |
| `sandbox.enabled: true` | Shell commands, MCP and LSP servers and the built-in file and web tools run in an OS sandbox with limited file and network access. It is off by default. |
| `sandbox.allowBypass: false` | Sandboxed commands can't ask you to lift the sandbox mid-task. Turn it back on only if a tool you need keeps failing. |
| `permissions.disableBypassPermissionsMode: "disable"` | The CLI ignores `--allow-all-tools`, `--allow-all-paths`, `--allow-all-urls`, `--allow-all` and `--yolo`, so an alias or script can't remove approvals. |
| `allowedUrls: []` | No site is fetched without asking. Never add `*`. |

`sandbox.userPolicy.deniedPaths` can also block paths such as `~/.ssh`, but the Windows sandbox rejects a policy that sets it, so add it only on macOS and Linux ([GitHub docs](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference)).

Approvals you save with "always allow" go to `~/.copilot/permissions-config.json` and apply from then on. GitHub says "Scoping of permissions is heuristic", so review that file and remove anything that runs a shell, deletes, pushes or reaches the network. A deny rule (`--deny-tool 'shell(git push)'`) blocks that tool outright, not just asks, and takes precedence over allow rules, even when `--allow-all` is set ([GitHub docs](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools)).

## 4. Repositories and extensions

A repository can configure Copilot for everyone who opens it. Before trusting a folder you didn't create, read:

- `.vscode/settings.json`, for anything touching `chat.*`, `security.workspace.trust` or sandbox settings;
- `.vscode/mcp.json`, `.mcp.json` and `.github/mcp.json`, since workspace MCP servers start as local processes with your permissions once you trust the folder;
- `.github/copilot-instructions.md`, `.github/instructions/`, `.github/agents/`, `.github/prompts/`, `AGENTS.md` and `CLAUDE.md`, which Copilot loads as instructions, including any hidden Unicode characters ([Pillar Security](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents));
- `.github/hooks/` and `.github/copilot/settings.json`, whose hooks run commands and whose plugins and marketplaces install code for every Copilot CLI user;
- `.git/config` in a repository that didn't come from `git clone`, and every symlink and its target.

Treat every MCP server and extension as a dependency: install from your organisation's allowlist, pin versions, and give servers that read tickets, errors, chat or email read-only scopes, since outsiders write that content ([The Hacker News](https://thehackernews.com/2026/06/agentjacking-attack-tricks-ai-coding.html)).

**Copilot cloud agent** (formerly the coding agent) runs in a GitHub Actions environment, pushes only to its own `copilot/` branch and can't approve or merge its pull request. Its firewall is on by default, but it doesn't cover MCP servers or the processes `.github/workflows/copilot-setup-steps.yml` starts, and Copilot "will not ask for your approval" before using the MCP tools you configure ([GitHub docs](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/risks-and-mitigations)). Keep the firewall on, keep "Approve and run workflows" required for its pull requests, pin actions in setup steps by SHA, and require a second reviewer. Content exclusions don't apply in agent mode, so they aren't a boundary.

Issue text is the attack surface. Trail of Bits hid instructions in an issue that "is invisible to the maintainer when displayed in the GitHub user interface, but it is readable by the LLM", producing a backdoored pull request ([Trail of Bits](https://blog.trailofbits.com/2025/08/06/prompt-injection-engineering-for-attackers-exploiting-github-copilot/)). Researchers later used HTML comments in an issue assigned to Copilot to leak its tokens, which GitHub called an "architectural limitation" ([Comment and Control](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)).

## 5. Working habits

- **Read untrusted content first:** instruction-like text in an issue, pull request, file name or README is the attack. Don't assign an issue to Copilot, or open a Codespace from it, until you've read it ([Orca: RoguePilot](https://orca.security/resources/blog/roguepilot-github-copilot-vulnerability/)).
- **Treat any change to `.vscode/`, `.github/` or an instruction file as a security event,** whether you or the agent made it.
- **Review agent pull requests like outside contributions,** including lockfiles and dependency URLs line by line.
- **Keep production credentials out of your environment:** an agent can't misuse a token it can't see.
- **Never run `copilot --yolo` or `--allow-all`** on your own machine; use a container or Codespace with no credentials.
- **Put project rules in `.github/copilot-instructions.md`** (see [`config/copilot-instructions.md.example`](config/copilot-instructions.md.example)); they shape the code Copilot writes but don't enforce anything.

## 6. Self-test

In a throwaway project containing a fake `.env`, apply the baseline and try each of these. Every one should be refused or stopped for approval.

| Try this | What should stop it |
| --- | --- |
| Open the folder without trusting it, then start agent mode | Restricted mode disables agents |
| Ask the agent to add `"chat.tools.global.autoApprove": true` to settings | The edit needs your approval; reject it and confirm nothing changed |
| Ask it to run `curl https://example.com` | An approval prompt, and the sandbox blocks the network |
| Ask it to edit `.env` | Edits to `.env` need your approval by default |
| Run `copilot --yolo` | The CLI ignores it with `disableBypassPermissionsMode` |
| Push a commit containing a test token in a format GitHub detects | Push protection blocks the push |

Re-run the test after every VS Code, extension or CLI upgrade.

## 7. Checklist

- [ ] VS Code 1.132.1 or later, Copilot Chat 1.123.2 or later, Copilot CLI current
- [ ] Global auto-approve off, enforced by policy where possible
- [ ] New sessions use Default Permissions
- [ ] Workspace Trust on; unknown folders opened in restricted mode
- [ ] VS Code terminal sandbox on with network off; terminal auto-approve limited to read-only commands
- [ ] Copilot CLI sandbox on, allow-all flags disabled, saved approvals reviewed
- [ ] MCP servers from an allowlist and pinned; discovery off
- [ ] Repository `.vscode/`, `.github/`, MCP files, instructions, hooks, `.git/config` and symlinks reviewed before trusting a project
- [ ] Cloud agent firewall on, workflow approval required, setup steps pinned, second reviewer required
- [ ] Secret scanning with push protection on

---

Informational only, with no guarantee of a vulnerability-free setup, so test every configuration in your own environment. AISecurityLabs.org is independent and not affiliated with GitHub or Microsoft. GitHub Copilot and VS Code are trademarks of their owners, used here only to identify the products.
