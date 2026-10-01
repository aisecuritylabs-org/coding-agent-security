# Securing OpenAI Codex

A developer's guide to running OpenAI Codex (CLI, IDE extension and desktop app) without handing it your credentials. Published by [AISecurityLabs.org](https://aisecuritylabs.org).

Codex ships with good defaults: an operating-system sandbox, command network access off, and cached web search. Most Codex incidents come from turning those defaults off, trusting a repository that carries configuration, or leaving secrets readable. This guide keeps the defaults working for you and closes the gaps they leave.

**Audit your setup in about a minute** with the [Codex security audit](audit/README.md), a throwaway container that is offline, read-only and deleted when it's done. Each finding points to a section below.

Every setting here is from OpenAI's [Codex documentation](https://learn.chatgpt.com/docs/config-file/config-reference). Setting names change as Codex evolves, so check them against the reference for your version.

## 1. Before you start

- **Update Codex, the desktop app and the IDE extension.** Fixed vulnerabilities include project config that ran on open ([CVE-2025-61260](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/)), a sandbox writable-root bypass ([CVE-2025-59532](https://github.com/openai/codex/security/advisories/GHSA-w5fx-fh39-j5rw), fixed in 0.39.0) and a PowerShell parsing bug that skipped approval ([CVE-2026-19591](https://nvd.nist.gov/vuln/detail/CVE-2026-19591), fixed in CLI 0.131.0), and [Plugin4Shell](https://www.air.security/blog-posts/plugin4shell), where a pinned plugin could be swapped on background auto-update (fixed in 0.146.0). Use 0.146.0 or later. Codex has no setting that enforces a minimum version, so updating is on you.
- **Sign in with ChatGPT for work,** so usage falls under your workspace's policies. Organisations can pin this with `forced_login_method = "chatgpt"` and `forced_chatgpt_workspace_id`.
- **Consider Advanced Account Security** if you're eligible: it requires passkeys or security keys and disables email and SMS recovery, and it protects Codex as well as ChatGPT. Keep a backup key, because OpenAI Support can't recover enrolled accounts ([OpenAI](https://openai.com/index/advanced-account-security/)).
- **On Windows,** use the native Windows sandbox (`[windows] sandbox = "elevated"` is the preferred mode), set `web_search = "disabled"`, and ask your administrator to lock `C:\ProgramData\OpenAI\Codex` with [`config/lock-programdata.ps1`](config/lock-programdata.ps1), run as administrator. Cymulate reported two unresolved Windows issues: [web content plus a PATH hijack reaching code execution](https://cymulate.com/blog/codex-cli-rce-prompt-injection-mitigations/), and a [ProgramData folder any local user could create](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/).
- **Remove `approval_policy = "untrusted"`** from every config and script. It was retired in Codex 0.149.0 ([PR #39630](https://github.com/openai/codex/pull/39630)) and an explicit setting can stop Codex from starting.

## 2. Baseline config.toml

Copy [`config/config.toml`](config/config.toml) to `~/.codex/config.toml` and adapt it. What it does:

| Setting | Why |
| --- | --- |
| `approval_policy = "on-request"` | Codex asks before anything leaves the sandbox. `never` removes every approval. |
| `default_permissions = "dev"` with `extends = ":workspace"` | A permission profile: edit the workspace, no command network. It's the only way to deny reads from your own config, because the sandbox limits writes, not reads. Don't also set the older `sandbox_mode` keys, or Codex uses them instead. |
| `"~/.ssh" = "deny"`, `"**/.env*" = "deny"` and the other deny entries | Keeps credentials and `.env` files unreadable to commands Codex runs. |
| `web_search = "cached"` | Results come from an OpenAI-maintained index rather than live pages. Use `"disabled"` on native Windows and regulated repositories. |
| `cli_auth_credentials_store = "keyring"` | Keeps Codex and MCP credentials in the OS keyring, not a file. |
| `allow_login_shell = false` | Commands don't load `~/.bashrc` or `~/.zprofile` and the secrets they often export. |
| `[features] network_proxy = true` | When a profile turns network on, only the listed domains are reachable. Without the proxy, `network.enabled = true` means open egress. |
| `skill_mcp_dependency_install = false` | Skills can't install and start MCP servers you haven't reviewed. |
| `disable_on_external_context = true` | Web and MCP content can't become lasting memories. |

Two network switches exist and you need both: `web_search` controls the search tool, while the permission profile's network setting controls commands. The network proxy doesn't filter web search, MCP servers, connectors or browser traffic ([Codex docs](https://learn.chatgpt.com/docs/agent-approvals-security)).

## 3. Command rules and hooks

**Rules** match the start of a command: `prompt` asks you before it runs, `forbidden` refuses it, and `allow` lets it run outside the sandbox without asking. The strictest matching rule wins, and a rule with no decision is an allow rule. Copy [`config/default.rules`](config/default.rules) to `~/.codex/rules/default.rules`, restart Codex, and test it:

```bash
codex execpolicy check --pretty --rules ~/.codex/rules/default.rules -- git push origin main
```

**Hooks** run your own commands on agent events. A `PreToolUse` hook matching `Bash` can block a command by exiting with code 2. Codex runs a non-managed hook only after you review and trust its exact definition with `/hooks`, and it asks again whenever the hook changes. Never use `--dangerously-bypass-hook-trust` outside a disposable environment ([Codex docs](https://learn.chatgpt.com/docs/hooks)).

## 4. Repositories and extensions

Codex loads a project's `.codex/` folder (config, hooks and rules) only after you trust the project, and then applies it to every session there. Before trusting a repository you didn't create:

- Read `.codex/config.toml`, `.codex/hooks.json`, `.codex/rules/` and `AGENTS.md`. Stop at any MCP server, hook or allow rule you didn't write, and at anything that lowers the sandbox or approvals.
- Check the project `.env` for `CODEX_*` variables; CVE-2025-61260 used one to point Codex at attacker configuration.
- Treat a repository that arrives with its own `.git/config` (an archive, a shared folder) with suspicion: `core.hooksPath`, `core.fsmonitor` and filter drivers run programs during ordinary git commands (CVE-2026-19590, -19592, -19593). A normal `git clone` never copies `.git/config`.
- List every symlink and its target: a harmless name pointing at `.codex/`, `AGENTS.md` or a dotfile is an attack.
- Open code you don't trust in a container or Codex cloud, never on a machine that holds your credentials.

Treat every MCP server, plugin and skill as a dependency: install from your organisation's allowlist, pin versions, and give servers that read tickets, errors, chat or email read-only scopes, since outsiders write that content.

## 5. Working habits

- **Read untrusted content first:** instruction-like text in an issue, pull request or web page is the attack.
- **Keep production credentials out of your environment:** an agent can't misuse a token it can't see.
- **Never run `--yolo` or full access on your own machine,** and never across a home directory. In [openai/codex#42875](https://github.com/openai/codex/issues/42875) a developer reported about 221 GB deleted from their home directory while auto-approved Codex sessions were running; the cause is unconfirmed.
- **Use one workspace per session,** and git worktrees for parallel or background work.
- **Put project rules in `AGENTS.md`** (see [`config/AGENTS.md.example`](config/AGENTS.md.example)); they shape the code Codex writes but don't enforce anything.
- **Treat auto-review as help, not a boundary:** OpenAI says it "can still make mistakes", and [PromptArmor](https://www.promptarmor.com/resources/agentic-auto-review-approves-malware) got it to approve a malicious npm install.

## 6. Self-test

In a throwaway project containing a fake `.env`, start Codex with the baseline and ask for each of these. Every one should be refused or stopped for approval.

| Ask Codex to... | What should stop it |
| --- | --- |
| "Print the .env file" | The permission profile's `.env` deny rule |
| "Show me ~/.ssh/config" | The profile's `~/.ssh` deny rule |
| "Download https://example.com/x with curl" | Command network is off; the `curl` rule asks first |
| "Delete the build folder recursively" | The `rm` rule forbids it |
| "Push this branch" | The `git push` rule asks first |
| "Search the web for X" | Cached results only (or none, where disabled) |

Then run `codex execpolicy check` on a few commands, and `/hooks` to confirm only the hooks you expect are trusted. Re-run the test after every Codex upgrade.

## 7. Checklist

- [ ] Codex, the desktop app and the IDE extension are current
- [ ] Work runs under a ChatGPT work sign-in, with credentials in the OS keyring
- [ ] A permission profile is the default, with no full access and no `--yolo` alias
- [ ] `approval_policy = "on-request"`, never `untrusted` or `never`
- [ ] Command network off by default; the proxy allow list when a task needs it
- [ ] `web_search` cached, or disabled on Windows and regulated repositories
- [ ] `.env` files and credential folders denied in the profile
- [ ] `~/.codex/rules/default.rules` in place and tested
- [ ] Repository `.codex/`, `AGENTS.md`, `.env`, `.git/config` and symlinks reviewed before trusting a project
- [ ] MCP servers, plugins and skills from an allowlist and pinned
- [ ] On Windows: native sandbox, web search disabled, ProgramData folder locked

---

Informational only, with no guarantee of a vulnerability-free setup, so test every configuration in your own environment. AISecurityLabs.org is independent and not affiliated with OpenAI. Codex is a trademark of its owner, used here only to identify the product.
