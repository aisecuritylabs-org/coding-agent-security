# Securing Gemini CLI and Gemini Code Assist

A developer's guide to running Gemini CLI and Gemini Code Assist agent mode without handing them your credentials. Published by [AISecurityLabs.org](https://aisecuritylabs.org).

Gemini CLI runs commands and edits files with your permissions, and Gemini Code Assist agent mode in VS Code and JetBrains uses the same engine and reads the same `~/.gemini/settings.json`. It asks before tools run and keeps untrusted folders from configuring it, but sandboxing is off by default, and a trusted folder's settings, `.env` file and MCP servers load without further questions. Most Gemini incidents come from text the agent reads, in a repository or an issue, getting it to run a command. This guide keeps the protections on and closes the gaps they leave.

**Audit your setup in about a minute** with the [Gemini security audit](audit/README.md), a throwaway container that is offline, read-only and deleted when it's done. Each finding points to a section below.

**Which users this applies to.** On June 18, 2026 Gemini CLI and the Code Assist IDE extensions stopped serving Google AI Pro, Ultra and free individual users, who moved to Antigravity CLI. For Gemini Code Assist Standard and Enterprise, "your access remains unchanged", and Google continues to support Gemini CLI ([Google](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/)). This guide is for those organisations.

Every setting here is from the [Gemini CLI documentation](https://geminicli.com/docs/reference/configuration). Settings change as Gemini CLI evolves, so check them against the reference for your version.

## 1. Before you start

- **Update Gemini CLI to 0.39.1 or later,** and `google-github-actions/run-gemini-cli` to 0.1.22 or later. Earlier versions running headless in CI "automatically trusted workspace folders for the purpose of loading configuration and environment variables", and under `--yolo` ignored tool allowlists ([CVE-2026-12537](https://github.com/advisories/GHSA-wpqr-6v78-jr5g), CVSS 3.1 10.0 by Google, 7.8 by NVD).
- **Keep folder trust on.** It is on by default. In an untrusted folder, Gemini CLI ignores the project's `.gemini/settings.json`, loads only four authentication variables from its `.env`, and starts no MCP servers ([Gemini CLI docs](https://geminicli.com/docs/cli/trusted-folders)).
- **On Windows,** ask your administrator to lock `C:\ProgramData\gemini-cli` with [`config/lock-programdata.ps1`](config/lock-programdata.ps1), run as administrator. Gemini CLI loads machine-wide `settings.json` and `system-defaults.json` from there, and Cymulate showed a standard user creating the folder and planting a session-start hook that runs for every user; Google said it would be "addressed as a documentation update" ([Cymulate](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/)).
- **Use your organisation's Code Assist Standard or Enterprise licence,** so its admin controls apply. Admin controls "cannot be overridden by users locally".

## 2. Baseline settings

Copy [`config/settings.json`](config/settings.json) to `~/.gemini/settings.json` and adapt it. Code Assist agent mode reads the same file. What it does:

| Setting | Why |
| --- | --- |
| `tools.sandbox: true` | Runs tools in a sandbox: Seatbelt on macOS, or Docker or Podman. "Sandboxing is disabled by default" ([Gemini CLI docs](https://geminicli.com/docs/cli/sandbox)). On macOS the default Seatbelt profile, `permissive-open`, confines writes but allows broad reads and network access, so set `SEATBELT_PROFILE` to a `strict-` profile, or use `"docker"`. `security.toolSandboxing: true` sandboxes individual tools instead. |
| `tools.sandboxNetworkAccess: false` | Keeps the sandbox from being given network access. This is the default; keep it. |
| `tools.allowed` with read-only commands only | Listed tools "bypass the confirmation dialog". Never list the bare `run_shell_command` or a shell, interpreter, delete or network tool. |
| `general.defaultApprovalMode: "default"` | Every edit and command asks first. `auto_edit` approves all edits. |
| `security.folderTrust.enabled: true` | Untrusted folders can't configure the agent. |
| `security.disableYoloMode: true` | `--yolo` is ignored, so an alias or script can't remove every confirmation. |
| `security.enablePermanentToolApproval: false` | Approvals don't carry into future sessions. |

For **Gemini Code Assist** in VS Code, also merge [`config/vscode-settings.jsonc`](config/vscode-settings.jsonc): it keeps `geminicodeassist.agentYoloMode` off, so agent mode asks before it acts ([Google](https://developers.google.com/gemini-code-assist/docs/use-agentic-chat-pair-programmer)).

## 3. Policies and hooks

**Policies** are TOML rules in `~/.gemini/policies/` that allow, deny or ask about tool calls, and the highest-priority matching rule wins ([Gemini CLI docs](https://geminicli.com/docs/reference/policy-engine)). Copy [`config/policies/baseline.toml`](config/policies/baseline.toml): it denies recursive deletes and `sudo`, and asks before pushes, publishing and network commands. Never write an `allow` rule for `run_shell_command` without a narrow `commandPrefix`. Project-level policies aren't enforced yet, so keep yours in your home folder.

Shell commands chained with `&&`, `||` or `;` are split and each part is checked against your rules. Tracebit showed why this matters: before 0.1.14, an allowed `grep` followed by a second command silently sent the user's environment variables to an attacker ([Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)).

**Hooks** in `settings.json` run your commands on agent events such as `BeforeTool` and `SessionStart` ([Gemini CLI docs](https://geminicli.com/docs/hooks)). Read every hook before you keep it, including ones that extensions add, and never run one that downloads code.

## 4. Repositories and extensions

Trusting a folder lets its `.gemini/settings.json` override yours, its `.env` set Gemini CLI variables, and its MCP servers and hooks start. Before trusting a repository you didn't create:

- Read `.gemini/settings.json` and stop at anything that turns the sandbox off, allows tools, adds hooks or marks an MCP server `"trust": true`, which "bypass[es] all tool call confirmations" ([Gemini CLI docs](https://geminicli.com/docs/tools/mcp-server)).
- Check the project `.env` for `GEMINI_*` variables: a trusted folder's `.env` can set `GEMINI_SANDBOX=false`.
- Read `GEMINI.md` and `AGENTS.md`, which Gemini loads as instructions, and check them for hidden Unicode. Tracebit hid its instructions in a file presented as a licence.
- Treat `.git/config` in a repository that didn't come from `git clone`, and every symlink, as suspect.

**MCP servers** are third-party code: install from your organisation's allowlist, pin versions, never set `"trust": true`, and give servers that read tickets, errors, chat or email read-only scopes ([The Hacker News](https://thehackernews.com/2026/06/agentjacking-attack-tricks-ai-coding.html)).

**Extensions** bundle MCP servers, hooks, context files and policies. AIR Security showed a Gemini CLI extension pinned to a commit being swapped for different code and reported no fix ([Plugin4Shell](https://www.air.security/blog-posts/plugin4shell)). Set `security.blockGitExtensions: true` or list approved extensions in `security.allowedExtensions`.

**GitHub Actions.** Researchers used text in issues to make the Gemini CLI Action leak its API key through a public comment ([Comment and Control](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)). Pin `run-gemini-cli` by SHA at 0.1.22 or later, never run it with `--yolo` on issues or pull requests from outsiders, and give it only the permissions and secrets it needs.

## 5. Working habits

- **Read untrusted content first:** instruction-like text in an issue, pull request, README or web page is the attack.
- **Keep production credentials out of your environment:** an agent can't misuse a token it can't see. Keep `.env` files gitignored.
- **Never run `gemini --yolo` on your own machine,** and never set `GEMINI_SANDBOX=false` or `GEMINI_CLI_TRUST_WORKSPACE=true` in your shell profile.
- **Treat changes to `.gemini/`, `GEMINI.md` and workflows as security events,** whether you or the agent made them.
- **Put project rules in `GEMINI.md`** (see [`config/GEMINI.md.example`](config/GEMINI.md.example)); they shape the code Gemini writes but don't enforce anything.

## 6. Self-test

In a throwaway project containing a fake `.env`, apply the baseline and try each of these. Every one should be refused or stopped for approval.

| Try this | What should stop it |
| --- | --- |
| Open the folder without trusting it | Gemini CLI asks you to trust it and ignores its settings until you do |
| Ask Gemini to "run rm -rf build" | The `rm -rf` policy rule denies it |
| Ask it to "push this branch" | The `git push` rule asks first |
| Ask it to "download https://example.com with curl" | The `curl` rule asks first |
| Run `gemini --yolo` | `disableYoloMode` ignores it |

Re-run the test after every Gemini CLI upgrade.

## 7. Checklist

- [ ] Gemini CLI 0.39.1 or later; `run-gemini-cli` 0.1.22 or later, pinned by SHA
- [ ] Folder trust on; sandboxing on, with a strict Seatbelt profile or a container on macOS
- [ ] `tools.allowed` limited to read-only commands; `auto_edit` not the default
- [ ] YOLO mode disabled; `geminicodeassist.agentYoloMode` off
- [ ] Policy rules deny destructive commands and ask before pushes and network commands
- [ ] No MCP server with `"trust": true`; servers from an allowlist and pinned
- [ ] Extensions restricted and reviewed
- [ ] Repository `.gemini/`, `.env`, `GEMINI.md`, `.git/config` and symlinks reviewed before trusting a project
- [ ] On Windows: `C:\ProgramData\gemini-cli` locked to administrators
- [ ] No production credentials on the machine

---

Informational only, with no guarantee of a vulnerability-free setup, so test every configuration in your own environment. AISecurityLabs.org is independent and not affiliated with Google. Gemini is a trademark of its owner, used here only to identify the product.
