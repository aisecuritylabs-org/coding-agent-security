# Securing Claude Code, step by step

Claude Code runs in your terminal with your permissions. Left unconfigured, it can read any file your user account can read (including `~/.ssh`, `~/.aws` and every `.env` on disk), run any shell command, reach the network, and load MCP servers and plugins that bring their own code. Everything it reads — READMEs, issues, web pages, tool output — can carry instructions aimed at the model.

This guide makes the harmful outcomes impossible rather than merely unlikely.

## Start with the audit

Before changing anything, see where you stand. The [audit container](audit/README.md) checks your current setup against this guide in about a minute — offline, read-only, and deleted when it exits:

```bash
cd ~/code/my-app                                     # your project folder
bash ~/coding-agent-security/claude-code/audit/run.sh
```

On Windows, see the [audit README](audit/README.md#run-it) for the Command Prompt / PowerShell command.

Each finding shows a step number in brackets, like `[2]`. Work through those steps below, then run the audit again until it reports no FAIL results.

## The steps

| Step | What you'll do | Time |
| --- | --- | --- |
| [1. Before you start](01-before-you-start.md) | Update, check your account and OS user, install sandbox dependencies | 10 min |
| [2. Sandbox and permissions](02-sandbox-and-permissions.md) | Install the baseline `settings.json` and turn on the sandbox in strict mode | 15 min |
| [3. Hooks](03-hooks.md) | Add two `PreToolUse` hooks that deterministically block dangerous actions | 15 min |
| [4. MCP servers, plugins and repositories](04-mcp-plugins-and-repos.md) | Vet extensions and inspect cloned repositories before trusting them | 10 min |
| [5. Working habits](05-working-habits.md) | Add project rules in `CLAUDE.md` and adopt the habits settings can't enforce | 10 min |
| [6. Self-test](06-self-test.md) | Prove every layer blocks what it should | 10 min |
| [7. Checklist](07-checklist.md) | One-page summary to re-check after every upgrade | 5 min |

**Why these steps?** [THREATS.md](THREATS.md) summarises the real attacks they defend against, with sources.

## The three principles behind every step

1. **Least agency.** Grant the fewest tools, paths, hosts and credentials that finish the job. Autonomy is earned through isolation, not trust.
2. **Defense in depth.** Permission rules, the sandbox, hooks, secret hygiene and code review each fail sometimes. Stack them.
3. **Everything is untrusted input.** Files, web pages, issues, PR comments, MCP tool output and plugin content can all carry prompt injection. Design as if they will.

## The four layers you will build

| Layer | Enforced by | Strength |
| --- | --- | --- |
| Sandbox (filesystem + network isolation) | The operating system, on the running process | Strongest — holds even when text is rephrased |
| Permission rules (`deny` / `ask` / `allow`) | Claude Code, by matching tool calls and command text | Strong for exact matches; can be talked around |
| `PreToolUse` hooks | Your scripts, before every tool call | Deterministic — no prompt to click through — but only as good as their patterns |
| `CLAUDE.md` project rules | The model, as instructions | Advisory — shapes output, never the only layer |

## Before you begin

- You need Claude Code installed, and a terminal on macOS, Linux or WSL2. Native Windows has no sandbox; use WSL2.
- You need `jq` for the hooks in step 3.
- Back up any existing `~/.claude/settings.json` before step 2.

Claude Code evolves weekly. Every setting here was checked against the official documentation in September 2026; verify key names against the [settings reference](https://code.claude.com/docs/en/settings-reference.md) for your version before relying on them.
