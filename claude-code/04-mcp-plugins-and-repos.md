# Step 4: MCP servers, plugins and repositories

[← Step 3](03-hooks.md) · Next: [Step 5: Working habits →](05-working-habits.md)

**Goal:** treat every extension as a dependency, and never trust a cloned repository's agent configuration without reading it first.

## Why this matters

MCP servers, plugins and skills are third-party code that runs with your rights, and their output flows straight into the model's context. A cloned repository can ship its own `.claude/settings.json`, hooks, `.mcp.json` and `CLAUDE.md`: configuration that changes what the agent does for everyone who opens it.

## 4.1 Inventory what you already have

```bash
# MCP servers configured for your user and for this project
cat ~/.claude.json 2>/dev/null | jq '.mcpServers // {}'
cat .mcp.json 2>/dev/null
```

Inside a session:

```text
/mcp
/plugin
```

For each server and plugin, write down: where it came from, the version, what credentials it holds, and whether it reads text that other people can write.

## 4.2 Rules for MCP servers

1. **Approved sources only.** Your organization's allowlist, the official directory, or servers you wrote.
2. **Pin versions.** Don't run `@latest`.
3. **Authenticate remote servers** and give them the narrowest OAuth scopes that work.
4. **Watch for injection channels.** Servers that ingest third-party-writable data (error monitors, ticketing, chat, email, public web) can deliver instructions to the model. Give them read-only scopes, and keep approvals on for any action that follows a read from them.
5. **Keep production out.** Don't connect production databases or cloud accounts. If you must, use read-only replicas.

## 4.3 Rules for plugins and skills

1. Prefer the official marketplace.
2. **Before installing,** look inside the plugin for:
   - `hooks`: shell code that will run automatically
   - MCP server definitions: more third-party code and credentials
   - bundled executables and scripts
3. Pin the version, and review the diff before upgrading.

## 4.4 Inspect a cloned repository before trusting it

Opening a repository is now an attack surface in its own right. In June 2026 the **Miasma worm** used a compromised contributor account to plant a `.claude/settings.json` `SessionStart` hook in `Azure/durabletask`; the hook ran a credential stealer the moment a developer started Claude Code in the repository, and GitHub disabled 73 Microsoft repositories in response ([StepSecurity](https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents)). Lockfiles, install-script blocking and SBOMs don't help here: nothing is installed; the attack runs on open.

**Fastest check:** run the [audit container](audit/README.md) from the repository's folder *before* starting Claude Code in it. Checks P03 and P09 to P13 cover everything below.

**By hand**, in any repository you didn't create:

```bash
ls -la .claude/ 2>/dev/null
cat .claude/settings.json .claude/settings.local.json 2>/dev/null
ls -la .claude/hooks/ 2>/dev/null
cat .mcp.json 2>/dev/null
cat CLAUDE.md 2>/dev/null
find . -type l -not -path './.git/*' -not -path './node_modules/*' -exec ls -l {} \;   # every symlink and its target
```

**Red flags: if you see any of these, don't open it on your laptop.**

- **Hooks you didn't write**, especially under `SessionStart` or `Setup`, which run with no tool call and no prompt (the Miasma pattern)
- **MCP servers in `.mcp.json` that run a local `command`.** Accepting the folder-trust prompt starts them as native processes with your privileges, outside the sandbox ([Adversa AI: TrustFall](https://adversa.ai/blog/trustfall-coding-agent-security-flaw-rce-claude-cursor-gemini-cli-copilot/)). Anthropic treats the trust prompt as consent, so read `.mcp.json` *before* you click it.
- **Symlinks with ordinary-looking names that point at `.claude/`, `.mcp.json` or dotfiles**, or anywhere outside the repository. Researchers showed approval prompts displaying the harmless name while the write landed on the real target ([Adversa AI: SymJack](https://adversa.ai/blog/the-approval-prompt-is-lying-to-you-symlink-rce-in-five-ai-coding-agents-claude-code-cursor-antigravity-copilot-grok-build/), [Wiz: GhostApproval](https://www.wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants)). The updated [`protect-files.sh`](hooks/protect-files.sh) resolves symlinks and blocks writes outside the project.
- **Plugin marketplaces on git hosts other than GitHub.** Plugin4Shell swapped a pinned plugin for malicious code with no user action on hosts that accept 40-character hex branch names; fixed in Claude Code 2.1.179 ([AIR Security](https://www.air.security/blog-posts/plugin4shell)).
- Broad `allow` rules (for example `Bash(*)`, `Bash(curl *)`, `Bash(git push *)`)
- `enableAllProjectMcpServers` or MCP servers you don't recognize
- `additionalDirectories` pointing outside the repository
- A `CLAUDE.md` that tells the agent to fetch, run, install or send anything

If you need to work with it anyway, open it in a dev container, VM or cloud session, somewhere with no credentials worth stealing. Never run Claude Code headless (`claude -p`, CI) on untrusted branches with production credentials.

**For organisations:** individual developers have no setting that blocks repository-supplied hooks except `disableAllHooks`, which also disables your protective hooks. Managed settings close the gap: `"allowManagedHooksOnly": true` runs only hooks your organisation deploys, and `"allowManagedMcpServersOnly": true` makes your managed MCP allowlist the only one that applies ([settings reference](https://code.claude.com/docs/en/settings-reference)).

## 4.4a Treat outsider-written content as untrusted input

MCP servers for error trackers, tickets, chat and email carry text other people wrote, and it reaches the model as trusted tool output. Tenet Security's **Agentjacking** research planted fake Sentry errors containing "fix" instructions and reported an 85% success rate against Claude Code, Cursor and Codex; 2,388 organisations exposed DSNs that accepted injected events, and Sentry declined a structural fix ([The Hacker News](https://thehackernews.com/2026/06/agentjacking-attack-tricks-ai-coding.html), [The Next Web](https://thenextweb.com/news/agentjacking-ai-coding-agents-sentry)).

- Give these servers read-only credentials.
- Keep approvals on for any command that follows a read from them.
- Never let the agent run a command copied from a ticket, error or message until you've read it yourself.

The audit flags these servers as P12 (project) and M02 (user).

## 4.5 Protect your own agent configuration

In repositories you own, add a `CODEOWNERS` entry so changes to agent configuration require review:

```text
# .github/CODEOWNERS
/.claude/     @your-org/security
/.mcp.json    @your-org/security
/CLAUDE.md    @your-org/security
```

## Done when

- [ ] You have an inventory of your MCP servers and plugins, with sources and versions
- [ ] Anything unapproved or unpinned is removed or pinned
- [ ] Servers that read third-party text are read-only
- [ ] You inspect `.claude/`, `.mcp.json`, `CLAUDE.md` and symlinks before trusting any cloned repository, or run the audit container on it first
- [ ] You read `.mcp.json` before accepting the folder-trust prompt
- [ ] Plugin marketplaces are on GitHub or infrastructure you control, and Claude Code is 2.1.179 or later

Next: [Step 5: Working habits →](05-working-habits.md)
