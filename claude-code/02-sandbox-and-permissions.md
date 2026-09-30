# Step 2 — Sandbox and permissions

[← Step 1](01-before-you-start.md) · Next: [Step 3 — Hooks →](03-hooks.md)

**Goal:** a user-level `~/.claude/settings.json` that turns on the OS sandbox in strict mode, blocks credential reads, narrows network access, and sets deny / ask / allow rules.

## Why the sandbox comes first

Permission rules match the *text* of a tool call before it runs, so a rephrased command can slip past them. The sandbox is enforced by the operating system on the running process and every child process it spawns, so it holds regardless of how a command is written. It is the real boundary; everything else in this guide sits on top of it.

Two defaults to know before you start:

- The sandbox's default read policy **still allows** `~/.aws/credentials` and `~/.ssh/`. You must deny them explicitly.
- The network proxy decides by **hostname** and does not inspect what is sent. A broad allowlist entry such as `github.com`, a paste site or a webhook domain is an exfiltration channel.

## 2.1 Back up your current settings

```bash
mkdir -p ~/.claude
[ -f ~/.claude/settings.json ] && cp ~/.claude/settings.json ~/.claude/settings.json.bak
```

## 2.2 Install the baseline

Copy [`config/settings.json`](config/settings.json) to `~/.claude/settings.json`. If you already had settings, merge the two by hand — keep your existing keys and add the ones below.

```bash
cp claude-code/config/settings.json ~/.claude/settings.json
```

## 2.3 Adapt it to your stack

Open `~/.claude/settings.json` and adjust:

1. **`sandbox.network.allowedDomains`** — add only the package registries and APIs your build actually needs. Keep it short. Avoid `github.com`, paste sites and webhook services.
2. **`permissions.allow`** — list only commands that cannot cause harm in your project (your test and lint commands, read-only git). Never put `git push`, `docker run` or anything that deploys in `allow`.
3. **`permissions.ask`** — add your deploy, publish, migration and infrastructure commands (for example `Bash(prisma migrate *)`, `Bash(helm *)`).
4. **`sandbox.credentials`** — add any other credential files and secret environment variables you keep on this machine (for example `~/.config/gcloud`, `~/.kube/config`, `OPENAI_API_KEY`).

## 2.4 Understand what each part does

| Setting | What it does |
| --- | --- |
| `permissions.deny` | Always blocked. Deny beats ask, and ask beats allow. Used here for secret files and raw network tools. |
| `permissions.ask` | Claude must stop and ask you. Used for anything that pushes, publishes or changes infrastructure. |
| `permissions.allow` | Runs without asking. Keep this list to harmless commands. |
| `sandbox.enabled` | Turns on OS-level filesystem and network isolation for Bash, PowerShell and Monitor commands. |
| `sandbox.allowUnsandboxedCommands: false` | "Strict sandbox mode": removes the escape hatch that lets a failing command retry outside the sandbox. |
| `sandbox.network.allowedDomains` | The only hosts sandboxed commands may reach. |
| `sandbox.network.strictAllowlist: true` | Hosts outside the allowlist are denied instead of prompted. Only honored in user, managed or `--settings` settings — a repository cannot turn it on or off for you. Requires a recent release (v2.1.219 or later). |
| `sandbox.credentials.files` | Blocks sandboxed reads of these credential paths. |
| `sandbox.credentials.envVars` | Removes these secret environment variables from sandboxed commands. |
| `enabledMcpjsonServers: []` | Doesn't auto-enable MCP servers a repository declares in `.mcp.json`. |
| `cleanupPeriodDays: 14` | Deletes local session transcripts after 14 days. Transcripts contain code and anything that entered the context. |

## 2.5 Settings you should never use on a laptop

| Setting | Why not |
| --- | --- |
| `enableAllProjectMcpServers: true` | Auto-enables every MCP server any repository declares — "run any server you find". |
| `permissions.additionalDirectories` beyond the project | Widens the write boundary, potentially to your home directory. |
| `--dangerously-skip-permissions` | Skips every permission check, including protected paths. Only for disposable, network-restricted containers. |
| `allowUnixSockets` containing `/var/run/docker.sock` | Access to the Docker socket is equivalent to root on the host. |
| Secrets in `env` | The `env` block applies to every session. |

## 2.6 When a tool genuinely needs a credential

Some tools inside the sandbox need a real token (for example a CLI that calls one API). Instead of removing the `deny`, use the sandbox's **mask** mode: the sandbox sees a placeholder, and the proxy swaps in the real value only for the hosts you name. See [Mask credentials](https://code.claude.com/docs/en/sandboxing.md) in the sandboxing docs. Mask entries are ignored in repository-level settings by design.

## 2.7 Verify

Start a new session in a project and run:

```text
/sandbox
/permissions
```

- `/sandbox` should show the sandbox enabled and **Strict sandbox mode** on in the Overrides tab.
- `/permissions` should list your deny, ask and allow rules exactly as written.

## A note on limits

- Deny rules match text as written — they are a speed bump, not a wall. The sandbox's network isolation is the boundary.
- The sandbox isolates Bash, PowerShell and Monitor. The Read, Edit and Write tools are governed by permission rules, not the sandbox — which is why step 3 adds hooks.
- Commands *you* type at the `!` prompt run outside the sandbox.

## Done when

- [ ] `~/.claude/settings.json` contains the baseline, adapted to your stack
- [ ] `/sandbox` shows enabled + strict mode
- [ ] `/permissions` shows your rules
- [ ] No setting from the "never use" table is present

Next: [Step 3 — Hooks →](03-hooks.md)
