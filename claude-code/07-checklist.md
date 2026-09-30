# Step 7 — Checklist

[← Step 6](06-self-test.md) · [Back to overview](README.md)

Re-check this list after every Claude Code upgrade and whenever you set up a new machine.

**Most of this list is checked automatically by the [audit container](audit/README.md).** Run it first. The items it can't see from configuration — your habits, and whether the controls work in a live session — are marked *manual* below.

## Installation and identity

- [ ] Latest Claude Code version; `claude doctor` is clean
- [ ] Work account for work code (`/status`)
- [ ] Standard (non-admin) OS user
- [ ] Sessions start in the project directory, never `~`
- [ ] On Windows: running inside WSL2

## Sandbox

- [ ] `sandbox.enabled: true`
- [ ] Strict mode: `allowUnsandboxedCommands: false`
- [ ] Narrow `allowedDomains`; `strictAllowlist: true`
- [ ] Credential files and secret environment variables denied under `sandbox.credentials`
- [ ] No Docker socket in `allowUnixSockets`

## Permissions

- [ ] Deny rules for secret files and raw network tools
- [ ] Ask rules for push, publish, deploy and infrastructure commands
- [ ] Allow list contains only harmless commands
- [ ] No `enableAllProjectMcpServers: true`; no `additionalDirectories` outside the project
- [ ] No `--dangerously-skip-permissions` aliases in your shell configuration

## Hooks

- [ ] `protect-files.sh` and `validate-commands.sh` registered and executable
- [ ] `tests/test-hooks.sh` passes
- [ ] Every hook in use has been reviewed by you

## Extensions and repositories

- [ ] MCP servers and plugins from approved sources, pinned, inventoried
- [ ] Servers that read third-party text are read-only
- [ ] `.claude/`, `.mcp.json` and `CLAUDE.md` inspected before trusting any cloned repository
- [ ] Untrusted repositories opened only in containers, VMs or cloud sessions

## Habits *(manual)*

- [ ] `CLAUDE.md` with security rules in each project
- [ ] Commit before each session; worktrees for parallel sessions
- [ ] No secrets or regulated data in prompts; no production credentials in the environment
- [ ] `/security-review` before each pull request

## Proof

- [ ] Audit container reports no FAIL results
- [ ] Self-test (step 6) passed after the most recent upgrade *(manual)*

## References

- Claude Code docs: [Security](https://code.claude.com/docs/en/security.md) · [Permissions](https://code.claude.com/docs/en/permissions.md) · [Sandboxing](https://code.claude.com/docs/en/sandboxing.md) · [Hooks guide](https://code.claude.com/docs/en/hooks-guide.md) · [Dev containers](https://code.claude.com/docs/en/devcontainer.md) · [Settings reference](https://code.claude.com/docs/en/settings-reference.md)
- Trail of Bits: [claude-code-config](https://github.com/trailofbits/claude-code-config) — a reference hardened configuration
