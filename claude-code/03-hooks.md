# Step 3 — Hooks

[← Step 2](02-sandbox-and-permissions.md) · Next: [Step 4 — MCP servers, plugins and repositories →](04-mcp-plugins-and-repos.md)

**Goal:** two `PreToolUse` hooks that block dangerous actions deterministically — no prompt, no override, nothing for a tired developer to click through.

## How a PreToolUse hook works

Before every tool call, Claude Code runs your hook and sends it the tool call as JSON on standard input. If the hook exits with code **2**, the action is blocked and whatever the hook printed to standard error is sent back to Claude as the reason. Exit code **0** lets the action through.

## Why you need two hooks, not one

When the Write tool is blocked from touching `.env`, a model will often try the same change through the Bash tool instead:

```bash
echo "API_KEY=abc" >> .env
```

A hook that only watches Edit and Write never sees that. So you need:

| Hook | Watches | Blocks |
| --- | --- | --- |
| [`protect-files.sh`](hooks/protect-files.sh) | `Edit`, `Write` | Edits to `.env*`, `secrets/`, keys, `.claude/`, `.mcp.json`, CI files, lockfiles, shell startup files |
| [`validate-commands.sh`](hooks/validate-commands.sh) | `Bash` | Recursive deletes, pipe-to-shell, destructive SQL, `--dangerously-skip-permissions`, `chmod 777`, reading/writing `.env` via the shell, network commands that mention a secret |

## 3.1 Copy the scripts into your project

From your project's root directory:

```bash
mkdir -p .claude/hooks
cp /path/to/coding-agent-security/claude-code/hooks/*.sh .claude/hooks/
chmod +x .claude/hooks/*.sh
```

> **Windows users:** do this inside WSL2. The scripts must keep LF line endings; this repository enforces that with `.gitattributes`, but check your editor if you modify them.

## 3.2 Register the hooks

Add the contents of [`config/hooks.json`](config/hooks.json) to your project's `.claude/settings.json` (create the file if it doesn't exist; merge if it does):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [{ "type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/protect-files.sh" }]
      },
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/validate-commands.sh" }]
      }
    ]
  }
}
```

`$CLAUDE_PROJECT_DIR` is set by Claude Code to the project root, so the path works wherever the project lives.

**Want them in every project?** Put the scripts in `~/.claude/hooks/` instead, and register them in `~/.claude/settings.json` with the command paths changed to `~/.claude/hooks/protect-files.sh` and `~/.claude/hooks/validate-commands.sh`.

## 3.3 Test the hooks outside Claude Code

Run the test suite from this repository. It feeds 41 sample tool calls to the two scripts, including symlinks disguised as ordinary files and malformed input, and checks each is blocked or allowed as expected:

```bash
bash claude-code/tests/test-hooks.sh
```

Expected output:

```text
41 passed, 0 failed
```

To test the copies in your project instead:

```bash
HOOKS_DIR=.claude/hooks bash /path/to/coding-agent-security/claude-code/tests/test-hooks.sh
```

## 3.4 Verify inside Claude Code

Start a new session in the project and run:

```text
/hooks
```

You should see both `PreToolUse` hooks with the matchers `Edit|Write` and `Bash`. Step 6 tests them end to end.

## 3.5 Extend them for your project

Add patterns for anything in your environment that should never be touched:

- Infrastructure files: `*.tf`, `*/k8s/*`, `*/helm/*`
- Other secret stores: `*/.npmrc`, `*/.pypirc`, `*/.netrc`
- Your production CLIs in `validate-commands.sh`: for example `kubectl delete`, `terraform destroy`

After every change, add a matching case to `tests/test-hooks.sh` and re-run it.

## A note on limits

Hooks are pattern-matching scripts: **guardrails, not walls**. A determined prompt injection can look for a phrasing the patterns miss. They raise the floor from zero; the sandbox from step 2 is what holds underneath them. Hooks are also shell code that runs with your privileges — review any hook you did not write, including hooks shipped inside plugins.

## Done when

- [ ] Both scripts are in `.claude/hooks/` (or `~/.claude/hooks/`) and executable
- [ ] Both are registered in settings
- [ ] `test-hooks.sh` reports 0 failures
- [ ] `/hooks` lists both

Next: [Step 4 — MCP servers, plugins and repositories →](04-mcp-plugins-and-repos.md)
