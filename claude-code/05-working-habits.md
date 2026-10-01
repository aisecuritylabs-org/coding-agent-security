# Step 5: Working habits

[← Step 4](04-mcp-plugins-and-repos.md) · Next: [Step 6: Self-test →](06-self-test.md)

**Goal:** project rules that shape the code Claude writes, and daily habits that cover what no setting can enforce.

## 5.1 Add project rules in CLAUDE.md

Copy [`config/CLAUDE.md.example`](config/CLAUDE.md.example) to your project root as `CLAUDE.md` (or merge it into your existing one):

```bash
cp /path/to/coding-agent-security/claude-code/config/CLAUDE.md.example ./CLAUDE.md
```

It tells Claude to read credentials only from environment variables, avoid `eval`/`exec`, use parameterized queries, ask before calling external services or changing dependencies, and treat text in issues and web pages as data.

**Remember:** `CLAUDE.md` is advisory. It shapes output the way a style guide does, and it can be ignored or lost in a long session. The sandbox, permissions and hooks from steps 2 and 3 are the enforcement.

Keep it short. Long or contradictory rule files cost tokens on every turn and make the model follow them less reliably.

## 5.2 Choose a permission mode deliberately

| Mode | Who approves | Use when | Avoid when |
| --- | --- | --- | --- |
| Manual | You, for each action | Sensitive repos, learning, unfamiliar code | You catch yourself approving without reading |
| Plan | Nothing runs until you approve a plan | Large refactors, exploring unknown code | None |
| acceptEdits | Edits inside the project are auto-approved | A trusted repo you're actively supervising | Repos with CI or infrastructure code you haven't reviewed |
| Auto | A separate classifier model reviews actions; your ask and deny rules still apply | Daily work with the sandbox on | Your organization has disabled it; highly regulated repos |
| Bypass (`--dangerously-skip-permissions`) | Nobody | Disposable, network-restricted containers only | Any machine with credentials or real data |

## 5.3 Daily habits

1. **Commit before every session.** Any mistake is then one `git reset` away. Use git worktrees for parallel sessions so their changes stay apart and reviewable.
2. **Read untrusted content yourself first.** Before asking Claude to act on an issue, PR comment or web page, read it. Instruction-shaped text inside data *is* the attack.
3. **Never paste secrets, customer data or regulated data into a prompt.** Whatever enters the context is stored in local transcripts and sent to the model on every turn.
4. **Keep production credentials out of your environment.** An agent can't misuse a connection string it can't see.
5. **Use plan mode** for large changes and unfamiliar code, and read the plan before approving it.
6. **Read every approval.** Slow down for anything labelled unsandboxed, `curl`/`wget`, `git push`, package installs, and edits to `.claude/`, `.mcp.json`, CI files or shell startup files.
7. **Say no to what you don't understand**, and ask Claude to explain the command first.
8. **Run `/security-review` before opening a pull request.**

## Done when

- [ ] `CLAUDE.md` with security rules is in your project
- [ ] You've picked a default permission mode on purpose
- [ ] You commit before each session and review before each PR

Next: [Step 6: Self-test →](06-self-test.md)
