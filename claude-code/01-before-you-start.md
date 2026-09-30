# Step 1 — Before you start

[← Overview](README.md) · Next: [Step 2 — Sandbox and permissions →](02-sandbox-and-permissions.md)

**Goal:** a current Claude Code install, running under the right account and OS user, with the sandbox's dependencies in place.

## 1.1 Update Claude Code and check its health

Several published vulnerabilities have been in the tool itself rather than the model — configuration that ran before the trust dialog, sandbox escapes, network-allowlist bypasses — and they were fixed in later releases. Treat Claude Code like a browser: keep it current.

```bash
claude update
claude doctor
```

`claude doctor` should report no problems. Make updating a weekly habit.

## 1.2 Use a work account for work code

Team and Enterprise plans come with commercial data terms and give administrators visibility and control. Never sign up for a personal plan with a work email address, and never point a personal plan at company code.

**Check:** inside a session, run `/status` and confirm the account and organization are the ones you expect.

## 1.3 Don't run as an administrator

Every subprocess Claude Code spawns inherits your privileges. Run your daily work under a standard (non-admin) user and use `sudo` only when you install software yourself.

**Check:**

```bash
# Linux / WSL2 / macOS — should NOT print 0
id -u
# macOS — your user should not be listed if you want a standard account
dscl . -read /Groups/admin GroupMembership
```

## 1.4 Always start in the project directory

The directory you launch Claude Code from is its write boundary. Launching from your home directory puts every dotfile, SSH key and project on your machine inside that boundary.

```bash
cd ~/code/my-project
claude
```

Never run `claude` from `~`.

## 1.5 Install the sandbox dependencies

The sandbox you'll enable in step 2 is built into Claude Code and runs on macOS, Linux and WSL2.

- **macOS:** nothing to install; it uses the built-in Seatbelt framework.
- **Ubuntu / Debian / WSL2:**

  ```bash
  sudo apt-get install bubblewrap socat
  ```

- **Fedora:**

  ```bash
  sudo dnf install bubblewrap socat
  ```

- **Optional (Linux / WSL2):** the seccomp filter adds Unix domain socket blocking:

  ```bash
  npm install -g @anthropic-ai/sandbox-runtime
  ```

- **Windows:** native Windows is not supported. Install WSL2, install Claude Code inside your WSL2 distribution, and follow the Linux steps there.

Restart Claude Code after installing, then run `/sandbox`. If a **Dependencies** tab appears, it lists what is still missing.

## 1.6 Install jq

The hooks in step 3 use `jq` to read the tool call Claude Code sends them.

```bash
sudo apt-get install jq      # Ubuntu / Debian / WSL2
sudo dnf install jq          # Fedora
brew install jq              # macOS
```

## Done when

- [ ] `claude doctor` is clean and you're on the latest version
- [ ] `/status` shows your work account
- [ ] You're a standard (non-admin) OS user
- [ ] You launch Claude Code from project directories only
- [ ] `/sandbox` shows no missing dependencies
- [ ] `jq --version` works

Next: [Step 2 — Sandbox and permissions →](02-sandbox-and-permissions.md)
