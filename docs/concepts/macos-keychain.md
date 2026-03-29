---
title: macOS Keychain as Tier 2
parent: Concepts
nav_order: 7
---

# macOS Keychain as Tier 2
{: .no_toc }

For environments without 1Password, the macOS `security` CLI provides a free, built-in credential store. This page assesses its practical strengths and limitations for developer credential management.

---

## How it works

The macOS Keychain stores secrets encrypted at rest, protected by the user's login password and optionally by per-item access control lists. The `security` command-line tool provides programmatic access.

```bash
# Store a secret
security add-generic-password -a "$USER" -s "my-api-key" -w "sk-abc123" -U

# Retrieve a secret
security find-generic-password -a "$USER" -s "my-api-key" -w

# Use in a shell profile or script
export API_KEY=$(security find-generic-password -a "$USER" -s "my-api-key" -w)
```

Many developer tools have built-in Keychain integration: Git's `osxkeychain` credential helper, Docker's `credsStore`, Cargo's `cargo:macos-keychain` provider, and SSH's `--apple-use-keychain` flag.

## Strengths

- **Fast:** 10-50ms retrieval latency, significantly faster than `op read` (~1 second). Suitable for shell startup and per-command injection where latency matters.
- **No additional software:** ships with every Mac. No installation, licensing, or account required.
- **Broad applicability:** works for Git, Docker, Cargo, RubyGems, SSH passphrases, and arbitrary environment variables.
- **Native integration:** several developer tools support Keychain natively without manual shell wrappers.

## Limitations

- **GUI permission dialogs:** the first time a new application accesses a Keychain item, macOS presents a blocking GUI dialog asking the user to Allow or Deny. The `-T /usr/bin/security` flag during storage can pre-authorize the `security` binary, but this grants access to any script that calls `security`, which is a broad trust grant.
- **Keychain locks on sleep:** the login keychain locks when the screen locks or the Mac sleeps. Subsequent access requires `security unlock-keychain`, which needs the keychain password. This interrupts automated scripts and background processes.
- **iCloud Keychain sync risk:** if the developer uses iCloud Keychain, secrets stored in the default login keychain may sync to other Apple devices (iPhone, iPad, other Macs). To prevent this, create a dedicated local keychain:

  ```bash
  security create-keychain -p "" dev-secrets.keychain-db
  security add-generic-password -a "$USER" -s "my-api-key" -w "sk-abc123" dev-secrets.keychain-db
  ```

- **No seamless environment injection:** unlike 1Password's `op run`, there is no native "run this command with secrets from Keychain" wrapper. Developers must write verbose shell functions or aliases to bridge the gap.
- **Unsuitable for CI/CD:** the GUI dialog requirement and screen-lock behavior make Keychain impractical for headless or automated environments.

## Where it fits

macOS Keychain is the right Tier 2 choice when:
- The tool has native Keychain support (Git, Docker, Cargo, SSH)
- The developer does not use 1Password or another secrets manager
- Retrieval latency matters (shell startup, rapid iteration)
- The workflow is interactive (human at the keyboard to dismiss dialogs)

It is not the right choice when:
- The workflow is unattended or automated
- Secrets must not sync across devices (unless a custom keychain is created)
- The developer needs a "run with secrets" wrapper (use 1Password `op run` or `direnv` instead)
