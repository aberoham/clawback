---
title: Unencrypted SSH Private Keys
parent: Remediation Guides
nav_order: 4
description: >-
  Remediate unencrypted SSH private keys found by clawback in ~/.ssh/.
clawback_category: ssh_keys
---

# Unencrypted SSH private keys
{: .no_toc }

Unencrypted SSH private keys on disk are immediately usable by any process with file read access. Supply chain malware routinely exfiltrates `~/.ssh/` as one of its first actions.

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## What clawback finds

| Path / indicator | Severity | Description |
|-----------------|----------|-------------|
| `~/.ssh/id_rsa` without `ENCRYPTED` header | HIGH | Unencrypted RSA private key |
| `~/.ssh/id_ed25519` without encryption | HIGH | Unencrypted Ed25519 private key |
| `~/.ssh/id_ecdsa` without encryption | HIGH | Unencrypted ECDSA private key |
| Any `~/.ssh/id_*` without passphrase protection | HIGH | Unencrypted private key material |

## Why it's exposed

When developers generate keys via `ssh-keygen`, they are prompted for a passphrase. Pressing Enter to skip creates an unencrypted key. This is the default in most tutorials and gets the developer working immediately at the cost of plaintext key exposure.

## Tier 1: Eliminate the static credential

### 1Password SSH agent

Keys stored entirely in the 1Password vault. The private key never touches the filesystem. Every SSH operation requires biometric (Touch ID) authentication.

**Setup:**

1. Import or generate SSH key in 1Password
2. Enable SSH agent in 1Password > Settings > Developer
3. Configure `~/.ssh/config`:

```
Host *
  IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
```

**Daily workflow:** SSH and Git operations trigger a Touch ID prompt. No key files on disk.

**Limitations:**
- Does **not** support `ed25519-sk` keys (hardware enclave keys) -- forces a choice between 1Password management and hardware-backed keys
- Tools expecting a file path to an SSH key (some Ansible configs, Docker containers) need socket forwarding
- 1Password must be running and unlocked
- SSH protocol tries max 6 keys before failing; if you have more than 6 keys in 1Password, add `IdentityFile` directives in `~/.ssh/config` to specify which key to use for each host

### YubiKey / FIDO2 resident keys

Private key resides on hardware, never on the filesystem. The `~/.ssh/id_ed25519_sk` file is a handle (public key + key handle), not key material.

**Requirements:** Homebrew OpenSSH (Apple's bundled OpenSSH has FIDO2 compiled out). OpenSSH >= 8.2 on target servers. YubiKey 5 series (~$55 each; buy two -- primary + backup).

**Setup:**

```bash
brew install openssh libfido2
export PATH="/opt/homebrew/bin:$PATH"

ykman fido access change-pin  # set YubiKey PIN if not already done

ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -O application=ssh:github -C "your_email@example.com"
```

**Daily workflow:** SSH connections require YubiKey PIN + physical tap. No caching.

**Extracting keys to a new machine:**

```bash
ssh-keygen -K  # extracts resident key handles from YubiKey after PIN entry
```

### SSH certificate authorities (Teleport, Smallstep, Vault SSH)

Issue short-lived SSH certificates instead of persistent keys. Certificates expire automatically (16 hours for Smallstep, configurable for others).

**Teleport setup:**

```bash
brew install teleport
tsh login --proxy=teleport.example.com --user=<USERNAME>
# Short-lived certificate loaded into agent
```

**Smallstep setup:**

```bash
brew install step smallstep/tap/step-ca
step ssh certificate alice@work ~/.ssh/id_ecdsa --not-after 8h
```

**Vault SSH setup:**

```bash
vault write -field=signed_key ssh-client-signer/sign/developer \
  public_key=@$HOME/.ssh/id_ed25519.pub > ~/.ssh/id_ed25519-cert.pub
```

## Tier 2: Vault the credential

### Passphrase + macOS Keychain

Encrypt the private key with a passphrase and store the passphrase in Keychain so it is auto-filled on use.

**Setup:**

```bash
# Add passphrase to existing key
ssh-keygen -p -f ~/.ssh/id_ed25519

# Convert older RSA keys to OpenSSH format (enables modern encryption)
ssh-keygen -p -o -f ~/.ssh/id_rsa

# Store passphrase in Keychain
ssh-add --apple-use-keychain ~/.ssh/id_ed25519
```

Add to `~/.ssh/config`:

```
Host *
  UseKeychain yes
  AddKeysToAgent yes
```

## Tier 3: Reduce blast radius

- Use separate keys per organization/service (don't reuse one key everywhere)
- Rotate keys on a schedule
- Restrict which servers accept which keys via `authorized_keys` constraints

## Verification

```bash
# Check if keys are encrypted (look for ENCRYPTED in header)
head -2 ~/.ssh/id_*

# Check SSH agent
ssh-add -l

# Verify 1Password agent is configured
grep -r "IdentityAgent" ~/.ssh/config

python3 clawback.py --category ssh_keys --pretty
```

## Common mistakes

- **Adding a passphrase but keeping the original unencrypted file as a backup.** The "backup" is the vulnerability. Delete it. See [The Orphaned File Anti-Pattern](../concepts/orphaned-files.md).
- **Using `ssh -A` (agent forwarding) instead of `ProxyJump`.** Agent forwarding lets compromised remote hosts abuse your local agent socket. Use `ProxyJump` (`ssh -J bastion target`) instead.
- **Loading key into `ssh-agent` but leaving the file unencrypted on disk.** The agent protects runtime use; the file remains exposed to disk-level exfiltration.
- **Retaining plaintext backup copies in cloud drives or external storage.**

## CI/CD implications

**CI change required: yes.**

CI should use per-repo deploy keys, not developer personal keys. For GitHub Actions, use the deploy key or app installation token pattern. Never share developer SSH keys with CI.
