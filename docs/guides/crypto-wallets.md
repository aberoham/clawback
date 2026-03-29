---
title: Cryptocurrency Wallets
parent: Remediation Guides
nav_order: 13
description: >-
  Remediate cryptocurrency wallet exposure found by clawback in
  ~/Library/Application Support/ and Solana keypairs.
clawback_category: crypto_wallets
---

# Cryptocurrency wallets
{: .no_toc }

Cryptocurrency wallets contain private keys or seed phrases that control on-chain assets. Unlike cloud credentials, wallet data cannot be "replaced" with a federated identity -- the private key *is* the identity. Remediation focuses on minimizing what the workstation can sign and keeping keys on hardware.

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
| `~/Library/Application Support/Exodus/` | HIGH | Exodus wallet data |
| `~/Library/Application Support/Electrum/` | HIGH | Electrum wallet data |
| Solana keypair files | HIGH | Solana CLI keypair (private key) |
| Other wallet application directories | HIGH | Various wallet data locations |

## Why it's exposed

Hot wallets store private keys on disk for convenience -- the developer can sign transactions without external hardware. Solana CLI generates keypair files in the home directory. Desktop wallet applications store encrypted (or unencrypted) wallet data in `~/Library/Application Support/`.

In 2025-2026, macOS-targeting malware has been observed replacing legitimate wallet applications with trojanized versions that exfiltrate keys on launch.

## Baseline: FileVault full-disk encryption

Full-disk encryption (AES-XTS) via FileVault is the minimum required control for any machine with wallet data.

```bash
# Check FileVault status
fdesetup status

# Enable if not already active
sudo fdesetup enable
```

{: .note }
> FileVault protects data at rest only. It is necessary but not sufficient against malware, clipboard theft, memory scraping, or screen capture while the machine is running and unlocked.

## Tier 1: Eliminate local key exposure

### Hardware wallet delegation

Move private keys to a hardware wallet (Ledger, Trezor). The private key lives in the device's Secure Element and never touches the filesystem. Transactions require physical confirmation on the device.

**Solana with Ledger:**

```bash
solana config set --keypair usb://ledger
```

Transactions are signed on the Ledger hardware. The keypair file on disk is replaced by a URI reference.

**Verify wallet app integrity:**

```bash
codesign --verify --deep --strict "/Applications/Ledger Live.app"
codesign --verify --deep --strict "/Applications/Trezor Suite.app"
```

This detects trojanized wallet applications that have been replaced by malware.

### Minimize hot wallet balances

Keep only operational minimum funds in hot wallets. Move the majority to hardware wallets or cold storage. This limits the blast radius if the workstation is compromised.

## Tier 2: Vault the credential

Not applicable in the traditional sense. Wallet applications require direct access to key material for signing. The Tier 2 equivalent is ensuring the wallet's own encryption is enabled (most wallets offer password protection for their data files).

## Verification

```bash
# FileVault status
fdesetup status  # should report "FileVault is On"

# Verify recovery key is valid
sudo fdesetup validaterecovery

# Check for Solana keypair files
ls -la ~/.config/solana/id.json 2>/dev/null

# Verify wallet app signatures
codesign --verify --deep --strict "/Applications/Ledger Live.app" 2>&1

python3 clawback.py --category crypto_wallets --pretty
```

## Common mistakes

- **Storing seed phrases digitally.** Never store seed phrases in text files, password managers, cloud drives, or screenshots. Use offline metal backup plates or paper in a physical safe.
- **Keeping hot wallets funded beyond operational minimum.** Every dollar in a hot wallet is a dollar at risk if the machine is compromised.
- **Not verifying wallet app signatures.** Trojanized wallet apps are an active macOS threat. Verify code signatures periodically, especially after OS or app updates.
- **Relying on FileVault alone.** Full-disk encryption protects against physical theft of a powered-off machine. It does nothing against malware running while the machine is unlocked.

## CI/CD implications

**N/A.** Cryptocurrency wallets should never exist in CI environments.
