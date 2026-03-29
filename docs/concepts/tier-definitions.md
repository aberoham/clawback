---
title: Tier Definitions
parent: Concepts
nav_order: 2
---

# Remediation tier definitions
{: .no_toc }

Every remediation guide in this library uses a three-tier model. The tiers represent decreasing levels of security posture improvement, from best to acceptable.

---

## Tier 1: Eliminate the static credential

No long-lived secret exists on the filesystem, even encrypted. Authentication uses federated identity, OIDC, hardware keys, or short-lived tokens from an identity provider.

**The test:** if the machine is fully compromised, no reusable credential can be extracted from disk.

**Examples:**
- AWS IAM Identity Center (SSO) -- no static keys, only auto-expiring session tokens
- YubiKey/FIDO2 SSH keys -- private key on hardware, never on filesystem
- 1Password SSH agent -- keys stored in vault, never written to `~/.ssh/`
- PyPI Trusted Publishers -- OIDC tokens valid for 15 minutes, no stored secret
- Git Credential Manager -- tokens in Keychain, plaintext `.git-credentials` eliminated

## Tier 2: Vault the credential

The credential exists but is encrypted at rest in a secure store (macOS Keychain, 1Password, HashiCorp Vault) and injected at runtime. The plaintext file is gone.

**The test:** an attacker with disk access sees encrypted blobs. Extracting the credential requires the user's biometric, passphrase, or active session.

**Examples:**
- `aws-vault` storing IAM keys in macOS Keychain, generating short-lived STS tokens
- SSH key encrypted with passphrase, passphrase stored in Keychain via `ssh-add --apple-use-keychain`
- 1Password `op run --env-file` injecting secrets from vault into subprocess environment
- Docker `credsStore: "osxkeychain"` moving registry auth from plaintext to Keychain

## Tier 3: Reduce blast radius

The credential remains on disk but is scoped, short-lived, or otherwise constrained to minimize damage from exfiltration.

**The test:** the credential is still exploitable if stolen, but the blast radius is limited by scope, IP allowlist, expiration, or MFA enforcement.

**Examples:**
- npm granular tokens scoped to specific packages with IP allowlisting and 7-day expiry
- Fine-grained GitHub PATs with repository-level scope and expiration dates
- IAM keys with least-privilege policies, MFA enforcement, and aggressive rotation
- RubyGems API keys scoped per-gem with OTP-enforced publishing

## Choosing a tier

Always aim for Tier 1. Fall back to Tier 2 when the tool ecosystem does not support credential elimination for a given workflow. Use Tier 3 only as a temporary measure while working toward Tier 1 or 2, or when organizational constraints prevent a better solution.

The [workflow friction ranking](workflow-friction.md) can help prioritize which Tier 1 approaches to adopt first based on developer impact.
