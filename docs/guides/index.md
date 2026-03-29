---
title: Remediation Guides
layout: default
nav_order: 3
has_children: true
has_toc: false
---

# Per-system remediation guides

Each guide covers one credential type that clawback detects, with tiered remediation options and copy-pasteable macOS commands.

Every guide follows the same structure: what clawback finds, why it is exposed, Tier 1/2/3 remediation options, verification, common mistakes, and CI/CD implications.

---

### Cloud credentials

| Credential type | Guide |
|----------------|-------|
| AWS static access keys | [Remediate](aws-keys.md) |
| GCP application default credentials | [Remediate](gcp-credentials.md) |
| Azure cached tokens and client secrets | [Remediate](azure-tokens.md) |

### SSH and Git

| Credential type | Guide |
|----------------|-------|
| Unencrypted SSH private keys | [Remediate](ssh-keys.md) |
| Git credentials (stored/cached helpers) | [Remediate](git-credentials.md) |

### Package manager tokens

| Credential type | Guide |
|----------------|-------|
| npm tokens | [Remediate](npm-tokens.md) |
| PyPI credentials | [Remediate](pypi-credentials.md) |
| Docker registry auth | [Remediate](docker-auth.md) |
| RubyGems API keys | [Remediate](rubygems-keys.md) |
| Cargo / crates.io tokens | [Remediate](cargo-tokens.md) |

### Infrastructure and secrets

| Credential type | Guide |
|----------------|-------|
| Kubernetes kubeconfig | [Remediate](kubernetes-kubeconfig.md) |
| Shell profile and .env file secrets | [Remediate](shell-env-secrets.md) |
| Cryptocurrency wallets | [Remediate](crypto-wallets.md) |
