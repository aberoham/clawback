---
title: Home
layout: default
nav_order: 1
---

# Clawback Remediation Library

This site is the companion to [clawback](https://github.com/aberoham/clawback), a macOS endpoint scanner that finds static credentials on developer workstations.

Clawback tells you **what is exposed**. This library tells you **how to fix it**.

---

## How to use this library

1. Run clawback on your machine:

   ```bash
   python3 clawback.py --pretty
   ```

2. For each finding, open the matching remediation guide below.
3. Pick a [tier](concepts/tier-definitions.md) appropriate to your situation.
4. Follow the commands. Verify with clawback.

## Concepts

Start here if you are a security engineer building a remediation program.

- [What "fully remediated" means](concepts/fully-remediated.md) -- the target state for a clean workstation
- [Tier definitions](concepts/tier-definitions.md) -- Eliminate, Vault, or Reduce blast radius
- [The orphaned file anti-pattern](concepts/orphaned-files.md) -- the most common remediation failure
- [Workflow friction ranking](concepts/workflow-friction.md) -- which approaches slow developers down
- [CI/CD implications](concepts/cicd-matrix.md) -- what breaks in pipelines when you remove local keys
- [1Password CLI](concepts/1password-cli.md) -- assessment as a universal Tier 2 solution
- [macOS Keychain](concepts/macos-keychain.md) -- assessment as a free, built-in Tier 2

## Remediation guides

Jump directly to a credential type.

| Credential type | clawback category | Guide |
|----------------|-------------------|-------|
| AWS static access keys | `cloud_credentials` | [Guide](guides/aws-keys.md) |
| GCP application default credentials | `cloud_credentials` | [Guide](guides/gcp-credentials.md) |
| Azure cached tokens | `cloud_credentials` | [Guide](guides/azure-tokens.md) |
| SSH private keys | `ssh_keys` | [Guide](guides/ssh-keys.md) |
| Git credentials | `git_credentials` | [Guide](guides/git-credentials.md) |
| npm tokens | `package_manager_tokens` | [Guide](guides/npm-tokens.md) |
| PyPI credentials | `package_manager_tokens` | [Guide](guides/pypi-credentials.md) |
| Docker registry auth | `package_manager_tokens` | [Guide](guides/docker-auth.md) |
| RubyGems API keys | `package_manager_tokens` | [Guide](guides/rubygems-keys.md) |
| Cargo/crates.io tokens | `package_manager_tokens` | [Guide](guides/cargo-tokens.md) |
| Kubernetes kubeconfig | `kubernetes` | [Guide](guides/kubernetes-kubeconfig.md) |
| Shell profile and .env secrets | `shell_profiles` / `env_files` | [Guide](guides/shell-env-secrets.md) |
| Cryptocurrency wallets | `crypto_wallets` | [Guide](guides/crypto-wallets.md) |

---

Research date: March 2026. Synthesized from independent deep research by Claude, ChatGPT, and Gemini. Version-specific details are noted throughout; check vendor documentation for the latest.
