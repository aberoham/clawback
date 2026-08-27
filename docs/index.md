---
title: Home
layout: default
nav_order: 1
---

# Rattlesnake Remediation Library

This site is the companion to [rattlesnake](https://github.com/aberoham/rattlesnake), a macOS endpoint scanner that finds static credentials on developer workstations.

Rattlesnake tells you **what is exposed**. This library tells you **how to fix it**.

---

## How to use this library

1. Run rattlesnake on your machine:

   ```bash
   python3 rattlesnake.py --pretty
   ```

2. For a credential-exposure finding, open the matching remediation guide
   below. Active-compromise findings carry incident-response instructions in
   the report and in Antivenom; follow those instructions before rotating any
   credential.
3. Pick a [tier](concepts/tier-definitions.md) appropriate to your situation.
4. Follow the commands. Verify with rattlesnake.

## Architecture

- [Architecture diagrams](architecture.md) -- scanning and antivenom flows

## Concepts

Start here if you are a security engineer building a remediation program.

- [What "fully remediated" means](concepts/fully-remediated.md) -- the target state for a clean workstation
- [Tier definitions](concepts/tier-definitions.md) -- Eliminate, Vault, or Reduce blast radius
- [The orphaned file anti-pattern](concepts/orphaned-files.md) -- the most common remediation failure
- [Workflow friction ranking](concepts/workflow-friction.md) -- which approaches slow developers down
- [CI/CD implications](concepts/cicd-matrix.md) -- what breaks in pipelines when you remove local keys
- [1Password CLI](concepts/1password-cli.md) -- assessment as a universal Tier 2 solution
- [macOS Keychain](concepts/macos-keychain.md) -- assessment as a free, built-in Tier 2
- [Roadmap](ROADMAP.md) -- proposed future scanner categories, paths, and severity model

## Remediation guides

Jump directly to a credential type.

| Credential type | rattlesnake category | Guide |
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
| Shell profile, live environment, and .env secrets | `shell_profile_secrets` / `environment_variables` / `env_files` | [Guide](guides/shell-env-secrets.md) |
| Cryptocurrency wallets | `crypto_wallets` | [Guide](guides/crypto-wallets.md) |

The scanner-selection names `shell_profiles` and `teampcp_iocs` emit the legacy
finding-category names `shell_profile_secrets` and `teampcp_ioc` respectively.
Antivenom's `--category` option uses the emitted name shown in scan JSON.

Active-compromise categories (`teampcp_ioc`, `npm_supply_chain`,
`agent_autostart_hooks`, `repo_worm_artifacts`, and `malware_persistence`) are
human-first incident response rather than ordinary credential remediation. See
the repository README and the finding-specific remediation text.

---

Vendor research date: March 2026. Repository behavior reconciled with the
scanner in August 2026. Version-specific vendor details can change; check the
current vendor documentation before operational use.
