---
title: What "Fully Remediated" Means
parent: Concepts
nav_order: 1
---

# What "fully remediated" means
{: .no_toc }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## The target state

A macOS developer workstation is fully remediated when clawback returns **zero findings** -- no long-lived, reusable secrets in plaintext on disk. The ideal output is a set of *observations* confirming compliant configurations (SSO profiles, credential helpers, exec plugins) without exposing secret values.

"Fully remediated" does not mean "zero secrets anywhere." It means **zero long-lived, reusable plaintext secrets on disk** -- in config files, dotfiles, environment variables, or shell profiles.

## Four testable parameters

A remediated workstation satisfies four criteria:

### 1. Absence of high-entropy strings on disk

No plaintext keys, tokens, or passwords in config files, dotfiles, or environment variables. Files like `~/.aws/credentials`, `~/.npmrc`, and `~/.pypirc` either do not exist, contain no secret values, or use vault references (`op://` URIs, `${VAR}` placeholders) instead of raw material.

### 2. Ephemeral execution chains

Authentication flows use `credential_process`, exec plugins, or SSO that produce short-lived tokens on demand, brokered by an external identity provider. The tokens expire and are not persisted in reusable form.

Examples: AWS IAM Identity Center sessions, GKE `gke-gcloud-auth-plugin` exec entries in kubeconfig, Azure `az login` with token cache purged on logout.

### 3. Vault references, not secrets

Dotfiles and `.env` files contain vault URIs (e.g., `op://vault/item/field`) or environment variable placeholders (e.g., `${NPM_TOKEN}`) rather than raw cryptographic material. These references are resolved entirely in-memory at runtime.

`op://` references and `${VAR}` placeholders are safe to commit to version control. Raw secret values are not.

### 4. Hardware-backed cryptography where possible

SSH and cryptographic keys are either stored in hardware enclaves (YubiKey, Secure Enclave) or managed dynamically by biometric-gated agents (1Password SSH agent), ensuring the private key never touches the filesystem.

## What clawback should report

After full remediation, a clawback scan should produce:

- **Zero findings** across all categories
- **Observations** confirming compliant configurations, such as:
  - AWS CLI profiles configured for IAM Identity Center (SSO metadata in `~/.aws/config`, no `aws_access_key_id` in `~/.aws/credentials`)
  - Docker configured with a credential store (`credsStore: "osxkeychain"`) instead of base64 credentials in `auths`
  - Git using `credential.helper = osxkeychain` with no `~/.git-credentials` file
  - Kubernetes kubeconfig using exec-based plugins with no embedded tokens or certificates
  - 1Password CLI or Vault CLI installed and available

## What "fully remediated" is not

- It is **not** "zero secrets anywhere." Local ADC files with `type: authorized_user` are acceptable -- they contain short-lived user tokens, not service account keys.
- It is **not** achievable by local changes alone. If CI pipelines still consume the same static secrets, the risk is relocated rather than eliminated. See [CI/CD Implications](cicd-matrix.md).
- It is **not** a one-time event. Credentials drift back as developers install new tools, onboard to new services, or take shortcuts under deadline pressure. Periodic re-scanning is the enforcement mechanism.
