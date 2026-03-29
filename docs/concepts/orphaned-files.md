---
title: The Orphaned File Anti-Pattern
parent: Concepts
nav_order: 3
---

# The orphaned file anti-pattern
{: .no_toc }

The single most common remediation failure across all credential types: developers successfully migrate to a secure mechanism but forget to delete the legacy plaintext file.

---

## Why it matters

When a developer sets up AWS SSO but leaves `~/.aws/credentials` intact, the AWS CLI silently falls back to the SSO profile. Everything works. The developer believes they are remediated. But the plaintext IAM keys remain on disk, fully exploitable by any malware or exfiltration tool.

This pattern repeats across nearly every credential type. The new secure mechanism masks the continued presence of the old insecure one.

## Common orphaned files

| After migrating to... | This file often remains |
|-----------------------|------------------------|
| AWS IAM Identity Center (SSO) | `~/.aws/credentials` with static `aws_access_key_id` / `aws_secret_access_key` |
| Azure CLI with MSAL | `~/.azure/accessTokens.json` (legacy ADAL cache) |
| Git `osxkeychain` credential helper | `~/.git-credentials` with plaintext tokens |
| Kubernetes exec plugins | `~/.kube/config` with stale embedded tokens and certificates |
| Encrypted or hardware-backed SSH key | Original unencrypted `~/.ssh/id_rsa` kept as "backup" |
| Docker credential store | `~/.docker/config.json` with base64 `auths` entries alongside `credsStore` |
| PyPI keyring | `~/.pypirc` still containing `password` field |
| Cargo Keychain provider | `~/.cargo/credentials.toml` with plaintext token |

## How to prevent it

**During remediation:** explicitly delete or clear the legacy file as a discrete step. Do not assume that configuring the new mechanism removes the old artifact.

**After remediation:** re-run clawback to verify the plaintext file is gone, not just that the new configuration is in place:

```bash
python3 clawback.py --pretty
```

**In clawback itself:** this pattern warrants a dedicated detection. After observing a secure configuration (SSO profile present, credential helper configured, exec plugin in kubeconfig), also check whether the legacy plaintext artifact still exists. If it does, emit a finding even though the "correct" configuration is in place.

## The AWS prioritization bug

A specific instance worth highlighting: when both `~/.aws/credentials` (with static keys) and `~/.aws/config` (with SSO profiles) exist, the AWS CLI uses the SSO profile for commands that specify it via `--profile`. But the static keys remain accessible to any process that reads the credentials file directly, and some SDKs will prefer the static keys over SSO when no profile is specified. The developer experiences no breakage, masking the latent exposure.

The fix is simple: after confirming SSO works, delete `~/.aws/credentials` entirely or remove the static key entries from it.
