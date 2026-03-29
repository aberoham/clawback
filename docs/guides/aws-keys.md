---
title: AWS Static Access Keys
parent: Remediation Guides
nav_order: 1
description: >-
  Remediate AWS access key IDs and secret access keys found by clawback
  in ~/.aws/credentials, environment variables, and shell profiles.
clawback_category: cloud_credentials
---

# AWS static access keys
{: .no_toc }

AWS static access keys are long-lived IAM credentials that grant programmatic access to AWS services. They are the most common cloud credential found on developer workstations and a primary target for supply chain malware.

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
| `~/.aws/credentials` | HIGH-CRITICAL | Static `aws_access_key_id` and `aws_secret_access_key` in INI format |
| `AWS_ACCESS_KEY_ID` env var | CRITICAL | Access key exported in environment |
| `AWS_SECRET_ACCESS_KEY` env var | CRITICAL | Secret key exported in environment |
| `AWS_SESSION_TOKEN` env var | MEDIUM | Session token (short-lived, but indicates credential workflow) |
| `~/.zshrc`, `.env` files | HIGH | Keys hardcoded in shell profiles or environment files |

## Why it's exposed

Running `aws configure` writes long-lived IAM user keys to `~/.aws/credentials`. Developers copy keys from the IAM console during onboarding and never revisit the setup. Some tools and tutorials still default to this workflow. Keys in `.zshrc` or `.env` files usually start as "temporary" and become permanent.

## Tier 1: Eliminate the static credential

### AWS IAM Identity Center (SSO)

The primary Tier 1 solution. Replaces static keys with short-lived session tokens obtained via browser-based SSO login.

**Requirements:** AWS CLI v2.22.0+ (for PKCE support). AWS Organizations with Identity Center configured.

**Setup** (one-time):

```bash
aws configure sso
# Follow the interactive prompts to configure:
#   SSO session name, SSO start URL, SSO region, account, role
```

**Daily workflow:**

```bash
aws sso login --profile <PROFILE_NAME>
aws sts get-caller-identity --profile <PROFILE_NAME>
```

Tokens are cached in `~/.aws/sso/cache/` and auto-expire. The `~/.aws/config` file contains only SSO metadata, no secrets.

**What breaks:** AWS CLI v1 does not support SSO. Some older Terraform providers (pre-v1.3) and legacy SDKs may not resolve SSO credential chains. Workaround: use `credential_process` or bridge through `aws-vault exec`.

### Granted / assume

A UX wrapper for AWS SSO profiles that exports credentials directly into the current shell (no subshell required).

**Setup:**

```bash
brew tap common-fate/granted && brew install granted
echo 'alias assume="source assume"' >> ~/.zshrc
```

**Daily workflow:**

```bash
assume <PROFILE_NAME>
# Credentials are exported into the current shell
aws s3 ls  # works directly, no wrapper needed
```

{: .note }
> Granted is a UX layer, not an auth mechanism. It is Tier 1 only when the underlying profile uses SSO. If the profile wraps static keys, Granted is Tier 2.

## Tier 2: Vault the credential

### aws-vault

Stores the IAM master key in an encrypted macOS Keychain, generates short-lived STS tokens (1-hour default) per session.

{: .warning }
> The original 99designs/aws-vault repo was marked abandoned in 2025. The maintained fork is ByteNess/aws-vault (v7.3+). Homebrew still ships v7.2.0 from the original formula.

**Setup:**

```bash
brew install aws-vault
aws-vault add <PROFILE_NAME>
# Enter Access Key Id and Secret Key when prompted
```

**Daily workflow:**

```bash
aws-vault exec <PROFILE_NAME> -- aws s3 ls

# Or spawn a subshell with credentials injected
aws-vault exec <PROFILE_NAME>
aws sts get-caller-identity
exit
```

**Friction note:** high friction due to the command-wrapping requirement. The default 5-minute keychain lock timeout exacerbates this. For long-running processes, use `--server` mode:

```bash
aws-vault exec --server <PROFILE_NAME> -- terraform apply
```

### 1Password CLI

```bash
# .env file with op:// references
AWS_ACCESS_KEY_ID="op://Development/AWS/access-key-id"
AWS_SECRET_ACCESS_KEY="op://Development/AWS/secret-access-key"

op run --env-file .env -- aws s3 ls
```

### macOS Keychain via envchain

```bash
brew install envchain
envchain --set aws AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
envchain aws aws s3 ls
```

## Tier 3: Reduce blast radius

When static keys cannot be eliminated or vaulted:

- Apply least-privilege IAM policies to the key's user
- Enable MFA on the IAM user and require MFA for sensitive operations
- Restrict source IP addresses via IAM policy conditions
- Rotate keys aggressively (every 30-90 days)
- Set up CloudTrail alerting on key usage from unexpected IPs or services

## Verification

**After Tier 1:**

```bash
# Confirm no static keys in credentials file
cat ~/.aws/credentials 2>/dev/null  # should be empty or not exist

# Confirm SSO is working
aws sts get-caller-identity --profile <PROFILE_NAME>

# Run clawback
python3 clawback.py --category cloud_credentials --pretty
```

**After Tier 2:**

```bash
# Confirm credentials file is gone
ls -la ~/.aws/credentials  # should not exist

# Confirm aws-vault has the key
aws-vault list
```

## Common mistakes

- **Setting up SSO but leaving `~/.aws/credentials` intact.** The AWS CLI prioritizes SSO when a profile is specified, masking the latent plaintext exposure. Delete the credentials file after confirming SSO works. See [The Orphaned File Anti-Pattern](../concepts/orphaned-files.md).
- **Using `credential_process` with a script that caches to a temp file.** This reintroduces plaintext on disk in a different location.
- **Exporting `AWS_ACCESS_KEY_ID` in `.zshrc` "temporarily" and forgetting.** Environment variables persist across all shells and child processes.
- **AWS CLI v1.** Does not support SSO natively. Upgrade to v2.22.0+ or use `aws-vault` as a bridge.

## CI/CD implications

**CI change required: yes.**

Remove static IAM keys from CI secrets. Replace with OIDC role assumption:

| CI platform | Pattern |
|-------------|---------|
| GitHub Actions | `aws-actions/configure-aws-credentials` with `role-to-assume` and `id-token: write` permission |
| GitLab CI | OIDC with `CI_JOB_JWT_V2` and IAM role trust policy |

Set up CI OIDC first, verify it works, then remove local keys.
