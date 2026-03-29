---
title: Azure Cached Tokens and Client Secrets
parent: Remediation Guides
nav_order: 3
description: >-
  Remediate Azure CLI token caches and service principal secrets found by
  clawback in ~/.azure/ and AZURE_CLIENT_SECRET.
clawback_category: cloud_credentials
---

# Azure cached tokens and client secrets
{: .no_toc }

Azure CLI caches authentication tokens on disk. On macOS, these caches are **stored in plaintext by default** -- unlike Windows, where DPAPI encryption is used. This makes them a high-value target for credential exfiltration.

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
| `~/.azure/msal_token_cache.json` | HIGH | MSAL token cache, plaintext on macOS by default |
| `~/.azure/accessTokens.json` | HIGH | Legacy ADAL token cache (deprecated, should not exist) |
| `AZURE_CLIENT_SECRET` env var | CRITICAL | Service principal client secret in environment |

## Why it's exposed

`az login` authenticates via browser or device code and caches the resulting tokens at `~/.azure/msal_token_cache.json`. On Windows, this cache is encrypted via DPAPI. On macOS, it is stored in plaintext -- a platform gap that Microsoft has not fully addressed. Refresh tokens in the cache can last up to 90 days of inactivity.

Service principal secrets (`AZURE_CLIENT_SECRET`) are often exported in `.zshrc` or `.env` for local development with Terraform or application code.

**Requirements:** Azure CLI v2.30.0+ (for MSAL integration). Starting September 2025, Microsoft requires MFA for all Azure CLI user identities.

## Tier 1: Eliminate the static credential

### Interactive login with cache hygiene

`az login` with browser or device code authentication, combined with explicit cache cleanup.

**Setup:**

```bash
az login
# Or for SSH/remote sessions:
az login --use-device-code
```

**Daily workflow:** authenticate when needed; purge the cache when done:

```bash
az logout
rm -f ~/.azure/msal_token_cache.json
rm -f ~/.azure/accessTokens.json
```

**The token encryption flag:** an experimental flag exists to encrypt the token cache on macOS:

```bash
az config set core.encrypt_token_cache=true
```

{: .warning }
> This flag has known reliability issues with the macOS Keychain. Set it, but do not rely on it as your sole protection. Also purge the cache on logout.

### Certificate-based service principal auth

Replaces client secrets with X.509 certificates for service principal authentication.

**Setup:**

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=MyAzureSP"
az login --service-principal -u <APP_ID> --tenant <TENANT_ID> --certificate cert.pem
```

### Managed Identity

For Azure-hosted workloads. No credentials on the developer workstation.

## Tier 2: Vault the credential

### Keychain injection for client secrets

```bash
# Store
security add-generic-password -U -s "AZURE_CLIENT_SECRET" \
  -a "$(whoami)" -w "<PASTE_SECRET_HERE>"

# Retrieve at runtime
export AZURE_CLIENT_SECRET=$(security find-generic-password \
  -s "AZURE_CLIENT_SECRET" -a "$(whoami)" -w)
```

### 1Password CLI

```bash
op run --env-file .env -- terraform apply
# Where .env contains: AZURE_CLIENT_SECRET="op://Infrastructure/Azure-SP/secret"
```

## Tier 3: Reduce blast radius

- Scope service principals to specific resource groups
- Enable Continuous Access Evaluation (CAE) for near-real-time token revocation
- Apply Conditional Access policies restricting login by location and device
- Rotate client secrets on a 90-day schedule

## Verification

```bash
# Check for plaintext token caches
ls -la ~/.azure/msal_token_cache.json  # should not exist after logout
ls -la ~/.azure/accessTokens.json      # legacy, should never exist

# Check encryption flag
az config get core.encrypt_token_cache

# Check for AZURE_CLIENT_SECRET in environment
env | grep AZURE_CLIENT_SECRET  # should be empty

python3 clawback.py --category cloud_credentials --pretty
```

## Common mistakes

- **Assuming `az login` is secure because it uses a browser.** The authentication is secure; the resulting tokens are cached in plaintext on macOS.
- **Not deleting `~/.azure/accessTokens.json` after upgrading Azure CLI.** The legacy ADAL cache may persist even after MSAL migration.
- **`az logout` alone is insufficient.** It revokes the session but does not always delete the cache file. Explicitly remove `~/.azure/msal_token_cache.json`.
- **Relying solely on `encrypt_token_cache`.** The flag is experimental and has documented reliability issues on macOS. Use it as defense-in-depth, not as the primary control.

## CI/CD implications

**CI change required: yes.**

Replace service principal client secrets in CI with Federated Credentials (OIDC) or Managed Identity:

| CI platform | Pattern |
|-------------|---------|
| GitHub Actions | `azure/login` with OIDC and Federated Credentials |
| Azure DevOps | Managed Identity on self-hosted agents |
