---
title: Docker Registry Auth
parent: Remediation Guides
nav_order: 8
description: >-
  Remediate Docker registry credentials found by clawback in
  ~/.docker/config.json.
clawback_category: package_manager_tokens
---

# Docker registry auth
{: .no_toc }

Docker stores registry credentials in `~/.docker/config.json`. By default, these are base64-encoded (not encrypted) in the `"auths"` section.

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
| `~/.docker/config.json` with `"auths"` containing base64 credentials | HIGH | Base64-encoded registry credentials (trivially decodable) |

## Why it's exposed

`docker login` writes base64-encoded credentials to `~/.docker/config.json` by default. Base64 is encoding, not encryption -- the credentials are trivially recoverable. Docker supports credential helpers but does not enable them by default.

## Tier 1: Eliminate the static credential

### Cloud-native credential helpers

Cloud registries provide helpers that generate short-lived tokens (ECR: 12 hours) with no persistent credential on disk.

**AWS ECR:**

```bash
brew install docker-credential-helper-ecr
```

**GCP Artifact Registry:**

```bash
gcloud auth configure-docker REGION-docker.pkg.dev
```

**Azure Container Registry:**

```bash
az acr login --name REGISTRY_NAME
```

**`~/.docker/config.json` with cloud helpers:**

```json
{
  "credHelpers": {
    "123456789.dkr.ecr.us-east-1.amazonaws.com": "ecr-login",
    "us-docker.pkg.dev": "gcloud",
    "myregistry.azurecr.io": "az"
  }
}
```

## Tier 2: Vault the credential

### macOS Keychain credential store

Moves all registry credentials from plaintext to Keychain.

**Setup:**

```bash
# Log out of all registries first
docker logout
docker logout ghcr.io
docker logout registry.example.com

# Install the helper (if not already present)
brew install docker-credential-helper

# Configure Docker to use Keychain
cat > ~/.docker/config.json << 'EOF'
{
  "credsStore": "osxkeychain"
}
EOF

# Re-authenticate (credentials now go to Keychain)
docker login
```

{: .warning }
> **Silent failure:** Installing `docker-credential-osxkeychain` via Homebrew does NOT automatically update `config.json`. Docker silently continues writing plaintext to the `auths` section. You must manually set `"credsStore": "osxkeychain"` in the config file.

## Verification

```bash
# Check Docker config
cat ~/.docker/config.json
# Should have "credsStore" or "credHelpers", NOT "auths" with base64 values

# The "auths" section should be empty or absent
python3 -c "
import json
with open('$HOME/.docker/config.json') as f:
    cfg = json.load(f)
auths = cfg.get('auths', {})
for reg, val in auths.items():
    if val.get('auth'):
        print(f'FINDING: {reg} has base64 credential')
if not auths or all(not v.get('auth') for v in auths.values()):
    print('OK: no plaintext credentials')
"

python3 clawback.py --category package_manager_tokens --pretty
```

## Common mistakes

- **Installing the credential helper binary without configuring `config.json`.** This is the most common Docker remediation failure. The helper sits unused while Docker continues writing plaintext.
- **Running `docker logout` for one registry but not others.** Each registry is stored independently. Log out of all registries before switching to the credential store.
- **Mixing `credsStore` and `credHelpers`.** `credHelpers` takes precedence for specific registries; `credsStore` is the fallback. This is fine, but ensure the `auths` section is empty.

## CI/CD implications

**CI change required: sometimes.** If CI pulls from cloud registries, use the cloud-native credential helpers with OIDC role assumption. Docker Hub credentials in CI should be stored in the platform's native secret store, not in `config.json`.
