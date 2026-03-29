---
title: GCP Application Default Credentials
parent: Remediation Guides
nav_order: 2
description: >-
  Remediate GCP service account key files and ADC configurations found by
  clawback in ~/.config/gcloud/ and GOOGLE_APPLICATION_CREDENTIALS.
clawback_category: cloud_credentials
---

# GCP application default credentials
{: .no_toc }

GCP Application Default Credentials (ADC) provide a uniform way for Google Cloud client libraries to authenticate. The problem is when ADC resolves to a service account key file -- a long-lived JSON credential that grants persistent access to GCP resources.

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
| `~/.config/gcloud/application_default_credentials.json` with `"type": "service_account"` | CRITICAL | Service account key file as ADC |
| `~/.config/gcloud/application_default_credentials.json` with `"type": "authorized_user"` | INFO (observation) | User ADC -- short-lived, acceptable |
| `GOOGLE_APPLICATION_CREDENTIALS` env var pointing to a key file | HIGH | Locator pointing to service account key material |
| Service account JSON files on disk | CRITICAL | Key files downloaded from GCP console |

## Why it's exposed

Developers download service account key files from the GCP console "for local testing" and set `GOOGLE_APPLICATION_CREDENTIALS` to point at them. Some tutorials still recommend this workflow. The key file is a JSON document containing a private RSA key with no expiration -- it grants access until explicitly revoked.

A common confusion: developers run `gcloud auth login` (authenticates only the `gcloud` CLI) and assume their SDKs are also authenticated. They are not -- SDKs use ADC, which requires `gcloud auth application-default login`.

## Tier 1: Eliminate the static credential

### User ADC (for local development)

Produces short-lived user credentials that SDKs pick up automatically. No key file on disk.

**Setup:**

```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project <PROJECT_ID>
```

**Daily workflow:** transparent. SDKs resolve ADC automatically. Re-auth when tokens expire (~1 hour).

**What breaks:** some operations require service account permissions that the user does not have directly. Use impersonation (below) for those cases.

### Service account impersonation

Your user identity assumes service account permissions. No key file on disk -- the ADC file contains a reference to the service account, not key material.

**Setup:**

```bash
# Grant your user the Token Creator role on the service account
gcloud iam service-accounts add-iam-policy-binding \
  SA_NAME@PROJECT_ID.iam.gserviceaccount.com \
  --member="user:YOUR_EMAIL@example.com" \
  --role="roles/iam.serviceAccountTokenCreator"

# Configure ADC to use impersonation
gcloud auth application-default login \
  --impersonate-service-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com
```

**Daily workflow:** transparent. SDKs request short-lived tokens (default 1 hour, configurable up to 12 hours with org policy) on your behalf.

### Workload Identity Federation

For non-GCP environments (CI, other clouds). Eliminates key distribution entirely by establishing OIDC trust between the identity provider and GCP.

**Setup:**

```bash
gcloud iam workload-identity-pools create-cred-config \
  projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$PROVIDER_ID \
  --service-account=$SERVICE_ACCOUNT_EMAIL \
  --output-file=credential-config.json
export GOOGLE_APPLICATION_CREDENTIALS=credential-config.json
```

The config file contains federation metadata, not key material.

## Tier 2: Vault the credential

### 1Password injection

For cases where a service account key file must temporarily exist (legacy tools that require a file path):

```bash
op read "op://Infrastructure/GCP-SA-Key/key.json" > /tmp/gcp-key.json
export GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp-key.json

# After use
rm /tmp/gcp-key.json
unset GOOGLE_APPLICATION_CREDENTIALS
```

{: .warning }
> Temporary files are vulnerable to crash dumps, process list inspection, and filesystem forensics. Prefer Tier 1 approaches.

## Tier 3: Reduce blast radius

- Restrict service account permissions to the minimum required
- Set organization policies limiting key creation (`constraints/iam.disableServiceAccountKeyCreation`)
- Rotate keys on a schedule if they must exist
- Use short-lived tokens where APIs support them

## Verification

```bash
# Check ADC file type (should be "authorized_user", not "service_account")
cat ~/.config/gcloud/application_default_credentials.json | python3 -c \
  "import sys,json; print(json.load(sys.stdin).get('type','missing'))"

# Check for service account key files
find ~ -name "*.json" -exec grep -l '"type": "service_account"' {} \; 2>/dev/null

# Check GOOGLE_APPLICATION_CREDENTIALS
echo "$GOOGLE_APPLICATION_CREDENTIALS"  # should be empty or point to a WIF config

python3 clawback.py --category cloud_credentials --pretty
```

## Common mistakes

- **Running `gcloud auth login` instead of `gcloud auth application-default login`.** The former authenticates only the `gcloud` CLI. SDKs use a separate credential chain (ADC) and remain unauthenticated.
- **Downloading a service account key "just for testing" and leaving it on disk.** Key files have no expiration. "Just for testing" becomes permanent.
- **Setting `GOOGLE_APPLICATION_CREDENTIALS` permanently in `.zshrc`.** Even if it points to a WIF config today, this locks the developer into a specific credential flow. Prefer letting ADC resolve naturally.
- **ADC resolution order confusion.** ADC resolves in order: (1) `GOOGLE_APPLICATION_CREDENTIALS` env var, (2) well-known ADC file (`~/.config/gcloud/application_default_credentials.json`), (3) metadata server. Setting the env var overrides the file, which can mask a migration.

## CI/CD implications

**CI change required: yes.**

Replace service account key files in CI with Workload Identity Federation (OIDC):

| CI platform | Pattern |
|-------------|---------|
| GitHub Actions | `google-github-actions/auth` with Workload Identity Federation |
| GitLab CI | OIDC token exchange with WIF pool |
