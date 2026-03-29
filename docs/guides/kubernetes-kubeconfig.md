---
title: Kubernetes Kubeconfig
parent: Remediation Guides
nav_order: 11
description: >-
  Remediate embedded tokens and certificates found by clawback in
  ~/.kube/config.
clawback_category: kubernetes
---

# Kubernetes kubeconfig
{: .no_toc }

Kubeconfig files can embed long-lived bearer tokens, client certificates, and private keys. These are persistent credentials that grant cluster access to any process that can read the file.

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
| `~/.kube/config` with `token` field | HIGH | Embedded bearer token |
| `~/.kube/config` with `client-certificate-data` | HIGH | Embedded client certificate |
| `~/.kube/config` with `client-key-data` | CRITICAL | Embedded client private key |

## Why it's exposed

Cloud provider CLI tools (`aws eks`, `gcloud container clusters`, `az aks`) write kubeconfig entries with embedded credentials when not configured for exec-based auth. Stale entries accumulate as developers work with multiple clusters over time. `kubectl config view --flatten` creates "portable" kubeconfig files that embed even more credentials.

## Tier 1: Eliminate the static credential

### Exec-based auth plugins

Replace embedded credentials with exec entries that generate short-lived tokens on each `kubectl` call.

**AWS EKS:**

```bash
aws eks update-kubeconfig --name <CLUSTER_NAME> --region <REGION>
# Generates exec entry using aws eks get-token (~15-minute bearer tokens)
```

**GKE:**

```bash
gcloud components install gke-gcloud-auth-plugin
gcloud container clusters get-credentials <CLUSTER> \
  --location=<REGION> --project=<PROJECT>
```

Required since GKE v1.26. The kubeconfig `user` entry uses `exec` with `gke-gcloud-auth-plugin`.

**AKS:**

```bash
brew install Azure/kubelogin/kubelogin
az aks get-credentials --resource-group <RG> --name <CLUSTER>
kubelogin convert-kubeconfig -l azurecli
```

**Teleport:**

```bash
tsh login --proxy=teleport.example.com
tsh kube login <CLUSTER>
# Issues short-lived Kubernetes certificates
```

After configuring exec plugins, clean up stale embedded credentials:

```bash
# Audit: find users with embedded credentials
kubectl config view --raw -o json | python3 -c "
import sys, json
cfg = json.load(sys.stdin)
for user in cfg.get('users', []):
    u = user.get('user', {})
    if u.get('exec'):
        print(f'{user[\"name\"]} -> exec (good)')
    elif u.get('token') or u.get('client-key-data'):
        print(f'{user[\"name\"]} -> EMBEDDED (remediate)')
    else:
        print(f'{user[\"name\"]} -> unknown')
"

# Remove stale entries
kubectl config delete-context <STALE_CONTEXT>
kubectl config unset users.<STALE_USER>
```

## Tier 3: Reduce blast radius

- Remove stale cluster contexts and users from kubeconfig
- Restrict kubeconfig file permissions: `chmod 600 ~/.kube/config`
- Use separate kubeconfig files per cluster via `KUBECONFIG` env var
- Never share kubeconfig files between team members

## Verification

```bash
# Check for embedded credentials
kubectl config view --raw -o json | python3 -c "
import sys, json
cfg = json.load(sys.stdin)
bad = [u['name'] for u in cfg.get('users', [])
       if u.get('user', {}).get('token')
       or u.get('user', {}).get('client-key-data')
       or u.get('user', {}).get('client-certificate-data')]
if bad:
    print(f'FINDING: embedded credentials in: {bad}')
else:
    print('OK: all users use exec plugins')
"

python3 clawback.py --category kubernetes --pretty
```

## Common mistakes

- **`kubectl config view --flatten` for portability.** This embeds all credentials into a single file, increasing blast radius. Never share flattened kubeconfig files.
- **Not cleaning up stale contexts.** Developers accumulate kubeconfig entries for clusters that no longer exist or that they no longer access. Each stale entry with embedded credentials is an unnecessary exposure.
- **Transitioning to exec plugins but not clearing orphaned `token` fields.** The exec plugin works, but the old embedded token remains in the file. Run `kubectl config unset users.<name>.token` explicitly.
- **Sharing kubeconfig files between team members.** Each developer should authenticate independently.

## CI/CD implications

**CI change required: yes.**

CI should use exec plugins or OIDC-based service accounts. For cloud-managed clusters, use the same exec plugin pattern as local development but with CI-specific service account credentials (injected via OIDC or the CI platform's secret store).
