---
title: CI/CD Implications Matrix
parent: Concepts
nav_order: 5
---

# CI/CD implications matrix
{: .no_toc }

Many static credentials on developer workstations exist because the same credential is used in CI. Removing the local key without first setting up independent CI authentication will break pipelines.

---

## The rule

**Set up CI authentication first, verify it works, then remove local keys.**

This ordering is non-negotiable. If CI pipelines still consume static secrets, endpoint remediation merely relocates risk rather than eliminating it.

## Matrix

| Credential type | CI change required? | Recommended CI pattern |
|----------------|--------------------|-----------------------|
| AWS static access keys | Yes | OIDC with GitHub Actions / GitLab CI, assuming an IAM role |
| GCP service account keys | Yes | Workload Identity Federation (OIDC) |
| Azure client secrets | Yes | Managed Identity or Federated Credentials (OIDC) |
| SSH keys | Yes | Per-repo deploy keys, not developer personal keys |
| Git credentials | Rarely | CI typically uses deploy tokens or app installation tokens already |
| npm tokens | Yes | OIDC Trusted Publishing (requires npm >=11.5.1, Node >=22.14.0) |
| PyPI credentials | Yes | Trusted Publishers via OIDC (15-minute ephemeral tokens) |
| Docker registry auth | Sometimes | Cloud-native helpers (ECR/GCR/ACR) with OIDC role assumption |
| RubyGems API keys | Yes | OIDC Trusted Publishing (`rubygems/release-gem@v1`) |
| Cargo/crates.io tokens | Not yet | OIDC Trusted Publishing (available July 2025+, not yet widely adopted) |
| Kubernetes kubeconfig | Yes | Exec plugins or OIDC-based service accounts |
| Shell/.env secrets | Yes | Secrets injection from CI platform's native secret store |
| Cryptocurrency wallets | N/A | Never in CI |

## The OIDC pattern

Most CI remediation converges on the same pattern: OpenID Connect (OIDC) establishes a cryptographically signed trust relationship between the CI provider (GitHub Actions, GitLab CI, CircleCI) and the target service (AWS, GCP, PyPI, npm).

Benefits:
- No static secrets to rotate or leak
- Access automatically scoped to specific repositories and branches
- Immutable audit trail
- Tokens are ephemeral (minutes, not months)

The CI provider generates a signed JWT on each pipeline run. The target service validates the JWT against the CI provider's OIDC discovery endpoint and issues short-lived credentials. No human-managed secret is involved.

## Trusted publishing adoption status

As of March 2026:

| Registry | OIDC support | Maturity |
|----------|-------------|----------|
| PyPI | Trusted Publishers | Mature, widely adopted |
| npm | Trusted Publishing | Available (npm >=11.5.1, Node >=22.14.0), strict version gate |
| RubyGems | Trusted Publishing | Available since December 2023 |
| crates.io | Trusted Publishing | Available since July 2025, early adoption |
| Docker Hub | Not available | Use cloud-native registries (ECR/GCR/ACR) instead |
