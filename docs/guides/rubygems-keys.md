---
title: RubyGems API Keys
parent: Remediation Guides
nav_order: 9
description: >-
  Remediate RubyGems API keys found by clawback in ~/.gem/credentials.
clawback_category: package_manager_tokens
---

# RubyGems API keys
{: .no_toc }

RubyGems API keys in `~/.gem/credentials` grant push access to the RubyGems.org registry.

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
| `~/.gem/credentials` | HIGH | YAML file containing RubyGems API key |

## Why it's exposed

`gem push` reads API keys from `~/.gem/credentials`. Developers create a key via the RubyGems.org web UI and paste it into this file. The file persists indefinitely.

## Tier 1: Eliminate the static credential

### OIDC Trusted Publishing (for CI)

RubyGems supports OIDC Trusted Publishing since December 2023. CI publishes gems using ephemeral tokens with no stored secret.

**CI setup (GitHub Actions):**

```yaml
permissions:
  id-token: write
steps:
  - uses: actions/checkout@v4
  - uses: rubygems/release-gem@v1
```

Configure the Trusted Publisher in RubyGems.org gem settings (link your GitHub repository and workflow).

**Implication:** developers stop publishing from local workstations.

## Tier 2: Vault the credential

### Environment variable injection

RubyGems reads `GEM_HOST_API_KEY` from the environment if `~/.gem/credentials` does not exist.

**With Keychain:**

```bash
security add-generic-password -U -s "GEM_HOST_API_KEY" \
  -a "$(whoami)" -w "<RUBYGEMS_API_KEY>"

export GEM_HOST_API_KEY=$(security find-generic-password \
  -s "GEM_HOST_API_KEY" -a "$(whoami)" -w)
gem push my_gem-1.0.0.gem
```

**With 1Password:**

```bash
op run --env-file .env -- gem push my_gem-1.0.0.gem
# Where .env contains: GEM_HOST_API_KEY="op://Development/RubyGems/api-key"
```

Then delete the credentials file:

```bash
rm ~/.gem/credentials
```

## Tier 3: Reduce blast radius

- Scope API keys per-gem (push-only for specific gems)
- Enforce MFA (OTP on publish): `gem push my_gem.gem --otp=123456`

{: .note }
> MFA is **not enabled by default** on RubyGems accounts. You must explicitly enable it in the RubyGems.org account settings. Do this regardless of which tier you adopt.

## Verification

```bash
ls -la ~/.gem/credentials  # should not exist

# If GEM_HOST_API_KEY is used, verify it's not hardcoded in shell profile
grep "GEM_HOST_API_KEY" ~/.zshrc ~/.bashrc 2>/dev/null  # should find nothing

python3 clawback.py --category package_manager_tokens --pretty
```

## Common mistakes

- **Not enabling MFA on the RubyGems account.** MFA is the single most effective blast-radius reduction for gem publishing, but it requires explicit opt-in.
- **Publishing from local workstations when CI OIDC eliminates the need.** With Trusted Publishing, the local API key can be deleted entirely.

## CI/CD implications

**CI change required: yes.**

OIDC Trusted Publishing via `rubygems/release-gem@v1` is the recommended pattern. Eliminates stored tokens from CI entirely.
