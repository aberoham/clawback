---
title: npm Tokens
parent: Remediation Guides
nav_order: 6
description: >-
  Remediate npm authentication tokens found by clawback in ~/.npmrc.
clawback_category: package_manager_tokens
---

# npm tokens
{: .no_toc }

npm tokens in `~/.npmrc` are a primary supply chain attack vector. The November 2025 Shai-Hulud worm exploited stolen `~/.npmrc` tokens to propagate across the npm ecosystem, accelerating npm's revocation of classic tokens on December 9, 2025.

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
| `~/.npmrc` containing `_authToken=` | CRITICAL | npm authentication token in plaintext |
| `~/.npmrc` containing `_auth=` | CRITICAL | Base64-encoded credentials |
| Project-level `.npmrc` with tokens | HIGH | Token in project directory (may be committed to Git) |

## Why it's exposed

`npm login` historically wrote a long-lived token to `~/.npmrc`. This token had full publish access to all packages the user owned. The CanisterWorm attack specifically targeted this file for worm-style propagation -- a stolen publish token lets malware publish compromised versions of every package the developer maintains.

## Tier 1: Eliminate the static credential

### Web-based session authentication

Generates 2-hour session tokens via browser-based SSO and WebAuthn. No persistent token stored.

**Requirements:** npm >= 10.

**Setup:**

```bash
npm login --auth-type=web
# Opens browser for authentication
# Generates a session-bound token that expires in 2 hours
```

**Daily workflow:**

```bash
npm whoami  # verify session
npm publish  # works within the 2-hour window
```

### OIDC Trusted Publishing (for CI)

Eliminates stored tokens from CI entirely. The CI platform exchanges a signed JWT for a short-lived publish token.

**Requirements:** npm >= 11.5.1 and Node >= 22.14.0 (strict version gate).

**CI setup (GitHub Actions):**

```yaml
permissions:
  id-token: write
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: '22'
      registry-url: 'https://registry.npmjs.org'
  - run: npm publish --provenance --access public
```

## Tier 2: Vault the credential

### Environment variable substitution

Use `${NPM_TOKEN}` in `.npmrc` and inject the value from a secure store at runtime.

**`.npmrc`:**

```ini
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

**With 1Password:**

```bash
# .env file
NPM_TOKEN="op://Development/npm/token"

op run --env-file .env -- npm publish
```

**With Keychain:**

```bash
security add-generic-password -U -s "NPM_TOKEN" -a "$(whoami)" -w "<TOKEN>"
export NPM_TOKEN=$(security find-generic-password -s "NPM_TOKEN" -a "$(whoami)" -w)
npm publish
```

## Tier 3: Reduce blast radius

Since November 2025, classic (unscoped) tokens are revoked. Only granular access tokens are supported:

- Scope tokens to specific packages
- Set expiration dates (7-day recommended for development)
- Enable IP address allowlisting (CIDR notation)
- Enforce 2FA on the npm account

```bash
npm token ls  # audit active tokens and their scopes
```

## Verification

```bash
# Check for tokens in .npmrc
grep -n "_authToken\|_auth=" ~/.npmrc .npmrc 2>/dev/null
# Should be empty or use ${NPM_TOKEN} substitution only

npm whoami  # verify current session

python3 clawback.py --category package_manager_tokens --pretty
```

## Common mistakes

- **Using `${NPM_TOKEN}` in `.npmrc` but hardcoding `export NPM_TOKEN="npm_..."` in `~/.zshrc`.** The `.npmrc` is clean, but the plaintext token is now in your shell profile. This is not remediation -- it is relocation.
- **Publishing from local workstations when CI Trusted Publishing eliminates the need.** If all publishing goes through CI, there is no reason for a local publish token to exist.
- **Not auditing active tokens.** Run `npm token ls` and revoke any tokens you do not recognize or no longer need.

## CI/CD implications

**CI change required: yes.**

OIDC Trusted Publishing is the recommended CI pattern. Note the strict version requirements: npm >= 11.5.1 and Node >= 22.14.0. If your CI environment cannot meet these requirements yet, use scoped granular tokens with short expiration stored in the CI platform's native secret store.
