---
title: Cargo / crates.io Tokens
parent: Remediation Guides
nav_order: 10
description: >-
  Remediate crates.io tokens found by clawback in
  ~/.cargo/credentials.toml.
clawback_category: package_manager_tokens
---

# Cargo / crates.io tokens
{: .no_toc }

Cargo stores crates.io authentication tokens in `~/.cargo/credentials.toml` in plaintext by default.

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
| `~/.cargo/credentials.toml` with plaintext token | HIGH | crates.io publish token |

## Why it's exposed

`cargo login` writes the token to `~/.cargo/credentials.toml`. Cargo's default credential provider (`cargo:token`) stores tokens unencrypted. Most Rust developers are unaware that alternative providers exist.

## Tier 1: Eliminate the static credential

### OIDC Trusted Publishing (for CI)

Available since July 2025 on crates.io. Not yet widely adopted but is the future direction.

Check crates.io documentation for current setup instructions, as the feature is still maturing.

## Tier 2: Vault the credential

### macOS Keychain provider (recommended)

Cargo has a native macOS Keychain credential provider. No additional software required.

**Setup:**

```bash
# Configure Cargo to use Keychain
cat >> ~/.cargo/config.toml << 'EOF'

[registry]
global-credential-providers = ["cargo:macos-keychain"]
EOF

# Re-login (token goes to Keychain)
cargo login
```

{: .warning }
> **Provider order matters.** Cargo's default provider is `cargo:token`, which stores unencrypted. You must explicitly configure `global-credential-providers` in `~/.cargo/config.toml` to use the Keychain provider. Without this configuration, `cargo login` writes plaintext regardless of whether the Keychain provider is installed.

Then delete the old plaintext credentials:

```bash
rm -f ~/.cargo/credentials.toml
```

### 1Password credential provider

For teams already on 1Password:

```bash
cargo install cargo-credential-1password
```

**`~/.cargo/config.toml`:**

```toml
[registry]
global-credential-providers = [
  "cargo:token",
  "cargo-credential-1password --account my.1password.com"
]
```

```bash
cargo login
```

## Tier 3: Reduce blast radius

crates.io supports scoped tokens with specific endpoint permissions:

- `publish-new` -- publish new crates
- `publish-update` -- publish new versions of existing crates
- `yank` -- yank versions

Set expiration dates on tokens. Use the most restrictive scope needed.

## Verification

```bash
# Check for plaintext credentials file
ls -la ~/.cargo/credentials.toml  # should not exist

# Verify credential provider configuration
grep "global-credential-providers" ~/.cargo/config.toml

python3 clawback.py --category package_manager_tokens --pretty
```

## Common mistakes

- **Not configuring `global-credential-providers`.** Without explicit configuration, Cargo uses `cargo:token` (unencrypted) by default.
- **Storing `CARGO_REGISTRIES_<NAME>_TOKEN` in dotfiles.** This reintroduces the plaintext problem through environment variables.
- **Deleting `credentials.toml` without configuring an alternative provider.** Publishing will fail.

## CI/CD implications

**CI change required: not yet (for most teams).** OIDC Trusted Publishing is available since July 2025 but not yet widely adopted. For now, store scoped tokens in the CI platform's native secret store. Monitor crates.io for maturation of the Trusted Publishing feature.
