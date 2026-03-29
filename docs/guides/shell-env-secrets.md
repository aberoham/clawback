---
title: Shell Profile and .env File Secrets
parent: Remediation Guides
nav_order: 12
description: >-
  Remediate hardcoded API keys and secrets found by clawback in shell
  profiles (~/.zshrc) and .env files.
clawback_category: shell_profiles
---

# Shell profile and .env file secrets
{: .no_toc }

Hardcoded secrets in shell profiles (`~/.zshrc`, `~/.bashrc`) and `.env` files are the most common form of credential exposure on developer workstations. Every child process inherits these values, and any malware with file read access can harvest them.

This guide covers three clawback categories: `shell_profiles`, `environment_variables`, and `env_files`.

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

---

## What clawback finds

| Path / indicator | Severity | Category | Description |
|-----------------|----------|----------|-------------|
| `export API_KEY=sk-...` in `~/.zshrc` | HIGH | `shell_profiles` | Hardcoded secret in shell profile |
| `export API_KEY=sk-...` in `~/.bashrc` | HIGH | `shell_profiles` | Hardcoded secret in shell profile |
| `API_KEY=sk-...` in `.env` files | HIGH | `env_files` | Plaintext secret in environment file |
| `API_KEY` in live environment | MEDIUM | `environment_variables` | Secret value detected in running environment |

## Why it's exposed

Developers export API keys in shell profiles for convenience: `export OPENAI_API_KEY=sk-...` in `~/.zshrc` makes the key available everywhere. `.env` files accumulate secrets as projects add service integrations. Both patterns start as "temporary" and become permanent.

## Tier 1: Eliminate the static credential

### 1Password `op run` with .env templates

Replace secret values with `op://` references. 1Password resolves them at runtime.

**`.env` file (safe to commit):**

```bash
OPENAI_API_KEY="op://Development/OpenAI/credential"
STRIPE_SECRET_KEY="op://Development/Stripe/secret-key"
DATABASE_URL="op://Development/Postgres/connection-string"
```

**Usage:**

```bash
op run --env-file .env -- npm run dev
op run --env-file .env -- python manage.py runserver
```

A single biometric touch authorizes the session. Secrets never touch the filesystem.

## Tier 2: Vault the credential

### direnv + vault integration

`direnv` loads environment variables per-project from `.envrc` files, with secrets fetched from a vault at directory entry time.

**Setup:**

```bash
brew install direnv
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc
```

**`.envrc` (per-project):**

```bash
export API_KEY=$(op read "op://Development/Stripe/secret-key")
export DB_PASS=$(vault kv get -field=password secret/myapp/database)
```

```bash
direnv allow  # explicit safety step
```

**Friction:** 1-3 seconds latency per directory change, compounding with multiple secrets.

### macOS Keychain via security CLI

Store arbitrary secrets in Keychain and retrieve them in shell profiles.

**Store:**

```bash
security add-generic-password -a "$USER" -s "OPENAI_API_KEY" -w "sk-abc123" -U
```

**Retrieve in `~/.zshrc`:**

```bash
export OPENAI_API_KEY=$(security find-generic-password -a "$USER" -s "OPENAI_API_KEY" -w)
```

**Friction:** high. Verbose syntax, GUI permission dialogs on first access, Keychain locks on sleep.

### envchain (lightweight alternative)

A purpose-built Keychain-backed environment variable tool. Simpler syntax than raw `security` CLI.

**Setup:**

```bash
brew install envchain
envchain --set myapp OPENAI_API_KEY STRIPE_SECRET_KEY
# Enter values when prompted
```

**Usage:**

```bash
envchain myapp npm run dev
```

## Tier 3: Reduce blast radius

- Use service-specific scoped tokens instead of master API keys
- Set expiration on tokens where the service supports it
- Rotate keys on a schedule

## Verification

```bash
# Check shell profiles for hardcoded secrets
grep -n "export.*=.*sk-\|export.*=.*ghp_\|export.*=.*AKIA" \
  ~/.zshrc ~/.bashrc ~/.zprofile 2>/dev/null

# Check .env files in common locations
find ~/Projects -name ".env" -exec grep -l "sk-\|ghp_\|AKIA" {} \; 2>/dev/null

python3 clawback.py --category shell_profiles --pretty
python3 clawback.py --category env_files --pretty
```

## Common mistakes

- **Moving secrets from `.env` to `~/.zshrc`.** This is not remediation -- it is relocation. The secret is still in plaintext on disk, now exposed to every shell session.
- **Using `op://` references in `.env` but not wrapping the command with `op run`.** The references are inert strings without `op run`. The application receives the literal string `op://...` instead of the secret value.
- **Hardcoding `export NPM_TOKEN="npm_..."` in `~/.zshrc` while `.npmrc` uses `${NPM_TOKEN}`.** The `.npmrc` is clean, but the secret is in the shell profile. Both locations must be remediated.

## CI/CD implications

**CI change required: yes.**

CI should inject secrets from the platform's native secret store (GitHub Actions secrets, GitLab CI variables, etc.), not from `.env` files checked into the repository or from environment variables set in CI configuration.
