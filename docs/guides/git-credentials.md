---
title: Git Credentials
parent: Remediation Guides
nav_order: 5
description: >-
  Remediate plaintext Git credentials and .netrc passwords found by clawback
  in ~/.git-credentials, ~/.netrc, and gitconfig.
clawback_category: git_credentials
---

# Git credentials
{: .no_toc }

Git's `credential.helper = store` saves passwords in plaintext at `~/.git-credentials`. The `.netrc` file serves a similar role for tools like curl, Go modules, and Heroku CLI.

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
| `~/.git-credentials` | HIGH | Plaintext credentials in URL format |
| `~/.config/git/credentials` | HIGH | XDG-style plaintext credentials |
| `~/.netrc` | HIGH | Plaintext passwords for HTTP services |
| `credential.helper = store` in gitconfig | MEDIUM | Configuration directing Git to store plaintext |

## Why it's exposed

`git config --global credential.helper store` is a common tutorial instruction. It writes credentials in `https://user:token@github.com` format to `~/.git-credentials`. The `.netrc` file predates modern credential helpers and is still required by some tools.

## Tier 1: Eliminate the static credential

### macOS Keychain credential helper

Stores credentials in encrypted Keychain. Eliminates the plaintext `~/.git-credentials` file entirely.

**Setup:**

```bash
# Remove the old helper and file
git config --global --unset-all credential.helper
rm -f ~/.git-credentials ~/.config/git/credentials

# Set Keychain helper
git config --global credential.helper osxkeychain

# Clear any cached entries
printf 'host=github.com\nprotocol=https\n\n' | git credential-osxkeychain erase
```

**Daily workflow:** transparent. Git prompts for credentials on first use, stores them in Keychain, and retrieves them silently thereafter.

### GitHub CLI

Manages GitHub tokens in Keychain via browser-based OAuth.

**Setup:**

```bash
brew install gh
gh auth login        # browser-based OAuth flow
gh auth setup-git    # configures Git to use gh for GitHub auth
```

{: .warning }
> Never use `gh auth login --insecure-storage`. This flag forces plaintext token storage in a config file instead of Keychain.

### Git Credential Manager (GCM)

Multi-provider credential manager supporting GitHub, GitLab, Bitbucket, and Azure DevOps. Stores tokens in Keychain.

**Requirements:** macOS >= 10.15.

**Setup:**

```bash
brew install --cask git-credential-manager
git-credential-manager configure
```

## Tier 3: Reduce blast radius

- Use fine-grained PATs instead of classic tokens
- Set expiration dates on all tokens
- Scope tokens to specific repositories where possible

## .netrc remediation

Some tools still require `~/.netrc`: legacy Go modules, curl-based tools, and Heroku CLI.

**For Go modules:** set `GOPRIVATE` and use Git credential helpers instead of `.netrc`:

```bash
go env -w GOPRIVATE=github.com/your-org/*
# Git credential helper handles authentication for private repos
```

**When .netrc is unavoidable:** generate a temporary `.netrc` from Keychain at runtime:

```bash
TOKEN=$(security find-generic-password -s "NETRC_GITHUB" -a "$(whoami)" -w)
echo "machine github.com login oauth password $TOKEN" > ~/.netrc
# Run the tool
rm ~/.netrc
```

Or use 1Password:

```bash
op run --env-file .env -- curl --netrc-file <(op read "op://Dev/netrc/file")  # ...
```

## Verification

```bash
# Confirm credential helper is set
git config --global --get credential.helper  # should be osxkeychain or manager

# Confirm plaintext files are gone
ls -la ~/.git-credentials 2>/dev/null      # should not exist
ls -la ~/.config/git/credentials 2>/dev/null  # should not exist
ls -la ~/.netrc 2>/dev/null                # should not exist (or have no passwords)

python3 clawback.py --category git_credentials --pretty
```

## Common mistakes

- **Switching to `osxkeychain` but not deleting `~/.git-credentials`.** The helper works, but the plaintext file remains. See [The Orphaned File Anti-Pattern](../concepts/orphaned-files.md).
- **Having `credential.helper = store` in a project-level `.gitconfig` that overrides the global setting.** Check both `git config --global --get credential.helper` and `git config --local --get credential.helper`.
- **Using `gh auth login --insecure-storage`.** Forces plaintext storage. There is no good reason to use this flag on macOS.

## CI/CD implications

**CI change required: rarely.** CI typically uses deploy tokens, app installation tokens, or SSH deploy keys that are already separate from developer credentials.
