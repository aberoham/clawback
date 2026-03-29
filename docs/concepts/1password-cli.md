---
title: 1Password CLI as Universal Tier 2
parent: Concepts
nav_order: 6
---

# 1Password CLI as universal Tier 2
{: .no_toc }

1Password's `op run` command is the most broadly applicable Tier 2 solution across credential types. This page assesses its strengths, limitations, and the workflows it covers.

---

## How it works

`op run` parses environment files containing `op://` URIs, fetches the referenced secrets from 1Password at runtime, and injects them into the subprocess environment. Secrets never touch the filesystem or appear in process listings.

```bash
# .env file (safe to commit -- contains only references)
AWS_ACCESS_KEY_ID="op://Development/AWS/access-key-id"
AWS_SECRET_ACCESS_KEY="op://Development/AWS/secret-access-key"

# Run any command with secrets injected
op run --env-file .env -- aws s3 ls
```

A single biometric touch (Touch ID) per session authorizes access.

## Strengths

- **Broad coverage:** works for any tool that reads environment variables, which covers most CLI tools and local development servers.
- **No plaintext on disk:** secrets are fetched in-memory and injected into the subprocess environment. The `.env` file contains only `op://` references.
- **Team secret sharing:** 1Password Environments allow teams to sync `.env` files without passing secrets through insecure channels like Slack or email.
- **Single authentication:** one biometric touch unlocks the session. Subsequent `op run` calls within the session do not re-prompt.

## Limitations

- **Cannot cover GUI applications:** desktop apps that are not launched from a terminal cannot receive `op run`-injected environment variables.
- **Cannot cover background daemons or cron jobs:** processes not started via `op run` have no access to the injected secrets.
- **~1 second latency per invocation:** acceptable for single commands but compounds in `direnv` workflows with multiple secrets or rapid iteration loops.
- **Shell completion breaks for some plugin-wrapped CLIs:** notably `gh` (GitHub CLI) loses tab completion when run through 1Password plugin wrappers.
- **Requires organizational licensing:** 1Password Teams or Business is needed for shared vaults and Environments.
- **Tools that read credential files directly:** some tools parse specific config files (e.g., `~/.aws/credentials`, `~/.docker/config.json`) rather than environment variables. These need credential-file-specific remediation (credential helpers, credential stores) rather than `op run`.
- **1Password must be running and unlocked:** if 1Password is locked or the app is not running, `op run` fails. This can surprise developers after a reboot or when using SSH sessions where 1Password desktop is not available.

## Where it fits

`op run` is the right Tier 2 choice when:
- The tool reads secrets from environment variables
- The developer or team already uses 1Password
- The workflow runs interactively from a terminal

It is not the right choice when:
- The tool requires a specific credential file format (use the tool's native credential helper instead)
- The process runs unattended (use a secrets manager with machine-to-machine auth instead)
- Latency sensitivity is high (use macOS Keychain for sub-50ms retrieval)
