---
title: Roadmap
layout: default
nav_order: 99
---

# Clawback Roadmap

This roadmap would expand `clawback` from a static-secret scanner into a broader **developer workstation exposure scanner** while preserving the current design constraints:

- single-file Python
- stdlib only
- macOS-first
- read-only
- fast enough for JAMF / RTR use
- never emit raw secret values

The priority order below is based on attacker utility, not implementation convenience.

---

## Severity model

Use one severity model across all new categories.

| Severity | Meaning |
|---------|---------|
| `critical` | Immediately reusable access: live session tokens, refresh tokens, plaintext signing keys, active browser abuse, or auth material that can directly produce privileged access without additional user interaction |
| `high` | High-value local secret stores or token caches that are commonly exfiltrated and often reusable, but may be shorter-lived, encrypted at rest, or require companion state |
| `medium` | Strong exposure indicators or posture weaknesses that materially increase theft/exfiltration risk but are not themselves a direct credential |
| `low` | Stale, likely expired, or lower-value artifacts that still matter for cleanup, awareness, or forensic triage |
| `info` | Observations only: secure posture signals, compliant config, or inventory useful for tuning |

### Suggested scoring rules

- Escalate to `critical` when the artifact is both present and plausibly live.
- Downgrade to `low` when the artifact is present but clearly expired, revoked, or only useful as historical data.
- Prefer `high` over `critical` when clawback can prove presence but not liveness.
- Use `info` for posture checks that should not fail compliance by themselves.

---

## Stage 1: Session-Bearing User State

Goal: cover the artifact classes that let attackers bypass MFA or hijack already-authenticated browser sessions.

### Proposed categories

#### `browser_sessions`

Detect browser profile stores that commonly contain cookies, saved credentials, autofill data, and local app state.

**Candidate macOS paths**

- `~/Library/Application Support/Google/Chrome/*/Cookies`
- `~/Library/Application Support/Google/Chrome/*/Login Data`
- `~/Library/Application Support/Google/Chrome/*/Web Data`
- `~/Library/Application Support/Google/Chrome/Local State`
- `~/Library/Application Support/BraveSoftware/Brave-Browser/*/Cookies`
- `~/Library/Application Support/Microsoft Edge/*/Cookies`
- `~/Library/Application Support/Vivaldi/*/Cookies`
- `~/Library/Application Support/Firefox/Profiles/*/cookies.sqlite`
- `~/Library/Application Support/Firefox/Profiles/*/logins.json`
- `~/Library/Application Support/Firefox/Profiles/*/key4.db`
- `~/Library/Cookies/Cookies.binarycookies`
- `~/Library/Safari/`

**Suggested severity**

- `critical`: browser cookie store plus active browser abuse signal in `browser_runtime_abuse`
- `high`: cookie/login store present in a primary profile
- `medium`: history/bookmark/profile metadata only
- `info`: managed browser profile with reduced local storage posture

**Implementation notes**

- Start with existence, size, and profile count. Do not parse or print contents.
- Treat Chromium-family browsers as one implementation with multiple roots.
- Add optional profile-name heuristics later (`Default`, `Profile 1`, work profile naming).

#### `browser_runtime_abuse`

Detect active browser features or process flags that make cookie/session theft easier.

**Candidate macOS paths / signals**

- `ps aux` / `ps -ef` for:
  - `--remote-debugging-port`
  - `--remote-debugging-pipe`
  - `--load-extension`
  - `--disable-extensions-except`
- environment variable:
  - `SSLKEYLOGFILE`
- managed preference candidates:
  - `/Library/Managed Preferences/com.google.Chrome.plist`
  - `~/Library/Preferences/com.google.Chrome.plist`
  - `/Library/Managed Preferences/com.microsoft.Edge.plist`

**Suggested severity**

- `critical`: active remote debugging or suspicious extension load on a running browser
- `high`: risky browser startup flags present in persistent config
- `medium`: unmanaged extension-heavy posture or weak browser policy signals
- `info`: managed browser with restrictive policy

**Implementation notes**

- This category is the best way to justify escalating browser artifact findings from `high` to `critical`.
- Keep the first pass limited to process flags and environment variables.

### Exit criteria

- New browser categories added to `ALL_SCANS`
- No secret values emitted
- Findings explain why browser state matters without requiring SQLite parsing

---

## Stage 2: Developer Token Caches And Secret Spill Paths

Goal: cover the local caches and workflow artifacts that sit between "plaintext config file" and "live browser session."

### Proposed categories

#### `developer_token_caches`

Detect CLI and workstation token caches for cloud, SCM, and infrastructure tooling.

**Candidate macOS paths**

- `~/.aws/sso/cache/*.json`
- `~/.config/gcloud/access_tokens.db`
- `~/.config/gcloud/credentials.db`
- `~/.config/gcloud/legacy_credentials/`
- `~/.config/gh/hosts.yml`
- `~/.config/glab-cli/`
- `~/.terraform.d/credentials.tfrc.json`
- `~/.terraformrc`
- `~/.pulumi/credentials.json`
- `~/.config/doctl/config.yaml`
- `~/.config/cloudflared/cert.pem`

**Suggested severity**

- `critical`: plaintext bearer or refresh token file, or explicit insecure-storage mode
- `high`: short-lived SSO cache or encrypted-but-reusable local token cache
- `medium`: metadata/config showing risky fallback posture without token material
- `info`: keychain-backed or short-lived-only posture when detectable

**Implementation notes**

- This category should absorb some gaps already documented in the guides, such as `gh auth login --insecure-storage`, without overloading `git_credentials`.
- Prefer targeted file presence checks over generic `~/.config` walking.

#### `terminal_history_and_transcripts`

Detect shell history and adjacent local artifacts that frequently contain pasted secrets.

**Candidate macOS paths**

- `~/.zsh_history`
- `~/.bash_history`
- `~/.local/share/fish/fish_history`
- `~/.python_history`
- `~/.psql_history`
- `~/.mysql_history`
- `~/.sqlite_history`
- `~/.tmux/resurrect/`
- `~/Library/Application Support/Code/User/workspaceStorage/`

**Suggested severity**

- `critical`: direct secret hits or multiple high-confidence tokens in history
- `high`: one or more high-value secrets in history or transcript stores
- `medium`: suspicious commands indicating manual secret handling without a clear secret hit
- `info`: history files present but no secret evidence in audit mode

**Implementation notes**

- Reuse the existing value classifier for token-shaped substrings.
- Cap reads aggressively. History files can be large.
- Consider splitting editor/AI transcript coverage into a later sub-phase if false positives are noisy.

#### `iac_and_ops_state`

Detect local infrastructure files that often embed credentials or resolved secrets outside `.env`.

**Candidate macOS paths / patterns**

- `terraform.tfstate`
- `terraform.tfstate.backup`
- `*.tfvars`
- `*.auto.tfvars`
- `Pulumi.*.yaml`
- `group_vars/`
- `host_vars/`
- `.vault_pass`
- `.vault-password-file`
- `secrets.yaml`
- `values-secret.yaml`
- `~/.pgpass`
- `~/.config/sops/age/keys.txt`
- `~/.gnupg/private-keys-v1.d/`

**Suggested severity**

- `critical`: plaintext private keys, vault passwords, or state files with clear secret material
- `high`: local state or vars files strongly associated with embedded credentials
- `medium`: encrypted artifacts plus adjacent local decryptor material
- `low`: stale or template-like files with no direct secret evidence

**Implementation notes**

- Keep the first pass narrow and opinionated. Repo-wide recursive search here can explode scan time.
- Prefer home-directory canonical paths first, then optionally add repo-local globs under known work roots.

### Exit criteria

- Token-cache findings cover the most common workstation auth caches outside current cloud scans
- History scanning reuses the existing classification logic
- IaC scanning stays targeted enough to remain fast

---

## Stage 3: Collaboration, Identity, And Signing Material

Goal: cover exfiltration targets that matter for internal recon, lateral movement, and software supply chain abuse.

### Proposed categories

#### `collab_and_mail_sessions`

Detect app support roots for chat and mail clients that often contain reusable auth state or sensitive local caches.

**Candidate macOS paths**

- `~/Library/Application Support/Slack/`
- `~/Library/Application Support/discord/`
- `~/Library/Application Support/Signal/`
- `~/Library/Group Containers/*.ru.keepcoder.Telegram/`
- `~/Library/Application Support/Microsoft/Teams/`
- `~/Library/Containers/com.apple.mail/`
- `~/Library/Mail/`
- `~/Library/Thunderbird/Profiles/`
- `~/Library/Group Containers/UBF8T346G9.Office/Outlook/`

**Suggested severity**

- `critical`: reusable auth/session cache clearly identified
- `high`: collaboration or mail client cache root with known token-bearing local state
- `medium`: mailbox/archive data without a session signal
- `low`: exported mail archives or stale local client data

**Implementation notes**

- Separate "auth/session cache" from "mailbox/archive data" in descriptions.
- Mail artifacts matter more for confidentiality and recon than for key rotation; keep descriptions honest about that.

#### `signing_and_identity_material`

Detect private material that can be used to sign code, releases, or packages.

**Candidate macOS paths**

- `~/.gnupg/private-keys-v1.d/`
- `~/private_keys/AuthKey_*.p8`
- `~/Library/MobileDevice/Provisioning Profiles/`
- `*.p12`
- `*.pfx`
- `*.jks`
- `*.keystore`
- `*.mobileprovision`
- `~/.ssh/config` posture checks for `ForwardAgent yes`
- `SSH_AUTH_SOCK` and loaded-key inventory when safely observable

**Suggested severity**

- `critical`: plaintext signing key, exportable private key, or agent posture enabling easy relay/signing abuse
- `high`: private signing material present without clear hardware-backed protection
- `medium`: posture weakness such as agent forwarding or broad agent use
- `info`: hardware-backed or clearly managed posture when detectable

**Implementation notes**

- This category matters disproportionately for maintainer laptops.
- Prefer evidence of exportable private material over generic developer-certificate presence.

#### `local_secure_store_posture`

Model secure stores as in-scope post-compromise targets without treating them as equal to plaintext files.

**Candidate macOS paths / signals**

- `~/Library/Keychains/`
- `security list-keychains`
- `security show-keychain-info`
- `~/.ssh/config`
- `SSH_AUTH_SOCK`

**Suggested severity**

- `high`: insecure secure-store posture, broad trust grants, or unusually exposed keychain/agent usage
- `medium`: weak-but-common posture needing hardening
- `info`: dedicated local keychain, keychain auto-lock, no agent forwarding, `UseKeychain yes`

**Implementation notes**

- Do not dump keychain contents.
- This category is posture-first. It should mostly produce `medium` and `info`.

### Exit criteria

- Collaboration and mail coverage exists without turning clawback into a general DLP tool
- Signing-key coverage is explicit enough to support maintainer-risk assessments
- Secure-store posture is modeled as a risk modifier, not a plaintext-secret detector

---

## Cross-cutting implementation rules

- Prefer path-presence, metadata, and posture checks before content parsing.
- Reuse the current classification engine where the artifact actually contains strings or assignments.
- Add categories only when they have a credible remediation story.
- Keep the report readable: findings should say whether the issue is about `session hijack`, `token reuse`, `secret spill`, `recon/data loss`, or `signing abuse`.
- Add tests with synthetic fixtures for every new category before broadening path coverage.

---

## Recommended implementation order

1. `browser_sessions`
2. `browser_runtime_abuse`
3. `developer_token_caches`
4. `terminal_history_and_transcripts`
5. `iac_and_ops_state`
6. `collab_and_mail_sessions`
7. `signing_and_identity_material`
8. `local_secure_store_posture`

This order follows the highest-likelihood post-compromise reuse path on a developer laptop: hijack current sessions first, then reuse local token caches, then mine workflow artifacts, then move into collaboration, mail, and signing abuse.
