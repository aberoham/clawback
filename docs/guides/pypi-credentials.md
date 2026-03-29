---
title: PyPI Credentials
parent: Remediation Guides
nav_order: 7
description: >-
  Remediate PyPI passwords and tokens found by clawback in ~/.pypirc.
clawback_category: package_manager_tokens
---

# PyPI credentials
{: .no_toc }

PyPI credentials in `~/.pypirc` grant publishing access to Python packages. A stolen token allows an attacker to push malicious package versions to PyPI.

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
| `~/.pypirc` with `password` field | HIGH | Plaintext API token or password |

## Why it's exposed

`twine upload` and older `python setup.py upload` workflows read credentials from `~/.pypirc`. Developers paste an API token into this file during initial setup and never revisit it.

## Tier 1: Eliminate the static credential

### Trusted Publishers (OIDC) -- for CI

PyPI's Trusted Publishers use OIDC to generate 15-minute ephemeral tokens. No stored secret required. This is the recommended approach for all package publishing.

**CI setup (GitHub Actions):**

```yaml
permissions:
  id-token: write
steps:
  - uses: actions/checkout@v4
  - uses: pypa/gh-action-pypi-publish@release/v1
```

Configure the Trusted Publisher in PyPI project settings (link your GitHub repository and workflow).

**Implication:** developers stop publishing from local workstations. All releases go through CI.

## Tier 2: Vault the credential

### Twine + keyring backend

The `keyring` library stores the PyPI token in macOS Keychain. Twine queries it automatically during upload.

**Setup:**

```bash
pip install keyring
keyring set https://upload.pypi.org/legacy/ __token__
# Paste your API token when prompted
```

**`~/.pypirc` (without the password):**

```ini
[distutils]
index-servers = pypi

[pypi]
username = __token__
```

```bash
chmod 600 ~/.pypirc
```

**Daily workflow:** `twine upload dist/*` queries the keyring automatically. No password in the file.

## Tier 3: Reduce blast radius

- Use per-project scoped API tokens instead of account-wide tokens
- Set token expiration where supported
- Enable 2FA on the PyPI account

## Verification

```bash
# Check for password in .pypirc
grep -n "password" ~/.pypirc 2>/dev/null  # should find nothing

# Verify keyring is working
python3 -c "import keyring; print(keyring.get_keyring())"

python3 clawback.py --category package_manager_tokens --pretty
```

## Common mistakes

- **Leaving the `password` field in `~/.pypirc` after setting up keyring.** The keyring works, but the plaintext token remains in the file.
- **Not setting file permissions.** `~/.pypirc` should be `chmod 600` even if it only contains the username.
- **Publishing from local workstations when Trusted Publishers are available.** If CI handles all publishing, there is no reason for a local token to exist.

## CI/CD implications

**CI change required: yes.**

Trusted Publishers (OIDC) is the standard CI pattern. Generates 15-minute ephemeral tokens with no stored secret. Supported on GitHub Actions, GitLab CI, and other major platforms.
