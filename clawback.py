#!/usr/bin/env python3
"""clawback — macOS secret exposure scanner and (soon) remediator.

Scans for credential files and secrets targeted by supply chain attacks
(TeamPCP/CanisterWorm campaign, March 2026). Designed for deployment via
JAMF or CrowdStrike RTR. Pure Python 3.9.6+ stdlib, single file, read-only.

Exit codes:
    0 — No findings
    1 — Findings present
    2 — Scan error
"""
from __future__ import annotations

import argparse
import base64
import datetime
import getpass
import json
import math
import os
import pathlib
import platform
import re
import socket
import stat
import struct
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0.0"
MAX_READ_BYTES = 65536
SSH_KEY_READ_BYTES = 2048
ENV_FILE_READ_BYTES = 4096

# Well-known secret variable names found in shell profiles and env.
# Tier 1: high-confidence exact matches.
NAMED_SECRET_VARS = frozenset({
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "ANTHROPIC_API_KEY",
    "CLOUDFLARE_API_TOKEN",
    "DATABASE_URL",
    "DATADOG_API_KEY",
    "DOCKER_PASSWORD",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "HOMEBREW_GITHUB_API_TOKEN",
    "MONGO_URI",
    "NODE_AUTH_TOKEN",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "REDIS_URL",
    "SENDGRID_API_KEY",
    "SLACK_TOKEN",
    "STRIPE_SECRET_KEY",
    "TWINE_PASSWORD",
    "TWINE_USERNAME",
})

# Tier 2: generic pattern for variable names that look like secrets.
GENERIC_SECRET_RE = re.compile(
    r"[A-Z_]*(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH_KEY|API_KEY|PRIVATE_KEY)"
    r"[A-Z_]*"
)

# Variables whose values are paths or locators pointing to secret material
# rather than secrets themselves. Flagged on presence (unless the value is
# a secrets-manager reference like op://), not on value entropy.
LOCATOR_SECRET_VARS = frozenset({
    "GOOGLE_APPLICATION_CREDENTIALS",
})

# Variables that match the generic pattern but are not secrets.
SECRET_VAR_ALLOWLIST = frozenset({
    "Apple_PubSub_Socket_Render",
    "COLORTERM",
    "GPG_AGENT_INFO",
    "ITERM_SESSION_ID",
    "SECURITYSESSIONID",
    "SHELL_SESSION_DIR",
    "SSH_AGENT_PID",
    "SSH_AUTH_SOCK",
    "TERM_PROGRAM_VERSION",
    "TERM_SESSION_ID",
})

COMMENT_RE = re.compile(r"^\s*#")
EXPORT_RE = re.compile(
    r"""(?:^|\s)export\s+([A-Za-z_][A-Za-z0-9_]*)=\s*(\S.*)"""
)
BARE_ASSIGN_RE = re.compile(
    r"""^([A-Za-z_][A-Za-z0-9_]*)=\s*(\S.*)"""
)

SSH_SKIP_FILES = frozenset({
    "authorized_keys",
    "config",
    "environment",
    "known_hosts",
    "known_hosts.old",
    "rc",
})

ENV_SCAN_DIRS = [
    "Desktop", "Documents", "Projects", "Developer", "repos",
    "src", "code", "workspace", "work", "dev", "go/src",
]
ENV_PRUNE_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".tox", "vendor", "dist", "build", ".next", ".cache",
})
ENV_MAX_DEPTH = 4

TEAMPCP_C2_DOMAINS = [
    "scan.aquasecurtiy.org",
    "checkmarx.zone",
    "models.litellm.cloud",
    "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io",
]
TEAMPCP_PLIST_MARKERS = ["pgmon", "icp0.io", "tdtqy", "teampcp", "tpcp"]

# Value prefixes that indicate real secrets regardless of variable name.
KNOWN_SECRET_PREFIXES = (
    "sk-",               # OpenAI, Stripe secret key
    "sk_live_",          # Stripe live
    "sk_test_",          # Stripe test
    "pk_live_",          # Stripe publishable
    "pk_test_",          # Stripe publishable
    "ghp_",              # GitHub personal access token
    "gho_",              # GitHub OAuth token
    "ghs_",              # GitHub server-to-server token
    "github_pat_",       # GitHub fine-grained PAT
    "xoxb-",             # Slack bot token
    "xoxp-",             # Slack user token
    "xoxa-",             # Slack app token
    "xoxr-",             # Slack refresh token
    "AKIA",              # AWS access key ID
    "glpat-",            # GitLab personal access token
    "pypi-",             # PyPI API token
    "npm_",              # npm token
    "whsec_",            # Stripe webhook secret
    "sq0atp-",           # Square access token
    "sq0csp-",           # Square OAuth secret
    "SG.",               # SendGrid API key
    "key-",              # Mailgun
    "rk_live_",          # Stripe restricted key
    "eyJ",               # JWT (base64 of '{"')
    "-----BEGIN",        # PEM encoded key/cert
    "AIZA",              # Google API key
    "AIza",              # Google API key
    "ya29.",             # Google OAuth token
    "AGE-SECRET-KEY-",   # age encryption key
    "lsv2_pt_",          # LangSmith / LangChain API key
)

# Regex patterns for values that are clearly not secrets.
INNOCUOUS_VALUE_RES = [
    re.compile(r"^(true|false|yes|no|on|off|none|null|nil)$", re.I),
    re.compile(r"^\d+$"),
    re.compile(r"^\d+\.\d+(\.\d+)?"),
    re.compile(
        r"^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$"
    ),
    re.compile(
        r"^(development|production|staging|test|testing|debug|"
        r"info|warn|error|verbose|local)$",
        re.I,
    ),
    re.compile(r"^https?://[^:@]*(?::\d+)?(?:/\S*)?$"),
    re.compile(r"^/[\w/.@+-]+$"),
    re.compile(r"^(/[\w/.@+-]+)(:/[\w/.@+-]+)+$"),
    re.compile(r"^[\w.-]+@[\w.-]+\.\w+$"),
    re.compile(r"^[\w.-]+\.[a-z]{2,10}$"),
    re.compile(r"^\d+[smhd]$"),
    re.compile(r"^[a-z]{2}(-[A-Z]{2})?$"),
    re.compile(r"^#[0-9a-fA-F]{3,8}$"),
    re.compile(r"^\d+(\.\d+)?(px|em|rem|pt|%)$"),
    re.compile(r"^\w{1,5}$"),
]

# Files that look like .env but aren't (editor artifacts).
ENV_IGNORE_SUFFIXES = (".swp", ".swo", ".bak", ".orig", ".tmp")

CRYPTO_WALLET_PATHS = [
    "Library/Application Support/Exodus",
    "Library/Application Support/Electrum/wallets",
    "Library/Application Support/Atomic",
    "Library/Application Support/com.liberty.jaxx",
    "Library/Application Support/Ethereum/keystore",
    "Library/Application Support/Bitcoin/wallets",
    "Library/Application Support/Ledger Live",
    "Library/Ethereum/keystore",
    ".electrum/wallets",
]


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    category: str
    path: str
    severity: str
    description: str
    remediation: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    home: pathlib.Path
    username: str
    hostname: str
    start_time: float
    audit_mode: bool = False
    findings: List[Finding] = field(default_factory=list)
    observations: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add(
        self,
        category: str,
        path: str,
        severity: Severity,
        description: str,
        remediation: str,
        **details: Any,
    ) -> None:
        self.findings.append(Finding(
            category=category,
            path=str(path),
            severity=severity.value,
            description=description,
            remediation=remediation,
            details=details if details else {},
        ))

    def observe(
        self,
        category: str,
        path: str,
        description: str,
        reason: str,
        **details: Any,
    ) -> None:
        """Record a compliant or informational observation.

        Observations appear in the report for visibility and feed the
        refinement loop, but do not count toward total_findings or
        affect the exit code.
        """
        self.observations.append(Finding(
            category=category,
            path=str(path),
            severity="info",
            description=description,
            remediation="",
            details={"reason": reason, **details} if details else {"reason": reason},
        ))


# -------------------------------------------------------------------
# Utilities
# -------------------------------------------------------------------

def safe_read(path: pathlib.Path, max_bytes: int = MAX_READ_BYTES) -> Optional[str]:
    """Read up to max_bytes from a file, returning None on any error."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except (OSError, PermissionError):
        return None


def safe_read_bytes(path: pathlib.Path, max_bytes: int) -> Optional[bytes]:
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
    except (OSError, PermissionError):
        return None


def file_exists_nonempty(path: pathlib.Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def octal_permissions(path: pathlib.Path) -> Optional[str]:
    try:
        mode = path.stat().st_mode
        return oct(stat.S_IMODE(mode))
    except OSError:
        return None


def run_cmd(args: List[str], timeout: int = 5) -> Optional[str]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except (OSError, subprocess.TimeoutExpired):
        return None


def progress(msg: str, quiet: bool) -> None:
    if not quiet:
        print(f"  scanning: {msg}", file=sys.stderr, flush=True)


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def _strip_quotes(val: str) -> str:
    """Remove surrounding single or double quotes."""
    v = val.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    return v


def classify_value(value: str) -> Tuple[bool, str]:
    """Decide whether an env-var value looks like a secret.

    Returns (is_secret, reason). Never inspects the variable name;
    this is purely value-based so it can be used for both .env and
    shell profile lines.
    """
    stripped = _strip_quotes(value)

    if not stripped or stripped.startswith("${") or stripped == "$":
        return False, "empty_or_variable_reference"

    # 1Password secret references are resolved at runtime by `op run`
    # and are not exposed secrets themselves.
    if stripped.startswith("op://"):
        return False, "1password_reference"

    # Shell variable expansion (e.g. $HOME/.nvm, /opt/foo:$PATH) is config,
    # not a secret. Must contain $ followed by a letter or brace.
    if re.search(r"\$[A-Za-z_{]", stripped):
        return False, "shell_variable_expansion"

    for prefix in KNOWN_SECRET_PREFIXES:
        if stripped.startswith(prefix):
            return True, f"known_prefix:{prefix}"

    for pat in INNOCUOUS_VALUE_RES:
        if pat.match(stripped):
            return False, "innocuous"

    # URL with embedded credentials (user:pass@host)
    if re.match(r"\w+://[^:]+:[^@]+@", stripped):
        return True, "url_with_credentials"

    # High entropy + sufficient length
    if len(stripped) >= 20:
        ent = shannon_entropy(stripped)
        if ent > 4.5:
            return True, f"high_entropy:{ent:.1f}"

    # Long hex string (>= 32 chars)
    if len(stripped) >= 32 and re.fullmatch(r"[0-9a-fA-F]+", stripped):
        return True, "long_hex"

    # Long base64-ish string with high entropy
    if len(stripped) >= 32 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        ent = shannon_entropy(stripped)
        if ent > 4.0:
            return True, f"likely_base64:{ent:.1f}"

    return False, "benign"


def _name_value_suspicious(raw_value: str) -> Tuple[bool, str]:
    """Relaxed value check for when the variable name indicates a secret.

    Called only when classify_value returned "benign" and the variable
    name matched GENERIC_SECRET_RE or NAMED_SECRET_VARS. Applies lower
    thresholds, since the name provides additional confidence that this
    is credential material rather than ordinary configuration.
    """
    stripped = _strip_quotes(raw_value)

    if len(stripped) < 20:
        return False, "short_value"

    ent = shannon_entropy(stripped)
    if ent < 3.5:
        return False, "low_entropy"

    if re.match(r"\w+://", stripped) and not re.match(
        r"\w+://[^:]+:[^@]+@", stripped
    ):
        return False, "url_without_credentials"

    segments = re.split(r"[-_./: ]+", stripped)
    alpha_words = [
        s for s in segments if s.isalpha() and len(s) >= 3
    ]
    word_chars = sum(len(w) for w in alpha_words)
    if word_chars / len(stripped) > 0.6:
        return False, "word_like_value"

    # Catch unseparated placeholder values like "sampletokenvalue12345"
    # where the alpha prefix dominates the string.
    alpha_run = re.match(r"[a-zA-Z]+", stripped)
    if alpha_run and alpha_run.end() / len(stripped) > 0.6:
        return False, "word_like_value"

    return True, f"name_plus_value:{ent:.1f}"


def _is_secret_locator(var_name: str, raw_value: str) -> bool:
    """True if the variable points to secret material (e.g. a key file path).

    Locator variables like GOOGLE_APPLICATION_CREDENTIALS hold a path
    to a secret, not the secret itself. They are findings unless the
    value is a secrets-manager reference resolved at runtime.
    """
    if var_name not in LOCATOR_SECRET_VARS:
        return False
    stripped = _strip_quotes(raw_value)
    return bool(stripped) and not stripped.startswith("op://")


def _parse_env_line(line: str) -> Optional[Tuple[str, str]]:
    """Extract (name, raw_value) from a KEY=VALUE line."""
    if not line or line.startswith("#"):
        return None
    m = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
    if m:
        return m.group(1), m.group(2)
    return None


def _value_fingerprint(value: str) -> str:
    """Structural fingerprint of a value — enough to classify, not reconstruct.

    Returns a short string like "hex32", "base64-88", "jwt", "uuid",
    "path", "url", "short-alpha", "numeric", "bool", or "mixed-N".
    """
    s = _strip_quotes(value)
    if not s:
        return "empty"
    if s.startswith("${") or re.search(r"\$[A-Za-z_{]", s):
        return "shell-ref"
    if re.fullmatch(r"(true|false|yes|no|on|off|none|null)", s, re.I):
        return "bool"
    if re.fullmatch(r"\d+", s):
        return "numeric"
    if re.fullmatch(r"[0-9a-fA-F-]{36}", s):
        return "uuid"
    if re.match(r"eyJ[A-Za-z0-9_-]+\.eyJ", s):
        return f"jwt-{len(s)}"
    if s.startswith("-----BEGIN"):
        return "pem-block"
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        return f"hex{len(s)}"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", s) and len(s) >= 20:
        return f"base64-{len(s)}"
    if re.match(r"https?://", s):
        has_creds = bool(re.match(r"\w+://[^:]+:[^@]+@", s))
        return "url-with-creds" if has_creds else "url"
    if s.startswith("/"):
        return "path"
    if len(s) <= 5:
        return f"short-{len(s)}"
    # Character class breakdown
    n_upper = sum(1 for c in s if c.isupper())
    n_lower = sum(1 for c in s if c.islower())
    n_digit = sum(1 for c in s if c.isdigit())
    n_special = len(s) - n_upper - n_lower - n_digit
    return f"mixed-{len(s)}"


def _char_class_distribution(value: str) -> Dict[str, float]:
    """Character class percentages — safe aggregate, no content leaked."""
    s = _strip_quotes(value)
    if not s:
        return {"upper": 0, "lower": 0, "digit": 0, "special": 0}
    n = len(s)
    return {
        "upper": round(sum(1 for c in s if c.isupper()) / n, 2),
        "lower": round(sum(1 for c in s if c.islower()) / n, 2),
        "digit": round(sum(1 for c in s if c.isdigit()) / n, 2),
        "special": round(
            sum(1 for c in s if not c.isalnum()) / n, 2
        ),
    }


def _source_category(path: str) -> str:
    """Anonymize a file path to a broad category for training data."""
    p = path.lower()
    if ".env.example" in p or ".env.sample" in p or ".env.template" in p:
        return "env_template"
    if ".env" in p:
        return "env_file"
    for name in (".zshrc", ".zprofile", ".zshenv",
                 ".bash_profile", ".bashrc", ".profile"):
        if name in p:
            return "shell_profile"
    return "other"


# -------------------------------------------------------------------
# Category 1: TeamPCP / CanisterWorm IoC Detection
# -------------------------------------------------------------------

def scan_teampcp_iocs(ctx: ScanContext, quiet: bool) -> None:
    progress("TeamPCP/CanisterWorm IoCs", quiet)
    cat = "teampcp_ioc"
    sev = Severity.CRITICAL
    remediation = (
        "Potential TeamPCP/CanisterWorm infection. Isolate this machine. "
        "Stop pgmon, remove LaunchAgents, rotate ALL credentials, "
        "rebuild from a clean image."
    )

    # File-based IoCs
    ioc_paths = [
        ctx.home / ".local/share/pgmon",
        ctx.home / ".local/share/pgmon/service.py",
        pathlib.Path("/tmp/pglog"),
        pathlib.Path("/tmp/.pg_state"),
        pathlib.Path("/tmp/tpcp.tar.gz"),
        ctx.home / "tpcp.tar.gz",
    ]
    for p in ioc_paths:
        try:
            if p.exists():
                ctx.add(cat, p, sev, f"TeamPCP IoC found: {p.name}", remediation)
        except OSError:
            pass

    # LaunchAgent persistence
    la_dir = ctx.home / "Library/LaunchAgents"
    if la_dir.is_dir():
        try:
            for plist in la_dir.iterdir():
                if not plist.name.endswith(".plist"):
                    continue
                name_lower = plist.name.lower()
                if any(m in name_lower for m in TEAMPCP_PLIST_MARKERS):
                    ctx.add(
                        cat, plist, sev,
                        f"Suspicious LaunchAgent: {plist.name}",
                        remediation,
                    )
                    continue
                content = safe_read(plist, MAX_READ_BYTES)
                if content:
                    content_lower = content.lower()
                    for marker in TEAMPCP_PLIST_MARKERS:
                        if marker in content_lower:
                            ctx.add(
                                cat, plist, sev,
                                f"LaunchAgent contains '{marker}': {plist.name}",
                                remediation,
                            )
                            break
        except OSError:
            pass

    # Python site-packages: litellm_init.pth
    site_out = run_cmd([
        sys.executable, "-c",
        "import site; print('\\n'.join(site.getsitepackages()))",
    ])
    if site_out:
        for line in site_out.strip().splitlines():
            pth = pathlib.Path(line.strip()) / "litellm_init.pth"
            if pth.exists():
                ctx.add(
                    cat, pth, sev,
                    "Malicious litellm_init.pth found in site-packages",
                    remediation,
                )

    # Process check
    ps_out = run_cmd(["ps", "aux"])
    if ps_out:
        for line in ps_out.splitlines():
            if "pgmon" in line and "secret_scanner" not in line:
                ctx.add(
                    cat, "process", sev,
                    "pgmon process running",
                    remediation,
                    process_line=line.strip(),
                )
                break


# -------------------------------------------------------------------
# Category 2: Cloud Provider Credentials
# -------------------------------------------------------------------

def scan_cloud_credentials(ctx: ScanContext, quiet: bool) -> None:
    progress("cloud provider credentials", quiet)
    cat = "cloud_credentials"

    _scan_aws(ctx, cat)
    _scan_gcp(ctx, cat)
    _scan_azure(ctx, cat)


def _scan_aws(ctx: ScanContext, cat: str) -> None:
    creds = ctx.home / ".aws/credentials"
    if file_exists_nonempty(creds):
        content = safe_read(creds)
        profile_count = content.count("[") if content else 0
        ctx.add(
            cat, creds, Severity.HIGH,
            f"AWS credentials file with ~{profile_count} profile(s)",
            "Use AWS SSO (aws sso login) or instance roles. "
            "Remove static keys with aws iam delete-access-key.",
            profiles=profile_count,
        )

    config = ctx.home / ".aws/config"
    if file_exists_nonempty(config):
        ctx.observe(
            cat, config,
            "AWS config file present",
            reason="compliant_config",
        )

    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        val = os.environ.get(var)
        if val:
            is_secret, _ = classify_value(val)
            if is_secret:
                ctx.add(
                    cat, f"env:{var}", Severity.CRITICAL,
                    f"Environment variable {var} is set",
                    "Unset this variable. Use IAM roles or AWS SSO instead.",
                )


def _scan_gcp(ctx: ScanContext, cat: str) -> None:
    gcloud_dir = ctx.home / ".config/gcloud"
    adc = gcloud_dir / "application_default_credentials.json"

    if file_exists_nonempty(adc):
        severity = Severity.HIGH
        detail = "application default credentials"
        content = safe_read(adc)
        if content:
            try:
                data = json.loads(content)
                cred_type = data.get("type", "unknown")
                if cred_type == "service_account":
                    severity = Severity.CRITICAL
                    detail = "service account key file"
                else:
                    detail = f"credentials (type={cred_type})"
            except json.JSONDecodeError:
                pass
        ctx.add(
            cat, adc, severity,
            f"GCP {detail}",
            "Use gcloud auth application-default login with short-lived "
            "credentials. Avoid service account key files.",
        )
    elif gcloud_dir.is_dir():
        ctx.observe(
            cat, gcloud_dir,
            "GCP gcloud config directory present",
            reason="compliant_config",
        )

    ga_creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if ga_creds and not _strip_quotes(ga_creds).startswith("op://"):
        ctx.add(
            cat, f"env:GOOGLE_APPLICATION_CREDENTIALS", Severity.HIGH,
            "GOOGLE_APPLICATION_CREDENTIALS env var points to a key file",
            "Use workload identity or short-lived credentials instead.",
            target_path=ga_creds,
        )


def _scan_azure(ctx: ScanContext, cat: str) -> None:
    azure_dir = ctx.home / ".azure"
    for name, sev in [
        ("accessTokens.json", Severity.HIGH),
        ("msal_token_cache.json", Severity.HIGH),
    ]:
        p = azure_dir / name
        if file_exists_nonempty(p):
            ctx.add(
                cat, p, sev,
                f"Azure cached tokens: {name}",
                "Use az login with short-lived tokens. "
                "Clear cache with az account clear.",
            )

    azure_secret = os.environ.get("AZURE_CLIENT_SECRET")
    if azure_secret:
        is_secret, _ = classify_value(azure_secret)
        if is_secret:
            ctx.add(
                cat, "env:AZURE_CLIENT_SECRET", Severity.CRITICAL,
                "AZURE_CLIENT_SECRET env var is set",
                "Use managed identity or certificate auth instead.",
            )


# -------------------------------------------------------------------
# Category 3: SSH Keys
# -------------------------------------------------------------------

def scan_ssh_keys(ctx: ScanContext, quiet: bool) -> None:
    progress("SSH keys", quiet)
    cat = "ssh_keys"
    ssh_dir = ctx.home / ".ssh"
    if not ssh_dir.is_dir():
        return

    try:
        entries = list(ssh_dir.iterdir())
    except OSError:
        return

    for entry in entries:
        if not entry.is_file():
            continue
        if entry.name in SSH_SKIP_FILES or entry.suffix == ".pub":
            continue

        content = safe_read(entry, SSH_KEY_READ_BYTES)
        if not content or "PRIVATE KEY" not in content:
            continue

        encrypted = _check_ssh_key_encryption(entry, content)
        perms = octal_permissions(entry)
        bad_perms = perms is not None and perms != "0o600"
        key_type = _detect_ssh_key_type(content)

        if not encrypted and bad_perms:
            severity = Severity.CRITICAL
            desc = (
                f"Unencrypted {key_type} SSH key with "
                f"overly permissive permissions ({perms})"
            )
        elif not encrypted:
            severity = Severity.HIGH
            desc = f"Unencrypted {key_type} SSH key"
        elif bad_perms:
            severity = Severity.MEDIUM
            desc = (
                f"Encrypted {key_type} SSH key with "
                f"overly permissive permissions ({perms})"
            )
        else:
            ctx.observe(
                cat, entry,
                f"Encrypted {key_type} SSH key",
                reason="compliant_encrypted_key",
                key_type=key_type,
                encrypted=True,
                permissions=perms,
            )
            continue

        ctx.add(
            cat, entry, severity, desc,
            "Add a passphrase: ssh-keygen -p -f <path>. "
            "Fix permissions: chmod 600 <path>. "
            "Consider using macOS Keychain: ssh-add --apple-use-keychain.",
            key_type=key_type,
            encrypted=encrypted,
            permissions=perms,
        )


def _check_ssh_key_encryption(path: pathlib.Path, text: str) -> bool:
    """Return True if the private key is passphrase-protected."""
    # PEM format: look for encryption header
    if "Proc-Type: 4,ENCRYPTED" in text:
        return True

    # OpenSSH format: the cipher name is embedded in the binary blob
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        raw = safe_read_bytes(path, SSH_KEY_READ_BYTES)
        if raw is None:
            return False  # can't determine, assume unencrypted
        try:
            b64_start = raw.index(b"-----\n") + 6
            b64_end = raw.index(b"\n-----END")
            decoded = base64.b64decode(raw[b64_start:b64_end])
            # openssh key format: "openssh-key-v1\0" then ciphername
            if b"openssh-key-v1\x00" in decoded:
                header_end = decoded.index(b"\x00") + 1
                # Next field is a length-prefixed string: the cipher name
                if len(decoded) > header_end + 4:
                    cipher_len = struct.unpack(
                        ">I", decoded[header_end:header_end + 4]
                    )[0]
                    start = header_end + 4
                    cipher = decoded[start:start + cipher_len]
                    return cipher != b"none"
        except (ValueError, struct.error, base64.binascii.Error):
            pass

    return False


def _detect_ssh_key_type(content: str) -> str:
    if "RSA" in content:
        return "RSA"
    if "EC" in content:
        return "ECDSA"
    if "ED25519" in content.upper():
        return "ED25519"
    if "DSA" in content:
        return "DSA"
    if "OPENSSH" in content:
        return "OpenSSH"
    return "unknown"


# -------------------------------------------------------------------
# Category 4: Git Credentials
# -------------------------------------------------------------------

def scan_git_credentials(ctx: ScanContext, quiet: bool) -> None:
    progress("git credentials", quiet)
    cat = "git_credentials"

    # Plaintext credential store
    git_creds = ctx.home / ".git-credentials"
    if file_exists_nonempty(git_creds):
        content = safe_read(git_creds)
        count = 0
        if content:
            count = sum(
                1 for line in content.splitlines()
                if re.match(r"https?://[^:]+:[^@]+@", line)
            )
        ctx.add(
            cat, git_creds, Severity.CRITICAL,
            f"Plaintext git credentials file with ~{count} stored credential(s)",
            "Switch to osxkeychain helper: "
            "git config --global credential.helper osxkeychain",
            credential_count=count,
        )

    # Git config: check credential helper
    gitconfig = ctx.home / ".gitconfig"
    if file_exists_nonempty(gitconfig):
        content = safe_read(gitconfig)
        if content:
            helper_match = re.search(
                r"helper\s*=\s*(.+)", content
            )
            if helper_match:
                helper = helper_match.group(1).strip()
                if helper == "store" or helper.startswith("store "):
                    ctx.add(
                        cat, gitconfig, Severity.HIGH,
                        "Git credential helper uses plaintext store",
                        "Switch to: git config --global "
                        "credential.helper osxkeychain",
                        helper=helper,
                    )
                elif "osxkeychain" in helper:
                    ctx.observe(
                        cat, gitconfig,
                        "Git credential helper uses macOS Keychain",
                        reason="compliant_credential_store",
                        helper=helper,
                    )

    # Netrc
    netrc = ctx.home / ".netrc"
    if file_exists_nonempty(netrc):
        content = safe_read(netrc)
        has_password = bool(
            content and re.search(r"password\s+\S+", content)
        )
        if has_password:
            ctx.add(
                cat, netrc, Severity.HIGH,
                "Plaintext passwords in .netrc",
                "Remove .netrc entries and use credential helpers "
                "or token-based auth.",
            )


# -------------------------------------------------------------------
# Category 5: Package Manager Tokens
# -------------------------------------------------------------------

def scan_package_manager_tokens(ctx: ScanContext, quiet: bool) -> None:
    progress("package manager tokens", quiet)
    cat = "package_manager_tokens"

    _scan_npmrc(ctx, cat)
    _scan_pypirc(ctx, cat)
    _scan_docker_config(ctx, cat)
    _scan_gem_credentials(ctx, cat)
    _scan_cargo_credentials(ctx, cat)


def _scan_npmrc(ctx: ScanContext, cat: str) -> None:
    npmrc = ctx.home / ".npmrc"
    if not file_exists_nonempty(npmrc):
        return
    content = safe_read(npmrc)
    if not content:
        return
    if re.search(r"_authToken|_password|(?:^|\n)\s*_auth\s*=", content):
        ctx.add(
            cat, npmrc, Severity.CRITICAL,
            "npm auth token in .npmrc (CanisterWorm propagation vector)",
            "Use npm login --auth-type=web for short-lived tokens. "
            "Scope tokens to minimum required packages.",
        )


def _scan_pypirc(ctx: ScanContext, cat: str) -> None:
    pypirc = ctx.home / ".pypirc"
    if not file_exists_nonempty(pypirc):
        return
    content = safe_read(pypirc)
    if content and re.search(r"password\s*=\s*\S+", content):
        ctx.add(
            cat, pypirc, Severity.HIGH,
            "PyPI credentials in .pypirc",
            "Use trusted publishers or API tokens with "
            "minimal scope instead of passwords.",
        )


def _scan_docker_config(ctx: ScanContext, cat: str) -> None:
    docker_cfg = ctx.home / ".docker/config.json"
    if not file_exists_nonempty(docker_cfg):
        return
    content = safe_read(docker_cfg)
    if not content:
        return
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return

    creds_store = data.get("credsStore") or data.get("credStore")
    auths = data.get("auths", {})
    has_plaintext = any(
        "auth" in v for v in auths.values() if isinstance(v, dict)
    )

    if has_plaintext:
        extra = (
            f" (credsStore={creds_store} also configured)"
            if creds_store else ""
        )
        ctx.add(
            cat, docker_cfg, Severity.CRITICAL,
            f"Docker config with plaintext auth for "
            f"{len(auths)} registry(ies){extra}",
            "Configure a credential store: "
            "docker-credential-osxkeychain.",
            registries=list(auths.keys()),
        )
    elif creds_store:
        ctx.observe(
            cat, docker_cfg,
            f"Docker config uses credential store: {creds_store}",
            reason="compliant_credential_store",
            creds_store=creds_store,
        )


def _scan_gem_credentials(ctx: ScanContext, cat: str) -> None:
    gem_creds = ctx.home / ".gem/credentials"
    if file_exists_nonempty(gem_creds):
        ctx.add(
            "package_manager_tokens", gem_creds, Severity.HIGH,
            "RubyGems API key file",
            "Use gem signin with short-lived tokens.",
        )


def _scan_cargo_credentials(ctx: ScanContext, cat: str) -> None:
    for name in ("credentials.toml", "credentials"):
        p = ctx.home / ".cargo" / name
        if file_exists_nonempty(p):
            ctx.add(
                cat, p, Severity.HIGH,
                "Cargo/crates.io registry token",
                "Use cargo login with scoped, short-lived tokens.",
            )
            break


# -------------------------------------------------------------------
# Category 6: Kubernetes
# -------------------------------------------------------------------

def _check_cert_expiry(b64_cert: str) -> Optional[str]:
    """Decode a base64 cert and check expiry via openssl.

    Returns the notAfter date string if expired, or None if still valid.
    Kubeconfig base64 decodes to PEM (with headers). Falls back to DER.
    """
    try:
        cert_bytes = base64.b64decode(b64_cert)
    except (ValueError, base64.binascii.Error):
        return None

    # Detect format: PEM starts with "-----BEGIN", otherwise assume DER.
    inform = "PEM" if cert_bytes[:10] == b"-----BEGIN" else "DER"

    try:
        check = subprocess.run(
            ["openssl", "x509", "-inform", inform,
             "-noout", "-checkend", "0"],
            input=cert_bytes,
            capture_output=True,
            timeout=5,
        )
        if check.returncode == 0:
            return None  # still valid

        date_proc = subprocess.run(
            ["openssl", "x509", "-inform", inform,
             "-noout", "-enddate"],
            input=cert_bytes,
            capture_output=True,
            timeout=5,
        )
        if date_proc.returncode == 0:
            out = date_proc.stdout.decode("utf-8", errors="replace")
            return out.strip().replace("notAfter=", "")
        return "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return None


def scan_kubernetes(ctx: ScanContext, quiet: bool) -> None:
    progress("Kubernetes config", quiet)
    cat = "kubernetes"
    kubeconfig_env = os.environ.get("KUBECONFIG", "")
    if kubeconfig_env:
        paths = [
            pathlib.Path(p) for p in kubeconfig_env.split(":")
            if p
        ]
    else:
        paths = [ctx.home / ".kube/config"]

    for kubeconfig in paths:
        _scan_single_kubeconfig(ctx, cat, kubeconfig)


def _scan_single_kubeconfig(
    ctx: ScanContext, cat: str, kubeconfig: pathlib.Path
) -> None:
    if not file_exists_nonempty(kubeconfig):
        return

    content = safe_read(kubeconfig)
    if not content:
        return

    embedded = []
    for pattern in ("client-key-data:", "client-certificate-data:"):
        if pattern in content:
            embedded.append(pattern.rstrip(":"))

    if re.search(r"^\s+token:\s+\S+", content, re.MULTILINE):
        embedded.append("token")
    if re.search(r"^\s+password:\s+\S+", content, re.MULTILINE):
        embedded.append("password")

    uses_external = bool(
        re.search(r"^\s+exec:", content, re.MULTILINE)
        or re.search(r"^\s+auth-provider:", content, re.MULTILINE)
    )

    if not embedded:
        if uses_external:
            ctx.observe(
                cat, kubeconfig,
                "Kubeconfig uses external auth provider",
                reason="compliant_external_auth",
            )
        return

    # If the only embedded items are cert/key data, check expiry.
    # Expired certs are useless to an attacker — downgrade to LOW.
    cert_only = set(embedded) <= {
        "client-key-data", "client-certificate-data"
    }
    cert_expired = False
    expiry_date = None

    if cert_only and "client-certificate-data" in embedded:
        cert_match = re.search(
            r"client-certificate-data:\s*(\S+)", content
        )
        if cert_match:
            expiry_date = _check_cert_expiry(cert_match.group(1))
            cert_expired = expiry_date is not None

    if cert_expired:
        ctx.add(
            cat, kubeconfig, Severity.LOW,
            f"Kubeconfig with expired embedded certificate "
            f"(expired {expiry_date})",
            "Certificate is expired and no longer usable. "
            "Remove stale kubeconfig entries or switch to "
            "exec-based auth.",
            embedded_types=embedded,
            cert_expired=True,
            cert_expiry=expiry_date,
        )
    else:
        severity = (
            Severity.CRITICAL
            if ("token" in embedded or "password" in embedded)
            else Severity.HIGH
        )
        ctx.add(
            cat, kubeconfig, severity,
            f"Kubeconfig with embedded credentials: "
            f"{', '.join(embedded)}",
            "Use exec-based auth (e.g., aws eks get-token, "
            "gke-gcloud-auth-plugin) instead of embedded secrets.",
            embedded_types=embedded,
        )


# -------------------------------------------------------------------
# Category 7: Shell Profile Secrets
# -------------------------------------------------------------------

def scan_shell_profiles(ctx: ScanContext, quiet: bool) -> None:
    progress("shell profiles", quiet)
    cat = "shell_profile_secrets"
    profiles = [
        ctx.home / name for name in
        (".zshrc", ".zprofile", ".zshenv",
         ".bash_profile", ".bashrc", ".profile")
    ]

    for profile in profiles:
        if not file_exists_nonempty(profile):
            continue
        content = safe_read(profile)
        if not content:
            continue

        for line_num, line in enumerate(content.splitlines(), 1):
            if COMMENT_RE.match(line):
                continue

            match = EXPORT_RE.search(line) or BARE_ASSIGN_RE.match(line)
            if not match:
                continue

            var_name = match.group(1)
            raw_value = match.group(2)

            name_hit = (
                var_name in NAMED_SECRET_VARS
                or (
                    var_name not in SECRET_VAR_ALLOWLIST
                    and GENERIC_SECRET_RE.fullmatch(var_name)
                )
            )
            if not name_hit:
                continue

            val_hit, val_reason = classify_value(raw_value)
            locator_hit = _is_secret_locator(var_name, raw_value)
            if val_hit or locator_hit:
                severity = (
                    Severity.HIGH
                    if var_name in NAMED_SECRET_VARS
                    else Severity.MEDIUM
                )
                reason = val_reason if val_hit else "secret_locator"
                ctx.add(
                    cat, profile, severity,
                    f"Secret variable '{var_name}' in "
                    f"{profile.name}:{line_num}",
                    "Move to macOS Keychain or 1Password CLI. "
                    "Use 'op run' to inject secrets at runtime.",
                    variable=var_name,
                    line=line_num,
                    reason=reason,
                )
            else:
                nv_hit = False
                nv_reason = val_reason
                if val_reason == "benign":
                    nv_hit, nv_reason = _name_value_suspicious(
                        raw_value
                    )
                if nv_hit:
                    nv_severity = (
                        Severity.HIGH
                        if var_name in NAMED_SECRET_VARS
                        else Severity.MEDIUM
                    )
                    ctx.add(
                        cat, profile, nv_severity,
                        f"Secret variable '{var_name}' in "
                        f"{profile.name}:{line_num}",
                        "Move to macOS Keychain or 1Password CLI. "
                        "Use 'op run' to inject secrets at runtime.",
                        variable=var_name,
                        line=line_num,
                        reason=nv_reason,
                    )
                elif ctx.audit_mode:
                    ctx.observe(
                        cat, profile,
                        f"Suspicious variable '{var_name}' in "
                        f"{profile.name}:{line_num} with benign value",
                        reason="suspicious_name_benign_value",
                        variable=var_name,
                        line=line_num,
                    )


# -------------------------------------------------------------------
# Category 8: Environment Variables
# -------------------------------------------------------------------

def scan_environment_variables(ctx: ScanContext, quiet: bool) -> None:
    progress("environment variables", quiet)
    cat = "environment_variables"

    # Cloud credential env vars are already checked in scan_cloud_credentials,
    # so skip those to avoid duplicate findings.
    already_checked = {
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
    }

    for var_name, var_value in os.environ.items():
        if var_name in already_checked:
            continue
        if var_name in SECRET_VAR_ALLOWLIST:
            continue

        name_hit = (
            var_name in NAMED_SECRET_VARS
            or GENERIC_SECRET_RE.fullmatch(var_name)
        )
        if not name_hit:
            continue

        val_hit, val_reason = classify_value(var_value)
        if val_hit:
            severity = (
                Severity.HIGH
                if var_name in NAMED_SECRET_VARS
                else Severity.MEDIUM
            )
            ctx.add(
                cat, f"env:{var_name}", severity,
                f"Secret in environment variable: {var_name}",
                "Unset this variable and use a secrets manager.",
                variable=var_name,
                reason=val_reason,
            )
        else:
            nv_hit = False
            nv_reason = val_reason
            if val_reason == "benign":
                nv_hit, nv_reason = _name_value_suspicious(
                    var_value
                )
            if nv_hit:
                nv_severity = (
                    Severity.HIGH
                    if var_name in NAMED_SECRET_VARS
                    else Severity.MEDIUM
                )
                ctx.add(
                    cat, f"env:{var_name}", nv_severity,
                    f"Secret in environment variable: {var_name}",
                    "Unset this variable and use a secrets manager.",
                    variable=var_name,
                    reason=nv_reason,
                )
            elif ctx.audit_mode:
                ctx.observe(
                    cat, f"env:{var_name}",
                    f"Suspicious environment variable '{var_name}' "
                    f"with benign value",
                    reason="suspicious_name_benign_value",
                    variable=var_name,
                )


# -------------------------------------------------------------------
# Category 9: .env Files
# -------------------------------------------------------------------

def scan_env_files(ctx: ScanContext, quiet: bool) -> None:
    progress(".env files", quiet)
    cat = "env_files"

    for dirname in ENV_SCAN_DIRS:
        root = ctx.home / dirname
        if not root.is_dir():
            continue
        _walk_for_env_files(ctx, cat, root, 0)


def _walk_for_env_files(
    ctx: ScanContext,
    cat: str,
    directory: pathlib.Path,
    depth: int,
) -> None:
    if depth > ENV_MAX_DEPTH:
        return
    try:
        entries = list(directory.iterdir())
    except OSError:
        return

    for entry in entries:
        try:
            if entry.is_dir():
                if entry.name in ENV_PRUNE_DIRS or entry.name.startswith("."):
                    continue
                _walk_for_env_files(ctx, cat, entry, depth + 1)
            elif entry.is_file() and _is_env_filename(entry.name):
                _report_env_file(ctx, cat, entry)
        except OSError:
            pass


def _is_env_filename(name: str) -> bool:
    if any(name.endswith(s) for s in ENV_IGNORE_SUFFIXES):
        return False
    return (
        name == ".env"
        or (name.endswith(".env") and not name.startswith("."))
        or name.startswith(".env.")
    )


def _report_env_file(
    ctx: ScanContext, cat: str, path: pathlib.Path
) -> None:
    name_lower = path.name.lower()
    is_template = any(
        tag in name_lower
        for tag in ("example", "sample", "template")
    )

    content = safe_read(path, ENV_FILE_READ_BYTES)
    if not content:
        return

    secret_vars: List[Dict[str, Any]] = []
    observed_vars: List[str] = []
    for line_num, line in enumerate(content.splitlines(), 1):
        parsed = _parse_env_line(line.strip())
        if not parsed:
            continue
        var_name, raw_value = parsed

        val_hit, val_reason = classify_value(raw_value)
        locator_hit = _is_secret_locator(var_name, raw_value)
        name_hit = (
            var_name in NAMED_SECRET_VARS
            or GENERIC_SECRET_RE.fullmatch(var_name)
        )

        if val_hit or locator_hit:
            secret_vars.append({
                "variable": var_name,
                "line": line_num,
                "reason": val_reason if val_hit else "secret_locator",
            })
        elif name_hit:
            if val_reason == "benign":
                nv_hit, nv_reason = _name_value_suspicious(
                    raw_value
                )
                if nv_hit:
                    secret_vars.append({
                        "variable": var_name,
                        "line": line_num,
                        "reason": nv_reason,
                    })
                else:
                    observed_vars.append(var_name)
            else:
                observed_vars.append(var_name)

    if observed_vars and ctx.audit_mode:
        ctx.observe(
            cat, path,
            f"{path.name}: {len(observed_vars)} suspicious name(s) "
            f"with benign values: {', '.join(observed_vars[:5])}"
            + (f" (+{len(observed_vars) - 5} more)"
               if len(observed_vars) > 5 else ""),
            reason="suspicious_name_benign_value",
            variables=observed_vars,
        )

    if not secret_vars:
        return

    if is_template:
        ctx.add(
            cat, path, Severity.LOW,
            f"Template env file with {len(secret_vars)} "
            f"secret-shaped variable(s): {path.name}",
            "Ensure this does not contain real secret values.",
            variables=[v["variable"] for v in secret_vars],
        )
        return

    has_cloud_cred = any(
        "known_prefix:AKIA" in v.get("reason", "")
        or v["variable"] in (
            "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
        )
        for v in secret_vars
    )
    severity = Severity.CRITICAL if has_cloud_cred else Severity.HIGH
    var_names = [v["variable"] for v in secret_vars]

    ctx.add(
        cat, path, severity,
        f".env file with {len(secret_vars)} secret(s): "
        f"{', '.join(var_names[:5])}"
        + (f" (+{len(var_names) - 5} more)" if len(var_names) > 5 else ""),
        "Add .env to .gitignore. Use a secrets manager or "
        "direnv with encrypted .envrc.",
        variables=var_names,
    )


# -------------------------------------------------------------------
# Category 10: Cryptocurrency Wallets
# -------------------------------------------------------------------

def scan_crypto_wallets(ctx: ScanContext, quiet: bool) -> None:
    progress("cryptocurrency wallets", quiet)
    cat = "crypto_wallets"

    for rel_path in CRYPTO_WALLET_PATHS:
        p = ctx.home / rel_path
        try:
            if p.is_dir() and any(p.iterdir()):
                wallet_name = rel_path.split("/")[-1]
                ctx.add(
                    cat, p, Severity.HIGH,
                    f"Cryptocurrency wallet data: {wallet_name}",
                    "Ensure wallet files are encrypted and backed up "
                    "securely. These are high-value exfiltration targets.",
                )
        except OSError:
            pass


# -------------------------------------------------------------------
# Category 11: Secrets Manager Status
# -------------------------------------------------------------------

def scan_secrets_manager_status(ctx: ScanContext, quiet: bool) -> None:
    progress("secrets manager availability", quiet)
    cat = "secrets_manager_status"

    # 1Password CLI
    op_path = run_cmd(["which", "op"])
    if op_path and op_path.strip():
        ctx.observe(
            cat, op_path.strip(),
            "1Password CLI (op) is installed",
            reason="tool_available",
            tool="1password",
        )

    # Hashicorp Vault
    vault_path = run_cmd(["which", "vault"])
    if vault_path and vault_path.strip():
        ctx.observe(
            cat, vault_path.strip(),
            "Hashicorp Vault CLI is installed",
            reason="tool_available",
            tool="vault",
        )


# -------------------------------------------------------------------
# Orchestration
# -------------------------------------------------------------------

ALL_SCANS = [
    ("teampcp_iocs", scan_teampcp_iocs),
    ("cloud_credentials", scan_cloud_credentials),
    ("ssh_keys", scan_ssh_keys),
    ("git_credentials", scan_git_credentials),
    ("package_manager_tokens", scan_package_manager_tokens),
    ("kubernetes", scan_kubernetes),
    ("shell_profiles", scan_shell_profiles),
    ("environment_variables", scan_environment_variables),
    ("env_files", scan_env_files),
    ("crypto_wallets", scan_crypto_wallets),
    ("secrets_manager_status", scan_secrets_manager_status),
]


def run_all_scans(
    ctx: ScanContext,
    quiet: bool,
    category: Optional[str] = None,
) -> None:
    for name, func in ALL_SCANS:
        if category and name != category:
            continue
        try:
            func(ctx, quiet)
        except Exception as exc:
            ctx.errors.append(f"{name}: {exc}")


def build_report(ctx: ScanContext) -> Dict[str, Any]:
    elapsed = time.monotonic() - ctx.start_time
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in ctx.findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    op_available = any(
        o.category == "secrets_manager_status"
        and o.details.get("tool") == "1password"
        for o in ctx.observations
    )

    return {
        "scanner_version": VERSION,
        "hostname": ctx.hostname,
        "username": ctx.username,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scan_duration_seconds": round(elapsed, 2),
        "findings": [asdict(f) for f in ctx.findings],
        "observations": [asdict(o) for o in ctx.observations],
        "summary": summary,
        "total_findings": len(ctx.findings),
        "op_cli_available": op_available,
        "errors": ctx.errors,
    }


def jamf_ea_line(summary: Dict[str, int], total: int) -> str:
    parts = [
        f"CRITICAL:{summary.get('critical', 0)}",
        f"HIGH:{summary.get('high', 0)}",
        f"MEDIUM:{summary.get('medium', 0)}",
        f"LOW:{summary.get('low', 0)}",
        f"TOTAL:{total}",
    ]
    return f"<result>{' '.join(parts)}</result>"


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="clawback",
        description="macOS secret exposure scanner",
    )
    parser.add_argument(
        "--pretty", action="store_true",
        help="Pretty-print JSON output",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress progress messages on stderr",
    )
    parser.add_argument(
        "--category",
        choices=[name for name, _ in ALL_SCANS],
        help="Run only a specific scan category",
    )
    parser.add_argument(
        "--audit-env", action="store_true",
        help="Dump all env variable names with classification metadata "
        "(no values) for LLM-assisted tuning of detection heuristics.",
    )
    parser.add_argument(
        "--training", action="store_true",
        help="Anonymize --audit-env output for safe fleet-wide collection. "
        "Replaces file paths with categories, value prefixes with "
        "structural fingerprints. No secret material in output.",
    )
    parser.add_argument(
        "--output-file", metavar="PATH",
        help="Write JSON output to this file instead of stdout. "
        "Useful for CrowdStrike RTR (put + runscript + get).",
    )
    return parser.parse_args(argv)


def _build_audit_record(
    source: str,
    line_num: int,
    var_name: str,
    raw_value: str,
    training: bool,
) -> Dict[str, Any]:
    """Build a single audit record, with optional training-mode anonymization."""
    stripped = _strip_quotes(raw_value)
    is_secret, reason = classify_value(raw_value)

    if not is_secret and _is_secret_locator(var_name, raw_value):
        is_secret = True
        reason = "secret_locator"

    if training:
        return {
            "source_type": _source_category(source),
            "variable": var_name,
            "value_length": len(stripped),
            "value_entropy": round(shannon_entropy(stripped), 2),
            "value_fingerprint": _value_fingerprint(raw_value),
            "char_classes": _char_class_distribution(raw_value),
            "classified_secret": is_secret,
            "reason": reason,
        }

    return {
        "source": source,
        "line": line_num,
        "variable": var_name,
        "value_length": len(stripped),
        "value_entropy": round(shannon_entropy(stripped), 2),
        "value_prefix": (
            stripped[:6] + "..." if len(stripped) > 6 else stripped
        ),
        "classified_secret": is_secret,
        "reason": reason,
    }


def run_audit_env(
    ctx: ScanContext,
    pretty: bool,
    training: bool,
    category: Optional[str] = None,
) -> Tuple[int, str]:
    """Dump every variable found in .env and shell profiles with metadata.

    Returns (exit_code, json_string). In training mode, file paths are
    replaced with categories, value prefixes with structural fingerprints,
    and no hostname or username appears in the output. When category is
    set, only the matching source type is scanned.
    """
    records: List[Dict[str, Any]] = []

    scan_profiles = category in (None, "shell_profiles")
    scan_env_files = category in (None, "env_files")

    if scan_profiles:
        profiles = [
            ctx.home / n for n in
            (".zshrc", ".zprofile", ".zshenv",
             ".bash_profile", ".bashrc", ".profile")
        ]
        for profile in profiles:
            if not file_exists_nonempty(profile):
                continue
            content = safe_read(profile)
            if not content:
                continue
            for line_num, line in enumerate(content.splitlines(), 1):
                if COMMENT_RE.match(line):
                    continue
                match = (
                    EXPORT_RE.search(line) or BARE_ASSIGN_RE.match(line)
                )
                if not match:
                    continue
                records.append(_build_audit_record(
                    str(profile), line_num,
                    match.group(1), match.group(2), training,
                ))

    if scan_env_files:
        for dirname in ENV_SCAN_DIRS:
            root = ctx.home / dirname
            if not root.is_dir():
                continue
            _audit_walk(root, 0, records, training)

    wrapper: Dict[str, Any] = {
        "clawback_version": VERSION,
        "mode": "training" if training else "audit",
        "record_count": len(records),
        "audit_env_variables": records,
    }
    if not training:
        wrapper["hostname"] = ctx.hostname
        wrapper["username"] = ctx.username

    indent = 2 if pretty else None
    return 0, json.dumps(wrapper, indent=indent)


def _audit_walk(
    directory: pathlib.Path,
    depth: int,
    records: List[Dict[str, Any]],
    training: bool,
) -> None:
    if depth > ENV_MAX_DEPTH:
        return
    try:
        entries = list(directory.iterdir())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_dir():
                if entry.name in ENV_PRUNE_DIRS or entry.name.startswith("."):
                    continue
                _audit_walk(entry, depth + 1, records, training)
            elif entry.is_file() and _is_env_filename(entry.name):
                content = safe_read(entry, ENV_FILE_READ_BYTES)
                if not content:
                    continue
                for line_num, line in enumerate(content.splitlines(), 1):
                    parsed = _parse_env_line(line.strip())
                    if not parsed:
                        continue
                    records.append(_build_audit_record(
                        str(entry), line_num,
                        parsed[0], parsed[1], training,
                    ))
        except OSError:
            pass


def _emit(json_str: str, output_file: Optional[str]) -> None:
    """Write JSON output to stdout or a file."""
    if output_file:
        with open(output_file, "w") as fh:
            fh.write(json_str)
            fh.write("\n")
    else:
        print(json_str)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    if args.training:
        args.audit_env = True

    ctx = ScanContext(
        home=pathlib.Path.home(),
        username=getpass.getuser(),
        hostname=socket.gethostname(),
        start_time=time.monotonic(),
        audit_mode=args.audit_env,
    )

    if args.audit_env:
        code, output = run_audit_env(
            ctx, args.pretty, args.training, args.category,
        )
        _emit(output, args.output_file)
        print(
            jamf_ea_line(
                {"critical": 0, "high": 0, "medium": 0, "low": 0}, 0,
            ),
            file=sys.stderr,
        )
        return code

    if not args.quiet:
        print(
            f"clawback v{VERSION} ({ctx.hostname}, {ctx.username})",
            file=sys.stderr,
        )

    try:
        run_all_scans(ctx, args.quiet, args.category)
    except Exception as exc:
        ctx.errors.append(f"fatal: {exc}")

    report = build_report(ctx)

    indent = 2 if args.pretty else None
    _emit(json.dumps(report, indent=indent), args.output_file)

    # JAMF EA summary to stderr (always, even in quiet mode)
    print(
        jamf_ea_line(report["summary"], report["total_findings"]),
        file=sys.stderr,
    )

    if ctx.errors:
        return 2
    if report["total_findings"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
