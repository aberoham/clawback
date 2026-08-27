#!/usr/bin/env python3
"""rattlesnake — macOS secret exposure scanner.

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
import hashlib
import json
import math
import os
import pathlib
import platform
import plistlib
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
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

VERSION = "1.0.0"
MAX_READ_BYTES = 65536
SSH_KEY_READ_BYTES = 2048
ENV_FILE_READ_BYTES = 4096
# Artifacts that must be read whole, not sampled: a truncated manifest, plist,
# workflow or payload yields a false-clean answer rather than a partial one.
# 4 MB is far above any legitimate example (the largest known payload is 728 KB)
# while keeping a pathological file from dominating a scan.
ARTIFACT_MAX_BYTES = 4 * 1024 * 1024
# Lockfiles are legitimately large (a big monorepo lock can exceed 10 MB), so
# they get a much higher ceiling than the hash path. Anything over this is
# reported as an explicit scan error rather than silently skipped.
LOCKFILE_MAX_BYTES = 64 * 1024 * 1024
# Bound on project roots inspected for npm compromise, so a workstation with
# hundreds of checkouts cannot turn one scan into a filesystem crawl.
NPM_MAX_PROJECT_ROOTS = 400
# Bound on packages inspected inside a single node_modules tree.
NPM_MAX_PACKAGES_PER_TREE = 4000
# Global install prefixes. `npm root -g` would be authoritative but needs a
# subprocess; these cover Homebrew, system, and per-version managers.
NPM_GLOBAL_PREFIXES = (
    "/usr/local/lib", "/usr/lib", "/opt/homebrew/lib", "/opt/local/lib",
)
NPM_GLOBAL_HOME_PREFIXES = (
    ".npm-global/lib", ".npm-packages/lib", ".local/lib", "node_modules",
    ".volta/tools/image/node",
)
# Supply-chain discovery goes one level deeper than the .env walk: checkouts
# are commonly nested (org/repo/subpackage) below a workspace directory.
SUPPLY_CHAIN_MAX_DEPTH = 5
# Caches and toolchain directories that never hold a checkout worth scanning.
# Unlike the .env walk, hidden directories ARE traversed (~/.dotfiles and
# similar hold real projects), so these must be named explicitly.
SUPPLY_CHAIN_PRUNE_DIRS = frozenset({
    ".Trash", ".npm", ".bun", ".pnpm-store", ".yarn", ".cargo", ".rustup",
    ".gradle", ".m2", ".gem", ".rbenv", ".pyenv", ".nvm", ".deno",
    ".terraform", ".vagrant", ".docker", ".colima", ".orbstack",
    ".local", ".cache", "Library", ".git", ".hg", ".svn",
    "site-packages", "virtualenvs", "Caches",
    # Database storage. Enumerating these is pathologically slow -- a single
    # ~/.dolt cost 74 seconds for three directories in testing -- and they
    # never contain a checkout.
    ".dolt", ".dolt-data", ".noms", ".minio", ".mysql", ".postgres",
    ".pgdata", ".mongodb", ".elasticsearch", ".influxdb", ".redis",
    ".plastic4", ".sonar", ".gvfs",
    # macOS metadata written beside extracted archives and by Spotlight.
    # No checkout lives here and nothing executes from it, so skipping these
    # avoids a permanent coverage gap without creating a blind spot.
    "__MACOSX", "__MACOSX__", ".fseventsd", ".Spotlight-V100",
    ".DocumentRevisions-V100", ".TemporaryItems",
})
# Hard ceilings on discovery. A prune list is always incomplete, so the walk
# also stops on a directory count and a wall-clock budget; whatever is skipped
# is reported as a scan error rather than passing as clean.
SUPPLY_CHAIN_MAX_DIRS = 25000
SUPPLY_CHAIN_TIME_BUDGET = 20.0

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
    # Harvested by the 2026-08 Shai-Hulud wave: Vault tokens, CI OIDC
    # exchange material, and kubeconfig pointers.
    "VAULT_TOKEN",
    "VAULT_ADDR",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
})

# Template placeholders: Jinja/Go/Helm `{{ … }}`, ERB `<%= … %>`, and the
# angle-bracket convention `<your-token-here>`. Shell-style `${…}` is handled
# separately, since it also appears in genuine config values.
#
# Anchored to the WHOLE value. An unanchored search exempts a value that mixes
# a real credential with a placeholder -- `postgres://admin:hunter2@{{ host }}`
# is a leaked password, not a template variable -- so only a value that is
# entirely a placeholder qualifies.
TEMPLATE_PLACEHOLDER_RE = re.compile(
    r"^(?:\{\{[^{}]*\}\}|<%=?[^<>]*%>|<[^<>\s][^<>]*>)$"
)

# Public cloud resource identifiers. These appear in dashboard URLs and in
# every API call made *with* the accompanying token, so knowing one grants
# nothing on its own -- but a 32-char hex ID trips the long-hex rule.
#
# The resource category is REQUIRED, not optional. Matching any `*_ID` name
# suppressed bearer credentials that happen to end that way: a hex SESSION_ID
# or AUTH_ID is a live token, and SECRET_ID names the thing outright.
RESOURCE_ID_NAME_RE = re.compile(
    r"_(?:ACCOUNT|ZONE|SERVICE|KV|PROJECT|ORG|TENANT|SUBSCRIPTION|"
    r"DISTRIBUTION|BUCKET|WORKSPACE|CUSTOMER|APP|CLIENT)_ID$"
)
# Names that are credentials regardless of the suffix, so never suppressed.
RESOURCE_ID_NEVER_SUPPRESS = (
    "SECRET", "TOKEN", "SESSION", "AUTH", "PASSWORD", "KEY", "CREDENTIAL",
    "PRIVATE", "SIGNATURE", "COOKIE", "BEARER", "REFRESH", "ACCESS",
)
_HEX_ONLY_RE = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)

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

# Home-directory folders that never contain source checkouts. Used only to
# widen the supply-chain search beyond ENV_SCAN_DIRS.
NPM_SCAN_SKIP_HOME_DIRS = frozenset({
    "Library", "Applications", "Movies", "Music", "Pictures",
    "Public", "Downloads", "Sites", "Parallels", "OneDrive",
})

TEAMPCP_C2_DOMAINS = [
    "scan.aquasecurtiy.org",
    "checkmarx.zone",
    "models.litellm.cloud",
    "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io",
]
TEAMPCP_PLIST_MARKERS = ["pgmon", "icp0.io", "tdtqy", "teampcp", "tpcp"]

# -------------------------------------------------------------------
# Supply-chain worm IoCs (Shai-Hulud "Here We Go Again", 2026-08-04)
# -------------------------------------------------------------------

# SHA-256 is the authoritative test for dropper artifacts. Filename alone is
# NOT sufficient: regenerate-unicode-properties (a common Babel transitive
# dependency) ships a legitimate General_Category/Math_Symbol.js, and
# motion-dom ships a legitimate setup.mjs. Matching on name would fire on a
# large share of healthy JS projects.
KNOWN_MALWARE_SHA256 = {
    "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668":
        "Shai-Hulud worm loader (setup.mjs, npm tarball variant)",
    "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb":
        "Shai-Hulud worm loader (setup.mjs, .claude/.vscode variant)",
    "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc":
        "Shai-Hulud stage-2 payload (Math_Symbol.js / math_init.js)",
    "927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f":
        "Shai-Hulud injected .vscode/tasks.json",
    "14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128":
        "Shai-Hulud injected .claude/settings.json",
    "3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7":
        "Shai-Hulud injected GitHub Actions exfil workflow",
    "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7":
        "Shai-Hulud CI runner-memory secret extractor",
    "619c56acf572df75b6004a6fc013c80900316a76099b241d64312da3a44f10b4":
        "Shai-Hulud token-monitor installer script",
}

# SHA-1 of the same artifacts, for cross-referencing fleet tooling that only
# records SHA-1. Not used for detection.
KNOWN_MALWARE_SHA1 = {
    "35a672cf34b996b91f3e1c28cbf3a05a37e036e4": "Math_Symbol.js / math_init.js",
    "686aa40d0fc22c8d569494543a0f891f359f2f99": ".claude/setup.mjs",
    "f525d52ceb966516686b482d3dc0137028cc6a63": ".vscode/setup.mjs",
}

# Candidate dropper filenames. Presence is only a reason to hash the file.
# router_runtime.js is a third stage-2 filename variant.
DROPPER_FILENAMES = (
    "setup.mjs", "Math_Symbol.js", "math_init.js", "router_runtime.js",
)

# Repository-relative directories where the worm stages loaders outside
# node_modules. The two IDE hooks are cross-wired -- .vscode/tasks.json runs
# node .claude/setup.mjs and .claude/settings.json runs node
# .vscode/setup.mjs -- so cleaning only one directory leaves the loader live.
DROPPER_SEARCH_DIRS = (".claude", ".vscode")

# Exact package@version pairs published with the worm payload. Exact-match
# only -- these projects have healthy releases on either side of the bad
# version, so range matching would produce false positives.
#
# This is the directly-compromised core plus notable second-generation
# packages, not the whole campaign: the affected set passed 450 packages and
# 2,200 versions while still growing, and an embedded copy would be stale
# within a day. Load the current full list at scan time with --ioc-file
# (see IOC_FILE_HELP).
#
# Versions verified against GitHub Security Advisories (OSV MAL-2026-*),
# Socket's campaign tracker, and Wiz's published IoC CSV.
# file-entry-cache 11.1.7 appears only in one vendor's prose, with no
# advisory; retained because npm unpublished both, so matching it is free.
COMPROMISED_NPM_PACKAGES = {
    # Directly compromised: keyv / cacheable maintainer account takeover
    "keyv": ("6.0.0",),
    "@keyv/redis": ("6.0.0",),
    "@keyv/sqlite": ("6.0.0",),
    "@keyv/mongo": ("6.0.0",),
    "@keyv/postgres": ("6.0.0",),
    "@keyv/mysql": ("6.0.0",),
    "@keyv/mssql": ("6.0.0",),
    "@keyv/etcd": ("6.0.0",),
    "@keyv/memcache": ("6.0.0",),
    "@keyv/valkey": ("6.0.0",),
    "@keyv/dynamo": ("6.0.0",),
    "@keyv/bigmap": ("6.0.0",),
    "@keyv/test-suite": ("6.0.0",),
    "@keyv/compress-brotli": ("6.0.0",),
    "@keyv/compress-gzip": ("6.0.0",),
    "@keyv/compress-lz4": ("6.0.0",),
    "cacheable": ("2.5.1",),
    "cacheable-request": ("13.0.20",),
    "@cacheable/net": ("2.1.1",),
    "@cacheable/node-cache": ("3.1.2",),
    "@cacheable/memory": ("2.2.1",),
    "@cacheable/utils": ("2.5.1",),
    "flat-cache": ("6.1.24",),
    "file-entry-cache": ("11.1.6", "11.1.7"),
    "cache-manager": ("7.2.10",),
    "ecto": ("5.0.1",),
    # Second generation: published by the worm using stolen maintainer tokens
    "@thiennq/docs-viewer": ("1.6.2", "1.6.3", "1.6.4"),
    "@deliveroo/reevent": ("1.0.1",),
    "@deliveroo/determinator": ("0.2.1",),
    "@or-sdk/invitations": ("1.4.8", "1.4.9", "1.4.10"),
    "@picsart/ai-sdk": ("3.32.2",),
    "@picsart/gen-ai": ("2.55.11",),
    "@qlik/embed-runtime": ("1.6.4",),
    "picasso.js": ("2.11.6",),
    "picasso-plugin-hammer": ("2.11.6",),
    "picasso-plugin-q": ("2.11.6",),
    "hamus.js": ("0.4.1",),
    "http-metrics-middleware": ("2.2.2",),
    "@workbench-stack/core": ("3.9.8",),
    "umadev": ("1.0.74",),
}

# Last known-good version, for remediation text. keyv is the trap here: the
# attacker pushed a 6.0.1 git tag during the takeover, so "upgrade to 6.0.1"
# is wrong -- there is no clean 6.x release.
SAFE_NPM_VERSIONS = {
    "keyv": "5.6.0",
    "flat-cache": "6.1.23",
    "file-entry-cache": "11.1.5",
    "cacheable": "2.5.0",
    "cacheable-request": "13.0.19",
    "cache-manager": "7.2.9",
    "ecto": "5.0.0",
    "@keyv/redis": "5.1.6",
}

# npm scopes with org-wide second-generation infections. Presence of these
# scopes is recorded as an observation, never a finding: most versions in
# them are clean, and a fleet scanner that cried wolf on every @qlik or
# @servicetitan dependency would be turned off within a day.
COMPROMISED_NPM_SCOPES = (
    "@servicetitan/", "@ornikar/", "@onereach/", "@or-sdk/", "@qlik/",
    "@nebula.js/", "@umacloud/", "@arv-bedrock/", "@hubsync/",
    "@cacheable/", "@keyv/", "@picsart/", "@deliveroo/",
)

IOC_FILE_HELP = (
    "JSON file extending the built-in compromised-package list, for the long "
    "tail of a live campaign. Format: {\"packages\": {\"name\": [\"1.2.3\"]}}"
)

# Network and blockchain indicators. Matched against autostart command
# strings and persistence scripts, never resolved or contacted.
SUPPLY_CHAIN_NET_IOCS = (
    "npm-cache.com",
    "js-mirror.com",
    "pypi-get.com",
    "eth-mainnet.nodereal.io",
    "eth.llamarpc.com",
    "go.getblock.io",
    "0xe1f2395ee43e45a1556ec6438a88c31b83493103",
    "oven-sh/bun/releases/download/bun-v1.3.13",
)

# Strings unique to the payload's fallback C2 and its runtime guards. Useful
# for hunting in scripts and injected config, and cheap to match.
SUPPLY_CHAIN_MARKER_STRINGS = (
    "thebeautifulmarchoftime",
    "thebeautifulsnadsoftime",
    "_NODE_RUNTIME_INIT",
)

# Dead-man's-switch persistence planted by the 2026-08 wave.
SHAI_HULUD_PERSISTENCE_PATHS = (
    ".config/gh-token-monitor",
    ".config/gh-token-monitor/token",
    ".config/gh-token-monitor/handler",
    ".config/gh-token-monitor/started_at",
    ".local/bin/gh-token-monitor.sh",
    "Library/LaunchAgents/com.user.gh-token-monitor.plist",
    ".config/systemd/user/gh-token-monitor.service",
)
SHAI_HULUD_TMP_PATHS = (
    "/tmp/gh-token-monitor.out.log",
    "/tmp/gh-token-monitor.err.log",
    "/tmp/tmp.dpkg_14527.lock",
)

# Campaign-specific indicators. None of these occur in legitimate code, so a
# match is sufficient on its own to call something malicious.
CAMPAIGN_AUTOSTART_MARKERS = (
    SUPPLY_CHAIN_NET_IOCS + SUPPLY_CHAIN_MARKER_STRINGS + ("gh-token-monitor",)
)
# Weak indicators: a command merely *naming* a dropper file. These filenames
# occur in healthy packages (motion-dom ships setup.mjs), so a name alone is
# not compromise -- the referenced file has to hash to a known payload. Same
# rule the installed-package preinstall check follows.
DROPPER_NAME_MARKERS = DROPPER_FILENAMES


# Injected CI workflow. Named "Run Copilot" inside a plausible filename, it
# dumps toJSON(secrets) to a text file and uploads it as a build artifact.
# This vector survives removal of the npm package and re-fires on every push.
WORKFLOW_SECRET_DUMP_MARKERS = (
    "tojson(secrets)",
    "format-results.txt",
)
# Without this, a formatting workflow that merely writes format-results.txt was
# reported as serialising the whole secret store. The filename is supporting
# evidence; expanding the secret context is the finding.
WORKFLOW_SECRET_DUMP_REQUIRED = "tojson(secrets)"

# Agent / IDE autostart surfaces. The 2026-08 wave commits hooks here so the
# payload runs when a developer opens the repo or starts an AI coding
# session -- no 'npm install' required.
AGENT_HOOK_RELPATHS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".vscode/tasks.json",
    ".cursor/environment.json",
)

# A LaunchAgent that relaunches a bare script out of a config/cache
# directory is the shape of this worm's watcher. Real applications launch a
# binary inside an .app bundle, so bundles are excluded to avoid flagging
# ordinary login items.
PERSISTENCE_SCRIPT_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl",
)
PERSISTENCE_SUSPECT_DIRS = (
    "/.config/", "/.local/", "/.cache/", "/library/caches/", "/tmp/",
    "/var/tmp/", "/.npm/", "/.bun/",
)

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
    # Extra compromised package -> versions, loaded from --ioc-file.
    extra_iocs: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    # Categories that ran to completion, reported as scan_scope so consumers
    # can tell an absent finding from an unscanned category.
    categories_scanned: List[str] = field(default_factory=list)
    # Artifacts this run could not inspect: unreadable directories, oversize
    # files, truncated discovery. Kept apart from `errors` because those set
    # exit code 2 ("scan error"), and an inaccessible ~/Documents/__MACOSX is
    # a coverage gap on an otherwise healthy host, not a malfunction.
    coverage_gaps: List[str] = field(default_factory=list)

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

    def gap(self, category: str, message: str) -> None:
        """Record something this scan could not inspect (deduplicated)."""
        entry = f"{category}: {message}"
        if entry not in self.coverage_gaps:
            self.coverage_gaps.append(entry)

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


def sha256_file(path: pathlib.Path, max_bytes: int = ARTIFACT_MAX_BYTES) -> Optional[str]:
    """Hex SHA-256 of a file, or None on any error or oversize file.

    Files larger than max_bytes are skipped rather than hashed: every known
    dropper artifact is under 1 MB, and hashing large bundles would slow the
    scan without adding detections.
    """
    try:
        if path.stat().st_size > max_bytes:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError):
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


def group_or_world_accessible(path: pathlib.Path) -> Optional[bool]:
    """Whether anyone other than the owner can reach a file.

    Tests the permission bits that matter rather than comparing against an
    exact mode: 0o400 and 0o000 are stricter than 0o600, not looser, and
    reporting them as "overly permissive" inverts the operator's triage order
    while advising a chmod that would loosen a correctly-protected file.
    """
    try:
        return bool(stat.S_IMODE(path.stat().st_mode) & 0o077)
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

    # A value that is entirely a template placeholder is substituted at deploy
    # time and holds no secret material. Checked on the value rather than the
    # filename, since the naming conventions are many (.env.j2, .env.tmpl,
    # templates/.env) and a filename-only rule keeps missing them.
    if TEMPLATE_PLACEHOLDER_RE.fullmatch(stripped):
        return False, "template_placeholder"

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

    # High entropy + sufficient length.
    #
    # A whitespace-separated value is scored per token rather than whole. Two
    # failure modes sit either side of this: scoring the whole string flags a
    # JVM options list, which reaches 5.1 through character variety alone,
    # while skipping such values entirely hides a credential embedded among
    # ordinary flags (`-Xmx512m -Dservice.token=<secret>`). Each token is
    # measured on its own, and a `flag=value` token is scored on the value.
    for token in re.split(r"\s+", stripped) if re.search(r"\s", stripped) else [stripped]:
        candidate = token
        if "=" in candidate:
            candidate = candidate.rsplit("=", 1)[1]
        candidate = _strip_quotes(candidate)
        if len(candidate) < 20:
            continue
        ent = shannon_entropy(candidate)
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


def is_public_resource_id(var_name: str, raw_value: str) -> bool:
    """True for a public cloud resource identifier misread as a secret.

    A 32-char hex Cloudflare zone ID or Fastly service ID satisfies the
    long-hex structural rule, but appears in dashboard URLs and in every API
    call made with the accompanying token, so it grants nothing alone. Both
    halves are required: the name must end in an `_ID` form and the value must
    be plain hex, which keeps `CLIENT_SECRET`-style variables untouched.
    """
    upper = var_name.upper()
    if any(word in upper for word in RESOURCE_ID_NEVER_SUPPRESS):
        return False
    if not RESOURCE_ID_NAME_RE.search(upper):
        return False
    return bool(_HEX_ONLY_RE.fullmatch(_strip_quotes(raw_value)))


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
        bad_perms = group_or_world_accessible(entry) is True
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

        # Only advise a chmod when the mode is actually the problem: telling an
        # operator to relax 0o400 to 0o600 would loosen a correct file.
        remediation = "Add a passphrase: ssh-keygen -p -f <path>. "
        if bad_perms:
            remediation += "Restrict permissions: chmod 600 <path>. "
        remediation += (
            "Consider using macOS Keychain: ssh-add --apple-use-keychain."
        )

        ctx.add(
            cat, entry, severity, desc, remediation,
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
            if val_hit and is_public_resource_id(var_name, raw_value):
                val_hit, val_reason = False, "public_resource_id"
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
        if val_hit and is_public_resource_id(var_name, var_value):
            val_hit = False
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
    # Templating suffixes and a `templates/` ancestor are both common
    # conventions that a filename-tag check alone misses. This is a secondary
    # signal only: placeholder values are recognised by classify_value(), so a
    # template is handled correctly even when nothing in its path says so.
    is_template = (
        any(tag in name_lower for tag in ("example", "sample", "template"))
        or name_lower.endswith((".j2", ".jinja", ".jinja2", ".tmpl", ".tpl",
                                ".erb", ".hbs", ".mustache", ".gotmpl"))
        or any(part.lower() in ("templates", "template")
               for part in path.parent.parts)
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
        if val_hit and is_public_resource_id(var_name, raw_value):
            val_hit, val_reason = False, "public_resource_id"
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

def scan_npm_supply_chain(ctx: ScanContext, quiet: bool) -> None:
    """Detect installed npm packages published with worm payloads.

    Three independent signals, cheapest first:
      1. lockfiles pinning a known-compromised package@version
      2. dropper artifacts inside an installed compromised package, by hash
      3. install-script posture (informational, not a finding)
    """
    progress("npm supply-chain compromise", quiet)
    cat = "npm_supply_chain"

    _scan_npm_install_posture(ctx, cat)

    roots = _find_npm_project_roots(ctx)
    for root in roots:
        _scan_lockfiles(ctx, cat, root)
        _scan_installed_packages(ctx, cat, root)

    # `npm install -g` puts the tree outside any project, so a globally
    # installed compromised package was invisible even though its lifecycle
    # hook had already run.
    for global_modules in _npm_global_module_dirs(ctx):
        _scan_installed_packages(ctx, cat, global_modules.parent)


def _npm_global_module_dirs(ctx: ScanContext) -> List[pathlib.Path]:
    """Global node_modules trees, without shelling out to `npm root -g`.

    Covers the common prefixes plus nvm/n version directories. Returned as
    node_modules paths; the caller passes the parent so the existing
    per-package logic applies unchanged.
    """
    found: List[pathlib.Path] = []
    seen: Set[pathlib.Path] = set()

    candidates = [pathlib.Path(p) for p in NPM_GLOBAL_PREFIXES]
    candidates.extend(ctx.home / rel for rel in NPM_GLOBAL_HOME_PREFIXES)

    # nvm / n / volta each keep one prefix per installed node version.
    for versioned in (
        ctx.home / ".nvm/versions/node",
        pathlib.Path("/usr/local/n/versions/node"),
        ctx.home / ".volta/tools/image/node",
    ):
        try:
            if versioned.is_dir():
                candidates.extend(sorted(versioned.iterdir()))
        except OSError:
            pass

    for prefix in candidates:
        if prefix.name == "node_modules":
            modules = prefix
        elif (prefix / "lib/node_modules").is_dir():
            # nvm / n / volta keep globals at <version>/lib/node_modules.
            modules = prefix / "lib/node_modules"
        else:
            modules = prefix / "node_modules"
        try:
            if not modules.is_dir():
                continue
            key = modules.resolve()
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        found.append(modules)
    return found


def _npm_search_roots(ctx: ScanContext) -> List[pathlib.Path]:
    """Directories to search for JS projects.

    ENV_SCAN_DIRS alone misses checkouts in personally-named directories
    (~/CLAUDE, ~/git, ~/acme), so every non-hidden top-level directory in the
    home folder is included, minus the macOS system folders that never hold
    source. ENV_SCAN_DIRS is deliberately left untouched: widening it would
    change which .env files the existing scanners report.
    """
    roots = [ctx.home / d for d in ENV_SCAN_DIRS]
    try:
        for entry in ctx.home.iterdir():
            try:
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            name = entry.name
            if name in NPM_SCAN_SKIP_HOME_DIRS:
                continue
            # Hidden top-level directories are included: ~/.dotfiles and
            # similar hold real checkouts. The heavy caches and toolchain
            # directories are excluded by SUPPLY_CHAIN_PRUNE_DIRS.
            if name in SUPPLY_CHAIN_PRUNE_DIRS or name in ENV_PRUNE_DIRS:
                continue
            if entry not in roots:
                roots.append(entry)
    except OSError:
        pass
    return [r for r in roots if r.is_dir()]


def _walk_project_tree(
    ctx: ScanContext,
    match: Callable[[pathlib.Path, List[pathlib.Path]], None],
    limit: int,
    counter: Callable[[], int],
) -> None:
    """Depth-limited walk of the developer directories.

    Directories are deduplicated by resolved path, so a symlink cycle or two
    paths onto the same tree cannot spend the discovery budget twice. Hidden
    directories are traversed -- checkouts do live under ~/.dotfiles and
    similar -- but the heavy caches in SUPPLY_CHAIN_PRUNE_DIRS are skipped.
    """
    visited: Set[pathlib.Path] = set()
    deadline = time.monotonic() + SUPPLY_CHAIN_TIME_BUDGET
    exhausted: List[str] = []

    def out_of_budget() -> bool:
        if len(visited) >= SUPPLY_CHAIN_MAX_DIRS:
            if not exhausted:
                exhausted.append(
                    f"directory limit ({SUPPLY_CHAIN_MAX_DIRS})"
                )
            return True
        if time.monotonic() > deadline:
            if not exhausted:
                exhausted.append(
                    f"time budget ({SUPPLY_CHAIN_TIME_BUDGET:.0f}s)"
                )
            return True
        return False

    def walk(directory: pathlib.Path, depth: int) -> None:
        if depth > SUPPLY_CHAIN_MAX_DEPTH or counter() >= limit:
            return
        if out_of_budget():
            return
        try:
            resolved = directory.resolve()
        except OSError:
            return
        if resolved in visited:
            return
        visited.add(resolved)

        try:
            entries = list(directory.iterdir())
        except OSError as exc:
            # Silently returning omitted every lockfile, hook and workflow
            # beneath this path while the scan still reported success.
            ctx.gap("supply_chain_discovery", f"could not list {directory} ({exc}); "
                "its contents were NOT scanned")
            return

        match(directory, entries)

        for entry in entries:
            if counter() >= limit or out_of_budget():
                return
            try:
                if not entry.is_dir():
                    continue
                name = entry.name
                if name in ENV_PRUNE_DIRS or name in SUPPLY_CHAIN_PRUNE_DIRS:
                    continue
                walk(entry, depth + 1)
            except OSError:
                pass

    for root in _npm_search_roots(ctx):
        walk(root, 0)

    if exhausted:
        ctx.gap("supply_chain_discovery", f"stopped early on {exhausted[0]} after "
            f"{len(visited)} directories; some projects were NOT scanned")
    elif counter() >= limit:
        ctx.gap("supply_chain_discovery", f"hit the {limit}-item cap; "
            "some projects were NOT scanned")


def _find_npm_project_roots(ctx: ScanContext) -> List[pathlib.Path]:
    """Project roots (directories holding a package.json) under dev dirs."""
    roots: List[pathlib.Path] = []

    def match(directory: pathlib.Path, entries: List[pathlib.Path]) -> None:
        if any(e.name == "package.json" for e in entries):
            roots.append(directory)

    _walk_project_tree(ctx, match, NPM_MAX_PROJECT_ROOTS, lambda: len(roots))
    return roots


def _compromised_versions(ctx: ScanContext, name: str) -> Tuple[str, ...]:
    """Compromised versions for a package: built-in list plus --ioc-file."""
    versions = tuple(COMPROMISED_NPM_PACKAGES.get(name, ()))
    extra = ctx.extra_iocs.get(name)
    if extra:
        versions = versions + tuple(v for v in extra if v not in versions)
    return versions


def _lockfile_remediation(name: str) -> str:
    safe = SAFE_NPM_VERSIONS.get(name)
    pin = (
        f"Pin {name} back to {safe} (the last release before the compromise). "
        if safe else
        "Pin this package to a version published before 2026-08-04. "
    )
    warn = (
        "Do NOT 'upgrade' keyv to 6.0.1 -- that tag was created by the "
        "attacker during the takeover and is not a fix. "
        if name == "keyv" else ""
    )
    return (
        "A known-malicious package version is pinned here. Treat this host as "
        "credential-compromised. ORDER MATTERS: first check the "
        "malware_persistence findings and remove any gh-token-monitor watcher "
        "-- its handler fires when the stolen token stops working, so revoking "
        "first is the trigger. Once no watcher remains, revoke (do not merely "
        "rotate) npm and GitHub tokens, then rotate cloud, Vault and "
        "Kubernetes credentials. "
        + pin + warn +
        "Delete node_modules and reinstall from the corrected lockfile."
    )


# Only npm's JSON lockfiles are parsed. Yarn, pnpm and bun each have several
# incompatible text encodings whose parsers were the highest-defect code in
# this scanner, and they buy little: a lockfile records *intent*, while
# node_modules records what actually landed on the machine -- which is what
# decides whether a lifecycle hook ran. Installed packages are scanned
# thoroughly, including pnpm's virtual store, so a yarn/pnpm/bun project with
# dependencies installed is still covered. The residual gap is a project whose
# lockfile pins a compromised version with nothing installed; that is reported
# as an observation rather than parsed.
LOCKFILE_NAMES = ("package-lock.json", "npm-shrinkwrap.json")
# Lockfiles from other package managers: not parsed, but their presence in a
# project with no node_modules means nothing here can be verified.
FOREIGN_LOCKFILE_NAMES = (
    "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
)
def _read_plist_as_text(
    ctx: ScanContext, cat: str, path: pathlib.Path
) -> Optional[str]:
    """Return a plist as XML text, converting the binary format if needed.

    A binary plist read as replacement-decoded text contains none of the XML
    the heuristics look for, so a malicious binary LaunchAgent produced no
    finding and no error. plistlib is stdlib, so converting costs nothing.
    """
    raw = safe_read_bytes(path, ARTIFACT_MAX_BYTES)
    if raw is None:
        ctx.errors.append(f"{cat}: could not read {path}")
        return None
    if not raw:
        return None

    if raw.lstrip()[:8] == b"bplist00":
        try:
            parsed = plistlib.loads(raw)
        except Exception as exc:  # noqa: BLE001 - report and move on
            ctx.gap(cat, f"{path} is a binary plist that could not be parsed "
                f"({type(exc).__name__}: {exc}); it was NOT inspected")
            return None
        try:
            return plistlib.dumps(parsed).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            ctx.gap(cat, f"{path} could not be normalised to XML ({exc}); "
                "it was NOT inspected")
            return None

    return raw.decode("utf-8", errors="replace")


PLIST_EXECUTABLE_KEYS = (
    "Program", "ProgramArguments", "BundleProgram", "WatchPaths",
    "StandardOutPath", "StandardErrorPath", "WorkingDirectory",
)


def _plist_executable_text(content: str) -> str:
    """Concatenate only the values of a plist's executable-ish keys.

    Comments and descriptive strings are not executed, so a marker appearing
    there is not evidence of anything.
    """
    parts: List[str] = []
    for key in PLIST_EXECUTABLE_KEYS:
        for match in re.finditer(
            r"<key>\s*" + re.escape(key) + r"\s*</key>\s*(.*?)(?=<key>|</dict>)",
            content,
            re.IGNORECASE | re.S,
        ):
            parts.extend(re.findall(r"<string>([^<]*)</string>", match.group(1)))
    # The Label is not executable but names the agent, and the campaign's
    # watcher is identified by its label.
    parts.extend(re.findall(
        r"<key>\s*Label\s*</key>\s*<string>([^<]*)</string>",
        content, re.IGNORECASE,
    ))
    return "\n".join(parts)


def _parent_traversable(path: pathlib.Path) -> bool:
    """Whether every existing ancestor of a path can be traversed.

    Distinguishes "this file is genuinely absent" from "we were not allowed to
    look", which decides whether an absent watcher can be trusted.
    """
    for ancestor in list(path.parents):
        try:
            if not ancestor.exists():
                continue
            if not os.access(str(ancestor), os.X_OK):
                return False
            break
        except OSError:
            return False
    return True


def _plist_flag_enabled(content: str, key: str) -> bool:
    """Whether a plist boolean key is present AND set true.

    KeepAlive also accepts a dict (e.g. {SuccessfulExit: false}), which counts
    as enabled: launchd will still relaunch under those conditions.
    """
    match = re.search(
        r"<key>\s*" + re.escape(key) + r"\s*</key>\s*(<[^>]+>)",
        content,
        re.IGNORECASE,
    )
    if not match:
        return False
    value = match.group(1).lower()
    if value.startswith("<true"):
        return True
    if value.startswith("<dict"):
        return True
    return False


def _strip_yaml_comments(text: str) -> str:
    """Drop YAML comments, leaving '#' that sits inside a quoted scalar.

    Used only to decide whether a marker is executable content. A '#' line
    inside a block scalar is treated as a comment, which is correct enough: a
    shell comment is not executable either.
    """
    out: List[str] = []
    for line in text.splitlines():
        quote = None
        cut = None
        i = 0
        while i < len(line):
            ch = line[i]
            if quote:
                if ch == "\\" and quote == '"':
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "#":
                # A comment needs whitespace before it, or to start the line.
                if i == 0 or line[i - 1] in " \t":
                    cut = i
                    break
            i += 1
        out.append(line if cut is None else line[:cut])
    return "\n".join(out)


def _strip_jsonc(text: str) -> str:
    """Normalise JSONC to strict JSON.

    One string-aware pass per concern, sharing a scanner. Both passes must know
    where strings are: a regex for "//" matches inside base64 integrity hashes
    ("sha512-...gg0y//+LQ..."), and stripping there corrupts the value. Comments
    go first, because judging trailing commas beforehand fails on `[1, // note`
    -- the lookahead stops at the comment and keeps a comma that only becomes
    trailing once the comment is gone.
    """
    return _scan_json_text(_scan_json_text(text, drop_comments=True),
                           drop_trailing_commas=True)


def _scan_json_text(
    text: str,
    drop_comments: bool = False,
    drop_trailing_commas: bool = False,
) -> str:
    """Copy JSON text, optionally removing comments or trailing commas.

    String literals (with escapes) are passed through untouched.
    """
    out: List[str] = []
    i = 0
    n = len(text)
    in_string = False

    while i < n:
        ch = text[i]

        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if drop_comments and ch == "/" and i + 1 < n:
            if text[i + 1] == "/":
                while i < n and text[i] not in "\r\n":
                    i += 1
                continue
            if text[i + 1] == "*":
                closing = text.find("*/", i + 2)
                i = n if closing == -1 else closing + 2
                continue

        if drop_trailing_commas and ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def _loads_jsonc(text: str) -> Any:
    """Parse JSON that may contain comments and trailing commas."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    return json.loads(_strip_jsonc(text))



def _iter_lockfile_entries(
    path: pathlib.Path, text: str
) -> List[Tuple[str, str]]:
    """Yield (package_name, resolved_version) pairs from an npm lockfile.

    Handles v1's nested `dependencies` tree and v2/v3's flat `packages` map,
    including both alias encodings, since a compromised package can hide behind
    an alias in either.
    """
    entries: List[Tuple[str, str]] = []
    name = path.name

    if name in LOCKFILE_NAMES:
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            raise
        if not isinstance(data, dict):
            return entries

        # v2/v3: flat "packages" map. Honour the alias case, where the tree
        # path is the alias and the real package is in meta["name"].
        packages = data.get("packages")
        if packages and not isinstance(packages, dict):
            raise ValueError("'packages' is not an object")
        for pkg_path, meta in (packages or {}).items():
            if not isinstance(meta, dict):
                continue
            if pkg_path == "":
                continue
            real = meta.get("name")
            pkg = str(real) if real else str(pkg_path).split("node_modules/")[-1]
            version = meta.get("version")
            if pkg and isinstance(version, str):
                entries.append((pkg, version))

        # v1: nested "dependencies" tree. Also present alongside "packages"
        # in v2 for backwards compatibility, so dedup happens downstream.
        def walk_deps(node: Any) -> None:
            if not isinstance(node, dict):
                return
            deps = node.get("dependencies")
            if deps and not isinstance(deps, dict):
                raise ValueError("'dependencies' is not an object")
            for dep_name, meta in (deps or {}).items():
                if not isinstance(meta, dict):
                    continue
                version = meta.get("version")
                if isinstance(version, str):
                    # npm v1 aliases record "npm:real@version" in version.
                    if version.startswith("npm:"):
                        aliased = version[4:]
                        at = aliased.rfind("@")
                        if at > 0:
                            entries.append((aliased[:at], aliased[at + 1:]))
                        else:
                            entries.append((str(dep_name), version))
                    else:
                        entries.append((str(dep_name), version))
                # Always recurse: an alias entry can carry its own dependency
                # tree, and returning early here hid compromised transitive
                # packages nested beneath it.
                walk_deps(meta)

        walk_deps(data)
        return entries

    return entries


def _note_unparsed_lockfiles(ctx: ScanContext, cat: str, root: pathlib.Path) -> None:
    """Flag a yarn/pnpm/bun project whose dependencies are not installed.

    With dependencies installed, those managers are covered by the
    installed-package scan. With nothing installed there is nothing to inspect
    and their lockfiles are not parsed, so say so rather than imply coverage.
    """
    if (root / "node_modules").is_dir():
        return
    present = [n for n in FOREIGN_LOCKFILE_NAMES if (root / n).is_file()]
    if not present:
        return
    ctx.observe(
        cat, root / present[0],
        f"{present[0]} present with no node_modules; compromised versions are "
        "detected from installed packages, so this project is unverified",
        "lockfile_not_parsed",
        lockfiles=present,
        guidance="Install dependencies and re-scan, or supply the current "
                 "campaign list with --ioc-file and check the lockfile by hand.",
    )


def _scan_lockfiles(ctx: ScanContext, cat: str, root: pathlib.Path) -> None:
    """Flag exact compromised package@version pairs pinned in a lockfile."""
    _note_unparsed_lockfiles(ctx, cat, root)

    for lockname in LOCKFILE_NAMES:
        lockfile = root / lockname
        if not lockfile.is_file():
            continue

        try:
            size = lockfile.stat().st_size
        except OSError as exc:
            ctx.errors.append(f"{cat}: cannot stat {lockfile}: {exc}")
            continue
        if size > LOCKFILE_MAX_BYTES:
            ctx.gap(cat, f"{lockfile} is {size} bytes (over the "
                f"{LOCKFILE_MAX_BYTES}-byte limit) and was NOT scanned")
            continue

        text = safe_read(lockfile, LOCKFILE_MAX_BYTES)
        if text is None:
            ctx.errors.append(f"{cat}: could not read {lockfile}")
            continue

        try:
            entries = _iter_lockfile_entries(lockfile, text)
        except Exception as exc:  # noqa: BLE001 - contain per lockfile
            # Includes AttributeError from a hostile schema (e.g. "packages"
            # as a string). Without containment here, run_all_scans() caught
            # it at the category level and every later project root went
            # unscanned.
            ctx.gap(cat, f"could not parse {lockfile}: "
                f"{type(exc).__name__}: {exc}; this lockfile was NOT scanned")
            continue

        scopes_seen = set()
        reported = set()
        for pkg, version in entries:
            if version in _compromised_versions(ctx, pkg):
                if (pkg, version) not in reported:
                    reported.add((pkg, version))
                    ctx.add(
                        cat, lockfile, Severity.CRITICAL,
                        f"Lockfile pins compromised package {pkg}@{version}",
                        _lockfile_remediation(pkg),
                        package=pkg, version=version,
                        campaign="shai-hulud-2026-08",
                    )
            scopes_seen.update(
                s for s in COMPROMISED_NPM_SCOPES if pkg.startswith(s)
            )

        if scopes_seen:
            ctx.observe(
                cat, lockfile,
                "Dependencies from npm scopes hit by the 2026-08 worm: "
                + ", ".join(sorted(scopes_seen)),
                "compromised_scope_present",
                scopes=sorted(scopes_seen),
                guidance="Most versions in these scopes are clean. Verify "
                         "against the current campaign list via --ioc-file.",
            )


def _iter_installed_packages(
    modules: pathlib.Path,
) -> Tuple[List[Tuple[str, pathlib.Path]], bool, List[str]]:
    """Yield (package_name, directory) for every installed package.

    Nested trees are traversed: a version conflict routinely puts a package at
    node_modules/parent/node_modules/keyv, and with no usable lockfile that is
    the only place it appears. Scoped packages live one level deeper.

    Returns (packages, truncated). `truncated` is True when the per-tree cap
    was hit, so the caller can report the gap instead of letting the remaining
    packages read as clean.
    """
    out: List[Tuple[str, pathlib.Path]] = []
    visited: Set[pathlib.Path] = set()
    truncated = False
    unreadable: List[str] = []

    def descend(tree: pathlib.Path) -> None:
        nonlocal truncated
        try:
            resolved = tree.resolve()
        except OSError as exc:
            unreadable.append(f"{tree} ({exc})")
            truncated = True
            return
        if resolved in visited:
            return
        visited.add(resolved)

        try:
            entries = sorted(tree.iterdir())
        except OSError as exc:
            # Failing quietly here let the scan exit clean while an entire
            # package tree went uninspected.
            unreadable.append(f"{tree} ({exc})")
            truncated = True
            return

        for entry in entries:
            if len(out) >= NPM_MAX_PACKAGES_PER_TREE:
                truncated = True
                return
            try:
                if not entry.is_dir() or entry.name in (".bin", ".cache"):
                    continue

                # pnpm's virtual store: every package, including transitive
                # ones, lives at .pnpm/<snapshot>/node_modules/<name> as a
                # sibling of its parent rather than nested beneath it.
                # Treating .pnpm as one package meant those manifests and
                # payloads were never inspected unless also hoisted.
                if entry.name == ".pnpm":
                    for snapshot in sorted(entry.iterdir()):
                        if len(out) >= NPM_MAX_PACKAGES_PER_TREE:
                            truncated = True
                            return
                        if not snapshot.is_dir():
                            continue
                        nested_store = snapshot / "node_modules"
                        if nested_store.is_dir():
                            descend(nested_store)
                    continue

                if entry.name.startswith("@"):
                    for scoped in sorted(entry.iterdir()):
                        if len(out) >= NPM_MAX_PACKAGES_PER_TREE:
                            truncated = True
                            return
                        if scoped.is_dir():
                            out.append((f"{entry.name}/{scoped.name}", scoped))
                            nested = scoped / "node_modules"
                            if nested.is_dir():
                                descend(nested)
                else:
                    out.append((entry.name, entry))
                    nested = entry / "node_modules"
                    if nested.is_dir():
                        descend(nested)
            except OSError:
                continue

    descend(modules)
    return out, truncated, unreadable


def _scan_installed_packages(ctx: ScanContext, cat: str, root: pathlib.Path) -> None:
    """Inspect installed packages for compromised versions and payloads.

    Every installed package is checked, not just the built-in name list:
    the worm republished whatever the stolen token could publish, so a
    second-generation package absent from the list would otherwise be missed
    entirely. Hashing stays cheap because a digest is only computed when a
    file already carries one of the dropper names.
    """
    modules = root / "node_modules"
    if not modules.is_dir():
        return

    packages, truncated, unreadable = _iter_installed_packages(modules)
    for failure in unreadable:
        ctx.gap(cat, f"could not enumerate {failure}; installed packages there "
            "were NOT scanned")
    if truncated and not unreadable:
        ctx.gap(cat, f"{modules} has more than {NPM_MAX_PACKAGES_PER_TREE} "
            "installed packages; the remainder were NOT scanned")

    for name, pkg_dir in packages:
        # One hostile or malformed manifest must not abandon the rest of the
        # tree. Without this, an AttributeError on a package.json whose
        # "scripts" was a string aborted the whole category -- so a
        # compromised package sitting in the same node_modules went unreported.
        try:
            _scan_one_installed_package(ctx, cat, name, pkg_dir)
        except Exception as exc:  # noqa: BLE001 - keep scanning the tree
            ctx.gap(cat, f"error inspecting {pkg_dir}: "
                f"{type(exc).__name__}: {exc}; this package was NOT scanned")


def _scan_one_installed_package(
    ctx: ScanContext, cat: str, name: str, pkg_dir: pathlib.Path
) -> None:
    """Inspect a single installed package directory."""
    manifest = pkg_dir / "package.json"
    installed_version = None
    text = safe_read(manifest, ARTIFACT_MAX_BYTES)

    # An unreadable manifest is not the same as an absent one: with no usable
    # lockfile it was the only place a compromised version would show up, so
    # skipping quietly produced neither a finding nor an error.
    if text is None:
        try:
            exists = manifest.is_file()
        except OSError:
            exists = False
        if exists:
            ctx.gap(cat, f"could not read {manifest}; version and preinstall "
                "were NOT checked")

    if text:
        try:
            meta = json.loads(text)
        except (ValueError, TypeError) as exc:
            ctx.gap(
                cat,
                f"could not parse {manifest}: {exc}; version and preinstall "
                "were NOT checked",
            )
            meta = None

        if isinstance(meta, dict):
            installed_version = meta.get("version")
            # The manifest name is authoritative; an aliased install has a
            # directory name that does not match the real package.
            real_name = meta.get("name")
            if isinstance(real_name, str) and real_name:
                name = real_name

            if installed_version in _compromised_versions(ctx, name):
                ctx.add(
                    cat, manifest, Severity.CRITICAL,
                    f"Installed package is a compromised version: "
                    f"{name}@{installed_version}",
                    _lockfile_remediation(name),
                    package=name, version=installed_version,
                    campaign="shai-hulud-2026-08",
                )

            # "scripts" is attacker-controlled and need not be an object.
            scripts = meta.get("scripts")
            preinstall = ""
            if isinstance(scripts, dict):
                preinstall = str(scripts.get("preinstall", ""))
            elif scripts:
                ctx.gap(cat, f"{manifest} has a non-object 'scripts' field "
                    f"({type(scripts).__name__}); preinstall NOT checked")
            referenced = [d for d in DROPPER_FILENAMES if d in preinstall]
            if referenced:
                # "preinstall": "node setup.mjs" is also a legitimate build
                # step. Declaring confirmed malware from the filename alone
                # breaks the same hash-gating rule that stopped this scanner
                # flagging regenerate-unicode-properties. Corroboration is
                # either a matching payload hash or a known-bad version.
                payload_matched = False
                for dropper in referenced:
                    candidate = pkg_dir / dropper
                    try:
                        if not candidate.is_file():
                            continue
                    except OSError:
                        continue
                    digest = sha256_file(candidate)
                    if digest and digest in KNOWN_MALWARE_SHA256:
                        payload_matched = True
                        break

                known_bad = (
                    installed_version in _compromised_versions(ctx, name)
                )

                if payload_matched or known_bad:
                    ctx.add(
                        cat, manifest, Severity.CRITICAL,
                        f"Installed {name} has a worm preinstall hook: "
                        f"{preinstall}",
                        "Confirmed worm payload staged in an installed "
                        "package. Isolate this host. Remove any "
                        "gh-token-monitor watcher BEFORE revoking tokens, then "
                        "revoke npm and GitHub tokens and rotate every "
                        "reachable credential.",
                        package=name, version=installed_version,
                        preinstall=preinstall,
                        corroboration="payload_hash" if payload_matched
                        else "compromised_version",
                        campaign="shai-hulud-2026-08",
                    )
                else:
                    ctx.observe(
                        cat, manifest,
                        f"{name} runs a preinstall referencing "
                        f"{', '.join(referenced)}; no known payload hash and "
                        "the version is not on the compromised list",
                        "preinstall_dropper_name_unverified",
                        package=name, version=installed_version,
                        preinstall=preinstall[:200],
                    )

    for dropper in DROPPER_FILENAMES:
        candidate = pkg_dir / dropper
        try:
            if not candidate.is_file():
                continue
        except OSError:
            continue
        _report_hash_match(
            ctx, cat, candidate,
            context=f"in package {name}",
            package=name, version=installed_version,
        )


def _report_hash_match(
    ctx: ScanContext,
    cat: str,
    path: pathlib.Path,
    context: str = "",
    **details: Any,
) -> bool:
    """Hash a file and report it if it matches a known payload.

    Returns True on a match. Oversize or unreadable candidates are recorded
    in the report's errors list rather than passing silently, because a
    skipped hash is indistinguishable from a clean one otherwise.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        ctx.errors.append(f"{cat}: cannot stat {path}: {exc}")
        return False

    if size > ARTIFACT_MAX_BYTES:
        ctx.gap(cat, f"{path} is {size} bytes (over the "
            f"{ARTIFACT_MAX_BYTES}-byte hash limit) and was NOT verified")
        return False

    digest = sha256_file(path)
    if digest is None:
        ctx.errors.append(f"{cat}: could not hash {path}")
        return False
    if digest not in KNOWN_MALWARE_SHA256:
        return False

    suffix = f" {context}" if context else ""
    ctx.add(
        cat, path, Severity.CRITICAL,
        f"Known worm payload{suffix}: {KNOWN_MALWARE_SHA256[digest]}",
        "Confirmed malware on disk. Isolate this host. Remove any "
        "gh-token-monitor watcher BEFORE revoking tokens, then revoke npm "
        "and GitHub tokens and rotate every credential reachable from here.",
        sha256=digest, campaign="shai-hulud-2026-08", **details,
    )
    return True


def _scan_npm_install_posture(ctx: ScanContext, cat: str) -> None:
    """Record whether npm lifecycle scripts are disabled.

    Reported as an observation, never a finding: leaving install scripts
    enabled is npm's default, so treating it as a finding would push every
    healthy workstation to a non-zero exit code.
    """
    npmrc = ctx.home / ".npmrc"
    text = safe_read(npmrc, MAX_READ_BYTES) or ""
    disabled = False
    for line in text.splitlines():
        stripped = line.strip().replace(" ", "").lower()
        if stripped.startswith("ignore-scripts=true"):
            disabled = True
            break

    if disabled:
        ctx.observe(
            cat, npmrc,
            "npm install scripts are disabled (ignore-scripts=true)",
            "hardened_install_posture",
        )
    else:
        ctx.observe(
            cat, npmrc if npmrc.exists() else ctx.home / ".npmrc",
            "npm install scripts are enabled; preinstall hooks run "
            "automatically on install",
            "default_install_posture",
            hardening="npm config set ignore-scripts true",
        )


def scan_agent_autostart_hooks(ctx: ScanContext, quiet: bool) -> None:
    """Audit AI-agent and IDE autostart surfaces for injected commands.

    The 2026-08 wave commits hooks into .claude/settings.json and
    .vscode/tasks.json so the payload executes when a developer opens the
    repository or starts an agent session, with no 'npm install' involved.

    Only executable fields are inspected. An earlier draft of this check
    grepped whole files and fired on security tooling whose *deny* lists
    legitimately mention 'curl ... | bash'; structural parsing avoids that.
    """
    progress("agent/IDE autostart hooks", quiet)
    cat = "agent_autostart_hooks"
    remediation = (
        "Malicious autostart command found. Remove the hook. ORDER MATTERS "
        "before any revocation: scan this host for malware_persistence and "
        "remove any gh-token-monitor watcher first -- its handler fires when "
        "the stolen token stops working, and a category-limited scan has not "
        "checked for it. Once no watcher remains, revoke GitHub and npm "
        "tokens and rotate all reachable credentials. Review git history for "
        "the injecting commit (the 2026-08 wave authored these as 'claude' "
        "with the message 'chore: update config')."
    )

    for target in _find_agent_hook_files(ctx):
        try:
            size = target.stat().st_size
        except OSError as exc:
            ctx.errors.append(f"{cat}: cannot stat {target}: {exc}")
            continue
        if size > ARTIFACT_MAX_BYTES:
            ctx.gap(cat, f"{target} is {size} bytes (over the "
                f"{ARTIFACT_MAX_BYTES}-byte limit) and was NOT inspected")
            continue

        # Read at the larger manifest limit: a hook further down a config
        # bigger than MAX_READ_BYTES would otherwise be truncated away and
        # the file would exit clean.
        text = safe_read(target, ARTIFACT_MAX_BYTES)
        if text is None:
            ctx.errors.append(f"{cat}: could not read {target}")
            continue
        if not text.strip():
            continue
        try:
            # JSONC, not JSON: VS Code documents tasks.json as allowing
            # comments and trailing commas, and they are common in real
            # files. Strict parsing rejected those, which both noised up a
            # clean host and skipped any malicious folderOpen task inside.
            data = _loads_jsonc(text)
        except (ValueError, TypeError) as exc:
            ctx.gap(cat, f"could not parse {target}: {exc}; "
                "autostart hooks in this file were NOT checked")
            continue

        repo_root = target.parent.parent

        for command, surface in _iter_autostart_commands(data):
            lowered = command.lower()

            # Manual-ness is decided first: a task the operator has to invoke
            # is not an autostart surface at all, whatever it references.
            if surface == "task:manual":
                marker = next(
                    (m for m in CAMPAIGN_AUTOSTART_MARKERS + DROPPER_NAME_MARKERS
                     if m.lower() in lowered),
                    None,
                )
                if marker:
                    ctx.observe(
                        cat, target,
                        f"Manual (non-autostart) VS Code task references "
                        f"'{marker}': {command[:200]}",
                        "manual_task_references_marker",
                        surface=surface, marker=marker,
                    )
                continue

            hit = next(
                (m for m in CAMPAIGN_AUTOSTART_MARKERS if m.lower() in lowered),
                None,
            )

            if not hit:
                # Only a dropper filename. A name by itself is not compromise
                # (motion-dom ships setup.mjs), so it needs corroboration:
                # either the referenced file hashes to a known payload, or the
                # command loads it from an agent/IDE *config* directory, which
                # is the worm's cross-wired signature and not where a genuine
                # build script lives.
                weak = next(
                    (m for m in DROPPER_NAME_MARKERS if m.lower() in lowered),
                    None,
                )
                if not weak:
                    continue
                staged_in_config_dir = any(
                    f"{sub}/{dropper}".lower() in lowered
                    for sub in DROPPER_SEARCH_DIRS
                    for dropper in DROPPER_FILENAMES
                )
                if staged_in_config_dir or _autostart_payload_confirmed(
                    ctx, cat, repo_root, command
                ):
                    hit = weak
                else:
                    ctx.observe(
                        cat, target,
                        f"{surface} command references '{weak}' but no known "
                        f"payload hash was found: {command[:200]}",
                        "autostart_dropper_name_unverified",
                        surface=surface, marker=weak,
                    )
                    continue

            ctx.add(
                cat, target, Severity.CRITICAL,
                f"Malicious {surface} autostart command references '{hit}'",
                remediation,
                surface=surface, marker=hit,
                command=command[:400],
                campaign="shai-hulud-2026-08",
            )


def scan_repo_worm_artifacts(ctx: ScanContext, quiet: bool) -> None:
    """Find worm artifacts committed into repositories.

    Two vectors that outlive `npm uninstall`:
      1. loaders staged in .claude/ and .vscode/ (cross-wired, so removing
         one directory leaves the other's loader able to re-stage it)
      2. an injected GitHub Actions workflow that dumps toJSON(secrets) to a
         file and uploads it as a build artifact, re-firing on every push
    """
    progress("repo worm artifacts", quiet)
    cat = "repo_worm_artifacts"

    # The injected settings.json / tasks.json have published digests of their
    # own, so hash them directly as well as parsing them.
    for target in _find_agent_hook_files(ctx):
        _report_hash_match(ctx, cat, target, context="(injected agent config)")

    # Repository roots are discovered independently of agent configs. Deriving
    # them from hook files meant a workflow or staged loader left behind after
    # the hooks were deleted -- the exact post-cleanup state -- was never
    # scanned, and a repo with both hooks was scanned (and reported) twice.
    for repo_root in _find_repo_roots(ctx):
        for subdir in DROPPER_SEARCH_DIRS:
            for dropper in DROPPER_FILENAMES:
                candidate = repo_root / subdir / dropper
                if not candidate.is_file():
                    continue
                digest = sha256_file(candidate)
                if digest and digest in KNOWN_MALWARE_SHA256:
                    ctx.add(
                        cat, candidate, Severity.CRITICAL,
                        f"Worm loader staged in repository: "
                        f"{KNOWN_MALWARE_SHA256[digest]}",
                        "Confirmed malware committed into this repository. "
                        "Remove BOTH .claude/ and .vscode/ loaders (they "
                        "reference each other), then follow the persistence "
                        "cleanup order: kill any gh-token-monitor watcher "
                        "before revoking tokens.",
                        sha256=digest, campaign="shai-hulud-2026-08",
                    )
                elif digest is None:
                    ctx.gap(cat, f"could not hash {candidate}; "
                        "presence NOT verified")
                else:
                    # Recorded, not flagged. The whole point of hash-gating is
                    # that these filenames occur legitimately, so a
                    # non-matching digest must not become an actionable
                    # finding -- that is the false positive the gate exists to
                    # prevent. It stays visible as an observation.
                    ctx.observe(
                        cat, candidate,
                        f"Unrecognised {subdir}/{dropper} present; hash does "
                        "not match any known worm payload",
                        "dropper_name_unknown_hash",
                        sha256=digest,
                        guidance="This filename is used by the 2026-08 worm "
                                 "to stage its loader. The hash clears, so "
                                 "this is informational only.",
                    )

        _scan_workflows(ctx, cat, repo_root)


def _scan_workflows(ctx: ScanContext, cat: str, repo_root: pathlib.Path) -> None:
    """Flag CI workflows that serialise the whole secret store into a file."""
    wf_dir = repo_root / ".github/workflows"
    if not wf_dir.is_dir():
        return
    try:
        entries = list(wf_dir.iterdir())
    except OSError as exc:
        ctx.gap(
            cat,
            f"could not enumerate {wf_dir} ({exc}); its workflows were "
            "NOT scanned",
        )
        return

    for wf in entries:
        if not wf.is_file() or wf.suffix.lower() not in (".yml", ".yaml"):
            continue
        digest = sha256_file(wf)
        if digest and digest in KNOWN_MALWARE_SHA256:
            ctx.add(
                cat, wf, Severity.CRITICAL,
                f"Injected exfiltration workflow: {KNOWN_MALWARE_SHA256[digest]}",
                "Delete this workflow. ORDER MATTERS before rotating: scan "
                "this host for malware_persistence and remove any "
                "gh-token-monitor watcher first, since revocation is what "
                "triggers its handler and a category-limited scan has not "
                "checked. Then rotate every secret exposed to GitHub Actions "
                "in this repository and check the Actions run history and "
                "artifacts for uploaded secret dumps.",
                sha256=digest, campaign="shai-hulud-2026-08",
            )
            continue

        # Read the whole workflow, not the first 64 KiB. A modified copy has
        # an unknown hash, so the marker search is the only remaining signal;
        # truncating it produced a false-clean result with no error, which is
        # the worst of both outcomes.
        try:
            wf_size = wf.stat().st_size
        except OSError as exc:
            ctx.errors.append(f"{cat}: cannot stat {wf}: {exc}")
            continue
        if wf_size > ARTIFACT_MAX_BYTES:
            ctx.gap(cat, f"{wf} is {wf_size} bytes (over the "
                f"{ARTIFACT_MAX_BYTES}-byte limit) and was NOT searched for "
                "secret-dumping markers")
            continue

        text = safe_read(wf, ARTIFACT_MAX_BYTES)
        if text is None:
            ctx.errors.append(f"{cat}: could not read {wf}")
            continue
        if not text:
            continue
        # Comments are not executable: a security guide or lint rule naming
        # toJSON(secrets) is not a workflow that exfiltrates secrets.
        lowered = _strip_yaml_comments(text).lower().replace(" ", "")
        # toJSON(secrets) is the substantive signal; format-results.txt is an
        # ordinary filename and only supporting evidence.
        hits = [m for m in WORKFLOW_SECRET_DUMP_MARKERS if m in lowered]
        if WORKFLOW_SECRET_DUMP_REQUIRED not in lowered:
            hits = []
        if hits:
            ctx.add(
                cat, wf, Severity.HIGH,
                "CI workflow serialises the entire Actions secret store "
                f"({', '.join(hits)})",
                "A workflow that expands toJSON(secrets) into a file or log "
                "exposes every repository secret to anyone who can read the "
                "run artifacts. The 2026-08 worm injected exactly this shape. "
                "Remove it and rotate the repository's Actions secrets.",
                markers=hits,
            )


def _find_repo_roots(ctx: ScanContext) -> List[pathlib.Path]:
    """Directories that look like a working tree, deduplicated.

    A repository qualifies on any of: a .git entry, a package manifest, or one
    of the agent/IDE config directories. Keyed on resolved path so a repo
    holding several markers is only scanned once.
    """
    roots: List[pathlib.Path] = []
    seen: Set[pathlib.Path] = set()
    markers = (".git", "package.json") + DROPPER_SEARCH_DIRS + (".github",)

    def match(directory: pathlib.Path, entries: List[pathlib.Path]) -> None:
        names = {e.name for e in entries}
        if not names.intersection(markers):
            return
        try:
            key = directory.resolve()
        except OSError:
            return
        if key in seen:
            return
        seen.add(key)
        roots.append(directory)

    _walk_project_tree(ctx, match, NPM_MAX_PROJECT_ROOTS, lambda: len(roots))
    match(ctx.home, list(_safe_iterdir(ctx.home)))
    return roots


def _safe_iterdir(directory: pathlib.Path) -> List[pathlib.Path]:
    try:
        return list(directory.iterdir())
    except OSError:
        return []


def _autostart_payload_confirmed(
    ctx: ScanContext,
    cat: str,
    repo_root: pathlib.Path,
    command: str,
) -> bool:
    """Whether a command's referenced dropper file hashes to a known payload.

    Resolves each dropper-looking token in the command against the repository
    root and the usual staging directories. Absence of a match means the
    command is unverified, not clean -- the caller records an observation.
    """
    for token in re.split(r"[\s'\"();|&]+", command):
        if not token:
            continue
        name = token.split("/")[-1]
        if name not in DROPPER_FILENAMES:
            continue
        candidates = [repo_root / token.lstrip("./")]
        candidates.extend(repo_root / sub / name for sub in DROPPER_SEARCH_DIRS)
        for candidate in candidates:
            try:
                if not candidate.is_file():
                    continue
            except OSError:
                continue
            digest = sha256_file(candidate)
            if digest and digest in KNOWN_MALWARE_SHA256:
                return True
    return False


def _find_agent_hook_files(ctx: ScanContext) -> List[pathlib.Path]:
    """Locate agent/IDE autostart configs under the home directory.

    Deliberately not tied to package.json: these hooks are injected into any
    repository the stolen token can reach, including non-JS ones, and the
    directory holding .claude/ is often not a package root at all.
    """
    found: List[pathlib.Path] = []
    seen: Set[pathlib.Path] = set()

    def collect(directory: pathlib.Path) -> None:
        for relpath in AGENT_HOOK_RELPATHS:
            candidate = directory / relpath
            try:
                if not candidate.is_file():
                    continue
                key = candidate.resolve()
            except OSError:
                continue
            if key in seen:
                continue
            seen.add(key)
            found.append(candidate)

    def match(directory: pathlib.Path, entries: List[pathlib.Path]) -> None:
        collect(directory)

    _walk_project_tree(ctx, match, NPM_MAX_PROJECT_ROOTS, lambda: len(found))
    collect(ctx.home)  # hooks directly in the home directory
    return found


def _iter_autostart_commands(data: Any) -> List[Tuple[str, str]]:
    """Yield (command, surface) pairs from agent/IDE config structures.

    Claude Code:   hooks.<Event>[].hooks[].command
    VS Code tasks: tasks[].command (+args), flagged with its runOn trigger
    """
    out: List[Tuple[str, str]] = []
    if not isinstance(data, dict):
        return out

    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                continue
            for group in groups:
                if not isinstance(group, dict):
                    continue
                nested = group.get("hooks")
                if not isinstance(nested, list):
                    # A truthy non-list here (e.g. {"hooks": 1}) raised
                    # TypeError, which the category-level handler turned into
                    # "skip every remaining agent config" -- letting one
                    # malformed file hide malicious hooks elsewhere.
                    continue
                for hook in nested:
                    if isinstance(hook, dict) and hook.get("command"):
                        out.append((str(hook["command"]), f"hook:{event}"))

    tasks = data.get("tasks")
    if isinstance(tasks, list):
        by_label: Dict[str, Dict[str, Any]] = {}
        for task in tasks:
            if isinstance(task, dict) and isinstance(task.get("label"), str):
                by_label[task["label"]] = task

        def task_command(task: Dict[str, Any]) -> str:
            parts = [str(task.get("command", ""))]
            args = task.get("args")
            if isinstance(args, list):
                parts.extend(str(a) for a in args)
            return " ".join(p for p in parts if p)

        def task_run_on(task: Dict[str, Any]) -> str:
            run_on = ((task.get("runOptions") or {}).get("runOn")
                      if isinstance(task.get("runOptions"), dict) else None)
            # VS Code's "default" means the task runs only when invoked, the
            # same as omitting runOn -- so it is not an autostart surface.
            if not isinstance(run_on, str) or run_on.lower() == "default":
                return "manual"
            return run_on

        def depends_labels(task: Dict[str, Any]) -> List[str]:
            depends = task.get("dependsOn")
            if isinstance(depends, str):
                return [depends]
            if isinstance(depends, list):
                return [d for d in depends if isinstance(d, str)]
            return []

        # A compound folderOpen task can carry no command of its own and
        # invoke the payload through dependsOn. Attributing only the parent's
        # (empty) command and calling the dependency "manual" meant opening
        # the folder executed the payload while the scan reported nothing.
        for task in tasks:
            if not isinstance(task, dict):
                continue
            run_on = task_run_on(task)
            command = task_command(task)
            if command:
                out.append((command, f"task:{run_on}"))

            if run_on == "manual":
                continue
            seen_labels: Set[str] = set()
            queue = depends_labels(task)
            while queue:
                label = queue.pop(0)
                if label in seen_labels:
                    continue
                seen_labels.add(label)
                dep = by_label.get(label)
                if not isinstance(dep, dict):
                    continue
                dep_command = task_command(dep)
                if dep_command:
                    out.append((dep_command, f"task:{run_on}"))
                queue.extend(depends_labels(dep))

    # Cursor: install/start run automatically when the environment is
    # prepared, so they are autostart surfaces in exactly the same sense as a
    # folderOpen task. The file was already being discovered and parsed while
    # these fields went unread.
    for field in ("install", "start", "build", "terminals"):
        value = data.get(field)
        if isinstance(value, str) and value.strip():
            out.append((value, f"cursor:{field}"))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    out.append((item, f"cursor:{field}"))
                elif isinstance(item, dict):
                    cmd = item.get("command")
                    if isinstance(cmd, str) and cmd.strip():
                        out.append((cmd, f"cursor:{field}"))

    return out


def scan_malware_persistence(ctx: ScanContext, quiet: bool) -> None:
    """Detect worm watcher persistence and generic autostart-script abuse."""
    progress("malware persistence", quiet)
    cat = "malware_persistence"
    remediation = (
        "Dead-man's-switch persistence from the 2026-08 Shai-Hulud wave. This "
        "watcher polls api.github.com every 60s and executes a "
        "remote-supplied command as soon as the stolen token stops working. "
        "ORDER MATTERS: unload the LaunchAgent (or disable the systemd user "
        "unit and run 'loginctl disable-linger') and delete these files "
        "BEFORE revoking any GitHub token. Revoking first is what triggers "
        "the handler, and the equivalent handler in the leaked framework this "
        "payload derives from ran 'rm -rf ~/'. Once the watcher is dead, "
        "revoke GitHub and npm tokens and rotate all reachable credentials."
    )

    for relpath in SHAI_HULUD_PERSISTENCE_PATHS:
        target = ctx.home / relpath
        try:
            exists = target.exists()
        except OSError as exc:
            # A denied parent (~/.config, say) makes this indeterminate, and
            # on newer Pythons exists() answers False rather than raising.
            # Either way a live watcher could sit behind it, so the probe is
            # recorded as a gap and keeps the rotation gate closed.
            ctx.gap(
                cat,
                f"could not determine whether {target} exists ({exc}); "
                "this persistence path was NOT checked",
            )
            continue
        if not exists:
            if not _parent_traversable(target):
                ctx.gap(
                    cat,
                    f"cannot traverse the parent of {target}; its absence is "
                    "unverified and it was NOT checked",
                )
            continue
        ctx.add(
            cat, target, Severity.CRITICAL,
            f"Shai-Hulud persistence artifact: {relpath}",
            remediation, campaign="shai-hulud-2026-08",
        )
        # The watcher installer script has a published hash; check it so that
        # digest is reachable and a repacked variant is still identified.
        try:
            if target.is_file():
                _report_hash_match(
                    ctx, cat, target, context="(watcher installer)",
                )
        except OSError:
            pass

    for tmp_path in SHAI_HULUD_TMP_PATHS:
        target = pathlib.Path(tmp_path)
        try:
            if target.exists():
                ctx.add(
                    cat, target, Severity.CRITICAL,
                    f"Shai-Hulud watcher log: {tmp_path}",
                    remediation, campaign="shai-hulud-2026-08",
                )
        except OSError:
            pass

    _scan_launch_agents_generic(ctx, cat)


def _scan_launch_agents_generic(ctx: ScanContext, cat: str) -> None:
    """Flag LaunchAgents that relaunch a bare script from a config directory.

    Campaign-specific filenames age out fast, so this heuristic targets the
    shape instead: RunAtLoad plus KeepAlive, pointing at a script under a
    dotfile/cache directory. Programs inside .app bundles are excluded --
    ordinary login items live there, and flagging them would drown the
    signal on a normal workstation.
    """
    la_dir = ctx.home / "Library/LaunchAgents"
    if not la_dir.is_dir():
        return

    try:
        entries = list(la_dir.iterdir())
    except OSError as exc:
        # Returning quietly recorded persistence as successfully scanned,
        # which would let antivenom lift the rotation gate without a single
        # LaunchAgent having been read.
        ctx.gap(cat, f"could not enumerate {la_dir} ({exc}); "
            "NO LaunchAgent was inspected")
        return

    for plist in entries:
        if not plist.name.endswith(".plist"):
            continue

        try:
            plist_size = plist.stat().st_size
        except OSError as exc:
            ctx.errors.append(f"{cat}: cannot stat {plist}: {exc}")
            continue
        if plist_size > ARTIFACT_MAX_BYTES:
            ctx.gap(cat, f"{plist} is {plist_size} bytes (over the "
                f"{ARTIFACT_MAX_BYTES}-byte limit) and was NOT inspected")
            continue

        # Read the whole plist: a truncated read hid ProgramArguments and the
        # RunAtLoad/KeepAlive keys further down the file, exiting clean on an
        # unscanned persistence definition.
        content = _read_plist_as_text(ctx, cat, plist)
        if not content:
            continue
        lowered = content.lower()

        # Campaign indicators only: a plist that merely names a dropper file
        # is not the watcher, and mislabelling it gates all remediation.
        # Weak filename markers get the observation below.
        # Only executable fields. Matching the whole XML meant a campaign
        # marker inside a comment or a descriptive string produced a CRITICAL
        # finding, gated the pack and advised a host rebuild.
        executable = _plist_executable_text(content).lower()
        marker = next(
            (m for m in CAMPAIGN_AUTOSTART_MARKERS if m.lower() in executable),
            None,
        )
        if not marker:
            weak = next(
                (m for m in DROPPER_NAME_MARKERS if m.lower() in executable),
                None,
            )
            if weak:
                ctx.observe(
                    cat, plist,
                    f"LaunchAgent mentions '{weak}' but carries no campaign "
                    "indicator and no matching payload hash",
                    "plist_dropper_name_unverified",
                    marker=weak,
                )
        if marker:
            ctx.add(
                cat, plist, Severity.CRITICAL,
                f"LaunchAgent references malware indicator '{marker}'",
                "Malicious LaunchAgent. Unload it and remove the file FIRST, "
                "before revoking any token, then rotate every credential "
                "reachable from this host.",
                marker=marker, campaign="shai-hulud-2026-08",
            )
            continue

        # Substring checks matched a plist that explicitly *disables* these
        # keys (<key>RunAtLoad</key><false/>), so a dormant login item naming
        # any script under a config directory produced a persistence finding
        # -- which then rotation-gated the whole antivenom pack.
        if not _plist_flag_enabled(content, "RunAtLoad"):
            continue
        if not _plist_flag_enabled(content, "KeepAlive"):
            continue
        if ".app/contents/" in lowered:
            continue

        targets = re.findall(r"<string>([^<]+)</string>", content)
        for target in targets:
            candidate = target.strip()
            if not candidate.startswith("/") and not candidate.startswith("~"):
                continue
            lowered_target = candidate.lower()
            if ".app/contents/" in lowered_target:
                break
            if not lowered_target.endswith(PERSISTENCE_SCRIPT_SUFFIXES):
                continue
            if not any(d in lowered_target for d in PERSISTENCE_SUSPECT_DIRS):
                continue
            ctx.add(
                cat, plist, Severity.MEDIUM,
                "LaunchAgent persistently relaunches a script from a "
                f"user-writable config directory: {candidate}",
                "Verify this login item is expected. Malware persistence "
                "commonly takes this shape (RunAtLoad + KeepAlive on a script "
                "under a dotfile or cache directory). If unrecognised, unload "
                "the agent and investigate the target script.",
                program=candidate,
            )
            break


ALL_SCANS = [
    ("teampcp_iocs", scan_teampcp_iocs),
    ("npm_supply_chain", scan_npm_supply_chain),
    ("agent_autostart_hooks", scan_agent_autostart_hooks),
    ("repo_worm_artifacts", scan_repo_worm_artifacts),
    ("malware_persistence", scan_malware_persistence),
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
        else:
            # Recorded only on success, so a category that crashed does not
            # count as covered.
            ctx.categories_scanned.append(name)


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
        # Which categories this run actually covered. Without it a consumer
        # cannot distinguish "no persistence finding" from "persistence was
        # never scanned" -- and antivenom relied on that distinction to decide
        # whether credential rotation is safe.
        "scan_scope": {
            "categories_scanned": list(ctx.categories_scanned),
            "categories_available": [name for name, _ in ALL_SCANS],
            "complete": len(ctx.categories_scanned) == len(ALL_SCANS),
            "coverage_gaps": list(ctx.coverage_gaps),
        },
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
        prog="rattlesnake",
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
    parser.add_argument(
        "--ioc-file", metavar="PATH",
        help=IOC_FILE_HELP,
    )
    return parser.parse_args(argv)


def load_ioc_file(path: str) -> Tuple[Dict[str, Tuple[str, ...]], Optional[str]]:
    """Load extra compromised package versions from a JSON file.

    Returns (packages, error). A malformed or unreadable file yields an empty
    mapping plus an error string for the report's errors list -- a fleet scan
    should still run its other checks rather than abort on a bad feed.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        return {}, f"--ioc-file {path}: {exc}"

    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return {}, f"--ioc-file {path}: expected object at key 'packages'"

    out: Dict[str, Tuple[str, ...]] = {}
    rejected: List[str] = []
    for name, versions in packages.items():
        if isinstance(versions, str):
            versions = [versions]
        if not isinstance(versions, list):
            rejected.append(str(name))
            continue
        cleaned = tuple(
            str(v).strip() for v in versions if isinstance(v, (str, int, float))
        )
        # Drop empty strings after stripping (e.g. "  ").
        cleaned = tuple(v for v in cleaned if v)
        if not cleaned:
            rejected.append(str(name))
            continue
        out[str(name)] = cleaned

    # A feed that parses but yields nothing usable is the dangerous case: the
    # scan would look successful while covering none of the campaign tail.
    if rejected and not out:
        return {}, (
            f"--ioc-file {path}: no usable entries; "
            f"{len(rejected)} malformed (e.g. {', '.join(rejected[:3])})"
        )
    if not out:
        return {}, f"--ioc-file {path}: 'packages' contained no entries"
    if rejected:
        return out, (
            f"--ioc-file {path}: skipped {len(rejected)} malformed "
            f"entr{'y' if len(rejected) == 1 else 'ies'} "
            f"(e.g. {', '.join(rejected[:3])})"
        )
    return out, None


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
        "rattlesnake_version": VERSION,
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

    if args.ioc_file:
        extra, ioc_error = load_ioc_file(args.ioc_file)
        ctx.extra_iocs = extra
        if ioc_error:
            ctx.errors.append(ioc_error)

    if args.audit_env:
        code, output = run_audit_env(
            ctx, args.pretty, args.training, args.category,
        )
        _emit(output, args.output_file)
        return code

    if not args.quiet:
        print(
            f"rattlesnake v{VERSION} ({ctx.hostname}, {ctx.username})",
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
