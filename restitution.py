#!/usr/bin/env python3
"""clawback-restitution — remediation pack generator.

Consumes clawback JSON output, performs deterministic analysis and
optional 1Password enrichment, and generates a remediation pack:
an ordered set of agent-ready markdown tasks, an operator-facing
index, and reviewable launcher helpers.
"""

from __future__ import annotations

import argparse
import datetime
import functools
import json
import os
import pathlib
import shlex
import shutil
import socket as _socket
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

VERSION = "0.2.0"

# ── ANSI colors ─────────────────────────────────────────────────────

_NO_COLOR = os.environ.get("NO_COLOR") is not None


def _c(code: str, text: str) -> str:
    if _NO_COLOR or not sys.stderr.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def red(t: str) -> str:
    return _c("31", t)


def yellow(t: str) -> str:
    return _c("33", t)


def green(t: str) -> str:
    return _c("32", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


# ── Constants ────────────────────────────────────────────────────────

SCRIPT_DIR = str(pathlib.Path(__file__).resolve().parent)

REQUIRED_REPORT_KEYS = {
    "findings",
    "summary",
    "total_findings",
}

REQUIRED_FINDING_KEYS = {
    "category",
    "path",
    "severity",
    "description",
    "remediation",
    "details",
}

PHASE_1_CATEGORIES = frozenset(
    {
        "env_files",
        "shell_profile_secrets",
        "environment_variables",
        "ssh_keys",
    }
)

FIX_TYPE_MAP: Dict[str, str] = {
    "env_files": "env_rewrite",
    "shell_profile_secrets": "profile_rewrite",
    "environment_variables": "env_var_trace",
    "ssh_keys": "ssh_harden",
    "git_credentials": "git_credential_store",
    "package_manager_tokens": "token_migrate",
    "cloud_credentials": "cloud_migrate",
    "kubernetes": "kubeconfig_migrate",
    "crypto_wallets": "wallet_secure",
    "teampcp_ioc": "incident_response",
}

GUIDE_MAP: Dict[str, str] = {
    "env_files": "shell-env-secrets.md",
    "shell_profile_secrets": "shell-env-secrets.md",
    "environment_variables": "shell-env-secrets.md",
    "ssh_keys": "ssh-keys.md",
    "git_credentials": "git-credentials.md",
    "cloud_credentials": "index.md",
    "kubernetes": "kubernetes-kubeconfig.md",
    "package_manager_tokens": "index.md",
    "crypto_wallets": "crypto-wallets.md",
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

PROJECT_MARKERS = (
    ".git",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
)

SHELL_PROFILE_NAMES = frozenset(
    {
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".zlogin",
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
    }
)

LOGICAL_AREA_DIRS = (
    (os.path.join(".ssh"), "ssh"),
    (os.path.join(".kube"), "kubernetes"),
    (os.path.join(".config", "gcloud"), "gcloud-credentials"),
    (os.path.join(".docker"), "docker"),
    (os.path.join(".aws"), "aws-credentials"),
    (os.path.join(".gnupg"), "gnupg"),
)


# ── Data model ───────────────────────────────────────────────────────


@dataclass
class NormalizedFinding:
    """Internal representation of a single clawback finding."""

    category: str
    path: str
    severity: str
    description: str
    remediation: str
    fix_type: str
    details: Dict[str, Any] = field(default_factory=dict)

    variable: Optional[str] = None
    variables: Optional[List[str]] = None
    line: Optional[int] = None
    reason: Optional[str] = None
    key_type: Optional[str] = None
    encrypted: Optional[bool] = None
    permissions: Optional[str] = None


@dataclass
class OpMatch:
    """Result of a 1Password enrichment lookup for a single secret."""

    status: str  # "exact", "ambiguous", "missing", "unchecked"
    vault: Optional[str] = None
    item_title: Optional[str] = None
    field_name: Optional[str] = None
    reference: Optional[str] = None
    candidates: Optional[List[Dict[str, str]]] = None


@dataclass
class WorkUnit:
    """A logical unit of remediation work: one repo or one config area."""

    id: str
    label: str
    severity: str
    work_type: str  # "repo" or "standalone"
    root_path: str
    findings: List[NormalizedFinding] = field(default_factory=list)
    enrichment: Dict[str, OpMatch] = field(default_factory=dict)


# ── CLI parsing ──────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="clawback-restitution",
        description=("Remediation pack generator for clawback scan findings."),
    )
    p.add_argument(
        "--input",
        "-i",
        help="Path to clawback JSON output (default: stdin)",
    )
    p.add_argument(
        "--vault",
        help="Restrict 1Password enrichment to a single vault",
    )
    p.add_argument(
        "--output-dir",
        help=("Pack destination (default: ./tmp/restitution-packs/<timestamp>/)"),
    )
    p.add_argument(
        "--combined",
        action="store_true",
        help="Emit combined markdown to stdout instead of a pack",
    )
    p.add_argument(
        "--category",
        help="Process only findings of this category",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip 1Password queries; use placeholder enrichment",
    )
    p.add_argument(
        "--preview",
        action="store_true",
        help="Print task details inline for operator triage",
    )
    p.add_argument(
        "--tmux",
        action="store_true",
        help=("Create a tmux session with one window per task"),
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return p


# ── JSON loading and validation ──────────────────────────────────────


def load_report(path: Optional[str]) -> Dict[str, Any]:
    """Read and parse clawback JSON from a file or stdin."""
    if path:
        try:
            text = pathlib.Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            _fatal(f"Cannot read input file: {exc}")
    else:
        if sys.stdin.isatty():
            _fatal("No input provided. Pipe clawback JSON or use --input FILE.")
        text = sys.stdin.read()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _fatal(f"Invalid JSON: {exc}")

    return data


def validate_report(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate the report structure and return the findings list."""
    if not isinstance(data, dict):
        _fatal("Report must be a JSON object.")

    missing = REQUIRED_REPORT_KEYS - set(data.keys())
    if missing:
        _fatal(f"Report missing required fields: {', '.join(sorted(missing))}")

    findings = data.get("findings")
    if not isinstance(findings, list):
        _fatal("'findings' must be a list.")

    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            _fatal(f"Finding #{i} is not a JSON object.")
        f_missing = REQUIRED_FINDING_KEYS - set(f.keys())
        if f_missing:
            _fatal(f"Finding #{i} missing fields: {', '.join(sorted(f_missing))}")

    return findings


# ── Finding normalization ────────────────────────────────────────────


def normalize_finding(raw: Dict[str, Any]) -> NormalizedFinding:
    """Convert a raw finding dict into a NormalizedFinding."""
    category = raw["category"]
    details = raw.get("details") or {}

    nf = NormalizedFinding(
        category=category,
        path=raw["path"],
        severity=raw["severity"],
        description=raw["description"],
        remediation=raw["remediation"],
        fix_type=FIX_TYPE_MAP.get(category, "generic"),
        details=details,
    )

    if "variable" in details:
        nf.variable = details["variable"]
    if "variables" in details:
        nf.variables = details["variables"]
    if "line" in details:
        nf.line = details["line"]
    if "reason" in details:
        nf.reason = details["reason"]
    if "key_type" in details:
        nf.key_type = details["key_type"]
    if "encrypted" in details:
        nf.encrypted = details["encrypted"]
    if "permissions" in details:
        nf.permissions = details["permissions"]

    return nf


def normalize_all(
    raw_findings: List[Dict[str, Any]],
    category_filter: Optional[str] = None,
) -> List[NormalizedFinding]:
    """Normalize and optionally filter findings."""
    results = []
    for raw in raw_findings:
        if category_filter and raw["category"] != category_filter:
            continue
        results.append(normalize_finding(raw))
    return results


# ── Project and area detection ───────────────────────────────────────


def detect_project_root(file_path: str) -> Optional[str]:
    """Find the nearest project root above file_path.

    Checks for .git first, then falls back to strong project markers
    like package.json or pyproject.toml.
    """
    current = pathlib.Path(file_path).parent

    # First pass: .git
    ancestor = current
    while ancestor != ancestor.parent:
        if (ancestor / ".git").exists():
            return str(ancestor)
        ancestor = ancestor.parent

    # Second pass: other project markers
    ancestor = current
    while ancestor != ancestor.parent:
        for marker in PROJECT_MARKERS[1:]:
            if (ancestor / marker).exists():
                return str(ancestor)
        ancestor = ancestor.parent

    return None


def detect_work_area(file_path: str) -> Tuple[str, str, str]:
    """Determine the work area for a finding's path.

    Returns (root_path, work_type, slug).
    """
    if file_path.startswith("env:"):
        home = str(pathlib.Path.home())
        return (home, "standalone", "runtime-environment")

    # Check for project root first.
    root = detect_project_root(file_path)
    if root:
        slug = pathlib.Path(root).name
        return (root, "repo", slug)

    # Check known logical area directories.
    home = str(pathlib.Path.home())
    resolved = str(pathlib.Path(file_path).resolve())
    if resolved.startswith(home + os.sep) or resolved == home:
        rel = os.path.relpath(resolved, home)
        for area_dir, area_slug in LOGICAL_AREA_DIRS:
            if rel == area_dir or rel.startswith(area_dir + os.sep):
                area_root = os.path.join(home, area_dir)
                return (area_root, "standalone", area_slug)

    # Check shell profile names.
    name = pathlib.Path(file_path).name
    if name in SHELL_PROFILE_NAMES:
        parent = str(pathlib.Path(file_path).resolve().parent)
        return (parent, "standalone", "shell-profiles")

    # Fallback: parent directory.
    parent = str(pathlib.Path(file_path).resolve().parent)
    slug = pathlib.Path(parent).name or "unknown"
    return (parent, "standalone", _safe_filename(slug))


# ── Work unit grouping ───────────────────────────────────────────────


def group_into_work_units(
    findings: List[NormalizedFinding],
) -> List[WorkUnit]:
    """Group findings into work units by project root or logical area.

    Keys on (root_path, slug) so that distinct logical areas under
    the same parent directory stay separate.
    """
    BucketKey = Tuple[str, str]
    area_buckets: Dict[BucketKey, List[Any]] = {}

    for nf in findings:
        root_path, work_type, slug = detect_work_area(nf.path)
        key: BucketKey = (root_path, slug)
        if key not in area_buckets:
            area_buckets[key] = [work_type, slug, root_path, []]
        area_buckets[key][3].append(nf)

    units: List[WorkUnit] = []
    for _key, bucket in area_buckets.items():
        work_type = bucket[0]
        slug = bucket[1]
        root_path = bucket[2]
        nfs = bucket[3]
        severity = _worst_severity(nfs)
        units.append(
            WorkUnit(
                id="",
                label=slug,
                severity=severity,
                work_type=work_type,
                root_path=root_path,
                findings=nfs,
            )
        )

    units.sort(key=_work_unit_sort_key)

    for i, unit in enumerate(units, 1):
        unit.id = f"{i:03d}-{unit.severity}-{unit.label}"

    return units


def _work_unit_sort_key(
    unit: WorkUnit,
) -> Tuple[int, int, int, str]:
    sev = SEVERITY_ORDER.get(unit.severity, 99)
    count = -len(unit.findings)
    wtype = 0 if unit.work_type == "repo" else 1
    return (sev, count, wtype, unit.root_path)


# ── 1Password enrichment ────────────────────────────────────────────


def _run_op(args: List[str]) -> Optional[str]:
    """Run an op CLI command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["op"] + args,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except (OSError, subprocess.TimeoutExpired):
        return None


def check_op_available() -> bool:
    """Return True if the op CLI is installed."""
    return shutil.which("op") is not None


def check_op_authenticated() -> bool:
    """Return True if op is authenticated."""
    return _run_op(["whoami", "--format", "json"]) is not None


def check_tmux_available() -> bool:
    """Return True if tmux is installed."""
    return shutil.which("tmux") is not None


def op_vault_list() -> List[str]:
    """Return list of accessible vault names."""
    out = _run_op(["vault", "list", "--format", "json"])
    if not out:
        return []
    try:
        vaults = json.loads(out)
        return [v["name"] for v in vaults if "name" in v]
    except (json.JSONDecodeError, KeyError, TypeError):
        return []


def op_item_search(
    query: str,
    vault: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search 1Password items by title. Returns matching items."""
    args = ["item", "list", "--format", "json"]
    if vault:
        args.extend(["--vault", vault])
    out = _run_op(args)
    if not out:
        return []
    try:
        items = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        return []

    query_lower = query.lower()
    query_parts = set(query_lower.replace("-", "_").split("_"))

    matches = []
    for item in items:
        title = item.get("title", "")
        title_lower = title.lower()
        title_parts = set(title_lower.replace("-", "_").replace(" ", "_").split("_"))
        if query_lower == title_lower:
            matches.insert(0, item)
        elif query_parts & title_parts:
            matches.append(item)

    return matches


def _op_item_fields(
    item_id: str,
    vault: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch item details and return the fields list."""
    args = ["item", "get", item_id, "--format", "json"]
    if vault:
        args.extend(["--vault", vault])
    out = _run_op(args)
    if not out:
        return []
    try:
        item = json.loads(out)
        return item.get("fields", [])
    except (json.JSONDecodeError, KeyError, TypeError):
        return []


def _build_reference(
    vault_name: str,
    item_title: str,
    field_name: str,
) -> str:
    """Build an op:// reference URI."""
    return f"op://{vault_name}/{item_title}/{field_name}"


def enrich_variable(
    var_name: str,
    vault: Optional[str] = None,
    vaults: Optional[List[str]] = None,
) -> OpMatch:
    """Search 1Password for a variable and classify the match."""
    search_vaults = [vault] if vault else (vaults or [])

    all_candidates: List[Dict[str, str]] = []

    for v in search_vaults:
        matches = op_item_search(var_name, vault=v)
        for m in matches:
            all_candidates.append(
                {
                    "vault": v,
                    "title": m.get("title", ""),
                    "id": m.get("id", ""),
                }
            )

    if not search_vaults:
        matches = op_item_search(var_name)
        for m in matches:
            v_info = m.get("vault", {})
            all_candidates.append(
                {
                    "vault": v_info.get("name", "Unknown"),
                    "title": m.get("title", ""),
                    "id": m.get("id", ""),
                }
            )

    if not all_candidates:
        return OpMatch(status="missing")

    if len(all_candidates) == 1:
        c = all_candidates[0]
        fields = _op_item_fields(c["id"], vault=c["vault"])
        field_name = _best_field_name(fields)
        return OpMatch(
            status="exact",
            vault=c["vault"],
            item_title=c["title"],
            field_name=field_name,
            reference=_build_reference(
                c["vault"],
                c["title"],
                field_name,
            ),
        )

    return OpMatch(
        status="ambiguous",
        candidates=[{"vault": c["vault"], "title": c["title"]} for c in all_candidates],
    )


def _best_field_name(fields: List[Dict[str, Any]]) -> str:
    """Pick the most likely credential field name from item fields."""
    preferred = {"credential", "password", "secret", "token", "key"}
    for f in fields:
        label = (f.get("label") or "").lower()
        if label in preferred:
            return f.get("label", "credential")
        ftype = (f.get("type") or "").upper()
        if ftype == "CONCEALED":
            return f.get("label", "credential")
    return "credential"


def enrich_work_units(
    units: List[WorkUnit],
    vault: Optional[str],
    dry_run: bool,
) -> None:
    """Run 1Password enrichment across all work units in place."""
    if dry_run or not check_op_available():
        _apply_placeholder_enrichment(units)
        return

    if not check_op_authenticated():
        print(
            dim(
                "  1Password CLI found but not authenticated. "
                "Using placeholder enrichment."
            ),
            file=sys.stderr,
        )
        _apply_placeholder_enrichment(units)
        return

    vaults = None if vault else op_vault_list()

    for unit in units:
        var_names = _extract_var_names(unit)
        for var in var_names:
            match = enrich_variable(var, vault=vault, vaults=vaults)
            unit.enrichment[var] = match


def _apply_placeholder_enrichment(
    units: List[WorkUnit],
) -> None:
    """Fill enrichment with placeholder OpMatch objects."""
    for unit in units:
        for var in _extract_var_names(unit):
            unit.enrichment[var] = OpMatch(status="unchecked")


def _extract_var_names(unit: WorkUnit) -> List[str]:
    """Extract secret variable names from a work unit."""
    var_names: List[str] = []
    seen: set = set()
    for nf in unit.findings:
        if nf.variables:
            for v in nf.variables:
                if v not in seen:
                    var_names.append(v)
                    seen.add(v)
        elif nf.variable and nf.variable not in seen:
            var_names.append(nf.variable)
            seen.add(nf.variable)
    return var_names


# ── Prompt helpers ───────────────────────────────────────────────────

OP_SSH_AGENT_SOCK = os.path.expanduser(
    "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
)


@functools.lru_cache(maxsize=1)
def _detect_op_ssh_agent() -> bool:
    """Check if 1Password SSH agent is configured and live.

    Requires both a live socket (not just a stale file) and an
    IdentityAgent directive in ~/.ssh/config pointing to it.
    A socket that exists but is not connectable indicates 1Password
    is installed but not running.
    """
    if not os.path.exists(OP_SSH_AGENT_SOCK):
        return False

    # Verify the socket is live, not stale.
    sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        sock.connect(OP_SSH_AGENT_SOCK)
    except (OSError, _socket.timeout):
        return False
    finally:
        sock.close()

    # Verify ~/.ssh/config routes through the 1Password agent.
    ssh_config = os.path.expanduser("~/.ssh/config")
    try:
        with open(ssh_config, encoding="utf-8") as f:
            content = f.read()
        if "2BUA8C4S2C.com.1password" not in content:
            return False
    except OSError:
        return False

    return True


def _gather_environment_lines(
    unit: "WorkUnit",
) -> List[str]:
    """Build the ## Environment section lines for a task file.

    Runs read-only checks at pack-generation time so agents do
    not waste cycles re-discovering tool availability.
    """
    lines: List[str] = [
        "## Environment",
        "",
    ]

    lines.append(
        f"- **Scanner:** `{SCRIPT_DIR}/clawback.py` (run with `uv run python`)"
    )

    categories = sorted(set(nf.category for nf in unit.findings))
    guide_files = sorted(set(GUIDE_MAP.get(c, "index.md") for c in categories))
    for gf in guide_files:
        guide_path = f"{SCRIPT_DIR}/docs/guides/{gf}"
        lines.append(f"- **Remediation guide:** `{guide_path}`")

    op_path = shutil.which("op")
    if op_path:
        lines.append("- **1Password CLI:** installed")
    else:
        lines.append("- **1Password CLI:** not installed")

    has_ssh = any(nf.fix_type == "ssh_harden" for nf in unit.findings)
    if has_ssh:
        if _detect_op_ssh_agent():
            lines.append(f"- **1Password SSH agent:** active (`{OP_SSH_AGENT_SOCK}`)")
        else:
            lines.append("- **1Password SSH agent:** not detected")

    has_kube = any(nf.fix_type == "kubeconfig_migrate" for nf in unit.findings)
    if has_kube:
        kubectl_path = shutil.which("kubectl")
        if kubectl_path:
            lines.append("- **kubectl:** installed")
        else:
            lines.append("- **kubectl:** not available — edit config files directly")

    return lines


def _collect_env_vars(
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> List[Dict[str, Any]]:
    """Collect variable info from env_files findings."""
    all_vars: List[Dict[str, Any]] = []
    seen: set = set()
    for nf in findings:
        if nf.variables:
            for var in nf.variables:
                if var not in seen:
                    match = enrichment.get(var)
                    ref = match.reference if match else None
                    all_vars.append(
                        {
                            "name": var,
                            "reason": nf.reason,
                            "line": nf.line,
                            "reference": ref,
                        }
                    )
                    seen.add(var)
        elif nf.variable and nf.variable not in seen:
            match = enrichment.get(nf.variable)
            ref = match.reference if match else None
            all_vars.append(
                {
                    "name": nf.variable,
                    "reason": nf.reason,
                    "line": nf.line,
                    "reference": ref,
                }
            )
            seen.add(nf.variable)
    return all_vars


def _format_op_match(
    var_name: str,
    match: Optional[OpMatch],
) -> List[str]:
    """Format a single 1Password match result as markdown lines."""
    if match and match.status == "unchecked":
        safe_name = "".join(c for c in var_name if c.isalnum() or c == "_")
        return [
            f"- `{var_name}`: **NOT CHECKED** — 1Password was "
            "not queried (dry-run or `op` unavailable). Search "
            "manually before proceeding:",
            f'  `op item list --format json | grep -i "{safe_name}"`',
        ]

    if not match or match.status == "missing":
        return [
            f"- `{var_name}`: **NOT FOUND** in 1Password. "
            "Store this secret before proceeding.",
        ]

    if match.status == "exact":
        return [
            f'- `{var_name}`: **FOUND** in vault "{match.vault}" → `{match.reference}`',
        ]

    if match.status == "ambiguous":
        lines = [
            f"- `{var_name}`: **AMBIGUOUS** — multiple candidates found:",
        ]
        for c in match.candidates or []:
            lines.append(f'  - Vault "{c["vault"]}": "{c["title"]}"')
        return lines

    return [f"- `{var_name}`: status unknown"]


def _worst_severity(findings: List[NormalizedFinding]) -> str:
    """Return the worst severity string from a list of findings."""
    if not findings:
        return "unknown"
    worst = min(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
    )
    return worst.severity


def _basename(path: str) -> str:
    """Return just the filename from a path string."""
    return pathlib.PurePosixPath(path).name


def _safe_filename(path: str) -> str:
    """Convert a path to a safe filename fragment."""
    name = pathlib.PurePosixPath(path).name or path
    safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in name)
    return safe[:60]


# ── Subtask section compilation ──────────────────────────────────────


def _subtask_groups(
    findings: List[NormalizedFinding],
) -> List[Tuple[str, str, List[NormalizedFinding]]]:
    """Group findings within a work unit into subtask units.

    Returns (fix_type, group_path, findings) tuples sorted by
    severity then path.
    """
    buckets: Dict[Tuple[str, str], List[NormalizedFinding]] = {}
    order: List[Tuple[str, str]] = []

    for nf in findings:
        key = (nf.fix_type, nf.path)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(nf)

    result = [(ft, path, buckets[(ft, path)]) for ft, path in order]
    result.sort(
        key=lambda x: (
            min(SEVERITY_ORDER.get(nf.severity, 99) for nf in x[2]),
            x[1],
        )
    )
    return result


def compile_subtask_section(
    num: int,
    fix_type: str,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Compile one subtask section within a task file."""
    if fix_type == "incident_response":
        return _section_incident_response(num, findings)

    compiler = SECTION_COMPILERS.get(fix_type)
    if compiler:
        return compiler(num, findings, enrichment)
    return _section_generic(num, findings, enrichment)


OP_SYNTAX_LINES = [
    "",
    "   Create a new item:",
    "   ```",
    '   op item create --vault "VaultName" '
    '--category "API Credential" '
    "--title \"Name\" 'credential=value'",
    "   ```",
    "   Add a field to an existing item:",
    "   ```",
    '   op item edit "ItemTitle" --vault "VaultName" \'new-field=value\'',
    "   ```",
]


def _env_rewrite_steps(
    path: str,
    all_vars: List[Dict[str, Any]],
    enrichment: Dict[str, OpMatch],
) -> List[str]:
    """Build the numbered remediation steps for env rewrite."""
    all_unchecked = bool(all_vars) and all(
        enrichment.get(v["name"]) and enrichment[v["name"]].status == "unchecked"
        for v in all_vars
    )

    if all_unchecked:
        op_step_text = (
            "2. **Check 1Password for existing items.** Each "
            "secret above was NOT CHECKED — verify whether it "
            "already exists before creating new items. Only "
            "store secrets that are genuinely missing. Verify "
            'with `op read "op://..."`.'
        )
    else:
        op_step_text = (
            "2. **Create missing 1Password items.** For each "
            "secret marked NOT FOUND above, store the current "
            "plaintext value in 1Password. Verify with "
            '`op read "op://..."`.'
        )

    lines: List[str] = [
        "",
        "**What to do**",
        "",
        f"1. **Find what consumes `{_basename(path)}`.** "
        "Search the project for `dotenv` / `load_dotenv` "
        "imports, `docker-compose.yml` `env_file:` directives, "
        "shell scripts that `source` this file, Makefile "
        "targets, and framework-specific env loading. This "
        "informs the `op run` setup in step 5.",
        "",
        op_step_text,
        *OP_SYNTAX_LINES,
        "",
        f"3. **Back up the original file.** Copy "
        f"`{_basename(path)}` to "
        f"`{_basename(path)}.plaintext.bak`.",
        "",
        "4. **Rewrite the file.** Replace each secret value "
        "with its `op://` reference. Preserve all comments, "
        "non-secret lines, and formatting. Example:",
        "   ```",
    ]

    if all_vars and all_vars[0].get("reference"):
        v = all_vars[0]
        lines.append(f"   {v['name']}={v['reference']}")
    else:
        lines.append("   SECRET_NAME=op://VaultName/ItemTitle/credential")

    lines.extend(
        [
            "   ```",
            "",
            "5. **Set up `op run`.** Based on step 1:",
            "   ```",
            f"   op run --env-file {shlex.quote(path)} -- <the-command>",
            "   ```",
            "   Add this as a note in the project README or a wrapper script.",
            "",
            f"6. **Check `.gitignore`.** Ensure `{_basename(path)}` "
            f"and `{_basename(path)}.plaintext.bak` are listed.",
            "",
            "7. **Delete the plaintext backup** once `op run` "
            "works and the secret is safely in 1Password.",
        ]
    )
    return lines


def _section_env_rewrite(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for .env file remediation."""
    path = findings[0].path
    severity = _worst_severity(findings)
    all_vars = _collect_env_vars(findings, enrichment)

    lines = [
        f"### {num}. Secure secrets in `{_basename(path)}`",
        "",
        f"File `{path}` contains plaintext secrets ({severity} severity):",
        "",
    ]

    for var_info in all_vars:
        name = var_info["name"]
        reason = var_info.get("reason") or "detected as secret"
        line_num = var_info.get("line")
        loc = f" (line {line_num})" if line_num else ""
        lines.append(f"- `{name}`{loc} — {reason}")

    lines.extend(["", "**1Password status**", ""])
    for var_info in all_vars:
        name = var_info["name"]
        lines.extend(_format_op_match(name, enrichment.get(name)))

    lines.extend(_env_rewrite_steps(path, all_vars, enrichment))

    return "\n".join(lines)


def _section_profile_rewrite(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for shell profile secret remediation."""
    path = findings[0].path
    severity = _worst_severity(findings)

    lines = [
        f"### {num}. Remove secrets from `{_basename(path)}`",
        "",
        f"Shell profile `{path}` contains exported secrets ({severity} severity):",
        "",
    ]

    for nf in findings:
        var = nf.variable or "unknown"
        line_num = nf.line
        reason = nf.reason or "detected as secret"
        loc = f":{line_num}" if line_num else ""
        lines.append(f"- `{var}` at `{_basename(path)}{loc}` — {reason}")

    lines.extend(["", "**1Password status**", ""])
    for nf in findings:
        if nf.variable:
            match = enrichment.get(nf.variable)
            lines.extend(_format_op_match(nf.variable, match))

    lines.extend(
        [
            "",
            "**What to do**",
            "",
            "For each secret variable listed above:",
            "",
            "1. **Ensure the value is in 1Password.** If not found "
            "above, store it manually before removing it from the "
            "profile.",
            "",
            "   ```",
            '   op item create --vault "VaultName" '
            '--category "API Credential" '
            "--title \"Name\" 'credential=value'",
            "   ```",
            "",
            f"2. **Remove the export line** from `{path}`. Do not "
            "comment it out — delete it entirely.",
            "",
            "3. **If the variable is needed at shell startup,** "
            "replace it with a runtime retrieval pattern:",
            "",
            "   a. **Wrapper script with `op run`** — if the "
            "variable is only needed by a specific command.",
            "",
            '   b. **`export VAR=$(op read "op://vault/item/'
            'field")`** — acceptable for variables that must be '
            "present in every shell session.",
            "",
            "4. **Check other shell profiles** for the same "
            "variable. Secrets often get duplicated across "
            "`.zshrc`, `.bash_profile`, `.zprofile`, etc.",
        ]
    )

    return "\n".join(lines)


def _section_env_var_trace(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for runtime environment variable findings."""
    nf = findings[0]
    var = nf.variable or "unknown"

    lines = [
        f"### {num}. Trace and fix source of `{var}`",
        "",
        f"The environment variable `{var}` contains a secret "
        f"value at runtime ({nf.severity} severity).",
        f"- Detection reason: {nf.reason or 'classified as secret'}",
        "",
        "Something is injecting this secret into the process "
        "environment. The source must be found and fixed.",
        "",
    ]

    match = enrichment.get(var)
    if match:
        lines.extend(["**1Password status**", ""])
        lines.extend(_format_op_match(var, match))
        lines.append("")

    lines.extend(
        [
            "**What to investigate**",
            "",
            f"Trace where `{var}` enters the environment:",
            "",
            "1. **Shell profiles** — check `~/.zshrc`, "
            "`~/.zprofile`, `~/.zshenv`, `~/.bash_profile`, "
            "`~/.bashrc`, `~/.profile` for "
            f"`export {var}=...`",
            "",
            "2. **Launch agents/daemons** — check "
            "`~/Library/LaunchAgents/` for plist files that set "
            "environment variables.",
            "",
            "3. **IDE configuration** — VS Code, JetBrains, and "
            "other IDEs can inject env vars into terminal sessions.",
            "",
            "4. **direnv or similar tools** — check for `.envrc` "
            "files in project directories.",
            "",
            "5. **Parent process** — the variable may come from a "
            "wrapper script or process manager.",
            "",
            "**What to do**",
            "",
            "Once you find the source:",
            "",
            "1. **Store the value in 1Password** if not already there.",
            "2. **Remove the plaintext assignment** at the source.",
            "3. **Replace with `op run` or `op read`** at the "
            "point where the variable is actually needed.",
        ]
    )

    return "\n".join(lines)


def _ssh_op_import_steps(path: str) -> List[str]:
    """Return the 1Password SSH import instruction lines."""
    return [
        "",
        "   **Important:** SSH key import requires the "
        "1Password desktop app — the CLI cannot import "
        "existing keys.",
        "   `op item create --ssh-generate-key` only "
        "generates new keys; it cannot import.",
        "",
        "   Steps:",
        "   1. Open 1Password desktop app → vault → + → SSH Key → Import",
        f"   2. Select `{path}`",
        "   3. Verify the key is served by the agent:",
        "      ```",
        '      SSH_AUTH_SOCK="$HOME/Library/Group Containers'
        '/2BUA8C4S2C.com.1password/t/agent.sock" ssh-add -l',
        "      ```",
        f"   4. Once confirmed, delete the private key: `rm {shlex.quote(path)}`",
        "      (keep the `.pub` file — it is not sensitive)",
    ]


def _ssh_dependent_checklist() -> List[str]:
    """Return the SSH key dependent-services checklist."""
    return [
        "   - `~/.ssh/config` for `IdentityFile` entries",
        "   - Git remote URLs that use SSH",
        "   - CI/CD pipelines or deploy scripts",
        "   - Cron jobs or automation that SSH to remote hosts",
        "",
    ]


def _ssh_remediation_steps(
    path: str,
    permissions: Optional[str],
    encrypted: Optional[bool],
    op_ssh_active: bool,
) -> List[str]:
    """Build the numbered SSH remediation steps."""
    lines: List[str] = ["", "**What to do**", ""]
    step = 1

    if permissions and permissions != "0o600":
        lines.append(f"{step}. **Fix permissions immediately:**")
        lines.append("   ```")
        lines.append(f"   chmod 600 {shlex.quote(path)}")
        lines.append("   ```")
        lines.append("")
        step += 1

    if op_ssh_active:
        lines.append(
            f"{step}. **Import into 1Password SSH agent.** "
            "The agent is already active on this machine — "
            "this is the recommended path."
        )
        lines.extend(_ssh_op_import_steps(path))
        lines.append("")
        step += 1

        lines.append(f"{step}. **Check which services use this key.** Look at:")
        lines.extend(_ssh_dependent_checklist())
    else:
        if encrypted is False:
            lines.append(f"{step}. **Add a passphrase:**")
            lines.append("   ```")
            lines.append(f"   ssh-keygen -p -f {shlex.quote(path)}")
            lines.append("   ```")
            lines.append("")
            step += 1

            lines.append(f"{step}. **Store the passphrase in macOS Keychain:**")
            lines.append("   ```")
            lines.append(f"   ssh-add --apple-use-keychain {shlex.quote(path)}")
            lines.append("   ```")
            lines.append("")
            step += 1

        lines.append(f"{step}. **Check which services use this key.** Look at:")
        lines.extend(_ssh_dependent_checklist())
        step += 1

        lines.append(
            f"{step}. **Consider 1Password SSH agent.** "
            "This eliminates the key file from disk entirely."
        )
        lines.extend(_ssh_op_import_steps(path))

    return lines


def _section_ssh_harden(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for SSH key remediation."""
    path = findings[0].path
    severity = _worst_severity(findings)

    key_type = None
    encrypted = None
    permissions = None
    for nf in findings:
        if nf.key_type:
            key_type = nf.key_type
        if nf.encrypted is not None:
            encrypted = nf.encrypted
        if nf.permissions:
            permissions = nf.permissions

    lines = [
        f"### {num}. Secure SSH key at `{_basename(path)}`",
        "",
    ]

    lines.append(f"- **Path:** `{path}`")
    if key_type:
        lines.append(f"- **Key type:** {key_type}")
    if encrypted is not None:
        enc_str = "Yes" if encrypted else "No"
        lines.append(f"- **Encrypted:** {enc_str}")
    if permissions:
        lines.append(f"- **Permissions:** {permissions}")
    lines.append(f"- **Severity:** {severity}")

    op_ssh_active = _detect_op_ssh_agent()

    lines.extend(["", "**Pre-conditions detected:**", ""])
    if op_ssh_active:
        lines.append(f"- 1Password SSH agent: **active** (`{OP_SSH_AGENT_SOCK}`)")
    else:
        lines.append("- 1Password SSH agent: not detected")

    lines.extend(
        _ssh_remediation_steps(
            path,
            permissions,
            encrypted,
            op_ssh_active,
        )
    )

    return "\n".join(lines)


def _section_incident_response(
    num: int,
    findings: List[NormalizedFinding],
) -> str:
    """Subtask section for TeamPCP IoC incident response."""
    lines = [
        f"### {num}. CRITICAL: Indicators of Compromise",
        "",
        "The following indicators of compromise were detected. "
        "This requires **immediate human-driven incident response**, "
        "NOT automated remediation.",
        "",
    ]

    for nf in findings:
        lines.append(f"- **{nf.path}**: {nf.description}")

    lines.extend(
        [
            "",
            "**Immediate actions**",
            "",
            "1. **Isolate this machine from the network.**",
            "2. Stop suspicious processes: `sudo launchctl unload` "
            "any matching LaunchAgents.",
            "3. Preserve forensic evidence before cleanup.",
            "4. **Rotate ALL credentials** that have ever been "
            "present on this machine.",
            "5. Rebuild from a clean image.",
            "",
            "Do not attempt automated remediation for these findings.",
        ]
    )

    return "\n".join(lines)


def _section_git_credential_store(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for git credential store remediation."""
    path = findings[0].path
    severity = _worst_severity(findings)

    lines = [
        f"### {num}. Migrate git credentials from `{_basename(path)}`",
        "",
        f"- **Path:** `{path}`",
        f"- **Severity:** {severity}",
        f"- **Description:** {findings[0].description}",
        "",
        "**What to do**",
        "",
        "1. **Switch to macOS Keychain credential helper:**",
        "   ```",
        "   git config --global --unset-all credential.helper",
        "   git config --global credential.helper osxkeychain",
        "   ```",
        "",
        "2. **Delete the plaintext credential file:**",
        "   ```",
        f"   rm {shlex.quote(path)}",
        "   ```",
        "",
        "3. **Clear cached Keychain entries** (forces re-authentication):",
        "   ```",
        "   printf 'host=github.com\\nprotocol=https\\n\\n'"
        " | git credential-osxkeychain erase",
        "   ```",
        "   Repeat for each host in the credential file "
        "(e.g. `gitlab.com`, `bitbucket.org`).",
        "",
        "4. **Verify by cloning or pulling** a private repo "
        "to trigger the Keychain credential prompt.",
        "",
        "5. **Alternative: use GitHub CLI** for a smoother OAuth flow:",
        "   ```",
        "   gh auth login",
        "   gh auth setup-git",
        "   ```",
    ]

    return "\n".join(lines)


def _detect_cloud_provider(path: str) -> str:
    """Guess the cloud provider from the finding path."""
    lower = path.lower()
    if "/.aws/" in lower or "/.aws" == lower[-4:]:
        return "aws"
    if "/gcloud/" in lower or "/gcp/" in lower:
        return "gcp"
    if "/.azure/" in lower or "/.azure" == lower[-6:]:
        return "azure"
    return "unknown"


def _section_cloud_migrate(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for cloud credential migration."""
    path = findings[0].path
    severity = _worst_severity(findings)
    provider = _detect_cloud_provider(path)

    lines = [
        f"### {num}. Remediate cloud credentials at `{_basename(path)}`",
        "",
        f"- **Path:** `{path}`",
        f"- **Severity:** {severity}",
        f"- **Provider:** {provider}",
        f"- **Description:** {findings[0].description}",
        "",
        "**What to do**",
        "",
    ]

    if provider == "aws":
        lines.extend(
            [
                "1. **Switch to AWS SSO:**",
                "   ```",
                "   aws configure sso",
                "   aws sso login --profile <profile>",
                "   ```",
                "",
                "2. **Delete static access keys** from the "
                "AWS console (IAM → Users → Security "
                "credentials → Delete access key).",
                "",
                "3. **Remove the local credentials file:**",
                f"   `rm {path}`",
                "",
                "4. **Unset environment variables** if set: "
                "`AWS_ACCESS_KEY_ID`, "
                "`AWS_SECRET_ACCESS_KEY`, "
                "`AWS_SESSION_TOKEN`.",
            ]
        )
    elif provider == "gcp":
        lines.extend(
            [
                "1. **Revoke application default credentials:**",
                "   ```",
                "   gcloud auth application-default revoke",
                "   ```",
                "",
                "2. **Use `gcloud auth login`** for "
                "interactive work. For service accounts, use "
                "workload identity federation instead of "
                "downloaded key files.",
                "",
                "3. **If the file is a service account key,** "
                "delete it from the GCP console (IAM → "
                "Service accounts → Keys → Delete) and "
                f"remove: `rm {shlex.quote(path)}`",
            ]
        )
    elif provider == "azure":
        lines.extend(
            [
                "1. **Re-authenticate with device code flow:**",
                "   ```",
                "   az login",
                "   ```",
                "",
                "2. **Clear cached tokens:**",
                "   ```",
                "   az account clear",
                "   ```",
                "",
                "3. **For service principals,** rotate the "
                "client secret in the Azure portal and use "
                "managed identity where possible.",
            ]
        )
    else:
        lines.append(findings[0].remediation)

    guide = GUIDE_MAP.get("cloud_credentials", "index.md")
    lines.extend(
        [
            "",
            f"See the full remediation guide at `{SCRIPT_DIR}/docs/guides/{guide}`.",
        ]
    )

    return "\n".join(lines)


def _section_kubeconfig_migrate(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for kubeconfig credential migration."""
    path = findings[0].path
    severity = _worst_severity(findings)
    kubectl_available = shutil.which("kubectl") is not None

    lines = [
        f"### {num}. Secure kubeconfig at `{_basename(path)}`",
        "",
        f"- **Path:** `{path}`",
        f"- **Severity:** {severity}",
        f"- **Description:** {findings[0].description}",
    ]
    if not kubectl_available:
        lines.append(
            "- **Note:** `kubectl` is not installed — edit the config file directly"
        )

    lines.extend(["", "**What to do**", ""])

    lines.extend(
        [
            "1. **Switch to exec-based auth plugins.** "
            "These generate short-lived tokens instead of "
            "storing static credentials:",
            "   - **AWS EKS:** `aws eks update-kubeconfig --name <CLUSTER>`",
            "   - **GKE:** `gcloud container clusters get-credentials <CLUSTER>`",
            "   - **AKS:** `az aks get-credentials "
            "--resource-group <RG> --name <CLUSTER>` "
            "then `kubelogin convert-kubeconfig -l azurecli`",
            "",
            "2. **Remove stale contexts and users** with embedded credentials:",
        ]
    )

    if kubectl_available:
        lines.extend(
            [
                "   ```",
                "   kubectl config delete-context <STALE_CONTEXT>",
                "   kubectl config unset users.<STALE_USER>",
                "   ```",
            ]
        )
    else:
        lines.append(
            f"   Edit `{path}` directly: remove `user:` "
            "entries that contain `client-certificate-data`, "
            "`client-key-data`, `token:`, or `password:` "
            "fields."
        )

    lines.extend(
        [
            "",
            "3. **Fix file permissions:**",
            f"   `chmod 600 {shlex.quote(path)}`",
            "",
            "4. **Verify no embedded credentials remain** "
            "by inspecting the `users:` section of the "
            "config for `token:`, `client-key-data:`, or "
            "`password:` fields.",
        ]
    )

    return "\n".join(lines)


def _section_token_migrate(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for package manager token migration."""
    path = findings[0].path
    severity = _worst_severity(findings)
    basename = _basename(path)

    lines = [
        f"### {num}. Migrate token in `{basename}`",
        "",
        f"- **Path:** `{path}`",
        f"- **Severity:** {severity}",
        f"- **Description:** {findings[0].description}",
        "",
        "**What to do**",
        "",
    ]

    lower = path.lower()
    if ".npmrc" in lower:
        lines.extend(
            [
                "1. **Remove the token from `.npmrc`:**",
                "   Delete or comment out the "
                "`//registry.npmjs.org/:_authToken=` line.",
                "",
                "2. **Use `npm login` instead** — this "
                "stores credentials in the OS keychain on "
                "macOS.",
                "",
                "3. **For CI, use `NPM_TOKEN` env var** "
                "injected from 1Password or a secrets "
                "manager, not a static `.npmrc`.",
            ]
        )
    elif ".pypirc" in lower or "/pip/" in lower or "pip.conf" in lower:
        lines.extend(
            [
                "1. **Remove tokens from `.pypirc`.**",
                "",
                "2. **Use `keyring` for PyPI uploads:**",
                "   ```",
                "   pip install keyring",
                "   keyring set https://upload.pypi.org/legacy/ __token__",
                "   ```",
                "",
                "3. **For CI, use trusted publishers** (OIDC) instead of API tokens.",
            ]
        )
    elif "docker" in lower:
        lines.extend(
            [
                "1. **Use `docker login`** — on macOS this "
                "stores credentials in the Keychain via "
                "the `osxkeychain` credential helper.",
                "",
                "2. **Remove plaintext auth** from "
                f"`{path}` — delete the `auths` section "
                "containing base64-encoded credentials.",
                "",
                "3. **Verify credential helper is active:**",
                "   `docker-credential-osxkeychain list`",
            ]
        )
    else:
        lines.append(findings[0].remediation)
        lines.extend(
            [
                "",
                "Move the token to 1Password or the "
                "platform's native credential store, then "
                "delete the plaintext file.",
            ]
        )

    return "\n".join(lines)


def _section_wallet_secure(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for cryptocurrency wallet security."""
    path = findings[0].path
    severity = _worst_severity(findings)

    lines = [
        f"### {num}. Secure wallet at `{_basename(path)}`",
        "",
        f"- **Path:** `{path}`",
        f"- **Severity:** {severity}",
        f"- **Description:** {findings[0].description}",
        "",
        "**What to do**",
        "",
        "1. **Ensure FileVault full-disk encryption is enabled:**",
        "   ```",
        "   fdesetup status",
        "   ```",
        "   If not active: `sudo fdesetup enable`",
        "",
        "2. **Back up the wallet** to an encrypted "
        "medium (1Password document, encrypted USB) "
        "before making any other changes.",
        "",
        "3. **Move funds to a hardware wallet** (Ledger, "
        "Trezor) if the balance is non-trivial. Keep only "
        "operational minimums in hot wallets.",
        "",
        "4. **For Solana keypairs,** switch to hardware wallet delegation:",
        "   `solana config set --keypair usb://ledger`",
        "",
        "5. **Restrict file permissions:**",
        f"   `chmod 600 {shlex.quote(path)}`",
    ]

    return "\n".join(lines)


def _section_generic(
    num: int,
    findings: List[NormalizedFinding],
    enrichment: Dict[str, OpMatch],
) -> str:
    """Subtask section for categories without specialized templates."""
    nf = findings[0]

    guide = GUIDE_MAP.get(nf.category, "index.md")
    guide_path = f"{SCRIPT_DIR}/docs/guides/{guide}"

    lines = [
        f"### {num}. Address {nf.category} finding",
        "",
        f"- **Category:** {nf.category}",
        f"- **Path:** `{nf.path}`",
        f"- **Severity:** {nf.severity}",
        f"- **Description:** {nf.description}",
        "",
        "**Recommended action**",
        "",
        nf.remediation,
        "",
        f"See the remediation guide at `{guide_path}` for detailed steps.",
    ]

    return "\n".join(lines)


SECTION_COMPILERS = {
    "env_rewrite": _section_env_rewrite,
    "profile_rewrite": _section_profile_rewrite,
    "env_var_trace": _section_env_var_trace,
    "ssh_harden": _section_ssh_harden,
    "git_credential_store": _section_git_credential_store,
    "cloud_migrate": _section_cloud_migrate,
    "kubeconfig_migrate": _section_kubeconfig_migrate,
    "token_migrate": _section_token_migrate,
    "wallet_secure": _section_wallet_secure,
}


# ── Task file compilation ────────────────────────────────────────────


def _compile_verification_tail(
    unit: WorkUnit,
    pack_path: Optional[str],
) -> List[str]:
    """Build the Verification and Pack status sections."""
    lines: List[str] = []
    ver_paths = sorted(
        set(nf.path for nf in unit.findings if not nf.path.startswith("env:"))
    )
    categories = sorted(set(nf.category for nf in unit.findings))
    lines.append(
        "Run a targeted clawback scan and check that "
        "the findings for these paths are resolved:"
    )
    lines.append("")
    lines.append("```bash")
    lines.append(f"cd {SCRIPT_DIR}")
    if len(categories) == 1:
        lines.append(f"uv run python clawback.py --category {categories[0]} --pretty")
    else:
        lines.append("uv run python clawback.py --pretty")
    lines.append("```")
    if ver_paths:
        lines.append("")
        lines.append("Affected paths to verify:")
        for p in ver_paths:
            lines.append(f"- `{p}`")

    if pack_path:
        index_ref = f"`{pack_path}/index.md`"
    else:
        index_ref = "`index.md`"
    lines.extend(
        [
            "",
            "## Pack status",
            "",
            f"Update the checkbox for this task in {index_ref} when complete.",
        ]
    )
    return lines


def compile_task_file(
    unit: WorkUnit,
    pack_path: Optional[str] = None,
) -> str:
    """Compile a WorkUnit into a complete agent-ready task file."""
    if all(nf.fix_type == "incident_response" for nf in unit.findings):
        return _compile_incident_response_task(unit)

    lines = [
        f"# Task {unit.id} ({unit.severity} severity)",
        "",
        "## Working directory",
        "",
        f"`{unit.root_path}`",
        "",
        "## Scope",
        "",
    ]

    if unit.work_type == "repo":
        lines.append(
            f"This task covers all findings within the `{unit.label}` repository."
        )
    else:
        lines.append(
            f"This task covers findings in the `{unit.label}` configuration area."
        )
    lines.extend(
        [
            "Out of scope: findings in other repositories or unrelated system areas.",
            "",
        ]
    )

    lines.extend(_gather_environment_lines(unit))
    lines.extend(["", "## Findings", ""])

    cats: Dict[str, List[NormalizedFinding]] = {}
    for nf in unit.findings:
        cats.setdefault(nf.category, []).append(nf)
    for cat, nfs in sorted(cats.items()):
        paths = sorted(set(nf.path for nf in nfs))
        path_str = ", ".join(f"`{_basename(p)}`" for p in paths)
        lines.append(f"- **{cat}**: {len(nfs)} finding(s) in {path_str}")

    lines.extend(["", "## Subtasks", ""])

    groups = _subtask_groups(unit.findings)
    for i, (fix_type, _path, nfs) in enumerate(groups, 1):
        section = compile_subtask_section(i, fix_type, nfs, unit.enrichment)
        lines.append(section)
        lines.append("")

    lines.extend(
        [
            "## Constraints",
            "",
            "- Do not relocate plaintext secrets to different plaintext files",
            "- Delete or neutralize orphaned credential files after migration",
            "- Preserve comments and formatting in edited files",
            "- Prefer targeted edits over unrelated cleanup",
            "",
            "## Verification",
            "",
        ]
    )

    lines.extend(_compile_verification_tail(unit, pack_path))

    return "\n".join(lines)


def _compile_incident_response_task(unit: WorkUnit) -> str:
    """Compile a task file for pure incident-response findings."""
    lines = [
        f"# Task {unit.id} (CRITICAL)",
        "",
        "**THIS TASK REQUIRES IMMEDIATE HUMAN ACTION.**",
        "**Do not use automated remediation for these findings.**",
        "",
        "## Indicators of Compromise",
        "",
    ]

    for nf in unit.findings:
        lines.append(f"- **`{nf.path}`**: {nf.description}")

    lines.extend(
        [
            "",
            "## Immediate Actions",
            "",
            "1. **Isolate this machine from the network.**",
            "2. Stop suspicious processes: "
            "`sudo launchctl unload` any matching LaunchAgents.",
            "3. Preserve forensic evidence before cleanup.",
            "4. **Rotate ALL credentials** that have ever been "
            "present on this machine.",
            "5. Rebuild from a clean image.",
            "",
            "Do not attempt automated remediation for these findings.",
        ]
    )

    return "\n".join(lines)


# ── Pack compilation ─────────────────────────────────────────────────


def _render_index_entry(unit: WorkUnit) -> List[str]:
    """Render a single work unit as an index checklist entry."""
    lines: List[str] = []
    is_ir = _is_incident_response(unit)
    task_rel = f"tasks/{unit.id}.md"
    wtype = "repo" if unit.work_type == "repo" else "standalone"
    lines.append(f"- [ ] **{unit.id}** — {unit.label} ({unit.severity}, {wtype})")
    lines.append(f"  - Task: `{task_rel}`")
    lines.append(f"  - Working directory: `{unit.root_path}`")

    categories = sorted(set(nf.category for nf in unit.findings))
    if len(categories) == 1:
        verify_cmd = f"uv run python clawback.py --category {categories[0]} --pretty"
    else:
        verify_cmd = "uv run python clawback.py --pretty"
    lines.append(f"  - Verify: `cd {SCRIPT_DIR} && {verify_cmd}`")
    if len(categories) > 1:
        cats = ", ".join(categories)
        lines.append(f"    (covers categories: {cats})")

    if is_ir:
        lines.append("  - **Human-only — no agent launcher**")
    else:
        launch_rel = f"launch/{unit.id}-claude.sh"
        lines.append(f"  - Launch: `bash {launch_rel}`")
    lines.append("")
    return lines


def compile_index(
    units: List[WorkUnit],
    report_data: Dict[str, Any],
    pack_path: str,
) -> str:
    """Compile the operator-facing index.md dashboard."""
    findings_flat = []
    for u in units:
        findings_flat.extend(u.findings)
    total = len(findings_flat)

    sev_counts: Dict[str, int] = {}
    cat_counts: Dict[str, int] = {}
    for nf in findings_flat:
        sev_counts[nf.severity] = sev_counts.get(nf.severity, 0) + 1
        cat_counts[nf.category] = cat_counts.get(nf.category, 0) + 1

    repo_count = sum(1 for u in units if u.work_type == "repo")
    standalone_count = len(units) - repo_count

    lines = [
        "# Remediation Pack",
        "",
        f"Generated by clawback-restitution v{VERSION}",
        "",
        "## Scan Summary",
        "",
        f"- **Total findings:** {total}",
    ]

    sev_parts = []
    for sev in ("critical", "high", "medium", "low"):
        count = sev_counts.get(sev, 0)
        if count:
            sev_parts.append(f"{count} {sev}")
    if sev_parts:
        lines.append(f"- **Severity:** {', '.join(sev_parts)}")

    cat_parts = []
    for cat in sorted(cat_counts):
        cat_parts.append(f"{cat} ({cat_counts[cat]})")
    if cat_parts:
        lines.append(f"- **Categories:** {', '.join(cat_parts)}")

    lines.extend(
        [
            "",
            "## Tasks",
            "",
            f"- **{len(units)} task(s)** "
            f"({repo_count} repo, {standalone_count} standalone)",
            "",
            "## Execution Queue",
            "",
        ]
    )

    for unit in units:
        lines.extend(_render_index_entry(unit))

    return "\n".join(lines)


def compile_metadata(
    report_data: Dict[str, Any],
    input_path: Optional[str],
) -> str:
    """Compile the metadata.md provenance file."""
    lines = [
        "# Pack Metadata",
        "",
        "## Provenance",
        "",
    ]

    scanner_ver = report_data.get("scanner_version", "unknown")
    lines.append(f"- **Scanner:** clawback v{scanner_ver}")

    hostname = report_data.get("hostname", "unknown")
    username = report_data.get("username", "unknown")
    lines.append(f"- **Host:** {hostname}")
    lines.append(f"- **User:** {username}")

    platform = report_data.get("platform", "unknown")
    lines.append(f"- **Platform:** {platform}")

    timestamp = report_data.get("timestamp", "unknown")
    lines.append(f"- **Scan timestamp:** {timestamp}")

    if input_path:
        lines.append(f"- **Input:** `{input_path}`")

    summary = report_data.get("summary", {})
    total = report_data.get("total_findings", 0)
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- {total} total finding(s)",
        ]
    )
    sev_parts = []
    for sev in ("critical", "high", "medium", "low"):
        count = summary.get(sev, 0)
        if count:
            sev_parts.append(f"{sev}: {count}")
    if sev_parts:
        lines.append(f"- {', '.join(sev_parts)}")

    lines.extend(
        [
            "",
            "## Staleness Warning",
            "",
            "This pack reflects the scan state at the time of "
            "generation. A newer clawback scan may "
            "find different results. Regenerate the pack after "
            "significant remediation work.",
        ]
    )

    return "\n".join(lines)


def _is_incident_response(unit: WorkUnit) -> bool:
    """True when the work unit is purely incident response."""
    return all(nf.fix_type == "incident_response" for nf in unit.findings)


def compile_claude_launcher(
    unit: WorkUnit,
    pack_path: str,
) -> str:
    """Generate a Claude Code launcher script.

    Displays the task prompt so the operator can review it, waits
    for confirmation, then starts an interactive Claude session in
    plan mode. Works both standalone and inside a tmux window.
    """
    task_path = f"{pack_path}/tasks/{unit.id}.md"
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f'cd "{unit.root_path}"',
        "",
        f'cat "{task_path}"',
        "echo ''",
        "read -r -p 'Press Enter to start Claude Code in plan mode...'",
        "",
        f'exec claude --permission-mode plan "$(cat "{task_path}")"',
        "",
    ]
    return "\n".join(lines)


def compile_codex_launcher(
    unit: WorkUnit,
    pack_path: str,
) -> str:
    """Generate an approximate Codex launcher script."""
    task_path = f"{pack_path}/tasks/{unit.id}.md"
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f'cd "{unit.root_path}"',
        "",
        "echo 'Review and run (approximate Codex equivalent):'",
        f'echo \'codex -p "$(cat "{task_path}")"\'',
        "",
    ]
    return "\n".join(lines)


# ── Pack generation ──────────────────────────────────────────────────


def generate_pack(
    units: List[WorkUnit],
    report_data: Dict[str, Any],
    output_dir: str,
    input_path: Optional[str],
) -> str:
    """Write the remediation pack to disk. Returns the pack path."""
    pack = pathlib.Path(output_dir).resolve()
    tasks_dir = pack / "tasks"
    launch_dir = pack / "launch"

    tasks_dir.mkdir(parents=True, exist_ok=True)
    launch_dir.mkdir(parents=True, exist_ok=True)

    meta_content = compile_metadata(report_data, input_path)
    (pack / "metadata.md").write_text(meta_content + "\n", encoding="utf-8")

    for unit in units:
        task_filename = f"{unit.id}.md"
        task_path = tasks_dir / task_filename
        task_path.write_text(
            compile_task_file(unit, pack_path=str(pack)) + "\n",
            encoding="utf-8",
        )

        # Incident-response units are human-only: no launchers.
        if _is_incident_response(unit):
            continue

        claude_path = launch_dir / f"{unit.id}-claude.sh"
        claude_content = compile_claude_launcher(unit, str(pack))
        claude_path.write_text(claude_content, encoding="utf-8")
        claude_path.chmod(claude_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

        codex_path = launch_dir / f"{unit.id}-codex.sh"
        codex_content = compile_codex_launcher(unit, str(pack))
        codex_path.write_text(codex_content, encoding="utf-8")
        codex_path.chmod(codex_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

    index_content = compile_index(units, report_data, str(pack))
    (pack / "index.md").write_text(index_content + "\n", encoding="utf-8")

    return str(pack)


def default_pack_dir() -> str:
    """Return a timestamped default pack directory path."""
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join("tmp", "restitution-packs", ts)


def print_preview(units: List[WorkUnit]) -> None:
    """Print inline task details for operator triage."""
    for unit in units:
        is_ir = _is_incident_response(unit)
        wtype = "repo" if unit.work_type == "repo" else "standalone"
        sev_str = unit.severity
        if unit.severity == "critical":
            sev_str = red(unit.severity)
        elif unit.severity == "high":
            sev_str = yellow(unit.severity)

        print(
            f"  {bold(unit.id)}  [{sev_str}] [{wtype}]",
            file=sys.stderr,
        )
        print(
            dim(f"  {unit.root_path}"),
            file=sys.stderr,
        )
        if is_ir:
            print(
                red("  INCIDENT RESPONSE — human-only, no agent launcher"),
                file=sys.stderr,
            )
        for nf in unit.findings:
            print(
                f"    {nf.description}",
                file=sys.stderr,
            )
        print("", file=sys.stderr)


def create_tmux_session(
    units: List[WorkUnit],
    pack_path: str,
    session_name: str,
) -> None:
    """Create a tmux session with one window per launchable task.

    Each window displays the task prompt and waits for the operator
    to press Enter before starting Claude Code in plan mode.
    """
    launchable = [u for u in units if not _is_incident_response(u)]
    if not launchable:
        print(
            yellow("No launchable tasks — skipping tmux session."),
            file=sys.stderr,
        )
        return

    if not check_tmux_available():
        _fatal("tmux is not installed. Install with: brew install tmux")

    first = launchable[0]
    launcher = f"{pack_path}/launch/{first.id}-claude.sh"
    try:
        subprocess.run(
            [
                "tmux",
                "new-session",
                "-d",
                "-s",
                session_name,
                "-n",
                first.id,
                "-c",
                first.root_path,
                f'bash "{launcher}"',
            ],
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        _fatal(f"Failed to create tmux session: {exc}")

    for unit in launchable[1:]:
        launcher = f"{pack_path}/launch/{unit.id}-claude.sh"
        try:
            subprocess.run(
                [
                    "tmux",
                    "new-window",
                    "-t",
                    session_name,
                    "-n",
                    unit.id,
                    "-c",
                    unit.root_path,
                    f'bash "{launcher}"',
                ],
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            print(
                yellow(f"  Warning: could not create window for {unit.id}: {exc}"),
                file=sys.stderr,
            )

    subprocess.run(
        [
            "tmux",
            "select-window",
            "-t",
            f"{session_name}:0",
        ],
        check=False,
    )

    print("", file=sys.stderr)
    print(
        bold(
            f"tmux session '{session_name}' created with {len(launchable)} window(s)."
        ),
        file=sys.stderr,
    )
    print("", file=sys.stderr)

    if os.environ.get("TMUX"):
        print(
            "  Already inside tmux. Switch with:",
            file=sys.stderr,
        )
        print(
            f"    tmux switch-client -t {session_name}",
            file=sys.stderr,
        )
    else:
        print(
            "  Connect with:",
            file=sys.stderr,
        )
        print(
            f"    tmux attach -t {session_name}",
            file=sys.stderr,
        )

    print("", file=sys.stderr)
    print(
        dim("  Each window shows the task prompt. Press Enter to start Claude."),
        file=sys.stderr,
    )
    print("", file=sys.stderr)


# ── Stdout summary ───────────────────────────────────────────────────


def print_pack_summary(
    pack_path: str,
    units: List[WorkUnit],
    findings: List[NormalizedFinding],
    op_available: bool,
    op_authenticated: bool,
) -> None:
    """Print a concise summary to stderr after pack generation."""
    print("", file=sys.stderr)
    print(bold("clawback-restitution"), file=sys.stderr)
    print("", file=sys.stderr)

    sev_counts: Dict[str, int] = {}
    cat_counts: Dict[str, int] = {}
    for nf in findings:
        sev_counts[nf.severity] = sev_counts.get(nf.severity, 0) + 1
        cat_counts[nf.category] = cat_counts.get(nf.category, 0) + 1

    total = len(findings)
    print(
        f"  {total} finding(s) across {len(cat_counts)} category(ies)",
        file=sys.stderr,
    )

    sev_parts = []
    for sev in ("critical", "high", "medium", "low"):
        count = sev_counts.get(sev, 0)
        if count:
            label = f"{count} {sev}"
            if sev == "critical":
                label = red(label)
            elif sev == "high":
                label = yellow(label)
            sev_parts.append(label)
    if sev_parts:
        print(
            f"  Severity: {', '.join(sev_parts)}",
            file=sys.stderr,
        )

    op_status = (
        green("authenticated")
        if op_authenticated
        else (
            yellow("installed but not authenticated")
            if op_available
            else dim("not installed")
        )
    )
    print(f"  1Password CLI: {op_status}", file=sys.stderr)

    print("", file=sys.stderr)
    print(
        f"  {bold(str(len(units)))} task(s) → {pack_path}/",
        file=sys.stderr,
    )
    print("", file=sys.stderr)

    for unit in units:
        wtype = "repo" if unit.work_type == "repo" else "standalone"
        suffix = ""
        if _is_incident_response(unit):
            suffix = "  [HUMAN-ONLY]"
        print(
            f"  {unit.id}  ({wtype}){suffix}",
            file=sys.stderr,
        )

    launchable = [u for u in units if not _is_incident_response(u)]
    if launchable:
        print("", file=sys.stderr)
        print(
            dim("  Launch commands:"),
            file=sys.stderr,
        )
        for unit in launchable:
            print(
                dim(f"    bash {pack_path}/launch/{unit.id}-claude.sh"),
                file=sys.stderr,
            )
    print("", file=sys.stderr)


# ── Legacy combined mode ─────────────────────────────────────────────


def write_combined(units: List[WorkUnit]) -> None:
    """Write all task files as one combined markdown document."""
    parts = [
        "# Clawback Remediation Prompts",
        "",
        f"Generated by clawback-restitution v{VERSION}. "
        f"{len(units)} task(s) to address.",
        "",
        "Work through each section in order.",
        "",
        "---",
        "",
    ]

    for unit in units:
        parts.append(compile_task_file(unit))
        parts.append("")
        parts.append("---")
        parts.append("")

    print("\n".join(parts))


# ── Fatal error helper ───────────────────────────────────────────────


def _fatal(msg: str) -> None:
    """Print an error message and exit."""
    print(f"{red('error')}: {msg}", file=sys.stderr)
    sys.exit(1)


# ── Main ─────────────────────────────────────────────────────────────


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Load
    data = load_report(args.input)

    # Validate
    raw_findings = validate_report(data)

    if not raw_findings:
        print(
            green("No findings to remediate. You're clean!"),
            file=sys.stderr,
        )
        return 0

    # Normalize
    findings = normalize_all(
        raw_findings,
        category_filter=args.category,
    )

    if not findings:
        print(
            f"No findings for category '{args.category}'.",
            file=sys.stderr,
        )
        return 0

    # Group
    units = group_into_work_units(findings)

    # Enrich
    op_available = not args.dry_run and check_op_available()
    op_authenticated = op_available and check_op_authenticated()
    enrich_work_units(units, vault=args.vault, dry_run=args.dry_run)

    # Combined mode: legacy stdout output
    if args.combined:
        if args.preview or args.tmux:
            print(
                "Warning: --combined ignores --preview and --tmux.",
                file=sys.stderr,
            )
        write_combined(units)
        return 0

    # Pack generation (default)
    output_dir = args.output_dir or default_pack_dir()
    pack_path = generate_pack(units, data, output_dir, input_path=args.input)

    # Summary
    print_pack_summary(pack_path, units, findings, op_available, op_authenticated)

    if args.preview:
        print_preview(units)

    if args.tmux:
        session_name = f"restitution-{pathlib.Path(pack_path).name}"
        create_tmux_session(units, pack_path, session_name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
