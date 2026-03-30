"""Tests for clawback-restitution remediation pack generator."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from restitution import (
    NormalizedFinding,
    OpMatch,
    WorkUnit,
    _is_incident_response,
    build_parser,
    compile_claude_launcher,
    compile_codex_launcher,
    compile_index,
    compile_metadata,
    compile_subtask_section,
    compile_task_file,
    default_pack_dir,
    detect_project_root,
    detect_work_area,
    enrich_work_units,
    generate_pack,
    group_into_work_units,
    load_report,
    main,
    normalize_all,
    normalize_finding,
    validate_report,
    write_combined,
)


# ── Fixtures ─────────────────────────────────────────────────────────


def _minimal_report(findings=None):
    """Build a minimal valid clawback report."""
    findings = findings or []
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "medium")
        summary[sev] = summary.get(sev, 0) + 1
    return {
        "scanner_version": "1.0.0",
        "hostname": "testhost",
        "username": "testuser",
        "platform": "macOS",
        "python_version": "3.13",
        "timestamp": "2026-01-01T00:00:00Z",
        "scan_duration_seconds": 1.0,
        "findings": findings,
        "observations": [],
        "summary": summary,
        "total_findings": len(findings),
        "op_cli_available": False,
        "errors": [],
    }


def _env_finding(path="/project/.env", variables=None):
    """Build a representative env_files finding."""
    variables = variables or ["SECRET_KEY", "API_TOKEN"]
    return {
        "category": "env_files",
        "path": path,
        "severity": "high",
        "description": (
            f".env file with {len(variables)} secret(s): "
            + ", ".join(variables)
        ),
        "remediation": "Add .env to .gitignore.",
        "details": {"variables": variables},
    }


def _shell_profile_finding(
    path="/Users/test/.zshrc",
    variable="AWS_SECRET_ACCESS_KEY",
    line=5,
    reason="known_prefix:AKIA",
):
    """Build a representative shell_profile_secrets finding."""
    return {
        "category": "shell_profile_secrets",
        "path": path,
        "severity": "high",
        "description": (
            f"Secret variable '{variable}' in .zshrc:{line}"
        ),
        "remediation": "Use op run to inject secrets at runtime.",
        "details": {
            "variable": variable,
            "line": line,
            "reason": reason,
        },
    }


def _env_var_finding(
    variable="GH_TOKEN", reason="known_prefix:ghp_"
):
    """Build a representative environment_variables finding."""
    return {
        "category": "environment_variables",
        "path": f"env:{variable}",
        "severity": "high",
        "description": (
            f"Secret in environment variable: {variable}"
        ),
        "remediation": "Unset and use a secrets manager.",
        "details": {"variable": variable, "reason": reason},
    }


def _ssh_finding(
    path="/Users/test/.ssh/id_rsa",
    key_type="RSA",
    encrypted=False,
    permissions="0o644",
):
    """Build a representative ssh_keys finding."""
    return {
        "category": "ssh_keys",
        "path": path,
        "severity": "high",
        "description": (
            f"Unencrypted {key_type} SSH key with "
            f"overly permissive permissions ({permissions})"
        ),
        "remediation": (
            "Add a passphrase: ssh-keygen -p -f <path>."
        ),
        "details": {
            "key_type": key_type,
            "encrypted": encrypted,
            "permissions": permissions,
        },
    }


def _teampcp_finding():
    """Build a representative teampcp_ioc finding."""
    return {
        "category": "teampcp_ioc",
        "path": "/usr/local/bin/pgmon",
        "severity": "critical",
        "description": "TeamPCP IoC found: pgmon",
        "remediation": "Isolate this machine.",
        "details": {},
    }


def _cloud_finding(
    path="/Users/test/.config/gcloud/"
    "application_default_credentials.json",
):
    """Build a representative cloud_credentials finding."""
    return {
        "category": "cloud_credentials",
        "path": path,
        "severity": "high",
        "description": "GCP credentials (type=authorized_user)",
        "remediation": "Use gcloud auth with short-lived creds.",
        "details": {},
    }


def _make_work_unit(
    findings_raw,
    unit_id="001-high-test",
    label="test",
    root_path="/project",
    work_type="repo",
):
    """Helper to build a WorkUnit with placeholder enrichment."""
    nfs = [normalize_finding(f) for f in findings_raw]
    unit = WorkUnit(
        id=unit_id,
        label=label,
        severity="high",
        work_type=work_type,
        root_path=root_path,
        findings=nfs,
    )
    for nf in nfs:
        if nf.variables:
            for v in nf.variables:
                unit.enrichment[v] = OpMatch(status="missing")
        elif nf.variable:
            unit.enrichment[nf.variable] = OpMatch(
                status="missing"
            )
    return unit


# ── JSON loading and validation ──────────────────────────────────────


class TestLoadReport:
    def test_load_from_file(self, tmp_path):
        report = _minimal_report()
        p = tmp_path / "scan.json"
        p.write_text(json.dumps(report))
        data = load_report(str(p))
        assert data["total_findings"] == 0

    def test_load_missing_file(self):
        with pytest.raises(SystemExit):
            load_report("/nonexistent/path.json")

    def test_load_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json")
        with pytest.raises(SystemExit):
            load_report(str(p))


class TestValidateReport:
    def test_valid_report(self):
        report = _minimal_report([_env_finding()])
        findings = validate_report(report)
        assert len(findings) == 1

    def test_empty_findings_valid(self):
        report = _minimal_report()
        findings = validate_report(report)
        assert findings == []

    def test_missing_required_fields(self):
        with pytest.raises(SystemExit):
            validate_report({"findings": []})

    def test_findings_not_a_list(self):
        report = _minimal_report()
        report["findings"] = "bad"
        with pytest.raises(SystemExit):
            validate_report(report)

    def test_finding_missing_fields(self):
        report = _minimal_report()
        report["findings"] = [{"category": "env_files"}]
        with pytest.raises(SystemExit):
            validate_report(report)

    def test_report_not_dict(self):
        with pytest.raises(SystemExit):
            validate_report([])


# ── Normalization ────────────────────────────────────────────────────


class TestNormalize:
    def test_env_finding_normalization(self):
        nf = normalize_finding(_env_finding())
        assert nf.category == "env_files"
        assert nf.fix_type == "env_rewrite"
        assert nf.variables == ["SECRET_KEY", "API_TOKEN"]

    def test_shell_profile_normalization(self):
        nf = normalize_finding(_shell_profile_finding())
        assert nf.variable == "AWS_SECRET_ACCESS_KEY"
        assert nf.line == 5
        assert nf.reason == "known_prefix:AKIA"
        assert nf.fix_type == "profile_rewrite"

    def test_ssh_normalization(self):
        nf = normalize_finding(_ssh_finding())
        assert nf.key_type == "RSA"
        assert nf.encrypted is False
        assert nf.permissions == "0o644"
        assert nf.fix_type == "ssh_harden"

    def test_env_var_normalization(self):
        nf = normalize_finding(_env_var_finding())
        assert nf.variable == "GH_TOKEN"
        assert nf.fix_type == "env_var_trace"

    def test_unknown_category_gets_generic(self):
        raw = {
            "category": "future_category",
            "path": "/some/path",
            "severity": "medium",
            "description": "Something new",
            "remediation": "Handle it.",
            "details": {},
        }
        nf = normalize_finding(raw)
        assert nf.fix_type == "generic"

    def test_category_filter(self):
        raw_findings = [
            _env_finding(),
            _ssh_finding(),
            _env_var_finding(),
        ]
        results = normalize_all(
            raw_findings, category_filter="ssh_keys"
        )
        assert len(results) == 1
        assert results[0].category == "ssh_keys"

    def test_no_filter_returns_all(self):
        raw_findings = [_env_finding(), _ssh_finding()]
        results = normalize_all(raw_findings)
        assert len(results) == 2


# ── Project and area detection ───────────────────────────────────────


class TestProjectDetection:
    def test_git_repo_detected(self, tmp_path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        env_file = repo / ".env"
        env_file.touch()
        root = detect_project_root(str(env_file))
        assert root == str(repo)

    def test_nested_file_finds_repo(self, tmp_path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        sub = repo / "src" / "config"
        sub.mkdir(parents=True)
        env_file = sub / ".env.local"
        env_file.touch()
        root = detect_project_root(str(env_file))
        assert root == str(repo)

    def test_project_marker_fallback(self, tmp_path):
        repo = tmp_path / "jsproject"
        repo.mkdir()
        (repo / "package.json").touch()
        env_file = repo / ".env"
        env_file.touch()
        root = detect_project_root(str(env_file))
        assert root == str(repo)

    def test_no_project_returns_none(self, tmp_path):
        loose = tmp_path / "loose"
        loose.mkdir()
        f = loose / "somefile"
        f.touch()
        root = detect_project_root(str(f))
        assert root is None


class TestWorkAreaDetection:
    def test_env_prefix_is_standalone(self):
        root, wtype, slug = detect_work_area("env:GH_TOKEN")
        assert wtype == "standalone"
        assert slug == "runtime-environment"

    def test_repo_detected(self, tmp_path):
        repo = tmp_path / "myapp"
        repo.mkdir()
        (repo / ".git").mkdir()
        env_file = repo / ".env"
        env_file.touch()
        root, wtype, slug = detect_work_area(str(env_file))
        assert root == str(repo)
        assert wtype == "repo"
        assert slug == "myapp"

    def test_ssh_logical_area(self):
        home = str(Path.home())
        ssh_path = os.path.join(home, ".ssh", "id_rsa")
        # Only test if .ssh exists (which it should on dev boxes).
        if os.path.isdir(os.path.join(home, ".ssh")):
            root, wtype, slug = detect_work_area(ssh_path)
            assert wtype == "standalone"
            assert slug == "ssh"

    def test_gcloud_logical_area(self):
        home = str(Path.home())
        gcloud_path = os.path.join(
            home, ".config", "gcloud", "credentials.json"
        )
        gcloud_dir = os.path.join(home, ".config", "gcloud")
        if os.path.isdir(gcloud_dir):
            root, wtype, slug = detect_work_area(gcloud_path)
            assert wtype == "standalone"
            assert slug == "gcloud-credentials"

    def test_fallback_uses_parent(self, tmp_path):
        loose = tmp_path / "randomdir"
        loose.mkdir()
        f = loose / "somefile.txt"
        f.touch()
        root, wtype, slug = detect_work_area(str(f))
        assert wtype == "standalone"
        assert root == str(loose)


# ── Work unit grouping ───────────────────────────────────────────────


class TestGrouping:
    def test_same_repo_grouped(self, tmp_path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".env").touch()
        (repo / "config.env").touch()

        findings = normalize_all(
            [
                _env_finding(
                    str(repo / ".env"), ["KEY_A"]
                ),
                _env_finding(
                    str(repo / "config.env"), ["KEY_B"]
                ),
            ]
        )
        units = group_into_work_units(findings)
        assert len(units) == 1
        assert units[0].work_type == "repo"
        assert len(units[0].findings) == 2

    def test_different_repos_separate(self, tmp_path):
        for name in ("repo-a", "repo-b"):
            repo = tmp_path / name
            repo.mkdir()
            (repo / ".git").mkdir()
            (repo / ".env").touch()

        findings = normalize_all(
            [
                _env_finding(
                    str(tmp_path / "repo-a" / ".env"), ["A"]
                ),
                _env_finding(
                    str(tmp_path / "repo-b" / ".env"), ["B"]
                ),
            ]
        )
        units = group_into_work_units(findings)
        assert len(units) == 2

    def test_severity_ordering(self, tmp_path):
        repo_hi = tmp_path / "hi"
        repo_hi.mkdir()
        (repo_hi / ".git").mkdir()
        (repo_hi / ".env").touch()

        repo_lo = tmp_path / "lo"
        repo_lo.mkdir()
        (repo_lo / ".git").mkdir()
        (repo_lo / ".env").touch()

        hi_finding = _env_finding(
            str(repo_hi / ".env"), ["X"]
        )
        lo_finding = _env_finding(
            str(repo_lo / ".env"), ["Y"]
        )
        lo_finding["severity"] = "low"

        findings = normalize_all([lo_finding, hi_finding])
        units = group_into_work_units(findings)
        assert units[0].severity == "high"
        assert units[1].severity == "low"

    def test_sequential_ids_assigned(self, tmp_path):
        for name in ("a", "b", "c"):
            repo = tmp_path / name
            repo.mkdir()
            (repo / ".git").mkdir()
            (repo / ".env").touch()

        findings = normalize_all(
            [
                _env_finding(
                    str(tmp_path / name / ".env"), ["K"]
                )
                for name in ("a", "b", "c")
            ]
        )
        units = group_into_work_units(findings)
        assert len(units) == 3
        ids = [u.id for u in units]
        assert ids[0].startswith("001-")
        assert ids[1].startswith("002-")
        assert ids[2].startswith("003-")

    def test_env_var_findings_grouped(self):
        findings = normalize_all(
            [
                _env_var_finding("KEY_A"),
                _env_var_finding("KEY_B"),
            ]
        )
        units = group_into_work_units(findings)
        # Both env: paths resolve to the same area
        # (home dir / runtime-environment).
        assert len(units) == 1
        assert units[0].label == "runtime-environment"

    def test_distinct_standalone_areas_not_merged(self):
        """env: findings and shell profile findings both resolve
        to $HOME, but must remain separate work units."""
        home = str(Path.home())
        zshrc_path = os.path.join(home, ".zshrc")
        findings = normalize_all(
            [
                _env_var_finding("GH_TOKEN"),
                _shell_profile_finding(
                    path=zshrc_path,
                    variable="AWS_SECRET_ACCESS_KEY",
                ),
            ]
        )
        units = group_into_work_units(findings)
        labels = sorted(u.label for u in units)
        assert "runtime-environment" in labels
        assert "shell-profiles" in labels
        assert len(units) == 2


# ── Subtask section compilation ──────────────────────────────────────


class TestSubtaskSections:
    def test_env_rewrite_section(self):
        nfs = [
            normalize_finding(
                _env_finding("/project/.env", ["SECRET_KEY"])
            )
        ]
        enrichment = {
            "SECRET_KEY": OpMatch(status="missing")
        }
        md = compile_subtask_section(
            1, "env_rewrite", nfs, enrichment
        )
        assert "### 1." in md
        assert "SECRET_KEY" in md
        assert "**1Password status**" in md
        assert "**What to do**" in md
        assert "op run --env-file" in md

    def test_env_rewrite_with_exact_match(self):
        nfs = [
            normalize_finding(
                _env_finding("/project/.env", ["API_KEY"])
            )
        ]
        enrichment = {
            "API_KEY": OpMatch(
                status="exact",
                vault="Development",
                item_title="My API Key",
                field_name="credential",
                reference=(
                    "op://Development/My API Key/credential"
                ),
            )
        }
        md = compile_subtask_section(
            1, "env_rewrite", nfs, enrichment
        )
        assert "**FOUND**" in md
        assert "op://Development/My API Key/credential" in md

    def test_profile_rewrite_section(self):
        nfs = [
            normalize_finding(_shell_profile_finding())
        ]
        enrichment = {
            "AWS_SECRET_ACCESS_KEY": OpMatch(status="missing")
        }
        md = compile_subtask_section(
            1, "profile_rewrite", nfs, enrichment
        )
        assert "### 1." in md
        assert "Remove secrets from" in md
        assert "AWS_SECRET_ACCESS_KEY" in md
        assert "**What to do**" in md

    def test_env_var_trace_section(self):
        nfs = [
            normalize_finding(_env_var_finding("GH_TOKEN"))
        ]
        enrichment = {
            "GH_TOKEN": OpMatch(status="missing")
        }
        md = compile_subtask_section(
            1, "env_var_trace", nfs, enrichment
        )
        assert "### 1." in md
        assert "GH_TOKEN" in md
        assert "**What to investigate**" in md

    def test_ssh_harden_section(self):
        nfs = [normalize_finding(_ssh_finding())]
        enrichment = {}
        md = compile_subtask_section(
            1, "ssh_harden", nfs, enrichment
        )
        assert "### 1." in md
        assert "chmod 600" in md
        assert "ssh-keygen -p" in md
        assert "ssh-add --apple-use-keychain" in md

    def test_ssh_encrypted_skips_passphrase(self):
        nfs = [
            normalize_finding(
                _ssh_finding(encrypted=True, permissions="0o644")
            )
        ]
        md = compile_subtask_section(
            1, "ssh_harden", nfs, {}
        )
        assert "chmod 600" in md
        assert "ssh-keygen -p" not in md

    def test_ssh_good_permissions_skips_chmod(self):
        nfs = [
            normalize_finding(
                _ssh_finding(
                    encrypted=False, permissions="0o600"
                )
            )
        ]
        md = compile_subtask_section(
            1, "ssh_harden", nfs, {}
        )
        assert "chmod 600" not in md
        assert "ssh-keygen -p" in md

    def test_incident_response_section(self):
        nfs = [normalize_finding(_teampcp_finding())]
        md = compile_subtask_section(
            1, "incident_response", nfs, {}
        )
        assert "CRITICAL" in md
        assert "Isolate" in md
        assert "Do not attempt automated remediation" in md

    def test_generic_section(self):
        raw = {
            "category": "crypto_wallets",
            "path": "/wallets/bitcoin",
            "severity": "high",
            "description": "Wallet found",
            "remediation": "Encrypt the wallet.",
            "details": {},
        }
        nfs = [normalize_finding(raw)]
        md = compile_subtask_section(
            1, "wallet_secure", nfs, {}
        )
        assert "crypto_wallets" in md
        assert "Encrypt the wallet." in md


# ── Task file compilation ────────────────────────────────────────────


class TestTaskFile:
    def test_task_file_has_required_sections(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["SECRET_KEY"])]
        )
        md = compile_task_file(unit)
        assert "# Task 001-high-test" in md
        assert "## Working directory" in md
        assert "## Scope" in md
        assert "## Findings" in md
        assert "## Subtasks" in md
        assert "## Constraints" in md
        assert "## Verification" in md
        assert "## Pack status" in md

    def test_repo_scope_message(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])],
            work_type="repo",
            label="myapp",
        )
        md = compile_task_file(unit)
        assert "`myapp` repository" in md

    def test_standalone_scope_message(self):
        unit = _make_work_unit(
            [_ssh_finding()],
            work_type="standalone",
            label="ssh",
            root_path="/Users/test/.ssh",
        )
        md = compile_task_file(unit)
        assert "`ssh` configuration area" in md

    def test_incident_response_task(self):
        unit = _make_work_unit(
            [_teampcp_finding()],
            unit_id="001-critical-ioc",
        )
        md = compile_task_file(unit)
        assert "CRITICAL" in md
        assert "IMMEDIATE HUMAN ACTION" in md
        assert "Do not use automated remediation" in md
        assert _is_incident_response(unit)

    def test_normal_unit_not_incident_response(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        assert not _is_incident_response(unit)

    def test_verification_uses_json_not_scan_path(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        md = compile_task_file(unit)
        assert "clawback.py --json" in md
        assert "--scan-path" not in md

    def test_verification_lists_affected_paths(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        md = compile_task_file(unit)
        assert "`/project/.env`" in md

    def test_multi_subtask_task(self):
        unit = _make_work_unit(
            [
                _env_finding("/project/.env", ["SECRET"]),
                _ssh_finding("/project/deploy_key"),
            ]
        )
        md = compile_task_file(unit)
        assert "### 1." in md
        assert "### 2." in md


# ── Pack compilation ─────────────────────────────────────────────────


class TestPackCompilation:
    def test_index_contains_queue(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        report = _minimal_report(
            [_env_finding("/project/.env", ["K"])]
        )
        md = compile_index([unit], report, "/tmp/pack")
        assert "# Remediation Pack" in md
        assert "## Scan Summary" in md
        assert "## Execution Queue" in md
        assert "- [ ]" in md
        assert "001-high-test" in md
        assert "tasks/" in md
        assert "launch/" in md

    def test_index_no_scan_path_flag(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        report = _minimal_report(
            [_env_finding("/project/.env", ["K"])]
        )
        md = compile_index([unit], report, "/tmp/pack")
        assert "--scan-path" not in md
        assert "clawback.py --json" in md

    def test_index_ir_unit_has_no_launcher(self):
        unit = _make_work_unit(
            [_teampcp_finding()],
            unit_id="001-critical-ioc",
        )
        report = _minimal_report([_teampcp_finding()])
        md = compile_index([unit], report, "/tmp/pack")
        assert "Human-only" in md
        assert "no agent launcher" in md
        assert "launch/001-critical-ioc-claude.sh" not in md

    def test_index_severity_counts(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        report = _minimal_report(
            [_env_finding("/project/.env", ["K"])]
        )
        md = compile_index([unit], report, "/tmp/pack")
        assert "1 high" in md

    def test_metadata_contains_provenance(self):
        report = _minimal_report([_env_finding()])
        md = compile_metadata(report, "/path/to/scan.json")
        assert "# Pack Metadata" in md
        assert "testhost" in md
        assert "testuser" in md
        assert "2026-01-01T00:00:00Z" in md
        assert "scan.json" in md
        assert "Staleness Warning" in md

    def test_metadata_without_input_path(self):
        report = _minimal_report()
        md = compile_metadata(report, None)
        assert "Input" not in md

    def test_claude_launcher_content(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        sh = compile_claude_launcher(unit, "/tmp/pack")
        assert "#!/usr/bin/env bash" in sh
        assert 'cd "/project"' in sh
        assert "claude -p" in sh
        assert "001-high-test.md" in sh

    def test_codex_launcher_content(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        sh = compile_codex_launcher(unit, "/tmp/pack")
        assert "codex -p" in sh


# ── Pack generation ──────────────────────────────────────────────────


class TestPackGeneration:
    def test_pack_creates_directory_layout(self, tmp_path):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        report = _minimal_report(
            [_env_finding("/project/.env", ["K"])]
        )
        out = tmp_path / "pack"
        pack_path = generate_pack(
            [unit], report, str(out), "/scan.json"
        )

        assert (out / "index.md").exists()
        assert (out / "metadata.md").exists()
        assert (out / "tasks").is_dir()
        assert (out / "launch").is_dir()

    def test_pack_creates_task_files(self, tmp_path):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        report = _minimal_report(
            [_env_finding("/project/.env", ["K"])]
        )
        out = tmp_path / "pack"
        generate_pack([unit], report, str(out), None)

        tasks = list((out / "tasks").iterdir())
        assert len(tasks) == 1
        assert tasks[0].name == "001-high-test.md"

        content = tasks[0].read_text()
        assert "# Task 001-high-test" in content

    def test_pack_creates_launcher_scripts(self, tmp_path):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        report = _minimal_report(
            [_env_finding("/project/.env", ["K"])]
        )
        out = tmp_path / "pack"
        generate_pack([unit], report, str(out), None)

        launchers = sorted((out / "launch").iterdir())
        assert len(launchers) == 2
        names = [l.name for l in launchers]
        assert "001-high-test-claude.sh" in names
        assert "001-high-test-codex.sh" in names

        # Verify executable bits.
        for launcher in launchers:
            assert launcher.stat().st_mode & 0o100

    def test_pack_with_multiple_units(self, tmp_path):
        unit_a = _make_work_unit(
            [_env_finding("/project-a/.env", ["A"])],
            unit_id="001-high-a",
            label="a",
            root_path="/project-a",
        )
        unit_b = _make_work_unit(
            [_ssh_finding()],
            unit_id="002-high-b",
            label="b",
            root_path="/Users/test/.ssh",
            work_type="standalone",
        )
        report = _minimal_report(
            [_env_finding("/project-a/.env", ["A"]), _ssh_finding()]
        )
        out = tmp_path / "pack"
        generate_pack(
            [unit_a, unit_b], report, str(out), None
        )

        tasks = sorted((out / "tasks").iterdir())
        assert len(tasks) == 2
        launchers = sorted((out / "launch").iterdir())
        assert len(launchers) == 4

        index = (out / "index.md").read_text()
        assert "001-high-a" in index
        assert "002-high-b" in index

    def test_ir_unit_gets_task_but_no_launchers(
        self, tmp_path
    ):
        ir_unit = _make_work_unit(
            [_teampcp_finding()],
            unit_id="001-critical-ioc",
        )
        report = _minimal_report([_teampcp_finding()])
        out = tmp_path / "pack"
        generate_pack([ir_unit], report, str(out), None)

        # Task file must exist.
        assert (out / "tasks" / "001-critical-ioc.md").exists()
        # No launcher scripts for incident response.
        launchers = list((out / "launch").iterdir())
        assert len(launchers) == 0

    def test_mixed_ir_and_normal_units(self, tmp_path):
        ir_unit = _make_work_unit(
            [_teampcp_finding()],
            unit_id="001-critical-ioc",
        )
        normal_unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])],
            unit_id="002-high-project",
            label="project",
        )
        report = _minimal_report(
            [_teampcp_finding(), _env_finding()]
        )
        out = tmp_path / "pack"
        generate_pack(
            [ir_unit, normal_unit], report, str(out), None
        )

        tasks = sorted((out / "tasks").iterdir())
        assert len(tasks) == 2
        launchers = list((out / "launch").iterdir())
        launcher_names = [l.name for l in launchers]
        assert "001-critical-ioc-claude.sh" not in launcher_names
        assert "002-high-project-claude.sh" in launcher_names
        assert "002-high-project-codex.sh" in launcher_names

    def test_default_pack_dir_is_timestamped(self):
        d = default_pack_dir()
        assert d.startswith("tmp/restitution-packs/")
        parts = d.split("/")
        timestamp = parts[-1]
        assert len(timestamp) == 15  # YYYYMMDD-HHMMSS


# ── 1Password enrichment ────────────────────────────────────────────


class TestEnrichment:
    def test_dry_run_skips_subprocess(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        # Clear enrichment so we can verify it gets populated.
        unit.enrichment.clear()
        with patch(
            "restitution.subprocess.run"
        ) as mock_run:
            enrich_work_units(
                [unit], vault=None, dry_run=True
            )
            mock_run.assert_not_called()
        assert "K" in unit.enrichment
        assert unit.enrichment["K"].status == "missing"

    def test_op_unavailable_uses_placeholders(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        unit.enrichment.clear()
        with patch(
            "restitution.shutil.which",
            return_value=None,
        ):
            enrich_work_units(
                [unit], vault=None, dry_run=False
            )
        assert unit.enrichment["K"].status == "missing"

    def test_op_unauthenticated_uses_placeholders(self):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        unit.enrichment.clear()
        with patch(
            "restitution.check_op_available",
            return_value=True,
        ), patch(
            "restitution.check_op_authenticated",
            return_value=False,
        ):
            enrich_work_units(
                [unit], vault=None, dry_run=False
            )
        assert unit.enrichment["K"].status == "missing"


# ── Stdout summary ───────────────────────────────────────────────────


class TestSummary:
    def test_summary_is_concise(self, capsys):
        from restitution import print_pack_summary

        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        findings = [normalize_finding(_env_finding())]
        print_pack_summary(
            "/tmp/pack", [unit], findings,
            op_available=False, op_authenticated=False,
        )
        err = capsys.readouterr().err
        assert "clawback-restitution" in err
        assert "1 finding" in err
        assert "1 task" in err
        assert "/tmp/pack" in err


# ── Legacy combined mode ─────────────────────────────────────────────


class TestCombinedMode:
    def test_combined_output(self, capsys):
        unit = _make_work_unit(
            [_env_finding("/project/.env", ["K"])]
        )
        write_combined([unit])
        out = capsys.readouterr().out
        assert "# Clawback Remediation Prompts" in out
        assert "---" in out
        assert "# Task 001-high-test" in out


# ── CLI integration ──────────────────────────────────────────────────


class TestCLI:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            build_parser().parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_full_pipeline_pack_mode(self, tmp_path):
        """Default mode generates a pack on disk."""
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".env").write_text("SECRET=value")

        report = _minimal_report(
            [_env_finding(str(repo / ".env"), ["SECRET"])]
        )
        scan = tmp_path / "scan.json"
        scan.write_text(json.dumps(report))

        out_dir = tmp_path / "pack"
        rc = main(
            [
                "--input", str(scan),
                "--dry-run",
                "--output-dir", str(out_dir),
            ]
        )
        assert rc == 0
        assert (out_dir / "index.md").exists()
        assert (out_dir / "metadata.md").exists()
        assert (out_dir / "tasks").is_dir()
        assert (out_dir / "launch").is_dir()

    def test_combined_mode_via_main(self, tmp_path, capsys):
        report = _minimal_report(
            [
                _env_finding("/project/.env", ["K"]),
                _ssh_finding(),
            ]
        )
        p = tmp_path / "scan.json"
        p.write_text(json.dumps(report))
        rc = main(
            [
                "--input", str(p),
                "--dry-run",
                "--combined",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "# Clawback Remediation Prompts" in out

    def test_category_filter_via_main(self, tmp_path, capsys):
        report = _minimal_report(
            [_env_finding(), _ssh_finding()]
        )
        p = tmp_path / "scan.json"
        p.write_text(json.dumps(report))
        out_dir = tmp_path / "pack"
        rc = main(
            [
                "--input", str(p),
                "--dry-run",
                "--category", "ssh_keys",
                "--output-dir", str(out_dir),
            ]
        )
        assert rc == 0
        tasks = list((out_dir / "tasks").iterdir())
        assert len(tasks) == 1
        content = tasks[0].read_text()
        assert "SSH key" in content

    def test_empty_findings_exits_clean(self, tmp_path):
        report = _minimal_report()
        p = tmp_path / "scan.json"
        p.write_text(json.dumps(report))
        rc = main(["--input", str(p), "--dry-run"])
        assert rc == 0
