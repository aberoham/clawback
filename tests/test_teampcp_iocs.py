"""Tests for TeamPCP/CanisterWorm IoC detection."""
from __future__ import annotations

import pathlib
import sys

import pytest

import clawback
from clawback import scan_teampcp_iocs


def _null_run_cmd(*args, **kwargs):
    return None


@pytest.fixture
def redirect_tmp(tmp_path, monkeypatch):
    """Redirect /tmp IoC checks to tmp_path-based paths.

    scan_teampcp_iocs hardcodes /tmp/pglog, /tmp/.pg_state, etc.
    This fixture intercepts Path.exists() to redirect those checks
    to a subdirectory of tmp_path, avoiding side effects outside tmp_path.
    """
    fake_tmp = tmp_path / "fake_tmp"
    fake_tmp.mkdir()

    original_exists = pathlib.Path.exists

    def patched_exists(self):
        s = str(self)
        if s.startswith("/tmp/"):
            return original_exists(fake_tmp / s[5:])
        return original_exists(self)

    monkeypatch.setattr(pathlib.Path, "exists", patched_exists)
    return fake_tmp


# -------------------------------------------------------------------
# File-based IoCs
# -------------------------------------------------------------------


class TestTeamPCPFileIoCs:
    def test_pgmon_directory(self, scan_ctx, monkeypatch, clean_env):
        monkeypatch.setattr(clawback, "run_cmd", _null_run_cmd)
        pgmon = scan_ctx.home / ".local" / "share" / "pgmon"
        pgmon.mkdir(parents=True)
        scan_teampcp_iocs(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings if "pgmon" in f.description.lower()
        ]
        assert len(findings) >= 1
        assert all(f.severity == "critical" for f in findings)

    def test_pgmon_service_py(self, scan_ctx, monkeypatch, clean_env):
        monkeypatch.setattr(clawback, "run_cmd", _null_run_cmd)
        pgmon = scan_ctx.home / ".local" / "share" / "pgmon"
        pgmon.mkdir(parents=True)
        (pgmon / "service.py").write_text("# malicious")
        scan_teampcp_iocs(scan_ctx, quiet=True)
        # Both the directory and file are IoCs.
        assert len(scan_ctx.findings) >= 2

    def test_tmp_pglog(
        self, scan_ctx, monkeypatch, redirect_tmp, clean_env
    ):
        monkeypatch.setattr(clawback, "run_cmd", _null_run_cmd)
        (redirect_tmp / "pglog").write_text("log data")
        scan_teampcp_iocs(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings if "pglog" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_tpcp_tar_in_home(self, scan_ctx, monkeypatch, clean_env):
        monkeypatch.setattr(clawback, "run_cmd", _null_run_cmd)
        (scan_ctx.home / "tpcp.tar.gz").write_text("fake")
        scan_teampcp_iocs(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings if "tpcp" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"


# -------------------------------------------------------------------
# LaunchAgent detection
# -------------------------------------------------------------------


class TestTeamPCPLaunchAgents:
    def test_plist_with_marker_in_content(
        self, scan_ctx, monkeypatch, clean_env
    ):
        monkeypatch.setattr(clawback, "run_cmd", _null_run_cmd)
        la_dir = scan_ctx.home / "Library" / "LaunchAgents"
        la_dir.mkdir(parents=True)
        plist = la_dir / "com.example.agent.plist"
        plist.write_text(
            '<?xml version="1.0"?>\n'
            "<plist>\n"
            "  <string>https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"
            "</string>\n"
            "</plist>\n"
        )
        scan_teampcp_iocs(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "launchagent" in f.description.lower()
        ]
        assert len(findings) >= 1
        assert all(f.severity == "critical" for f in findings)

    def test_plist_with_marker_in_name(
        self, scan_ctx, monkeypatch, clean_env
    ):
        monkeypatch.setattr(clawback, "run_cmd", _null_run_cmd)
        la_dir = scan_ctx.home / "Library" / "LaunchAgents"
        la_dir.mkdir(parents=True)
        (la_dir / "com.pgmon.agent.plist").write_text("<plist/>")
        scan_teampcp_iocs(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "launchagent" in f.description.lower()
        ]
        assert len(findings) >= 1

    def test_clean_plist_no_finding(
        self, scan_ctx, monkeypatch, clean_env
    ):
        monkeypatch.setattr(clawback, "run_cmd", _null_run_cmd)
        la_dir = scan_ctx.home / "Library" / "LaunchAgents"
        la_dir.mkdir(parents=True)
        (la_dir / "com.apple.something.plist").write_text(
            "<plist><string>normal content</string></plist>"
        )
        scan_teampcp_iocs(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0


# -------------------------------------------------------------------
# Process check
# -------------------------------------------------------------------


class TestTeamPCPProcessCheck:
    def test_pgmon_in_ps_output(
        self, scan_ctx, monkeypatch, clean_env
    ):
        def fake_run_cmd(args, timeout=5):
            if args == ["ps", "aux"]:
                return (
                    "USER  PID %CPU\n"
                    "user  1234  0.0 pgmon --exfiltrate\n"
                )
            return None

        monkeypatch.setattr(clawback, "run_cmd", fake_run_cmd)
        scan_teampcp_iocs(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "pgmon process" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_clean_ps_output(self, scan_ctx, monkeypatch, clean_env):
        def fake_run_cmd(args, timeout=5):
            if args == ["ps", "aux"]:
                return "USER  PID %CPU\nroot  1  0.0 /sbin/init\n"
            return None

        monkeypatch.setattr(clawback, "run_cmd", fake_run_cmd)
        scan_teampcp_iocs(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0


# -------------------------------------------------------------------
# Site-packages: litellm_init.pth
# -------------------------------------------------------------------


class TestTeamPCPSitePackages:
    def test_litellm_init_pth(
        self, scan_ctx, monkeypatch, tmp_path, clean_env
    ):
        site_dir = tmp_path / "site-packages"
        site_dir.mkdir()
        (site_dir / "litellm_init.pth").write_text("import os")

        def fake_run_cmd(args, timeout=5):
            if (
                len(args) >= 3
                and args[0] == sys.executable
                and "site" in args[2]
            ):
                return str(site_dir) + "\n"
            return None

        monkeypatch.setattr(clawback, "run_cmd", fake_run_cmd)
        scan_teampcp_iocs(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "litellm_init" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"
