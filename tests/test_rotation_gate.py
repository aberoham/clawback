"""antivenom's rotation-order interlock.

The 2026-08 watcher's handler fires when the stolen token stops working, so
revoking a credential is the trigger rather than the fix. Every output path a
human might act on has to say so, and the gate has to fail closed when the
scan cannot prove a watcher is absent.
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import subprocess
import sys
import time

import pytest

import rattlesnake
from rattlesnake import ScanContext, build_report, run_all_scans
from antivenom import (
    _compile_incident_response_task,
    _is_generic_persistence,
    _is_incident_response,
    compile_index,
    compile_task_file,
    generate_pack,
    group_into_work_units,
    is_rotation_gated,
    live_persistence_findings,
    normalize_all,
    persistence_scan_incomplete,
    report_has_live_persistence,
    write_combined,
)

REPO = pathlib.Path(__file__).resolve().parent.parent

FULL_SCOPE = {
    "categories_scanned": ["malware_persistence", "package_manager_tokens",
                           "npm_supply_chain", "env_files"],
    "categories_available": ["malware_persistence", "package_manager_tokens",
                             "npm_supply_chain", "env_files"],
    "complete": True,
    "coverage_gaps": [],
}


def _finding(category, path, severity="critical", remediation="do it",
             details=None):
    return {
        "category": category, "path": path, "severity": severity,
        "description": f"{category} at {path}",
        "remediation": remediation, "details": details or {},
    }


def _report(findings, scope=None, errors=None):
    return {
        "scanner_version": "1.0.0", "hostname": "h", "username": "u",
        "findings": findings, "observations": [],
        "summary": {"critical": 1, "high": 1, "medium": 0, "low": 0},
        "total_findings": len(findings), "errors": errors or [],
        "scan_scope": FULL_SCOPE if scope is None else scope,
    }


def _units(report, category=None):
    return group_into_work_units(normalize_all(report["findings"], category))


WATCHER = _finding(
    "malware_persistence", "/Users/x/.config/gh-token-monitor/handler",
    remediation="ORDER MATTERS: kill the watcher first.",
    details={"campaign": "shai-hulud-2026-08"},
)
GENERIC_AGENT = _finding(
    "malware_persistence", "/Users/x/Library/LaunchAgents/com.mytool.plist",
    severity="medium",
    remediation="Verify this login item is expected.",
    details={"program": "/Users/x/.config/mytool/run.sh"},
)
NPMRC = _finding("package_manager_tokens", "/Users/x/.npmrc", "high",
                 remediation="use the keychain")
LOCKFILE = _finding("npm_supply_chain", "/Users/x/Projects/app/package-lock.json",
                    remediation="pin keyv back to 5.6.0")


class TestWhatCountsAsAWatcher:
    def test_campaign_detail_gates(self):
        assert is_rotation_gated(_units(_report([WATCHER])),
                                 _report([WATCHER])) is True

    def test_known_watcher_path_gates_without_the_detail(self):
        raw = dict(WATCHER, details={})
        assert is_rotation_gated(_units(_report([raw])), _report([raw])) is True

    def test_generic_login_item_does_not_gate(self):
        """A custom LaunchAgent must not withhold all remediation."""
        report = _report([GENERIC_AGENT, NPMRC])

        assert report_has_live_persistence(report) is False
        assert is_rotation_gated(_units(report), report) is False

    def test_only_watcher_findings_are_listed(self):
        report = _report([WATCHER, GENERIC_AGENT, NPMRC])

        found = live_persistence_findings(_units(report))

        assert len(found) == 1
        assert "gh-token-monitor" in found[0].path


class TestScanScopeClosesTheGate:
    def test_full_scan_reports_complete_scope(self, tmp_path):
        ctx = ScanContext(home=tmp_path, username="u", hostname="h",
                          start_time=time.monotonic())
        run_all_scans(ctx, quiet=True)

        scope = build_report(ctx)["scan_scope"]

        assert scope["complete"] is True
        assert "malware_persistence" in scope["categories_scanned"]

    def test_category_filtered_scan_reports_partial_scope(self, tmp_path):
        ctx = ScanContext(home=tmp_path, username="u", hostname="h",
                          start_time=time.monotonic())
        run_all_scans(ctx, quiet=True, category="package_manager_tokens")

        scope = build_report(ctx)["scan_scope"]

        assert scope["complete"] is False
        assert scope["categories_scanned"] == ["package_manager_tokens"]

    def test_crashed_category_is_not_counted_as_scanned(self, tmp_path, monkeypatch):
        def boom(ctx, quiet):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(rattlesnake, "ALL_SCANS",
                            [("malware_persistence", boom)])
        ctx = ScanContext(home=tmp_path, username="u", hostname="h",
                          start_time=time.monotonic())
        run_all_scans(ctx, quiet=True)

        assert build_report(ctx)["scan_scope"]["categories_scanned"] == []
        assert ctx.errors

    def test_unscanned_persistence_gates(self):
        """Silence is not safety: nothing looked for a watcher."""
        scope = dict(FULL_SCOPE, categories_scanned=["package_manager_tokens"],
                     complete=False)
        report = _report([NPMRC], scope=scope)

        assert persistence_scan_incomplete(report) is True
        assert is_rotation_gated(_units(report), report) is True

    @pytest.mark.parametrize("key", ["errors", "gaps"])
    def test_persistence_failure_gates_even_when_the_category_completed(self, key):
        """One unreadable plist means the scan cannot vouch for absence."""
        message = "malware_persistence: could not read a plist"
        if key == "errors":
            report = _report([NPMRC], errors=[message])
        else:
            report = _report([NPMRC],
                             scope=dict(FULL_SCOPE, coverage_gaps=[message]))

        assert persistence_scan_incomplete(report) is True

    def test_unrelated_failure_does_not_gate(self):
        report = _report([NPMRC], errors=["env_files: could not read something"])

        assert persistence_scan_incomplete(report) is False

    def test_report_without_scope_is_trusted(self):
        """Older reports predate the field; do not gate every one of them."""
        report = {
            "scanner_version": "0.9", "findings": [NPMRC], "observations": [],
            "summary": {}, "total_findings": 1, "errors": [],
        }

        assert persistence_scan_incomplete(report) is False
        assert is_rotation_gated(_units(report), report) is False

    def test_category_filter_cannot_hide_the_watcher(self):
        """Units alone cannot see it; the raw report can."""
        report = _report([WATCHER, NPMRC])
        filtered = _units(report, "package_manager_tokens")

        assert is_rotation_gated(filtered) is False
        assert is_rotation_gated(filtered, report) is True


class TestHumanOnlyUnits:
    @pytest.mark.parametrize("category", [
        "npm_supply_chain", "agent_autostart_hooks", "repo_worm_artifacts",
    ])
    def test_compromise_categories_are_incident_response(self, category):
        nf = normalize_all([_finding(category, f"/Users/x/{category}")])[0]

        assert nf.fix_type == "incident_response"

    def test_any_incident_member_makes_the_unit_human_only(self):
        """Units group by repository, so a mixed unit is normal."""
        report = _report([LOCKFILE,
                          _finding("env_files", "/Users/x/Projects/app/.env",
                                   "high")])
        mixed = [u for u in _units(report) if len(u.findings) > 1]
        assert mixed

        assert all(_is_incident_response(u) for u in mixed)

    def test_predicate_and_compiler_cannot_drift(self):
        """Whatever marks a unit human-only must pick the same compiler."""
        report = _report([LOCKFILE,
                          _finding("env_files", "/Users/x/Projects/app/.env",
                                   "high")])

        for unit in _units(report):
            task = compile_task_file(unit, "/tmp/pack")
            is_ir_task = "THIS TASK REQUIRES IMMEDIATE HUMAN ACTION" in task
            assert _is_incident_response(unit) == is_ir_task

    def test_generic_persistence_keeps_its_proportion(self):
        """A medium "verify this" finding is not a rebuild-the-host incident."""
        nf = normalize_all([GENERIC_AGENT])[0]

        assert _is_generic_persistence(nf) is True
        assert nf.fix_type == "verify_login_item"

        task = compile_task_file(group_into_work_units([nf])[0], "/tmp/pack")
        assert "Rebuild from a clean image" not in task
        assert "gh-token-monitor" not in task


class TestTaskContent:
    def test_watcher_task_puts_shutdown_before_rotation(self):
        unit = _units(_report([WATCHER]))[0]

        task = _compile_incident_response_task(unit)

        assert "before ANY credential rotation" in task
        assert "systemctl --user disable --now gh-token-monitor" in task
        assert "loginctl disable-linger" in task
        assert task.index("before ANY credential rotation") < task.index(
            "Rotate ALL credentials"
        )

    def test_scanner_remediation_text_survives(self):
        unit = _units(_report([WATCHER]))[0]

        assert "ORDER MATTERS" in _compile_incident_response_task(unit)

    def test_every_flagged_artifact_is_listed_for_deletion(self):
        paths = [
            "/Users/x/.config/gh-token-monitor/handler",
            "/tmp/tmp.dpkg_14527.lock",
            "/Users/x/.local/bin/gh-token-monitor.sh",
        ]
        report = _report([_finding("malware_persistence", p,
                                   details={"campaign": "shai-hulud-2026-08"})
                          for p in paths])

        for unit in _units(report):
            task = compile_task_file(unit, "/tmp/pack", pack_gated=True)
            for nf in unit.findings:
                assert f"`{nf.path}`" in task

    def test_non_persistence_incident_task_has_no_shutdown_block(self):
        unit = _units(_report([LOCKFILE]))[0]

        task = _compile_incident_response_task(unit)

        assert "before ANY credential rotation" not in task
        assert "systemctl --user disable" not in task
        assert "THIS TASK REQUIRES IMMEDIATE HUMAN ACTION" in task


class TestEveryOutputPathIsGated:
    def test_all_task_files_carry_the_notice(self, tmp_path):
        """Persistence in its own unit must still warn the other tasks."""
        report = _report([WATCHER, LOCKFILE, NPMRC])
        units = _units(report)
        assert len(units) > 1

        generate_pack(units, report, str(tmp_path / "pack"), None)

        tasks = list((tmp_path / "pack" / "tasks").glob("*.md"))
        assert tasks
        for task in tasks:
            assert "STOP" in task.read_text(), f"{task.name} lacks the notice"

    def test_index_carries_the_banner(self, tmp_path):
        report = _report([WATCHER, NPMRC])

        index = compile_index(_units(report), report, str(tmp_path))

        assert "STOP" in index
        assert "gh-token-monitor" in index
        assert "on revocation" in index

    def test_combined_mode_is_gated(self):
        """main() returns through write_combined without generate_pack."""
        report = _report([WATCHER, NPMRC])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            write_combined(_units(report), report_data=report)

        out = buf.getvalue()
        assert "STOP" in out and "gh-token-monitor" in out

    def test_combined_mode_gated_under_a_category_filter(self):
        report = _report([WATCHER, NPMRC])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            write_combined(_units(report, "package_manager_tokens"),
                           report_data=report)

        assert "STOP" in buf.getvalue()

    def test_clean_pack_has_no_notice_and_keeps_launchers(self, tmp_path):
        report = _report([NPMRC])

        generate_pack(_units(report), report, str(tmp_path / "pack"), None)

        index = (tmp_path / "pack" / "index.md").read_text()
        assert "STOP" not in index
        assert list((tmp_path / "pack" / "launch").glob("*.sh"))

    def test_incomplete_scan_notice_states_the_real_reason(self, tmp_path):
        """It previously claimed a watcher was found and pointed nowhere."""
        scope = dict(FULL_SCOPE, categories_scanned=["package_manager_tokens"],
                     complete=False)
        report = _report([NPMRC], scope=scope)

        generate_pack(_units(report), report, str(tmp_path / "pack"), None)

        task = next((tmp_path / "pack" / "tasks").glob("*.md")).read_text()
        assert "did not check for malware persistence" in task
        assert "was found elsewhere" not in task
        assert "rattlesnake.py --pretty" in task


class TestLaunchersAndStaleFiles:
    def test_no_launchers_while_gated(self, tmp_path):
        report = _report([WATCHER, NPMRC])

        generate_pack(_units(report), report, str(tmp_path / "pack"), None)

        assert list((tmp_path / "pack" / "launch").glob("*.sh")) == []

    def test_clearing_the_watcher_restores_launchers(self, tmp_path):
        pack = tmp_path / "pack"
        infected = _report([WATCHER, NPMRC])
        generate_pack(_units(infected), infected, str(pack), None)
        assert list((pack / "launch").glob("*.sh")) == []

        cleaned = _report([NPMRC])
        generate_pack(_units(cleaned), cleaned, str(pack), None)

        assert list((pack / "launch").glob("*.sh"))

    def test_unit_becoming_human_only_loses_its_launcher(self, tmp_path):
        """Same generated ID, now incident response: the old script must go."""
        pack = tmp_path / "pack"
        clean = _report([NPMRC])
        generate_pack(_units(clean), clean, str(pack), None)
        assert list((pack / "launch").glob("*.sh"))

        ir = _report([LOCKFILE])
        assert is_rotation_gated(_units(ir), ir) is False
        generate_pack(_units(ir), ir, str(pack), None)

        assert list((pack / "launch").glob("*.sh")) == []

    def test_obsolete_task_file_is_removed(self, tmp_path):
        pack = tmp_path / "pack"
        first = _report([NPMRC])
        generate_pack(_units(first), first, str(pack), None)
        before = {p.name for p in (pack / "tasks").glob("*.md")}

        second = _report([WATCHER])
        generate_pack(_units(second), second, str(pack), None)
        after = {p.name for p in (pack / "tasks").glob("*.md")}

        assert before - after
        for name in after:
            assert "STOP" in (pack / "tasks" / name).read_text()

    @pytest.mark.parametrize("subdir,marker", [
        ("launch", "stale launchers"),
        ("tasks", "stale task files"),
    ])
    def test_uncleanable_directory_aborts_generation(self, tmp_path, subdir, marker):
        """Better to fail loudly than ship a pack that misreports itself."""
        pack = tmp_path / "pack"
        (pack / "launch").mkdir(parents=True)
        (pack / "tasks").mkdir()
        if subdir == "launch":
            stale = pack / "launch/001-old-claude.sh"
            stale.write_text("#!/bin/sh\necho rotate\n")
        else:
            stale = pack / "tasks/999-old-task.md"
            stale.write_text("# obsolete\nRotate ALL credentials first.\n")
        (pack / subdir).chmod(0o500)

        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(_report([NPMRC])))

        try:
            result = subprocess.run(
                [sys.executable, str(REPO / "antivenom.py"),
                 "-i", str(report_path), "--output-dir", str(pack)],
                capture_output=True, text=True, cwd=str(REPO),
            )
            assert result.returncode != 0
            assert marker in result.stderr
        finally:
            (pack / subdir).chmod(0o700)
