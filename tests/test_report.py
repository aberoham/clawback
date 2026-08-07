"""Tests for report structure and JAMF EA line formatting."""
from __future__ import annotations

from rattlesnake import Severity, build_report, jamf_ea_line


class TestBuildReport:
    def test_all_required_keys(self, scan_ctx):
        report = build_report(scan_ctx)
        required = {
            "scanner_version", "hostname", "username", "platform",
            "python_version", "timestamp", "scan_duration_seconds",
            "findings", "observations", "summary", "total_findings",
            "op_cli_available", "errors",
            # Added so a consumer can tell an absent finding from an unscanned
            # category; antivenom refuses to emit rotation launchers when
            # persistence was not covered.
            "scan_scope",
        }
        assert set(report.keys()) == required

    def test_scan_scope_shape(self, scan_ctx):
        report = build_report(scan_ctx)
        scope = report["scan_scope"]

        assert isinstance(scope["categories_scanned"], list)
        assert isinstance(scope["categories_available"], list)
        assert isinstance(scope["complete"], bool)
        # build_report() alone runs no scanners, so nothing is covered yet.
        assert scope["categories_scanned"] == []
        assert scope["complete"] is False

    def test_summary_counts_match_findings(self, scan_ctx):
        scan_ctx.add("cat", "p", Severity.CRITICAL, "d", "r")
        scan_ctx.add("cat", "p", Severity.HIGH, "d", "r")
        scan_ctx.add("cat", "p", Severity.HIGH, "d", "r")
        scan_ctx.add("cat", "p", Severity.LOW, "d", "r")
        report = build_report(scan_ctx)
        assert report["summary"]["critical"] == 1
        assert report["summary"]["high"] == 2
        assert report["summary"]["medium"] == 0
        assert report["summary"]["low"] == 1
        assert report["total_findings"] == 4
        assert report["total_findings"] == len(report["findings"])

    def test_empty_report(self, scan_ctx):
        report = build_report(scan_ctx)
        assert report["total_findings"] == 0
        assert report["findings"] == []
        assert report["errors"] == []


class TestJamfEaLine:
    def test_with_findings(self):
        result = jamf_ea_line(
            {"critical": 1, "high": 2, "medium": 0, "low": 3}, 6
        )
        assert result == (
            "<result>CRITICAL:1 HIGH:2 MEDIUM:0 LOW:3 TOTAL:6</result>"
        )

    def test_zero_findings(self):
        result = jamf_ea_line(
            {"critical": 0, "high": 0, "medium": 0, "low": 0}, 0
        )
        assert result == (
            "<result>CRITICAL:0 HIGH:0 MEDIUM:0 LOW:0 TOTAL:0</result>"
        )
