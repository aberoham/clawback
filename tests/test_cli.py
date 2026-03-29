"""Tests for argument parsing, exit codes, and main() integration."""
from __future__ import annotations

import json
import pathlib

import clawback
from clawback import main, parse_args


# -------------------------------------------------------------------
# parse_args
# -------------------------------------------------------------------


class TestParseArgs:
    def test_defaults(self):
        args = parse_args([])
        assert args.pretty is False
        assert args.quiet is False
        assert args.category is None
        assert args.audit_env is False
        assert args.training is False
        assert args.output_file is None

    def test_pretty(self):
        assert parse_args(["--pretty"]).pretty is True

    def test_quiet(self):
        assert parse_args(["--quiet"]).quiet is True

    def test_category(self):
        args = parse_args(["--category", "teampcp_iocs"])
        assert args.category == "teampcp_iocs"

    def test_output_file(self):
        args = parse_args(["--output-file", "/tmp/out.json"])
        assert args.output_file == "/tmp/out.json"

    def test_training_does_not_set_audit_at_parse_time(self):
        """--training sets training=True; main() handles the implication."""
        args = parse_args(["--training"])
        assert args.training is True
        assert args.audit_env is False

    def test_audit_env(self):
        assert parse_args(["--audit-env"]).audit_env is True


# -------------------------------------------------------------------
# main() integration
# -------------------------------------------------------------------


class TestMainIntegration:
    def _patch_main(self, monkeypatch, tmp_path):
        """Common patches: redirect home, suppress subprocesses."""
        monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr(
            clawback, "run_cmd", lambda *a, **kw: None
        )

    def test_clean_home_exit_0(self, tmp_path, monkeypatch, clean_env):
        self._patch_main(monkeypatch, tmp_path)
        code = main(["--quiet"])
        assert code == 0

    def test_findings_exit_1(self, tmp_path, monkeypatch, clean_env):
        self._patch_main(monkeypatch, tmp_path)
        aws = tmp_path / ".aws"
        aws.mkdir()
        (aws / "credentials").write_text(
            "[default]\naws_access_key_id = AKIA...\n"
        )
        code = main(["--quiet"])
        assert code == 1

    def test_scan_error_exit_2(self, tmp_path, monkeypatch, clean_env):
        self._patch_main(monkeypatch, tmp_path)

        def exploding_scan(ctx, quiet):
            raise RuntimeError("boom")

        monkeypatch.setattr(
            clawback, "ALL_SCANS", [("boom", exploding_scan)]
        )
        code = main(["--quiet"])
        assert code == 2

    def test_training_implies_audit(
        self, tmp_path, monkeypatch, clean_env
    ):
        self._patch_main(monkeypatch, tmp_path)
        code = main(["--training", "--quiet"])
        assert code == 0

    def test_output_file_written(self, tmp_path, monkeypatch, clean_env):
        self._patch_main(monkeypatch, tmp_path)
        out = tmp_path / "report.json"
        code = main(["--quiet", "--output-file", str(out)])
        assert code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "scanner_version" in data

    def test_pretty_output(self, tmp_path, monkeypatch, clean_env):
        self._patch_main(monkeypatch, tmp_path)
        out = tmp_path / "report.json"
        main(["--quiet", "--pretty", "--output-file", str(out)])
        text = out.read_text()
        # Pretty-printed JSON contains newlines and indentation.
        assert "\n  " in text

    def test_category_limits_scan(
        self, tmp_path, monkeypatch, clean_env
    ):
        self._patch_main(monkeypatch, tmp_path)
        # Create a finding that would appear in cloud_credentials scan.
        aws = tmp_path / ".aws"
        aws.mkdir()
        (aws / "credentials").write_text("[default]\n")
        # But run only teampcp_iocs category.
        code = main(["--quiet", "--category", "teampcp_iocs"])
        assert code == 0  # No findings because we skipped cloud scan.
