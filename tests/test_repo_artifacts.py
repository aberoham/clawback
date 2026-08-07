"""Worm artifacts committed into a repository.

Both vectors here outlive `npm uninstall`: loaders staged in agent config
directories, and an injected CI workflow that re-fires on every push.
"""
from __future__ import annotations

import json
import time

import pytest

import rattlesnake
from rattlesnake import ScanContext, scan_repo_worm_artifacts

CAT = "repo_worm_artifacts"


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "Projects" / "app"
    root.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"name": "app"}))
    ctx = ScanContext(
        home=tmp_path, username="u", hostname="h", start_time=time.monotonic(),
    )
    return root, ctx


def _scan(ctx):
    scan_repo_worm_artifacts(ctx, quiet=True)
    return [f for f in ctx.findings if f.category == CAT]


def _reasons(ctx):
    return [o.details.get("reason") for o in ctx.observations]


def _workflow(root, name, body):
    wf = root / ".github/workflows"
    wf.mkdir(parents=True, exist_ok=True)
    path = wf / name
    path.write_text(body)
    return path


class TestStagedLoaders:
    def test_known_payload_is_critical(self, project, monkeypatch):
        root, ctx = project
        (root / ".claude").mkdir()
        (root / ".claude/settings.json").write_text("{}")
        loader = root / ".claude/setup.mjs"
        loader.write_text("// simulated loader\n")
        monkeypatch.setitem(
            rattlesnake.KNOWN_MALWARE_SHA256,
            rattlesnake.sha256_file(loader), "test loader",
        )

        hits = [f for f in _scan(ctx) if f.severity == "critical"]
        assert len(hits) == 1
        # Both directories must be cleaned: they reference each other.
        assert "BOTH" in hits[0].remediation

    def test_unknown_hash_is_an_observation_not_a_finding(self, project):
        """A cleared hash must not become actionable.

        Same class as flagging a legitimate Math_Symbol.js: the filename is a
        reason to hash, never a finding on its own.
        """
        root, ctx = project
        (root / ".claude").mkdir()
        (root / ".claude/settings.json").write_text("{}")
        (root / ".claude/setup.mjs").write_text("// something else\n")

        assert _scan(ctx) == []
        assert "dropper_name_unknown_hash" in _reasons(ctx)

    def test_injected_agent_config_hash_is_checked(self, project, monkeypatch):
        """settings.json and tasks.json have published digests of their own."""
        root, ctx = project
        (root / ".claude").mkdir()
        target = root / ".claude/settings.json"
        target.write_text("{}")
        monkeypatch.setitem(
            rattlesnake.KNOWN_MALWARE_SHA256,
            rattlesnake.sha256_file(target), "injected settings.json",
        )

        assert [f for f in _scan(ctx) if f.severity == "critical"]


class TestInjectedWorkflows:
    def test_secret_dumping_workflow_is_high(self, project):
        root, ctx = project
        (root / ".claude").mkdir()
        (root / ".claude/settings.json").write_text("{}")
        _workflow(root, "codeql_analysis.yml",
                  "name: Run Copilot\non: [push]\n"
                  "env:\n  VARIABLE_STORE: ${{ toJSON(secrets) }}\n")

        hits = [f for f in _scan(ctx) if f.severity == "high"]
        assert len(hits) == 1
        assert "tojson(secrets)" in hits[0].details["markers"]

    def test_known_workflow_hash_is_critical_and_orders_watcher_first(
        self, project, monkeypatch
    ):
        root, ctx = project
        target = _workflow(root, "codeql_analysis.yml",
                           "name: Run Copilot\non: [push]\n")
        monkeypatch.setitem(
            rattlesnake.KNOWN_MALWARE_SHA256,
            rattlesnake.sha256_file(target), "test workflow",
        )

        hits = [f for f in _scan(ctx) if f.severity == "critical"]
        assert hits
        remediation = hits[0].remediation
        assert remediation.index("gh-token-monitor") < remediation.index(
            "rotate every secret"
        )

    def test_ordinary_workflow_is_not_flagged(self, project):
        root, ctx = project
        _workflow(root, "ci.yml",
                  "name: CI\non: [push]\njobs:\n  test:\n"
                  "    steps:\n      - run: npm test\n"
                  "        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n")

        assert _scan(ctx) == []

    def test_format_results_alone_is_not_a_secret_dump(self, project):
        """An ordinary formatting workflow, not exfiltration."""
        root, ctx = project
        _workflow(root, "fmt.yml",
                  "name: Format\non: [push]\njobs:\n  f:\n    steps:\n"
                  "      - run: prettier --check . > format-results.txt\n"
                  "      - uses: actions/upload-artifact@v4\n"
                  "        with:\n          path: format-results.txt\n")

        assert _scan(ctx) == []

    @pytest.mark.parametrize("line", [
        "# never do: ${{ toJSON(secrets) }}",
        "  # detect: toJSON(secrets)",
    ])
    def test_marker_in_a_comment_is_not_executable(self, project, line):
        """A security guide or lint rule is not an exfiltration workflow."""
        root, ctx = project
        _workflow(root, "ci.yml",
                  f"name: CI\n{line}\njobs:\n  t:\n    steps:\n"
                  "      - run: npm test\n")

        assert _scan(ctx) == []

    def test_marker_past_64k_is_found(self, project):
        """A modified workflow has an unknown hash, so this is the only signal."""
        root, ctx = project
        target = _workflow(root, "big.yml",
                           "name: CI\n" + ("# padding\n" * 14000)
                           + "env:\n  V: ${{ toJSON(secrets) }}\n")
        assert target.stat().st_size > 65536

        assert [f for f in _scan(ctx) if f.severity == "high"]

    def test_oversize_workflow_is_reported(self, project, monkeypatch):
        root, ctx = project
        _workflow(root, "x.yml", "env:\n  V: ${{ toJSON(secrets) }}\n")
        monkeypatch.setattr(rattlesnake, "ARTIFACT_MAX_BYTES", 8)

        scan_repo_worm_artifacts(ctx, quiet=True)

        assert any("NOT searched" in g for g in ctx.coverage_gaps)

    def test_unreadable_workflow_dir_is_reported(self, project):
        root, ctx = project
        wf = root / ".github/workflows"
        wf.mkdir(parents=True)
        wf.chmod(0o000)

        try:
            scan_repo_worm_artifacts(ctx, quiet=True)
            assert any("NOT scanned" in g for g in ctx.coverage_gaps)
        finally:
            wf.chmod(0o755)


class TestRepositoryDiscovery:
    def test_workflow_found_after_the_hooks_were_removed(self, project):
        """The post-cleanup state: hooks deleted, exfil workflow still live."""
        root, ctx = project
        _workflow(root, "codeql_analysis.yml",
                  "name: Run Copilot\non: [push]\n"
                  "env:\n  V: ${{ toJSON(secrets) }}\n")

        assert [f for f in _scan(ctx) if f.severity == "high"]

    def test_loader_found_in_a_git_repo_without_a_manifest(self, tmp_path):
        root = tmp_path / "Projects" / "norepo"
        (root / ".git").mkdir(parents=True)
        (root / ".claude").mkdir()
        (root / ".claude/setup.mjs").write_text("// staged loader\n")
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        scan_repo_worm_artifacts(ctx, quiet=True)

        assert "dropper_name_unknown_hash" in _reasons(ctx)

    def test_repo_with_both_hooks_reports_once(self, project):
        """The cross-wired shape must not double-count."""
        root, ctx = project
        for sub in (".claude", ".vscode"):
            (root / sub).mkdir()
        (root / ".claude/settings.json").write_text("{}")
        (root / ".vscode/tasks.json").write_text("{}")
        _workflow(root, "x.yml", "env:\n  V: ${{ toJSON(secrets) }}\n")

        assert len([f for f in _scan(ctx) if f.severity == "high"]) == 1
