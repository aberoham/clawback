"""Remediation for credentials at rest must lead with removing them.

The previous advice for a `.env` finding opened with "Add .env to .gitignore",
which reads as *keep using .env, just don't commit it*. That inverts the
priority: this scanner exists to report plaintext credentials sitting on a
disk, readable by anything running as the user and by anything that lands on
the host later. Keeping the file out of git prevents a different leak and does
nothing about that one.
"""
from __future__ import annotations

import time

import pytest

import rattlesnake
from rattlesnake import (
    ScanContext,
    scan_env_files,
    scan_environment_variables,
    secret_at_rest_remediation,
    secrets_manager_installed,
)


@pytest.fixture(autouse=True)
def clear_tool_cache():
    """The detector caches per process; keep tests independent."""
    rattlesnake._SECRETS_MANAGER_CACHE.clear()
    yield
    rattlesnake._SECRETS_MANAGER_CACHE.clear()


@pytest.fixture
def no_tools(monkeypatch):
    monkeypatch.setattr(rattlesnake.shutil, "which", lambda _tool: None)


@pytest.fixture
def has_op(monkeypatch):
    monkeypatch.setattr(
        rattlesnake.shutil, "which",
        lambda tool: "/opt/homebrew/bin/op" if tool == "op" else None,
    )


@pytest.fixture
def has_vault(monkeypatch):
    monkeypatch.setattr(
        rattlesnake.shutil, "which",
        lambda tool: "/usr/local/bin/vault" if tool == "vault" else None,
    )


def _ctx(home):
    return ScanContext(
        home=home, username="u", hostname="h", start_time=time.monotonic(),
    )


def _env_finding(ctx):
    scan_env_files(ctx, quiet=True)
    hits = [f for f in ctx.findings if f.category == "env_files"]
    assert hits, "expected an env_files finding"
    return hits[0]


def _write_env(ctx, relpath, body):
    path = ctx.home / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


REAL_SECRET = (
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
)


class TestPriorityOrdering:
    def test_secrets_manager_comes_before_gitignore(self, tmp_path, no_tools):
        ctx = _ctx(tmp_path)
        _write_env(ctx, "Desktop/proj/.env", REAL_SECRET)

        remediation = _env_finding(ctx).remediation

        assert "secrets manager" in remediation
        assert remediation.index("secrets manager") < remediation.index(
            ".gitignore"
        )

    def test_gitignore_is_not_the_opening_advice(self, tmp_path, no_tools):
        """The exact regression: the old string began with it."""
        ctx = _ctx(tmp_path)
        _write_env(ctx, "Desktop/proj/.env", REAL_SECRET)

        remediation = _env_finding(ctx).remediation

        assert not remediation.startswith("Add .env to .gitignore")
        assert remediation.startswith("1)")

    def test_env_files_are_called_a_last_resort(self, tmp_path, no_tools):
        ctx = _ctx(tmp_path)
        _write_env(ctx, "Desktop/proj/.env", REAL_SECRET)

        assert "last resort" in _env_finding(ctx).remediation

    def test_gitignore_is_qualified_rather_than_offered_as_a_fix(
        self, tmp_path, no_tools
    ):
        """Silent on this, an operator reasonably believes .gitignore fixes it."""
        ctx = _ctx(tmp_path)
        _write_env(ctx, "Desktop/proj/.env", REAL_SECRET)

        remediation = _env_finding(ctx).remediation

        assert "does not apply to files already tracked" in remediation
        assert "never reduces the on-disk exposure" in remediation


class TestPostExploitationWarning:
    def test_warning_states_the_actual_risk(self, tmp_path, no_tools):
        ctx = _ctx(tmp_path)
        _write_env(ctx, "Desktop/proj/.env", REAL_SECRET)

        remediation = _env_finding(ctx).remediation

        assert "readable by any process running as you" in remediation
        assert "long after an initial compromise" in remediation

    def test_warning_appears_for_non_env_findings_too(self, tmp_path, no_tools):
        """Shell profiles and env vars share the same underlying exposure."""
        text = secret_at_rest_remediation()

        assert "readable by any process running as you" in text
        # The .env-specific stopgap does not belong on a non-file finding.
        assert ".gitignore" not in text


class TestConcreteCommandsWhenAToolIsPresent:
    def test_1password_is_named_with_a_runnable_command(self, has_op):
        text = secret_at_rest_remediation(env_file=True)

        assert "1Password" in text
        assert "op run" in text
        assert "op://" in text

    def test_op_reference_is_described_as_clearing_the_finding(self, has_op):
        """True, and it gives the operator a verifiable end state."""
        text = secret_at_rest_remediation(env_file=True)

        assert "stops being a finding" in text

    def test_vault_is_named_when_only_vault_is_present(self, has_vault):
        text = secret_at_rest_remediation()

        assert "Vault" in text
        assert "op run" not in text

    def test_generic_advice_when_no_tool_is_installed(self, no_tools):
        text = secret_at_rest_remediation()

        assert "Install one" in text
        assert "1Password CLI" in text and "Keychain" in text

    def test_detection_is_cached(self, monkeypatch):
        calls = []

        def counting_which(tool):
            calls.append(tool)
            return None

        monkeypatch.setattr(rattlesnake.shutil, "which", counting_which)

        secrets_manager_installed("op")
        secrets_manager_installed("op")
        secrets_manager_installed("op")

        assert calls == ["op"]


class TestTheReportedFinding:
    def test_reported_fixture_carries_the_reordered_advice(
        self, tmp_path, has_op
    ):
        """The reported .env, end to end.

        Scoped to this change: the advice attached to the finding. Which
        *variables* it lists is the separate concern of the resource-identifier
        suppression on fix/scanner-false-positives, so it is not asserted here.
        """
        ctx = _ctx(tmp_path)
        _write_env(ctx, "Desktop/altitude-api/.env", (
            "COPILOT_SNS_TOPIC_ARNS=arn:aws:sns:eu-west-1:123456789012:events\n"
            + REAL_SECRET +
            "FASTLY_MTE_KV_ID=0a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
            "FASTLY_SERVICE_ID=f9e8d7c6b5a4938271605f4e3d2c1b0a\n"
            "CLOUDFLARE_ACCOUNT_ID=1122334455667788990011223344556677\n"
            "CLOUDFLARE_ZONE_ID=aabbccddeeff00112233445566778899\n"
        ))

        finding = _env_finding(ctx)

        assert "AWS_SECRET_ACCESS_KEY" in finding.details["variables"]
        assert finding.severity == "critical"
        assert finding.remediation.startswith("1) Move this value into 1Password")
        assert not finding.remediation.startswith("Add .env to .gitignore")

    def test_an_op_converted_file_produces_no_finding(self, tmp_path, has_op):
        """The end state the advice points at is actually reachable."""
        ctx = _ctx(tmp_path)
        _write_env(ctx, "Desktop/proj/.env", (
            "AWS_SECRET_ACCESS_KEY=op://vault/aws/secret_access_key\n"
        ))

        scan_env_files(ctx, quiet=True)

        assert [f for f in ctx.findings if f.category == "env_files"] == []


class TestEnvironmentVariableFindings:
    def test_env_var_advice_also_leads_with_the_manager(
        self, tmp_path, monkeypatch, no_tools
    ):
        # Not AWS_*: those are deliberately skipped here to avoid
        # duplicating scan_cloud_credentials.
        monkeypatch.setenv(
            "STRIPE_SECRET_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        ctx = _ctx(tmp_path)

        scan_environment_variables(ctx, quiet=True)

        hits = [f for f in ctx.findings
                if f.category == "environment_variables"]
        assert hits
        assert hits[0].remediation.startswith("1)")
        assert "secrets manager" in hits[0].remediation
