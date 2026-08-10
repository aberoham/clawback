"""Regression tests for the false positives reported in issue #11.

All three shared a failure mode worth naming: the scanner reported non-secrets
while the actual credential beside them went unflagged, so the finding an
operator triaged was made entirely of noise. Each test below pins the
distinction rather than the symptom, and each is paired with a case that must
still fire.
"""
from __future__ import annotations

import secrets
import time

import pytest

from rattlesnake import (
    ScanContext,
    classify_value,
    group_or_world_accessible,
    is_public_resource_id,
    scan_env_files,
    scan_ssh_keys,
)

# Credential fixtures are generated at runtime rather than written literally,
# following the convention already used for _fake_langsmith_key(): a literal
# sk_live_/ghp_/xoxb- string trips GitHub push protection on this repository.


def _fake_stripe_key() -> str:
    return f"sk_live_{secrets.token_hex(12)}{secrets.token_hex(6)}"


def _fake_github_pat() -> str:
    return f"ghp_{secrets.token_hex(18)}"


def _fake_slack_token() -> str:
    return f"xoxb-{secrets.randbits(40)}-{secrets.token_hex(12)}"


def _fake_cf_token() -> str:
    return f"v1.0-{secrets.token_hex(18)}"


UNENCRYPTED_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAxGZ8xL0Kk1p2wQ3rT4yU5iO6pA7sD8fG9hJ0kL1mN2oP3qR4\n"
    "-----END RSA PRIVATE KEY-----\n"
)


@pytest.fixture
def ctx(tmp_path):
    return ScanContext(
        home=tmp_path, username="u", hostname="h", start_time=time.monotonic(),
    )


def _write_key(ctx, name, mode):
    ssh = ctx.home / ".ssh"
    ssh.mkdir(exist_ok=True)
    path = ssh / name
    path.write_text(UNENCRYPTED_KEY)
    path.chmod(mode)
    return path


def _write_env(ctx, relpath, body):
    path = ctx.home / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def _env_findings(ctx):
    scan_env_files(ctx, quiet=True)
    return [f for f in ctx.findings if f.category == "env_files"]


def _reported_vars(findings):
    out = []
    for f in findings:
        out.extend(f.details.get("variables") or [])
    return out


# -------------------------------------------------------------------
# 1. Stricter-than-expected file modes
# -------------------------------------------------------------------


class TestFileModesTestTheBitsThatMatter:
    @pytest.mark.parametrize("mode,accessible", [
        (0o600, False),   # the canonical correct mode
        (0o400, False),   # stricter: read-only owner-only
        (0o000, False),   # stricter still
        (0o644, True),    # group + world readable
        (0o640, True),    # group readable
        (0o604, True),    # world readable
        (0o660, True),    # group writable
    ])
    def test_only_group_or_world_access_counts(self, ctx, mode, accessible):
        path = _write_key(ctx, "k", mode)

        assert group_or_world_accessible(path) is accessible

    def test_missing_file_is_indeterminate(self, ctx):
        assert group_or_world_accessible(ctx.home / "absent") is None

    def test_0400_key_is_high_not_critical(self, ctx):
        """The severity inversion: a better-protected key outranked a worse one."""
        _write_key(ctx, "id_rsa", 0o400)

        scan_ssh_keys(ctx, quiet=True)

        assert len(ctx.findings) == 1
        assert ctx.findings[0].severity == "high"
        assert "overly permissive" not in ctx.findings[0].description

    def test_0400_key_is_not_told_to_loosen_itself(self, ctx):
        """Advising chmod 600 on 0o400 is actively harmful if followed."""
        _write_key(ctx, "id_rsa", 0o400)

        scan_ssh_keys(ctx, quiet=True)

        assert "chmod 600" not in ctx.findings[0].remediation

    def test_world_readable_key_is_still_critical(self, ctx):
        _write_key(ctx, "id_rsa", 0o644)

        scan_ssh_keys(ctx, quiet=True)

        assert ctx.findings[0].severity == "critical"
        assert "chmod 600" in ctx.findings[0].remediation

    def test_strict_key_ranks_below_a_loose_one(self, ctx):
        """The property that actually matters for triage order."""
        _write_key(ctx, "strict_key", 0o400)
        _write_key(ctx, "loose_key", 0o644)

        scan_ssh_keys(ctx, quiet=True)

        by_name = {f.path.split("/")[-1]: f.severity for f in ctx.findings}
        assert by_name["strict_key"] == "high"
        assert by_name["loose_key"] == "critical"


# -------------------------------------------------------------------
# 2. Template placeholders
# -------------------------------------------------------------------


class TestTemplatePlaceholders:
    @pytest.mark.parametrize("value", [
        "{{ app_password }}",
        "{{app_password}}",
        "{{ .Values.secret }}",       # Helm
        "<%= ENV['SECRET'] %>",       # ERB
        "<% secret %>",
        "<your-token-here>",
        "${DB_PASSWORD}",             # already handled; pinned to stay so
    ])
    def test_placeholders_are_not_secrets(self, value):
        is_secret, _ = classify_value(value)

        assert is_secret is False

    def test_placeholder_detection_is_value_based_not_filename_based(self, ctx):
        """`.env.j2` is one convention of many; the value is the reliable signal."""
        _write_env(ctx, "Desktop/proj/.env", (
            "APP_PASSWORD={{ app_password }}\n"
            "DB_PASSWORD={{ db_password }}\n"
        ))

        assert _env_findings(ctx) == []

    @pytest.mark.parametrize("relpath", [
        "Desktop/proj/.env.j2",
        "Desktop/proj/.env.tmpl",
        "Desktop/proj/.env.jinja2",
        "Desktop/templates/proj/.env",   # parent-directory convention
    ])
    def test_template_paths_are_recognised(self, ctx, relpath):
        _write_env(ctx, relpath, "DB_PASSWORD={{ db_password }}\n")

        assert _env_findings(ctx) == []

    def test_a_real_secret_in_a_template_is_still_reported(self, ctx):
        """Template handling must not become a blanket exemption."""
        _write_env(ctx, "Desktop/proj/.env.j2", (
            "DB_PASSWORD={{ db_password }}\n"
            f"STRIPE_KEY={_fake_stripe_key()}\n"
        ))

        findings = _env_findings(ctx)

        assert findings
        assert "STRIPE_KEY" in _reported_vars(findings)
        assert "DB_PASSWORD" not in _reported_vars(findings)


class TestCommandLineStringsAreNotSecrets:
    def test_jvm_option_string_is_not_a_secret(self):
        """105 chars of JVM flags scores 5.1 on entropy through variety alone."""
        value = ("-Xms64m -Xmx512m -XX:MetaspaceSize=96m -XX:+UseG1GC "
                 "-Djava.net.preferIPv4Stack=true -Dfile.encoding=UTF-8")

        is_secret, _ = classify_value(value)

        assert is_secret is False

    @pytest.mark.parametrize("value", [
        "--flag one --flag two --another-flag three --and-more four",
        "a quick brown fox jumped over the lazy dog repeatedly today",
        "/usr/local/bin:/usr/bin:/bin /opt/homebrew/bin extra path bits",
    ])
    def test_whitespace_separated_config_is_not_a_secret(self, value):
        is_secret, _ = classify_value(value)

        assert is_secret is False

    def test_contiguous_credentials_are_still_detected(self):
        """The tier this narrows must keep catching what it is for."""
        for value in (
            _fake_stripe_key(),
            _fake_github_pat(),
            _fake_slack_token(),
            "AKIAIOSFODNN7EXAMPLE",
            "postgres://user:hunter2@db.internal:5432/app",
        ):
            is_secret, _ = classify_value(value)
            assert is_secret is True, value[:12]

    def test_a_long_contiguous_high_entropy_value_still_fires(self):
        is_secret, reason = classify_value("Zx9Qm4Lp7Rt2Wv8Kn3Yb6Hd1Fj5Gs0Ac")

        assert is_secret is True
        assert reason.startswith("high_entropy")


# -------------------------------------------------------------------
# 3. Public cloud resource identifiers
# -------------------------------------------------------------------


class TestPublicResourceIds:
    @pytest.mark.parametrize("name", [
        "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_ZONE_ID", "FASTLY_SERVICE_ID",
        "CF_KV_ID", "GCP_PROJECT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
    ])
    def test_hex_identifiers_are_not_secrets(self, name):
        assert is_public_resource_id(
            name, "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        ) is True

    def test_both_halves_are_required(self):
        # Right name shape, but the value is not a plain hex identifier.
        assert is_public_resource_id(
            "CLOUDFLARE_ACCOUNT_ID", _fake_stripe_key()
        ) is False
        # Hex value, but the name is not an identifier.
        assert is_public_resource_id(
            "API_SECRET", "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        ) is False

    def test_client_secret_is_untouched(self):
        """Adjacent naming that must keep firing."""
        assert is_public_resource_id(
            "AZURE_CLIENT_SECRET", "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        ) is False

    def test_resource_ids_are_not_reported_in_an_env_file(self, ctx):
        _write_env(ctx, "Desktop/proj/.env", (
            "CLOUDFLARE_ACCOUNT_ID=0a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
            "CLOUDFLARE_ZONE_ID=f9e8d7c6b5a4938271605f4e3d2c1b0a\n"
            "CLOUDFLARE_API_TOKEN={{API TOKEN}}\n"
        ))

        assert _env_findings(ctx) == []

    def test_a_real_token_beside_them_is_still_reported(self, ctx):
        """The inversion, corrected: the credential is what gets flagged."""
        _write_env(ctx, "Desktop/proj/.env", (
            "CLOUDFLARE_ACCOUNT_ID=0a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
            "CLOUDFLARE_ZONE_ID=f9e8d7c6b5a4938271605f4e3d2c1b0a\n"
            f"CLOUDFLARE_API_TOKEN={_fake_cf_token()}\n"
        ))

        findings = _env_findings(ctx)
        reported = _reported_vars(findings)

        assert "CLOUDFLARE_API_TOKEN" in reported
        assert "CLOUDFLARE_ACCOUNT_ID" not in reported
        assert "CLOUDFLARE_ZONE_ID" not in reported


class TestTheReportedHostScenario:
    def test_neither_fixture_from_the_issue_produces_a_finding(self, ctx):
        """End to end on both .env fixtures from issue #11."""
        _write_env(ctx, "Desktop/templates/proj-a/.env.j2", (
            "APP_PASSWORD={{ app_password }}\n"
            "DB_PASSWORD={{ db_password }}\n"
            "JAVA_OPTS=-Xms64m -Xmx512m -XX:MetaspaceSize=96m -XX:+UseG1GC "
            "-Djava.net.preferIPv4Stack=true -Dfile.encoding=UTF-8\n"
        ))
        _write_env(ctx, "Desktop/proj-b/.env", (
            "CLOUDFLARE_ACCOUNT_ID=0a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
            "CLOUDFLARE_ZONE_ID=f9e8d7c6b5a4938271605f4e3d2c1b0a\n"
            "CLOUDFLARE_API_TOKEN={{API TOKEN}}\n"
        ))

        assert _env_findings(ctx) == []


# -------------------------------------------------------------------
# Boundaries: each false-positive fix above must not become a blind spot.
# These pin the three false negatives found reviewing the fixes themselves.
# -------------------------------------------------------------------


class TestPlaceholderExemptionIsWholeValueOnly:
    @pytest.mark.parametrize("value", [
        "postgres://admin:hunter2@{{ db_host }}/app",
        "mysql://root:letmein@{{ host }}:3306/db",
        "https://user:pass@{{ domain }}/hook",
    ])
    def test_credential_mixed_with_a_placeholder_is_still_a_secret(self, value):
        """A templated *host* does not make a hardcoded password benign."""
        is_secret, reason = classify_value(value)

        assert is_secret is True
        assert reason != "template_placeholder"

    def test_whole_value_placeholders_remain_exempt(self):
        for value in ("{{ db_password }}", "{{db_password}}",
                      "<%= ENV['SECRET'] %>", "<your-token-here>"):
            is_secret, reason = classify_value(value)
            assert is_secret is False, value
            assert reason == "template_placeholder", value

    def test_env_file_reports_the_mixed_credential(self, ctx):
        _write_env(ctx, "Desktop/proj/.env.j2", (
            "DB_PASSWORD={{ db_password }}\n"
            "DATABASE_URL=postgres://admin:hunter2@{{ db_host }}/app\n"
        ))

        reported = _reported_vars(_env_findings(ctx))

        assert "DATABASE_URL" in reported
        assert "DB_PASSWORD" not in reported


class TestResourceIdExemptionRequiresAKnownCategory:
    @pytest.mark.parametrize("name", [
        "SESSION_ID",      # a hex session ID is a bearer credential
        "AUTH_ID",
        "TOKEN_ID",
        "SECRET_ID",
        "ACCESS_ID",
        "REFRESH_ID",
        "COOKIE_ID",
    ])
    def test_credential_shaped_ids_are_never_suppressed(self, name):
        assert is_public_resource_id(
            name, "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        ) is False

    @pytest.mark.parametrize("name", [
        "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_ZONE_ID", "FASTLY_SERVICE_ID",
        "GCP_PROJECT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
        "AWS_DISTRIBUTION_ID", "CF_KV_ID",
    ])
    def test_known_public_identifiers_are_still_suppressed(self, name):
        assert is_public_resource_id(
            name, "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        ) is True

    def test_bare_id_suffix_is_not_enough(self):
        """An unqualified *_ID gives no evidence that it is public."""
        assert is_public_resource_id(
            "THING_ID", "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        ) is False

    def test_session_id_is_reported_in_an_env_file(self, ctx):
        _write_env(ctx, "Desktop/proj/.env", (
            "CLOUDFLARE_ZONE_ID=f9e8d7c6b5a4938271605f4e3d2c1b0a\n"
            "SESSION_ID=0a1b2c3d4e5f60718293a4b5c6d7e8f9\n"
        ))

        reported = _reported_vars(_env_findings(ctx))

        assert "SESSION_ID" in reported
        assert "CLOUDFLARE_ZONE_ID" not in reported


class TestEntropyIsScoredPerToken:
    def test_credential_embedded_among_flags_is_detected(self):
        """Skipping whitespace values wholesale hid this."""
        value = "-Xmx512m -Dservice.token=Zx9Qm4Lp7Rt2Wv8Kn3Yb6Hd1Fj5Gs0Ac"

        is_secret, reason = classify_value(value)

        assert is_secret is True
        assert reason.startswith("high_entropy")

    def test_quoted_embedded_credential_is_detected(self):
        value = '--auth "Zx9Qm4Lp7Rt2Wv8Kn3Yb6Hd1Fj5Gs0Ac"'

        is_secret, _ = classify_value(value)

        assert is_secret is True

    @pytest.mark.parametrize("value", [
        # Every token is short or low-entropy, so nothing should fire.
        ("-Xms64m -Xmx512m -XX:MetaspaceSize=96m -XX:+UseG1GC "
         "-Djava.net.preferIPv4Stack=true -Dfile.encoding=UTF-8"),
        "a quick brown fox jumped over the lazy dog repeatedly today",
        "--flag one --flag two --another-flag three --and-more four",
    ])
    def test_ordinary_command_strings_stay_benign(self, value):
        is_secret, _ = classify_value(value)

        assert is_secret is False

    def test_env_file_reports_the_embedded_credential(self, ctx):
        _write_env(ctx, "Desktop/proj/.env", (
            "JAVA_OPTS=-Xmx512m -Dservice.token=Zx9Qm4Lp7Rt2Wv8Kn3Yb6Hd1Fj5Gs0Ac\n"
        ))

        assert "JAVA_OPTS" in _reported_vars(_env_findings(ctx))
