"""Tests for .env and shell profile line parsing."""
from __future__ import annotations

import secrets

import pytest

from clawback import (
    _is_env_filename,
    _parse_env_line,
    scan_env_files,
    scan_shell_profiles,
)


def _fake_langsmith_key() -> str:
    return f"lsv2_pt_{secrets.token_hex(16)}_{secrets.token_hex(5)}"


# -------------------------------------------------------------------
# _parse_env_line
# -------------------------------------------------------------------


class TestParseEnvLine:
    def test_simple_assignment(self):
        assert _parse_env_line("KEY=value") == ("KEY", "value")

    def test_export_assignment(self):
        assert _parse_env_line("export KEY=value") == ("KEY", "value")

    def test_double_quoted_value(self):
        assert _parse_env_line('KEY="quoted value"') == (
            "KEY",
            '"quoted value"',
        )

    def test_single_quoted_value(self):
        assert _parse_env_line("KEY='single quoted'") == (
            "KEY",
            "'single quoted'",
        )

    def test_empty_value(self):
        # KEY= with nothing after — regex is (.*)$ so empty matches.
        assert _parse_env_line("KEY=") == ("KEY", "")

    def test_comment_returns_none(self):
        assert _parse_env_line("# this is a comment") is None

    def test_blank_line_returns_none(self):
        assert _parse_env_line("") is None

    def test_space_before_equals_no_match(self):
        assert _parse_env_line("KEY =value") is None

    def test_inline_comment_included_in_value(self):
        name, val = _parse_env_line("KEY=value # comment")
        assert name == "KEY"
        # The regex captures everything after = starting from first
        # non-whitespace, so the inline comment is part of the value.
        assert "comment" in val

    def test_underscore_in_name(self):
        assert _parse_env_line("MY_VAR=123") == ("MY_VAR", "123")

    def test_numeric_in_name(self):
        assert _parse_env_line("VAR2=abc") == ("VAR2", "abc")


# -------------------------------------------------------------------
# _is_env_filename
# -------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        (".env", True),
        (".env.local", True),
        (".env.production", True),
        ("docker-compose.env", True),
        (".env.swp", False),
        (".env.bak", False),
        (".env.orig", False),
        (".envrc", False),
        ("Dockerfile", False),
        ("README.md", False),
        (".env.example", True),
        (".env.tmp", False),
    ],
)
def test_is_env_filename(name, expected):
    assert _is_env_filename(name) is expected


# -------------------------------------------------------------------
# scan_shell_profiles
# -------------------------------------------------------------------


class TestScanShellProfiles:
    def test_secret_export_produces_finding(self, scan_ctx, clean_env):
        zshrc = scan_ctx.home / ".zshrc"
        zshrc.write_text(
            "export PATH=/usr/local/bin:$PATH\n"
            'export AWS_SECRET_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"\n'
            "export EDITOR=vim\n"
        )
        scan_shell_profiles(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        f = scan_ctx.findings[0]
        assert f.category == "shell_profile_secrets"
        assert f.details["variable"] == "AWS_SECRET_ACCESS_KEY"
        assert f.details["line"] == 2

    def test_op_reference_no_finding(self, scan_ctx, clean_env):
        profile = scan_ctx.home / ".bash_profile"
        profile.write_text(
            'export OPENAI_API_KEY="op://vault/openai/key"\n'
        )
        scan_shell_profiles(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_shell_expansion_locator_still_flagged(self, scan_ctx, clean_env):
        """GOOGLE_APPLICATION_CREDENTIALS is a LOCATOR_SECRET_VARS entry.
        Even with $HOME expansion, _is_secret_locator flags it because
        the value is not an op:// reference."""
        zshenv = scan_ctx.home / ".zshenv"
        zshenv.write_text(
            'export GOOGLE_APPLICATION_CREDENTIALS="$HOME/.config/gcp/key.json"\n'
        )
        scan_shell_profiles(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].details["reason"] == "secret_locator"

    def test_shell_expansion_normal_var_no_finding(self, scan_ctx, clean_env):
        """Non-locator variable with shell expansion is not a secret."""
        zshenv = scan_ctx.home / ".zshenv"
        zshenv.write_text(
            'export OPENAI_API_KEY="$HOME/.config/openai/key"\n'
        )
        scan_shell_profiles(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_mixed_profile_correct_counts(self, scan_ctx, clean_env):
        zshrc = scan_ctx.home / ".zshrc"
        zshrc.write_text(
            "export PATH=/usr/bin\n"
            "export GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n"
            "export EDITOR=vim\n"
            "export STRIPE_SECRET_KEY=sk_test_FAKE\n"
            "export SHELL=/bin/zsh\n"
        )
        scan_shell_profiles(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 2
        variables = {f.details["variable"] for f in scan_ctx.findings}
        assert variables == {"GH_TOKEN", "STRIPE_SECRET_KEY"}

    def test_no_profiles_no_findings(self, scan_ctx, clean_env):
        scan_shell_profiles(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0


# -------------------------------------------------------------------
# scan_env_files
# -------------------------------------------------------------------


class TestScanEnvFiles:
    def _make_project(self, ctx, *parts):
        """Create a project directory under Desktop (a scanned root)."""
        d = ctx.home / "Desktop" / "project"
        for part in parts:
            d = d / part
        d.mkdir(parents=True, exist_ok=True)
        return d

    def test_env_with_secret_produces_finding(self, scan_ctx, clean_env):
        proj = self._make_project(scan_ctx)
        (proj / ".env").write_text(
            "DB_HOST=localhost\n"
            "DB_PASSWORD=sk-proj-abc123def456ghi789jkl012mno345\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].severity == "high"

    def test_env_example_low_severity(self, scan_ctx, clean_env):
        proj = self._make_project(scan_ctx)
        (proj / ".env.example").write_text(
            "API_KEY=sk-proj-abc123def456ghi789jkl012mno345\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].severity == "low"

    def test_env_swp_ignored(self, scan_ctx, clean_env):
        proj = self._make_project(scan_ctx)
        (proj / ".env.swp").write_text(
            "SECRET=sk-proj-abc123def456ghi789jkl012mno345\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_env_in_node_modules_pruned(self, scan_ctx, clean_env):
        proj = self._make_project(scan_ctx, "node_modules", "lib")
        (proj / ".env").write_text(
            "SECRET=sk-proj-abc123def456ghi789jkl012mno345\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_env_beyond_max_depth_ignored(self, scan_ctx, clean_env):
        # ENV_MAX_DEPTH is 4; create .env at depth 5 below the scan root.
        deep = scan_ctx.home / "Desktop"
        for i in range(6):
            deep = deep / f"d{i}"
        deep.mkdir(parents=True)
        (deep / ".env").write_text(
            "SECRET=sk-proj-abc123def456ghi789jkl012mno345\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_env_in_dot_dir_pruned(self, scan_ctx, clean_env):
        proj = self._make_project(scan_ctx, ".git")
        (proj / ".env").write_text(
            "SECRET=sk-proj-abc123def456ghi789jkl012mno345\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_env_local_scanned(self, scan_ctx, clean_env):
        proj = self._make_project(scan_ctx)
        (proj / ".env.local").write_text(
            "API_KEY=sk-proj-abc123def456ghi789jkl012mno345\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1

    def test_env_langsmith_key_detected(self, scan_ctx, clean_env):
        """LangSmith/LangChain API keys are detected via prefix."""
        proj = self._make_project(scan_ctx)
        fake_key = _fake_langsmith_key()
        (proj / ".env").write_text(
            f"LANGCHAIN_API_KEY={fake_key}\n"
            f"LANGSMITH_API_KEY={fake_key}\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        found_vars = set(
            scan_ctx.findings[0].details.get("variables", [])
        )
        assert "LANGCHAIN_API_KEY" in found_vars
        assert "LANGSMITH_API_KEY" in found_vars

    def test_env_secret_name_config_value_no_finding(
        self, scan_ctx, clean_env
    ):
        """Word-like config values should not trigger findings even
        when the variable name matches GENERIC_SECRET_RE."""
        proj = self._make_project(scan_ctx)
        (proj / ".env").write_text(
            "MY_SECRET=some_config_value_here\n"
            "DATABASE_PASSWORD=my-database-name\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0


    def test_env_placeholder_value_no_finding(self, scan_ctx, clean_env):
        """Unseparated alpha-dominant placeholders should not trigger
        findings even with a secret-shaped variable name."""
        proj = self._make_project(scan_ctx)
        (proj / ".env").write_text(
            "OPENAI_API_KEY=sampletokenvalue12345\n"
        )
        scan_env_files(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0


class TestShellProfileLangSmith:
    def test_langsmith_key_in_profile_detected(
        self, scan_ctx, clean_env
    ):
        """LangSmith key exported in a shell profile produces a finding."""
        fake_key = _fake_langsmith_key()
        zshrc = scan_ctx.home / ".zshrc"
        zshrc.write_text(
            f"export LANGCHAIN_API_KEY={fake_key}\n"
        )
        scan_shell_profiles(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].details["variable"] == (
            "LANGCHAIN_API_KEY"
        )

    def test_named_var_nv_hit_gets_high_severity(
        self, scan_ctx, clean_env
    ):
        """Tier-1 variable names should get HIGH severity even when
        the value is detected via the name_plus_value fallback path."""
        zshrc = scan_ctx.home / ".zshrc"
        zshrc.write_text(
            "export OPENAI_API_KEY=0123456789abcdef0123\n"
        )
        scan_shell_profiles(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        f = scan_ctx.findings[0]
        assert f.severity == "high"
        assert f.details["reason"].startswith("name_plus_value:")
