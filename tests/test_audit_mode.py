"""Tests for audit mode, training mode, and supporting functions."""
from __future__ import annotations

import json

import pytest

from clawback import (
    _char_class_distribution,
    _source_category,
    _value_fingerprint,
    run_audit_env,
)


# -------------------------------------------------------------------
# _value_fingerprint
# -------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", "empty"),
        ("${HOME}", "shell-ref"),
        ("$PATH:/usr/bin", "shell-ref"),
        ("true", "bool"),
        ("false", "bool"),
        ("None", "bool"),
        ("42", "numeric"),
        ("550e8400-e29b-41d4-a716-446655440000", "uuid"),
        ("-----BEGIN RSA PRIVATE KEY-----", "pem-block"),
        ("abcdef0123456789", "hex16"),
        ("https://example.com", "url"),
        # postgres:// is not matched by the https? regex in _value_fingerprint,
        # so it falls through to mixed-N. Only http(s) URLs are fingerprinted.
        ("https://user:pass@host/path", "url-with-creds"),
        ("/usr/local/bin", "path"),
        ("hi", "short-2"),
        ("x", "short-1"),
    ],
)
def test_value_fingerprint(value, expected):
    assert _value_fingerprint(value) == expected


def test_value_fingerprint_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    result = _value_fingerprint(jwt)
    assert result.startswith("jwt-")


def test_value_fingerprint_base64():
    val = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    result = _value_fingerprint(val)
    assert result.startswith("base64-")


# -------------------------------------------------------------------
# _char_class_distribution
# -------------------------------------------------------------------


class TestCharClassDistribution:
    def test_mixed_input(self):
        # "Hello123!" -> H(upper), ello(lower=4), 123(digit=3), !(special=1)
        result = _char_class_distribution("Hello123!")
        assert result["upper"] == round(1 / 9, 2)
        assert result["lower"] == round(4 / 9, 2)
        assert result["digit"] == round(3 / 9, 2)
        assert result["special"] == round(1 / 9, 2)

    def test_empty(self):
        result = _char_class_distribution("")
        assert result == {
            "upper": 0, "lower": 0, "digit": 0, "special": 0,
        }

    def test_all_digits(self):
        result = _char_class_distribution("12345")
        assert result["digit"] == 1.0
        assert result["upper"] == 0
        assert result["lower"] == 0
        assert result["special"] == 0


# -------------------------------------------------------------------
# _source_category
# -------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/home/user/.env", "env_file"),
        ("/home/user/project/.env.local", "env_file"),
        ("/home/user/.env.example", "env_template"),
        ("/home/user/.env.sample", "env_template"),
        ("/home/user/.env.template", "env_template"),
        ("/home/user/.zshrc", "shell_profile"),
        ("/home/user/.bash_profile", "shell_profile"),
        ("/home/user/.bashrc", "shell_profile"),
        ("/home/user/.profile", "shell_profile"),
        ("/home/user/.config/something", "other"),
    ],
)
def test_source_category(path, expected):
    assert _source_category(path) == expected


# -------------------------------------------------------------------
# run_audit_env — audit mode
# -------------------------------------------------------------------


class TestRunAuditEnv:
    def test_audit_record_fields(self, audit_ctx):
        zshrc = audit_ctx.home / ".zshrc"
        zshrc.write_text(
            "export EDITOR=vim\n"
            "export GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n"
        )
        code, output = run_audit_env(audit_ctx, pretty=False, training=False)
        assert code == 0
        data = json.loads(output)
        assert data["mode"] == "audit"
        assert "hostname" in data
        assert "username" in data
        records = data["audit_env_variables"]
        assert len(records) >= 1
        for rec in records:
            for key in (
                "source", "line", "variable", "value_length",
                "value_entropy", "value_prefix",
                "classified_secret", "reason",
            ):
                assert key in rec, f"Missing key {key!r} in record"

    def test_value_prefix_truncated(self, audit_ctx):
        zshrc = audit_ctx.home / ".zshrc"
        zshrc.write_text(
            "export GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n"
        )
        code, output = run_audit_env(audit_ctx, pretty=False, training=False)
        data = json.loads(output)
        rec = data["audit_env_variables"][0]
        # value_prefix is first 6 chars + "..."
        assert rec["value_prefix"].endswith("...")
        assert len(rec["value_prefix"]) == 9  # 6 + len("...")

    def test_no_full_secret_in_output(self, audit_ctx):
        secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
        zshrc = audit_ctx.home / ".zshrc"
        zshrc.write_text(f"export GH_TOKEN={secret}\n")
        _, output = run_audit_env(audit_ctx, pretty=False, training=False)
        assert secret not in output

    def test_training_mode_fields(self, audit_ctx):
        zshrc = audit_ctx.home / ".zshrc"
        zshrc.write_text(
            "export GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n"
        )
        code, output = run_audit_env(audit_ctx, pretty=False, training=True)
        data = json.loads(output)
        assert data["mode"] == "training"
        # Training mode must not include identifying info.
        assert "hostname" not in data
        assert "username" not in data
        rec = data["audit_env_variables"][0]
        # Training fields present.
        assert "source_type" in rec
        assert "value_fingerprint" in rec
        assert "char_classes" in rec
        # Audit-only fields absent.
        assert "source" not in rec
        assert "value_prefix" not in rec

    def test_training_source_type_values(self, audit_ctx):
        zshrc = audit_ctx.home / ".zshrc"
        zshrc.write_text("export FOO=bar\n")
        _, output = run_audit_env(audit_ctx, pretty=False, training=True)
        data = json.loads(output)
        valid = {"env_file", "env_template", "shell_profile", "other"}
        for rec in data["audit_env_variables"]:
            assert rec["source_type"] in valid

    def test_env_file_collection_via_audit_walk(self, audit_ctx):
        """Verify _audit_walk picks up .env files under scan dirs."""
        proj = audit_ctx.home / "Desktop" / "project"
        proj.mkdir(parents=True)
        (proj / ".env").write_text(
            "DB_HOST=localhost\n"
            "API_KEY=sk-proj-abc123def456ghi789jkl012mno345\n"
        )
        _, output = run_audit_env(
            audit_ctx, pretty=False, training=False,
        )
        data = json.loads(output)
        records = data["audit_env_variables"]
        env_records = [
            r for r in records if ".env" in r.get("source", "")
        ]
        assert len(env_records) == 2
        vars_found = {r["variable"] for r in env_records}
        assert "DB_HOST" in vars_found
        assert "API_KEY" in vars_found

    def test_env_file_training_source_type(self, audit_ctx):
        """Training mode classifies .env files as 'env_file'."""
        proj = audit_ctx.home / "Desktop" / "project"
        proj.mkdir(parents=True)
        (proj / ".env").write_text("SECRET=value\n")
        _, output = run_audit_env(
            audit_ctx, pretty=False, training=True,
        )
        data = json.loads(output)
        env_records = [
            r for r in data["audit_env_variables"]
            if r.get("source_type") == "env_file"
        ]
        assert len(env_records) >= 1

    def test_env_template_training_source_type(self, audit_ctx):
        """Training mode classifies .env.example as 'env_template'."""
        proj = audit_ctx.home / "Desktop" / "project"
        proj.mkdir(parents=True)
        (proj / ".env.example").write_text("TOKEN=placeholder\n")
        _, output = run_audit_env(
            audit_ctx, pretty=False, training=True,
        )
        data = json.loads(output)
        template_records = [
            r for r in data["audit_env_variables"]
            if r.get("source_type") == "env_template"
        ]
        assert len(template_records) >= 1

    def test_env_pruned_dirs_not_walked(self, audit_ctx):
        """_audit_walk skips node_modules and dot-dirs."""
        proj = audit_ctx.home / "Desktop" / "project"
        nm = proj / "node_modules" / "lib"
        nm.mkdir(parents=True)
        (nm / ".env").write_text("LEAKED=secret\n")
        _, output = run_audit_env(
            audit_ctx, pretty=False, training=False,
        )
        data = json.loads(output)
        leaked = [
            r for r in data["audit_env_variables"]
            if r.get("variable") == "LEAKED"
        ]
        assert len(leaked) == 0

    def test_category_filter_shell_profiles_only(self, audit_ctx):
        """category='shell_profiles' skips .env file collection."""
        audit_ctx.home.joinpath(".zshrc").write_text("export A=1\n")
        proj = audit_ctx.home / "Desktop" / "project"
        proj.mkdir(parents=True)
        (proj / ".env").write_text("B=2\n")
        _, output = run_audit_env(
            audit_ctx, pretty=False, training=False,
            category="shell_profiles",
        )
        data = json.loads(output)
        variables = {r["variable"] for r in data["audit_env_variables"]}
        assert "A" in variables
        assert "B" not in variables

    def test_category_filter_env_files_only(self, audit_ctx):
        """category='env_files' skips shell profile collection."""
        audit_ctx.home.joinpath(".zshrc").write_text("export A=1\n")
        proj = audit_ctx.home / "Desktop" / "project"
        proj.mkdir(parents=True)
        (proj / ".env").write_text("B=2\n")
        _, output = run_audit_env(
            audit_ctx, pretty=False, training=False,
            category="env_files",
        )
        data = json.loads(output)
        variables = {r["variable"] for r in data["audit_env_variables"]}
        assert "B" in variables
        assert "A" not in variables

    def test_no_raw_path_leaked_in_training(self, audit_ctx):
        """Training output must not contain the raw .env file path."""
        proj = audit_ctx.home / "Desktop" / "project"
        proj.mkdir(parents=True)
        (proj / ".env").write_text("SECRET=value\n")
        _, output = run_audit_env(
            audit_ctx, pretty=False, training=True,
        )
        assert str(proj / ".env") not in output
