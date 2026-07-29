"""Tests for the mcp_configs category.

Covers literal-secret detection across MCP config layouts, the secure
${ENV} reference path (must NOT be a finding), placeholder rejection,
Authorization: Bearer handling, and the invariant that no secret VALUE
ever appears in the emitted report.
"""
from __future__ import annotations

import json

from rattlesnake import scan_mcp_configs, build_report


def _run(ctx):
    scan_mcp_configs(ctx, quiet=True)
    return ctx


def test_literal_github_pat_in_cursor_config(scan_ctx):
    cfg = scan_ctx.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({
        "mcpServers": {
            "github": {"command": "npx", "env": {
                "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_" + "A1b2C3" * 6
            }}
        }
    }))
    _run(scan_ctx)
    assert len(scan_ctx.findings) == 1
    f = scan_ctx.findings[0]
    assert f.category == "mcp_configs"
    assert f.severity == "critical"
    assert f.details["literal_count"] == 1
    assert f.details["secrets"][0]["reason"] == "known_prefix:ghp_"
    assert f.details["secrets"][0]["location"] == \
        "mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN"


def test_anthropic_key_prefix(scan_ctx):
    cfg = scan_ctx.home / ".claude.json"
    cfg.write_text(json.dumps({
        "mcpServers": {"a": {"env": {"ANTHROPIC_API_KEY": "sk-ant-api03-" + "Z9" * 30}}}
    }))
    _run(scan_ctx)
    # Anthropic keys resolve via the existing "sk-" prefix.
    assert scan_ctx.findings[0].details["secrets"][0]["reason"] == "known_prefix:sk-"


def test_env_reference_is_not_a_finding(scan_ctx):
    cfg = scan_ctx.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({
        "mcpServers": {"b": {"env": {"BRAVE_API_KEY": "${BRAVE_API_KEY}"}}}
    }))
    _run(scan_ctx)
    assert scan_ctx.findings == []
    # Clean config still recorded as an observation (prevalence denominator).
    assert len(scan_ctx.observations) == 1
    assert scan_ctx.observations[0].details["reason"] == "mcp_config_no_literal_secret"
    assert scan_ctx.observations[0].details["ref_count"] == 1


def test_placeholder_value_is_not_a_finding(scan_ctx):
    cfg = scan_ctx.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({
        "mcpServers": {"c": {"env": {"API_KEY": "your-api-key-here"}}}
    }))
    _run(scan_ctx)
    assert scan_ctx.findings == []


def test_authorization_bearer_literal(scan_ctx):
    proj = scan_ctx.home / "Documents" / "repo" / ".vscode"
    proj.mkdir(parents=True)
    (proj / "mcp.json").write_text(json.dumps({
        "servers": {"api": {"url": "https://x", "headers": {
            "Authorization": "Bearer glpat-" + "abc123" * 4
        }}}
    }))
    _run(scan_ctx)
    assert len(scan_ctx.findings) == 1
    assert scan_ctx.findings[0].details["secrets"][0]["reason"] == "known_prefix:glpat-"


def test_no_secret_value_in_report(scan_ctx):
    secret = "ghp_" + "S3cr3t" * 6
    cfg = scan_ctx.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"mcpServers": {"g": {"env": {"TOKEN": secret}}}}))
    _run(scan_ctx)
    blob = json.dumps(build_report(scan_ctx))
    assert secret not in blob
    assert "S3cr3t" not in blob


# --- Regression tests for PR #8 review (GPT-5.6 Sol), 2026-07-28 ---

def _findings(ctx):
    return {f.details["secrets"][0]["key"]: f for f in ctx.findings for _ in [0]} if ctx.findings else {}


def test_yaml_continue_config_secrets_detected(scan_ctx):
    """[P1] .continue/config.yaml must be value/key-aware, not prefix-only.
    Catches both a known-prefix key and an UNPREFIXED long-hex under a cred key."""
    cfg = scan_ctx.home / ".continue" / "config.yaml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(
        "name: my-assistant\n"
        "models:\n"
        "  - name: gpt-4\n"
        "    provider: openai\n"
        "    apiKey: sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII\n"
        "mcpServers:\n"
        "  - name: db\n"
        "    env:\n"
        "      DATABASE_TOKEN: 9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c\n"
        "      SAFE_REF: ${DATABASE_TOKEN}\n"
    )
    _run(scan_ctx)
    assert len(scan_ctx.findings) == 1
    keys = {s["key"] for s in scan_ctx.findings[0].details["secrets"]}
    assert "apiKey" in keys            # known-prefix sk-
    assert "DATABASE_TOKEN" in keys    # unprefixed long-hex under a cred key
    assert "SAFE_REF" not in keys      # ${ENV} ref is not a finding


def test_yaml_raw_prefix_substring_is_not_a_false_positive(scan_ctx):
    """[P2] `name: task-runner` / `risk-assessment` contain the `sk-` substring
    but must NOT be reported (prefix matched at value-start only)."""
    cfg = scan_ctx.home / ".continue" / "config.yaml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(
        "name: task-runner\n"
        "description: low-risk-assessment-tool\n"
        "command: npx\n"
    )
    _run(scan_ctx)
    assert scan_ctx.findings == []


def test_camelcase_and_lowercase_credential_keys(scan_ctx):
    """[P1] clientSecret / privateKey / githubToken / github_token must gate open
    even without a known value prefix."""
    cfg = scan_ctx.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"mcpServers": {"x": {
        "clientSecret": "aGVsbG8gd29ybGQgc3VwZXIgc2VjcmV0IHZhbHVlIDEyMzQ1Njc4OTA=",
        "githubToken": "ghp_" + "A1b2C3" * 6,
        "github_token": "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
    }}}))
    _run(scan_ctx)
    keys = {s["key"] for s in scan_ctx.findings[0].details["secrets"]}
    assert {"clientSecret", "githubToken", "github_token"} <= keys


def test_vscode_user_profile_mcp_json_discovered(scan_ctx):
    """[P1] VS Code first-party user-profile mcp.json must be scanned."""
    cfg = scan_ctx.home / "Library" / "Application Support" / "Code" / "User" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"servers": {"gh": {"env": {"GITHUB_TOKEN": "ghp_" + "Z9y8X7" * 6}}}}))
    _run(scan_ctx)
    assert len(scan_ctx.findings) == 1
    assert scan_ctx.findings[0].details["secrets"][0]["reason"] == "known_prefix:ghp_"


def test_yaml_no_secret_value_in_report(scan_ctx):
    secret = "sk-proj-" + "S3cr3tV" * 6
    cfg = scan_ctx.home / ".continue" / "config.yaml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(f"models:\n  - apiKey: {secret}\n")
    _run(scan_ctx)
    blob = json.dumps(build_report(scan_ctx))
    assert secret not in blob and "S3cr3tV" not in blob


def test_token_substring_in_metadata_key_is_not_a_finding(scan_ctx):
    """A key that merely CONTAINS 'token' but is not a credential (e.g. Claude
    Code's own claudeCodeFirstTokenDate) must NOT gate a value into a finding."""
    cfg = scan_ctx.home / ".claude.json"
    cfg.write_text(json.dumps({
        "claudeCodeFirstTokenDate": "2026-01-15T09:33:41.512Z-session-abc123",
        "tokenExpiry": "1785249149888",
        "mcpServers": {"ok": {"env": {"REAL_TOKEN": "ghp_" + "Q1w2E3" * 6}}},
    }))
    _run(scan_ctx)
    keys = {s["key"] for f in scan_ctx.findings for s in f.details["secrets"]}
    assert "claudeCodeFirstTokenDate" not in keys
    assert "tokenExpiry" not in keys
    assert "REAL_TOKEN" in keys        # a genuine env token is still caught
