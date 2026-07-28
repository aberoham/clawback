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
