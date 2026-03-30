"""Shared fixtures for clawback test suite."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from clawback import (  # noqa: E402
    GENERIC_SECRET_RE,
    NAMED_SECRET_VARS,
    ScanContext,
)


@pytest.fixture
def scan_ctx(tmp_path):
    """ScanContext with tmp_path as home directory."""
    return ScanContext(
        home=tmp_path,
        username="testuser",
        hostname="testhost",
        start_time=time.monotonic(),
    )


@pytest.fixture
def audit_ctx(tmp_path):
    """ScanContext with audit_mode enabled."""
    return ScanContext(
        home=tmp_path,
        username="testuser",
        hostname="testhost",
        start_time=time.monotonic(),
        audit_mode=True,
    )


@pytest.fixture
def clean_env(monkeypatch):
    """Remove secret-shaped env vars to prevent host environment pollution.

    Deletes every env var that scan_environment_variables would inspect:
    NAMED_SECRET_VARS members plus anything matching GENERIC_SECRET_RE
    (e.g. ACTIONS_RUNTIME_TOKEN on CI runners). Without this, scan
    functions pick up real host credentials and produce non-deterministic
    findings.
    """
    for var in list(os.environ):
        if var in NAMED_SECRET_VARS or GENERIC_SECRET_RE.fullmatch(var):
            monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("KUBECONFIG", raising=False)
