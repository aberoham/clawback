"""Tests for SSH key encryption detection and type identification."""
from __future__ import annotations

import os

import pytest

from clawback import (
    _check_ssh_key_encryption,
    _detect_ssh_key_type,
    scan_ssh_keys,
)

# --- Inline key fixtures (throwaway keys, no security value) ---

UNENCRYPTED_RSA_PEM = """\
-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJMzXCxpEFHmSEiJ1MsRkfEwVyg
E817dLFyBCKHG9xJHFBBFMCJUqOBMvQhRLECAwEAAQJAc9L0d2Xp6Yv8Wt2Wirfa
TESTDATANOTAREALKEYBUTSTRUCTURALLYVALID012345678901234567890
-----END RSA PRIVATE KEY-----
"""

ENCRYPTED_RSA_PEM = """\
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AABBCCDDEEFF00112233445566778899

MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJMzXCxpEFHmSEiJ1MsRkfEwVyg
E817dLFyBCKHG9xJHFBBFMCJUqOBMvQhRLECAwEAAQJAc9L0d2Xp6Yv8Wt2Wirfa
TESTDATANOTAREALKEYBUTSTRUCTURALLYVALID012345678901234567890
-----END RSA PRIVATE KEY-----
"""

# Real ed25519 keys generated with ssh-keygen for testing.
UNENCRYPTED_ED25519_OPENSSH = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCuP/hHi7zfsLGYs8rUSVaE6A5+HH2pqcoHRbbGaRqc+AAAAIgYPTstGD07
LQAAAAtzc2gtZWQyNTUxOQAAACCuP/hHi7zfsLGYs8rUSVaE6A5+HH2pqcoHRbbGaRqc+A
AAAEBkV7q3HgGjHDPF9ObnwUqQ2dWJxg/ZPTEDBIdlFpChqK4/+EeLvN+wsZizytRJVoTo
Dn4cfampygdFtsZpGpz4AAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----
"""

ENCRYPTED_ED25519_OPENSSH = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABArCrXEF5
gJLg3OIM6zgBExAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDdmTNRqWRDImJqa
kt4MhKJAoPeuVuAb+Ukq7RadvYAEAAAAkFh4ASobpkx/ProRPgPjorBQNJ5fFss6ctytwG
MUgSd1Bm20BU3qVvmnS0imDmXTV5Q2qNXmBaCV+qCm9Rux/+R2GaNwrAGRzjbDmDtDiCWe
6NBB3QwTI9y5VvWNZQE+Rcmec3GpEfz5OwFL4kt9XmMuCMSVlEuwkUZavYFOpVBih1czOp
Yt8IP+NOuB/nO6lw==
-----END OPENSSH PRIVATE KEY-----
"""


# -------------------------------------------------------------------
# _check_ssh_key_encryption
# -------------------------------------------------------------------


class TestCheckSshKeyEncryption:
    def test_pem_unencrypted(self, tmp_path):
        key = tmp_path / "id_rsa"
        key.write_text(UNENCRYPTED_RSA_PEM)
        assert _check_ssh_key_encryption(key, UNENCRYPTED_RSA_PEM) is False

    def test_pem_encrypted(self, tmp_path):
        key = tmp_path / "id_rsa"
        key.write_text(ENCRYPTED_RSA_PEM)
        assert _check_ssh_key_encryption(key, ENCRYPTED_RSA_PEM) is True

    def test_openssh_unencrypted(self, tmp_path):
        key = tmp_path / "id_ed25519"
        key.write_text(UNENCRYPTED_ED25519_OPENSSH)
        assert (
            _check_ssh_key_encryption(key, UNENCRYPTED_ED25519_OPENSSH)
            is False
        )

    def test_openssh_encrypted(self, tmp_path):
        key = tmp_path / "id_ed25519"
        key.write_text(ENCRYPTED_ED25519_OPENSSH)
        assert (
            _check_ssh_key_encryption(key, ENCRYPTED_ED25519_OPENSSH)
            is True
        )


# -------------------------------------------------------------------
# _detect_ssh_key_type
# -------------------------------------------------------------------


@pytest.mark.parametrize(
    "content,expected",
    [
        ("-----BEGIN RSA PRIVATE KEY-----\ndata", "RSA"),
        ("-----BEGIN EC PRIVATE KEY-----\ndata", "ECDSA"),
        ("-----BEGIN DSA PRIVATE KEY-----\ndata", "DSA"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\ndata", "OpenSSH"),
        ("-----BEGIN PRIVATE KEY-----\ndata", "unknown"),
    ],
)
def test_detect_ssh_key_type(content, expected):
    assert _detect_ssh_key_type(content) == expected


# -------------------------------------------------------------------
# scan_ssh_keys integration
# -------------------------------------------------------------------


class TestScanSshKeys:
    def _write_key(self, ctx, name, content, mode):
        ssh_dir = ctx.home / ".ssh"
        ssh_dir.mkdir(exist_ok=True)
        key = ssh_dir / name
        key.write_text(content)
        os.chmod(key, mode)
        return key

    def test_unencrypted_bad_perms_critical(self, scan_ctx, clean_env):
        self._write_key(
            scan_ctx, "id_rsa", UNENCRYPTED_RSA_PEM, 0o644
        )
        scan_ssh_keys(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].severity == "critical"

    def test_unencrypted_good_perms_high(self, scan_ctx, clean_env):
        self._write_key(
            scan_ctx, "id_rsa", UNENCRYPTED_RSA_PEM, 0o600
        )
        scan_ssh_keys(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].severity == "high"

    def test_encrypted_bad_perms_medium(self, scan_ctx, clean_env):
        self._write_key(
            scan_ctx, "id_rsa", ENCRYPTED_RSA_PEM, 0o644
        )
        scan_ssh_keys(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].severity == "medium"

    def test_unencrypted_0400_treated_as_bad_perms(
        self, scan_ctx, clean_env
    ):
        """0o400 (owner read-only) is more restrictive than 0o600, but the
        scanner currently treats anything != 0o600 as bad_perms. This pins
        the current behavior: unencrypted + 0o400 = CRITICAL. If the scanner
        is updated to accept 0o400 as valid, this test should be updated to
        expect HIGH (unencrypted, good perms)."""
        self._write_key(
            scan_ctx, "id_rsa", UNENCRYPTED_RSA_PEM, 0o400
        )
        scan_ssh_keys(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].severity == "critical"
        assert "0o400" in scan_ctx.findings[0].description

    def test_encrypted_good_perms_observation(self, scan_ctx, clean_env):
        self._write_key(
            scan_ctx, "id_rsa", ENCRYPTED_RSA_PEM, 0o600
        )
        scan_ssh_keys(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0
        assert len(scan_ctx.observations) == 1
        assert scan_ctx.observations[0].details["encrypted"] is True

    def test_pub_file_skipped(self, scan_ctx, clean_env):
        ssh_dir = scan_ctx.home / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa.pub").write_text("ssh-rsa AAAA... test")
        scan_ssh_keys(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_config_files_skipped(self, scan_ctx, clean_env):
        ssh_dir = scan_ctx.home / ".ssh"
        ssh_dir.mkdir()
        for name in ("authorized_keys", "config", "known_hosts"):
            (ssh_dir / name).write_text("some content")
        scan_ssh_keys(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_no_ssh_dir(self, scan_ctx, clean_env):
        scan_ssh_keys(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0
        assert len(scan_ctx.errors) == 0
