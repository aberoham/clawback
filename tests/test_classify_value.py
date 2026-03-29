"""Tests for classify_value — the core heuristic engine."""
from __future__ import annotations

import pytest

from clawback import classify_value, shannon_entropy, _strip_quotes


# -------------------------------------------------------------------
# shannon_entropy
# -------------------------------------------------------------------


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_distinct_chars(self):
        assert abs(shannon_entropy("ab") - 1.0) < 0.01

    def test_high_entropy_hex(self):
        val = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        assert shannon_entropy(val) > 3.5


# -------------------------------------------------------------------
# _strip_quotes
# -------------------------------------------------------------------


class TestStripQuotes:
    def test_double_quotes(self):
        assert _strip_quotes('"hello"') == "hello"

    def test_single_quotes(self):
        assert _strip_quotes("'hello'") == "hello"

    def test_no_quotes(self):
        assert _strip_quotes("hello") == "hello"

    def test_mismatched_quotes(self):
        assert _strip_quotes("'hello\"") == "'hello\""

    def test_whitespace_padding(self):
        assert _strip_quotes('  "hello"  ') == "hello"

    def test_empty(self):
        assert _strip_quotes("") == ""

    def test_single_char_not_stripped(self):
        assert _strip_quotes('"') == '"'


# -------------------------------------------------------------------
# classify_value — true positives
# -------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected_prefix",
    [
        (
            "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx",
            "known_prefix:sk-",
        ),
        (
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
            "known_prefix:ghp_",
        ),
        ("AKIAIOSFODNN7EXAMPLE", "known_prefix:AKIA"),
        (
            "xoxb-not-a-real-token-at-all",
            "known_prefix:xoxb-",
        ),
        ("glpat-xxxxxxxxxxxxxxxxxxxx", "known_prefix:glpat-"),
        (
            "pypi-AgEIcHlwaS5vcmcCJGI0MDAwMDAwMDAwMDAwMDAwMDAwMDA",
            "known_prefix:pypi-",
        ),
        (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            "known_prefix:eyJ",
        ),
        ("-----BEGIN RSA PRIVATE KEY-----", "known_prefix:-----BEGIN"),
        (
            "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
            "QQQQQQQQQQQQQQQQQQQ",
            "known_prefix:AGE-SECRET-KEY-",
        ),
        (
            "postgres://admin:s3cretP@ss@db.example.com:5432/mydb",
            "url_with_credentials",
        ),
        (
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
            "a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2",
            "long_hex",
        ),
    ],
)
def test_true_positives(value, expected_prefix):
    is_secret, reason = classify_value(value)
    assert is_secret is True, (
        f"Expected secret for {value!r}, got reason={reason}"
    )
    assert reason.startswith(expected_prefix), (
        f"Expected prefix {expected_prefix!r}, got {reason!r}"
    )


def test_high_entropy_true_positive():
    """34-char mixed-case alphanumeric string with entropy ~5.09."""
    val = "aB3kL9mNpQ7rS1tU5vW8xY0zA2cD4eF6gH"
    is_secret, reason = classify_value(val)
    assert is_secret is True
    assert reason.startswith("high_entropy:")


# -------------------------------------------------------------------
# classify_value — true negatives
# -------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "true",
        "false",
        "production",
        "3000",
        "1.2.3",
        "localhost",
        "127.0.0.1",
        "https://api.example.com/v1",
        "/usr/local/bin/node",
        "user@example.com",
        "us-east-1",
        "op://development/aws/Access Keys/access_key_id",
        "${HOME}/.config/app",
        "$PATH:/usr/local/bin",
        "/usr/local/bin:/usr/bin:/bin",
        "#ff6600",
        "24px",
        "10s",
        "en-US",
        "myapp",
    ],
)
def test_true_negatives(value):
    is_secret, reason = classify_value(value)
    assert is_secret is False, (
        f"False positive for {value!r}: reason={reason}"
    )


# -------------------------------------------------------------------
# classify_value — edge cases
# -------------------------------------------------------------------


class TestClassifyEdgeCases:
    def test_empty_string(self):
        is_secret, reason = classify_value("")
        assert is_secret is False
        assert reason == "empty_or_variable_reference"

    def test_bare_dollar(self):
        is_secret, reason = classify_value("$")
        assert is_secret is False
        assert reason == "empty_or_variable_reference"

    def test_quoted_secret_detected(self):
        val = '"sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"'
        is_secret, reason = classify_value(val)
        assert is_secret is True
        assert "sk-" in reason

    def test_quoted_1password_ref(self):
        is_secret, reason = classify_value("'op://vault/item/field'")
        assert is_secret is False
        assert reason == "1password_reference"

    def test_whitespace_only(self):
        is_secret, _ = classify_value("   ")
        assert is_secret is False

    def test_19_char_below_length_threshold(self):
        val = "aB3kL9mNpQ7rS1tU5vW"
        assert len(val) == 19
        is_secret, _ = classify_value(val)
        assert is_secret is False

    def test_20_char_at_threshold_low_entropy(self):
        val = "aB3kL9mNpQ7rS1tU5vW8"
        assert len(val) == 20
        is_secret, _ = classify_value(val)
        # Entropy is 4.32, below the 4.5 threshold.
        assert is_secret is False

    def test_31_char_hex_below_threshold(self):
        val = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
        assert len(val) == 31
        is_secret, _ = classify_value(val)
        assert is_secret is False

    def test_32_char_hex_at_threshold(self):
        val = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        assert len(val) == 32
        is_secret, reason = classify_value(val)
        assert is_secret is True
        assert reason == "long_hex"

    def test_akia_prefix_wins_over_short(self):
        """AKIA is only 4 chars but prefix check runs first."""
        is_secret, reason = classify_value("AKIA")
        assert is_secret is True
        assert reason == "known_prefix:AKIA"

    def test_variable_reference_with_brace(self):
        is_secret, reason = classify_value("${DATABASE_URL}")
        assert is_secret is False
        assert reason == "empty_or_variable_reference"

    def test_shell_expansion_with_dollar(self):
        is_secret, reason = classify_value("$HOME/.nvm")
        assert is_secret is False
        assert reason == "shell_variable_expansion"
