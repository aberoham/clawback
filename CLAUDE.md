# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
uv run pytest tests/ -q                          # run all tests
uv run pytest tests/test_classify_value.py -q     # run one test file
uv run pytest tests/test_cli.py::TestMainIntegration::test_clean_home_exit_0 -v  # run one test

uv run python clawback.py --pretty                # scan (human-readable)
uv run python clawback.py --audit-env --pretty     # audit mode (heuristic tuning)
uv run python clawback.py --training --output-file /tmp/training.json  # training mode
```

CI runs `uv run pytest tests/ -q` across macOS + Ubuntu on Python 3.9, 3.12, 3.13.

## Architecture

Single-file macOS secret exposure scanner (`clawback.py`, stdlib-only, read-only) with a companion remediation pack generator (`restitution.py`). Designed for JAMF and CrowdStrike RTR deployment.

### Core data flow

`ScanContext` accumulates `Finding` objects (actionable) and observations (informational) as each scanner runs. `run_all_scans()` iterates `ALL_SCANS` — a list of `(category_name, scan_function)` pairs registered at line ~1535. Every scanner follows the signature `scan_X(ctx: ScanContext, quiet: bool) -> None`.

Exit codes: 0 = clean, 1 = findings, 2 = scan error.

### Value classification (classify_value + _name_value_suspicious)

`classify_value(value)` is purely value-based — it never sees the variable name. Three tiers:
1. **Known prefixes** (`KNOWN_SECRET_PREFIXES`): `sk-`, `ghp_`, `AKIA`, `lsv2_pt_`, etc. Highest confidence.
2. **Structural patterns**: URL with embedded credentials, long hex (>=32), high-entropy base64-ish.
3. **Entropy threshold**: Shannon entropy > 4.5 for strings >= 20 chars.

When `classify_value` returns `"benign"` but the variable *name* matches `NAMED_SECRET_VARS` or `GENERIC_SECRET_RE`, `_name_value_suspicious()` applies relaxed thresholds (entropy >= 3.5, length >= 20) with filters for URLs, word-like values, and placeholder strings.

### Severity tiers

`NAMED_SECRET_VARS` (tier-1 exact matches like `OPENAI_API_KEY`) get HIGH severity. `GENERIC_SECRET_RE` pattern matches (tier-2, e.g. `MY_CUSTOM_API_KEY`) get MEDIUM. This applies consistently across both the `val_hit` and `nv_hit` code paths in all three scanners.

### Scan categories (11)

teampcp_iocs, cloud_credentials, ssh_keys, git_credentials, package_manager_tokens, kubernetes, shell_profiles, environment_variables, env_files, crypto_wallets, secrets_manager_status. The `--category` flag restricts to one.

### Restitution

`restitution.py` consumes clawback JSON output and generates a remediation pack: `index.md` (operator checklist), `metadata.md` (provenance), `tasks/*.md` (agent-ready prompts), `launch/*.sh` (Claude Code/Codex launchers). Findings are grouped into `WorkUnit` objects by project root or standalone config area. `teampcp_ioc` findings produce human-only incident response checklists with no agent launchers.

## Test conventions

- All scanners are tested by building fixture files under `tmp_path` (via the `scan_ctx` fixture which sets `home=tmp_path`) then calling the scanner directly.
- The `clean_env` fixture removes secret-shaped env vars from the test runner to prevent non-deterministic findings.
- Test keys for prefixes like `lsv2_pt_` are generated at runtime via `secrets.token_hex` to avoid tripping GitHub secret scanning. See `_fake_langsmith_key()` in the test files.
- `.env` file scanning walks from `~/Desktop`, `~/Documents`, etc. with `ENV_MAX_DEPTH = 4`. Tests create projects under `scan_ctx.home / "Desktop" / "project"`.
