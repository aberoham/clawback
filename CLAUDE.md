# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
uv run pytest tests/ -q                          # run all tests
uv run pytest tests/test_classify_value.py -q     # run one test file
uv run pytest tests/test_cli.py::TestMainIntegration::test_clean_home_exit_0 -v  # run one test

uv run python rattlesnake.py --pretty                          # scan (human-readable)
uv run python rattlesnake.py --quiet --output-file scan.json   # scan (JSON for antivenom)
uv run python rattlesnake.py --audit-env --pretty              # audit mode (heuristic tuning)
uv run python rattlesnake.py --ioc-file iocs.json              # extend compromised-package list

uv run python antivenom.py -i scan.json --preview --dry-run  # triage findings
uv run python antivenom.py -i scan.json --tmux               # launch tmux sessions
```

CI runs `uv run pytest tests/ -q` across macOS + Ubuntu on Python 3.9, 3.12, 3.13.

## Architecture

Single-file macOS secret exposure scanner (`rattlesnake.py`, stdlib-only, read-only) with a companion remediation pack generator (`antivenom.py`). Designed for JAMF and CrowdStrike RTR deployment.

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

### Scan categories (15)

teampcp_iocs, npm_supply_chain, agent_autostart_hooks, repo_worm_artifacts, malware_persistence, cloud_credentials, ssh_keys, git_credentials, package_manager_tokens, kubernetes, shell_profiles, environment_variables, env_files, crypto_wallets, secrets_manager_status. The `--category` flag restricts to one.

### Supply-chain / malware IoC scanners

Four categories detect an active compromise rather than exposure at rest. Two
invariants hold across all of them:

1. **Dropper detection is hash-gated** (`KNOWN_MALWARE_SHA256` +
   `sha256_file()`). Filenames are only a reason to hash, never a finding:
   `regenerate-unicode-properties` ships a legitimate `Math_Symbol.js` and
   `motion-dom` ships a legitimate `setup.mjs`.
2. **Config scanners parse structure, not text.** `_iter_autostart_commands()`
   reads only fields that execute (`hooks[].hooks[].command`, `tasks[].command`)
   so that a `permissions.deny` entry blocking `curl ... | bash` is not a hit.

Compromised package versions are matched exactly (`COMPROMISED_NPM_PACKAGES`);
these projects have healthy releases either side of the bad one, so range
matching would false-positive. `--ioc-file` extends the list at runtime for a
campaign's long tail. Affected npm *scopes* produce observations, never
findings — most versions in them are clean.

`_iter_lockfile_entries()` normalises every lockfile format to
`(name, resolved_version)` pairs. Substring matching on `"name@version"` does
not work and was the original bug. Format traps, all of which produced
false-clean scans at some point:

- **npm v1** has no `packages` map — walk nested `dependencies`.
- **Yarn classic** puts the *range* in the key, version on a later line.
- **Yarn Berry** embeds `npm:`, so the header regex must tolerate a colon
  inside the descriptor.
- **pnpm** uses `/name/version` or `name@version`, and *quotes* scoped keys
  (`'@keyv/redis@6.0.0':`) because a YAML plain scalar cannot start with `@`.
- **bun.lock** is JSONC with a `packages` table whose values are arrays
  starting `"name@version"` — not a Yarn-style file.
- **Aliases** resolve from the manifest/meta `name`, not the directory path;
  npm v1 encodes them as `"npm:real@version"` in the version string.

`_strip_jsonc()` is string-aware for a concrete reason: a regex for `//`
matches inside base64 integrity hashes (`sha512-...gg0y//+LQ...`), which
corrupted the string and made every real bun.lock fail to parse. It runs in two
passes — comments first, then trailing commas — because judging both at once
failed on `[1, // note`: the comma lookahead stopped at the comment's `/`,
kept the comma, and the comma then became genuinely trailing.

Yarn descriptors carry aliases: `innocent@npm:keyv@6.0.0` must resolve to
`keyv`, not `innocent@npm:keyv`. Splitting on the last `@` hid aliased installs
of compromised packages.

Anything attacker-controlled needs a type check before use. A `package.json`
whose `scripts` was a bare string raised `AttributeError` and, because the
orchestration only caught errors per *category*, abandoned every remaining
package and project root — a crash-induced false negative. Each package is now
inspected inside its own try/except that records the error and continues.

Agent/IDE configs are read with `_loads_jsonc()` too — VS Code documents
`tasks.json` as allowing comments and trailing commas, and strict parsing both
noised up clean hosts and skipped malicious `folderOpen` tasks. npm lockfiles
and `package.json` stay on strict `json.loads()`, since neither format permits
comments.

Read limits are per-artifact and each one exists because a smaller limit hid a
detection: `MANIFEST_MAX_BYTES` for `package.json` and agent configs (64 KiB
truncated `date-fns`, and would truncate a hook placed after padding),
`WORKFLOW_MAX_BYTES` for CI workflows (a modified workflow has an unknown
hash, so the marker search is the only signal left and must cover the whole
file), `LOCKFILE_MAX_BYTES` for lockfiles. Exceeding any of them is a
reported error, never a silent skip.

`_scan_installed_packages()` walks *every* installed package, including nested
`node_modules` trees (a version conflict routinely puts the only copy at
`node_modules/parent/node_modules/keyv`), because the worm republished
whatever the stolen token could reach. `_find_repo_roots()` discovers
repositories independently of agent configs and deduplicates by resolved path
— deriving roots from hook files missed artifacts left after the hooks were
deleted, and double-reported repos carrying both hooks.

Failure is never silent: unreadable/unparseable/oversize files and truncated
discovery all append to `ctx.errors`. Discovery is bounded by
`SUPPLY_CHAIN_MAX_DIRS` and `SUPPLY_CHAIN_TIME_BUDGET` in addition to
`SUPPLY_CHAIN_PRUNE_DIRS`, since prune lists are always incomplete — `~/.dolt`
cost 74s for three directories before it was pruned.

Severity convention here: confirmed malware is `critical`, a structural pattern
that is dangerous but not proof of compromise (secret-dumping CI workflow,
KeepAlive script in a config dir) is `high`/`medium`, and posture signals such
as npm's install-script default are observations so a healthy host still exits 0.

### Antivenom

`antivenom.py` consumes rattlesnake JSON output and generates a remediation pack: `index.md` (operator checklist), `metadata.md` (provenance), `tasks/*.md` (agent-ready prompts), `launch/*.sh` (Claude Code/Codex launchers). Findings are grouped into `WorkUnit` objects by project root or standalone config area. `teampcp_ioc` findings produce human-only incident response checklists with no agent launchers.

`--preview` prints inline task details to stderr for triage. `--tmux` creates a detached tmux session with one named window per launchable task; each window displays the task prompt and waits for Enter before starting `claude --permission-mode plan`.

### Rotation gate (`is_rotation_gated`)

A `malware_persistence` finding makes credential rotation unsafe as a *first*
step: that watcher's handler fires on revocation. Since nearly every launchable
task rotates or revokes something, such a finding gates the **entire pack** —
`generate_pack()` writes no launchers, `compile_index()` prepends a stop
notice, and `create_tmux_session()` refuses. Task files are still written.
Clearing the watcher and re-scanning lifts the gate.

The ordering guarantee has to hold on **every output path**, because each is
consumed independently: the raw scanner JSON (`_lockfile_remediation()` and the
preinstall finding both state watcher-first), each individual task file
(`pack_gated` prepends `_pack_gate_notice()` — an operator opening one task
never sees `index.md`), the `--combined` document (`write_combined()` gates too;
it returns before `generate_pack()` is ever reached), and `index.md` itself.
Fixing one path has repeatedly left another unguarded.

Six properties this gate must keep, each of which was once broken:

1. **Decided from the raw report, not from work units.** Pass `report_data`
   into `is_rotation_gated()`. `--category package_manager_tokens` filters the
   watcher out during `normalize_all()`, which un-gated the pack and emitted
   the exact credential-rotation launcher that must not run.
2. **`_is_incident_response()` is `any`, not `all`.** Units group by
   repository, so a compromise finding and an ordinary `.env` finding share a
   unit; requiring every member to be incident response handed that unit a
   launcher. **`compile_task_file()` must use the same predicate** — while it
   still used `all(...)`, a mixed unit was correctly marked human-only but
   compiled through the generic path, producing a task with no shutdown
   section and a bare "rotate ALL credentials" step.
3. **`launch/` is cleared on every run, gated or not.** `--output-dir` may
   reuse an earlier pack. Clearing only when gated meant a unit that had newly
   become human-only — same generated ID, now carrying an incident-response
   finding — kept its previous executable launcher.
4. **`--combined` is gated as well.** `main()` returns through
   `write_combined()` without touching `generate_pack()`.
5. **Every task file carries the notice when the pack is gated**, not just the
   unit holding the watcher.
6. **The shutdown block deletes every flagged artefact**, enumerated from the
   findings — including `/tmp/tmp.dpkg_14527.lock`. Listing only the two
   token-monitor logs left the pack permanently gated after "cleanup".

`_compile_incident_response_task()` emits each finding's own `remediation`
text, and for persistence findings prepends an explicit shutdown block
covering macOS *and* Linux (`systemctl --user disable`, `loginctl
disable-linger`) plus deleting the watcher files. The generic checklist's
"rotate ALL credentials" step is otherwise the dangerous order.

Scoped to `malware_persistence` only. `teampcp_ioc` is persistence too but was
not revocation-triggered, and widening the gate to it would change that
campaign's established pack behaviour for no safety gain.

## Test conventions

- All scanners are tested by building fixture files under `tmp_path` (via the `scan_ctx` fixture which sets `home=tmp_path`) then calling the scanner directly.
- The `clean_env` fixture removes secret-shaped env vars from the test runner to prevent non-deterministic findings.
- Test keys for prefixes like `lsv2_pt_` are generated at runtime via `secrets.token_hex` to avoid tripping GitHub secret scanning. See `_fake_langsmith_key()` in the test files.
- `.env` file scanning walks from `~/Desktop`, `~/Documents`, etc. with `ENV_MAX_DEPTH = 4`. Tests create projects under `scan_ctx.home / "Desktop" / "project"`.
