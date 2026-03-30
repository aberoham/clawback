# clawback

`clawback` is a small macOS secret exposure scanner written as a single Python file.

It exists for a very specific reason: most secret scanners are built to search source code for hardcoded secrets. That is useful, but it is not the same problem as asking, "what static credentials and credential files are sitting on a developer workstation right now, ready for the next supply chain compromise to steal?"

`clawback` is aimed at that second problem.

It was shaped around the kinds of material TeamPCP / CanisterWorm-style malware actually goes after on macOS developer machines: cloud credentials, SSH keys, Git credential stores, package manager auth, kubeconfigs, `.env` files, shell-profile secrets, wallet files, and a few campaign-specific indicators of compromise.

The design constraints were simple:

- one file
- Python stdlib only
- read-only
- fast enough to run from JAMF or CrowdStrike RTR
- never print raw secret values in normal scan mode

## What It Does

In normal scan mode, `clawback` reports actionable findings and separates them from informational observations.

Findings are things that likely represent real exposure: plaintext credentials, embedded kube secrets, unencrypted SSH keys, static cloud credentials, secret-bearing `.env` files, and similar material.

Observations are posture signals that are still useful to know about but should not make a machine fail a compliance check by themselves. Examples include:

- `op` is installed
- Git is using `osxkeychain`
- Docker is using a credential store
- a kubeconfig uses external auth

The JAMF extension attribute line only summarizes findings, not observations.

## Operating Modes

`clawback` has three practical modes.

### 1. Scan mode

This is the default. It is meant for compliance measurement.

```bash
python3 clawback.py --pretty
```

Or quietly for JAMF:

```bash
/usr/bin/python3 /path/to/clawback.py --quiet
```

### 2. Audit mode

Audit mode is for heuristic tuning. It walks shell profiles and `.env` files and emits metadata about variables without turning that output into scan findings.

```bash
python3 clawback.py --audit-env --pretty
```

You can scope it:

```bash
python3 clawback.py --audit-env --category shell_profiles
python3 clawback.py --audit-env --category env_files
```

### 3. Training mode

Training mode is audit mode with anonymized output for aggregation and classifier refinement. It automatically implies `--audit-env`.

```bash
python3 clawback.py --training --output-file /tmp/clawback-training.json
```

## Output

Normal scan mode emits:

- JSON to `stdout`, or to a file with `--output-file`
- a JAMF EA summary to `stderr`
- exit code `0` for clean, `1` for findings, `2` for scan errors

The JSON report includes:

- `findings`
- `observations`
- severity summary
- total findings
- scan errors

Audit and training mode emit audit records instead of the normal scan report, plus a zeroed JAMF EA line.

## A Note on 1Password References

`clawback` intentionally treats `op://...` values as non-secret references, not as exposed secrets.

That means patterns like:

```bash
AWS_ACCESS_KEY_ID="op://development/aws/Access Keys/access_key_id"
AWS_SECRET_ACCESS_KEY="op://development/aws/Access Keys/secret_access_key"
```

are understood as runtime references for `op run`, not as leaked credentials.

## What It Does Not Do

Right now `clawback` is a detector, not a validator.

If it finds a path to a credential file or a likely static secret, it reports the exposure. It does not yet try to prove whether the credential is still live, revoked, expired, or unusable. That may come later, but the current tool is intentionally conservative and read-only.

## Deployment Notes

The script was designed around macOS systems where Python 3 is available via Xcode Command Line Tools.

For CrowdStrike RTR, a typical flow looks like:

```bash
put clawback.py
runscript -Raw="python3 /tmp/clawback.py --quiet --output-file /tmp/clawback.json"
get /tmp/clawback.json
```

For early rollout, the sensible approach is:

1. use normal scan mode for a small set of manual runs
2. use RTR to inspect the JSON output on real machines
3. use audit or training mode to refine heuristics where needed
4. only then widen deployment through JAMF

## Restitution

`restitution.py` is the companion remediation tool. It consumes clawback JSON output and generates a **remediation pack**: an ordered set of agent-ready markdown tasks, an operator-facing index, and reviewable launcher scripts.

### Quick start

```bash
python3 clawback.py --json > scan.json
python3 restitution.py -i scan.json
```

This creates a timestamped pack under `./tmp/restitution-packs/<timestamp>/` containing:

- `index.md` — operator dashboard with execution checklist
- `metadata.md` — scan provenance and staleness warning
- `tasks/*.md` — one self-contained agent prompt per work unit
- `launch/*.sh` — reviewable Claude Code and Codex launcher scripts

### Workflow

1. Run `clawback.py --json` to scan
2. Run `restitution.py -i scan.json` to generate a pack
3. Open `index.md` and work through the queue in order
4. Feed each task file to Claude Code or another coding agent
5. Mark progress via checkboxes in `index.md`
6. Re-scan and regenerate after remediation to confirm findings are resolved

### Options

| Flag | Purpose |
|------|---------|
| `--input, -i` | Path to clawback JSON (default: stdin) |
| `--output-dir` | Explicit pack destination |
| `--vault` | Restrict 1Password enrichment to one vault |
| `--category` | Process only one finding category |
| `--dry-run` | Skip 1Password queries |
| `--combined` | Emit combined markdown to stdout (legacy) |

### Grouping

Findings are grouped into work units by the logical area where edits happen: one task per repository, one task per standalone config area (`.ssh/`, `.kube/`, `.config/gcloud/`, shell profiles, etc.). `teampcp_ioc` findings produce human-only incident response checklists with no agent launchers.

## License

MIT. See [LICENSE](LICENSE).
