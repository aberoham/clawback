# rattlesnake

Rattlesnake finds easily exposed secrets, then Antivenom turns the findings into remediation work for your favorite fount' of tokens.

## Quick start

```bash
# Scan your machine
curl -fsSL https://raw.githubusercontent.com/aberoham/rattlesnake/main/rattlesnake.py | python3 - --pretty
```

Or _really_ dig in:

```bash
git clone https://github.com/aberoham/rattlesnake.git && cd rattlesnake
python3 rattlesnake.py --quiet --output-file tmp/scan.json
python3 antivenom.py -i tmp/scan.json --preview --dry-run

# Launch antivenom remediation sessions (requires tmux + Claude Code)
python3 antivenom.py -i tmp/scan.json --tmux
tmux attach -t antivenom-<timestamp>
```

## What the heck, why

`rattlesnake` is a small macOS exposure scanner written as a single Python file, designed to quickly answer the question, "what static credentials or keys are sitting unencrypted and exposed on my workstation(s) right now?" `rattlesnake` was inspired by prompt injection malware that goes after cloud credentials, SSH keys, Git credential stores, package manager auth, kubeconfigs, `.env` files, shell-profile secrets, wallet files, and other juicy bits often left laying around on vibe coder's laptops.

The design constraints are simple: one file using Python 3.x stdlib as shipped within Xcode command-line tools, fast enough to run from fleet management tools (JAMF, Crowdstrike RTR, Intune, etc), read-only and easy to improve.

## What It Does

In normal scan mode, `rattlesnake` reports actionable findings and separates them from informational observations. Findings are things that likely represent real exposure: plaintext credentials, embedded k8s secrets, unencrypted SSH keys, static cloud credentials, secret-bearing `.env` files, etc. Observations are useful posture signals that aren't findings by themselves but help understand the state of a machine. Examples of posture signals include, is `op` (1Password CLI) installed, is Git using `osxkeychain`, is Docker using a credential store, does kubeconfig point to external auth, etc.

The JAMF extension attribute ("EA") line only summarizes findings, not observations.

## Audit and Train Modes

Audit mode is for heuristic tuning, where `rattlesnake` emits metadata about found variables without bothering with classification. Training mode is audit mode extended with anonymized output, useful for "autoresearch" style aggregation and classifier refinement. We aim to have zero false positives and no false negatives -- the noise must be squelched!

### 1. Scan mode

just tell me how exposed I am

```bash
python3 rattlesnake.py --pretty
```

Or quietly for JAMF:

```bash
/usr/bin/python3 /path/to/rattlesnake.py --quiet
```

### 2. Audit mode

walk shell profiles and `.env` files, then emit metadata

```bash
python3 rattlesnake.py --audit-env --pretty
```

### 3. Training mode

audit but also dump a bunch of data for classifier training

```bash
python3 rattlesnake.py --training --output-file /tmp/rattlesnake-training.json
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

Audit and training mode emit audit records instead of the normal scan report.

## MCP / AI-agent config secrets

The `mcp_configs` category detects hardcoded, plaintext secrets in local
MCP (Model Context Protocol) / AI-agent configuration files — the config that
AI coding assistants use to wire up tool servers, and a common place for
long-lived API keys and PATs to end up in cleartext.

It looks at Claude Desktop, Claude Code (`~/.claude.json`, `.claude/settings*.json`),
Cursor (`~/.cursor/mcp.json`, project `.cursor/mcp.json`), Cline/Roo (VS Code
globalStorage), Windsurf, Continue, and VS Code MCP (`.vscode/mcp.json`,
project `.mcp.json`). Inside each it inspects `env` blocks, `headers`
(`Authorization: Bearer …`), and any credential-shaped key.

Crucially, the **secure pattern is not a finding**: a value like
`"GITHUB_TOKEN": "${GITHUB_TOKEN}"` (an env-var reference resolved at launch)
or an `op://` reference is treated as target-state, not exposure. Only a
**literal** secret value is reported. Clean configs are recorded as
observations so you can measure how widely MCP tooling is in use, not just where
it leaks.

As with every other category, output contains **locations and classification
reasons only — never the secret value**. Run it alone with:

```bash
python3 rattlesnake.py --category mcp_configs --pretty
```

## A Note on 1Password References

`rattlesnake` intentionally treats `op://...` values as non-secret references, not as exposed secrets.

That means patterns like `AWS_ACCESS_KEY_ID="op://development/aws/Access Keys/access_key_id"` or 
`AWS_SECRET_ACCESS_KEY="op://development/aws/Access Keys/secret_access_key"` are understood 
as runtime references for `op run`, not as leaked credentials.

## What It Does Not Do

`rattlesnake` is a detector, not a validator, that simply reports potential exposure. `rattlesnake` does not try to prove whether the credential is still live, revoked, expired, or unusable. The goal is to make you aware and give your agent a strong headstart around how best to remediate that exposure.

## Deployment Notes

The script was designed around macOS systems where Python 3 is available via Xcode Command Line Tools.  For usage via CrowdStrike realtime response (Crowdstrike RTR), a typical flow looks like:

```bash
put rattlesnake.py
runscript -Raw="python3 /tmp/rattlesnake.py --quiet --output-file /tmp/rattlesnake.json"
get /tmp/rattlesnake.json
```

A sensible approach for fleet-wide rollout would be:

1. use normal scan mode for a small set of manual runs
2. use Crowdstrike RTR to inspect the JSON output on real machines, looking especially for false positives or false negatives
3. use audit or training mode to refine heuristics, contribute those back upstream to this project
4. only then widen deployment fleet-wide through JAMF, Intune, etc

## Antivenom

`antivenom.py` is the companion remediation tool that consumes rattlesnake JSON output and generates a **remediation pack** which isn't much more than an ordered set of agent-ready markdown tasks ready for your coding agent.

### Workflow

```bash
# Scan and review 
python3 rattlesnake.py --quiet --output-file tmp/scan.json
python3 antivenom.py -i tmp/scan.json --preview --dry-run

# 3. Remediate — launch Claude Code sessions in tmux
python3 antivenom.py -i tmp/scan.json --tmux
tmux attach -t antivenom-<timestamp>

# Note: Each tmux window shows the task prompt and waits for you to press Enter before starting Claude Code in plan mode. Cycle windows with `Ctrl-b n`.

# 4. Re-scan to confirm findings are resolved
python3 rattlesnake.py --quiet --output-file tmp/scan2.json
```

## License

MIT. See [LICENSE](LICENSE).
