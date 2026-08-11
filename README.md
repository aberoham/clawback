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

## Supply-Chain Compromise Detection

Alongside "what is exposed here", `rattlesnake` answers a second question: "has
something already stolen it?" The 2026-08 Shai-Hulud npm worm made that
distinction concrete. It reached workstations through `keyv@6.0.0` and 450-odd
other packages, but it did not stop at reading credentials off disk: it planted
a watcher for persistence, committed loaders into `.claude/` and `.vscode/` so
they ran without an `npm install`, and injected a CI workflow that dumped the
whole Actions secret store into a build artifact.

Four categories cover that ground:

| Category | Looks for |
|---|---|
| `npm_supply_chain` | lockfiles pinning a known-malicious `package@version`; worm loaders and `preinstall` hooks inside installed copies of targeted packages |
| `agent_autostart_hooks` | injected commands in AI-agent and IDE autostart surfaces (`.claude/settings.json` hooks, `.vscode/tasks.json` tasks) |
| `repo_worm_artifacts` | loaders staged in `.claude/` and `.vscode/`, and CI workflows that serialise `toJSON(secrets)` to a file |
| `malware_persistence` | the `gh-token-monitor` dead-man's switch, plus any LaunchAgent that persistently relaunches a bare script from a config or cache directory |

Lockfile parsing covers npm only — v1's nested `dependencies` and v2/v3's
`packages` map, plus `npm-shrinkwrap.json` — including both alias encodings.
Yarn, pnpm and bun lockfiles are deliberately not parsed: a lockfile records
*intent*, while `node_modules` records what actually landed on the machine,
which is what decides whether a lifecycle hook ran. Installed packages are
inspected thoroughly — nested trees, pnpm's virtual store, and global installs
under nvm/n/volta — so those projects are covered once dependencies exist. A
yarn/pnpm/bun project with no `node_modules` is reported as unverified rather
than passed off as clean.

Repository artifacts (staged loaders, injected CI workflows) are found by
discovering repositories directly, not by following agent config files, so a
workflow left behind *after* the hooks were removed is still caught.

Three design notes worth keeping in mind when extending these:

**Hashes, not filenames.** Every dropper check is gated on SHA-256. Matching on
filename alone is not viable: `regenerate-unicode-properties` ships a
legitimate `General_Category/Math_Symbol.js` and `motion-dom` ships a
legitimate `setup.mjs`, so a name-based rule fires on a large share of healthy
JS projects.

**Only executable fields.** The hook scanner parses JSON structure and reads
just the fields that actually execute, so security tooling whose
`permissions.deny` list legitimately blocks `curl ... | bash` is not mistaken
for the thing it defends against.

**Nothing is skipped silently.** A lockfile or manifest that cannot be read or
parsed, a file too large to hash, and a discovery walk that hits its budget all
land in `scan_scope.coverage_gaps`. On a scanner whose whole purpose is to
answer "am I compromised", an unscanned file that reports nothing is
indistinguishable from a clean one, so it has to say so. Gaps are kept separate
from `errors` because `errors` sets exit code 2: an inaccessible directory is a
coverage gap on a healthy host, not a malfunction. Discovery is bounded by a
directory count and a wall-clock budget as well as a prune list, since a prune
list is always incomplete — one database storage directory (`~/.dolt`) cost 74
seconds for three directories during testing.

### Tracking a live campaign with `--ioc-file`

The built-in list carries the directly-compromised core plus notable
second-generation packages. A live campaign's tail is far longer than is
sensible to embed — this one passed 450 packages and 2,200 versions while still
spreading — so the current list can be supplied at scan time:

```bash
python3 rattlesnake.py --quiet --ioc-file iocs.json
```

The file is `{"packages": {"name": ["1.2.3", "1.2.4"]}}`. Published vendor
feeds convert in one step; for example, from Wiz's IoC CSV:

```bash
python3 -c 'import csv,json,sys; print(json.dumps({"packages":{r["Package"]:[v.strip() for v in r["Malicious Versions"].split(",") if v.strip()] for r in csv.DictReader(open(sys.argv[1]))}}))' \
  keyv-packages.csv > iocs.json
```

A malformed or missing feed is reported in the report's `errors` list and the
rest of the scan still runs, so a bad push cannot blind a fleet. A feed that
parses but yields no usable entries is an error too, rather than a silent
success.

### If a finding fires, order matters — and antivenom enforces it

The persistence watcher polls GitHub every 60 seconds and runs a
remote-supplied command as soon as the stolen token stops working. **Remove the
watcher before revoking any token.** Revoking first is the trigger, and the
equivalent handler in the leaked framework this payload derives from ran
`rm -rf ~/`. Note also that valid SLSA provenance and a green
GitHub-verified badge were present on the malicious releases — verify against
hashes, not attestations.

Because that ordering is the opposite of normal credential-leak advice, it is
not left to whoever reads the report. When a scan contains a
`malware_persistence` finding, `antivenom` treats the whole pack as
rotation-gated:

- `index.md` opens with a stop notice naming the offending paths and the
  correct three-step order;
- **no agent launchers are generated at all** — not just for the malware
  finding, but for every unit in the pack, because nearly every automated
  remediation task rotates or revokes something;
- any launchers left in a reused `--output-dir` from an earlier ungated run are
  deleted, so a stale rotation script cannot still be sitting there;
- `--category` cannot lift the gate: it is decided from the unfiltered report,
  so filtering the persistence finding out of the pack does not un-gate it;
- `--tmux` refuses to start sessions.

The generated incident-response task carries the shutdown steps for **both**
macOS and Linux (`launchctl bootout`, `systemctl --user disable`, `loginctl
disable-linger`) plus deletion of the watcher's files, ahead of any rotation
step, and preserves the scanner's own per-finding remediation text.

Task files are still written, so an operator has the instructions. Removing the
watcher and re-scanning lifts the gate and launchers reappear. The four
compromise categories are additionally mapped to `incident_response`, so they
are human-only regardless of the gate — an autonomous agent should never be
pointed at live malware.

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

## A Note on 1Password References

`rattlesnake` intentionally treats `op://...` values as non-secret references, not as exposed secrets.

That means patterns like `AWS_ACCESS_KEY_ID="op://development/aws/Access Keys/access_key_id"` or 
`AWS_SECRET_ACCESS_KEY="op://development/aws/Access Keys/secret_access_key"` are understood 
as runtime references for `op run`, not as leaked credentials.

This is also the end state the remediation text points at, which makes it
verifiable: convert a flagged file to `op://` references and re-scan, and the
finding goes away.

### Remediation is ordered by what removes exposure

A plaintext credential on disk is readable by every process running as the user
and by anything that reaches the machine afterwards, so it stays usable long
after an initial compromise. That is the exposure these findings describe, and
remediation is ordered accordingly:

1. **Move the value into a secrets manager and reference it at runtime.** This
   is the only step that removes the credential from the disk. Where `op` or
   `vault` is detected on the host, the finding names it with a runnable
   command rather than advising "use a secrets manager" generically.
2. **The reason**, stated in the finding, so the priority is not just asserted.
3. **`.env` as a last resort, not a fix.** Restrict it (`chmod 600`), keep it
   out of git, and rotate anything already committed.

`.gitignore` deliberately comes last and is qualified: it prevents a *future*
commit, does not apply to files already tracked, and does not reduce the
on-disk exposure at all. Earlier versions of this tool opened with it, which
read as "keep using `.env`, just don't commit it".

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
