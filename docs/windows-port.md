# Windows port — design notes and validation record

`rattlesnake.ps1` is a separate implementation of the secrets-at-rest scanner for the Windows estate, against the same JSON contract as `rattlesnake.py`. This document records the design decisions that are specific to Windows and the real-RTR validation, so a reviewer does not have to reconstruct them from the code.

## Why this is a rewrite, not a translation

The macOS scanner is Python; the Windows estate cannot rely on Python. Measured across the CrowdStrike fleet on 2026-08-27:

| runtime | hosts | share |
|---|---|---|
| `powershell.exe` (Windows PowerShell 5.1) | 2,999 | 98.7% |
| `pwsh.exe` (PowerShell 7) | 30 | 1.0% |
| Windows hosts total | 3,037 | — |

So the target is **Windows PowerShell 5.1**, single file, stdlib/.NET-Framework only. This is the mirror image of the macOS constraint (~41% of Macs lack `/usr/bin/python3`, which is why `rattlesnake.pl` exists).

## The two delivery invariants

**No backticks anywhere in the source.** RTR sends inline payloads inside a triple-backtick `runscript -Raw=` delimiter; a backtick in the payload closes it early. In PowerShell the backtick is *also* the escape character, so the file uses `[char]10` / `[char]34` and splatting rather than `` `n `` / `` `" `` / line continuations. `tools/Build-RtrPayload.ps1` fails the build if a backtick is present in the generated payload.

**Run inline, never write-then-execute.** Managed builds run ExecutionPolicy `Restricted` in every scope, so a dropped `.ps1` will not run. Falcon's `runscript` host executes the payload directly, bypassing the policy, and writes nothing — a better read-only posture than the macOS path (which wrote a temp file and self-deleted).

## Windows-specific detection surface

Beyond the eight remapped secrets-at-rest categories, two categories exist only here:

- **`windows_native`** — GPP `cpassword` (reversible via the MS-published AES key; MS14-025 stopped new ones but not existing cached copies), sysprep/unattend answer files, Winlogon `DefaultPassword`, machine-scope env vars, IIS `web.config` connection strings.
- **`wsl_homes`** — a second POSIX filesystem per endpoint with its own `.aws`/`.ssh`/`.config`.

And within `shell_profiles`, **PSReadLine `ConsoleHost_history.txt`** is the highest-yield artifact with no macOS equivalent: every credential pasted at a prompt, plaintext, retained across sessions, OneDrive-backed.

The value classifier is a faithful port of the Python (`classify_value` → `Test-SecretValue`, `_name_value_suspicious` → `Test-NameValueSuspicious`): identical `KNOWN_SECRET_PREFIXES`, `NAMED_SECRET_VARS`, `GENERIC_SECRET_RE`, entropy thresholds and innocuous-value filters, so a value is classified the same way on both platforms.

## Bugs the validation caught (each is a comment in the source)

1. **`op://` reported as an exposed secret.** The name-based second look ran on any non-secret verdict, so `OPENAI_API_KEY=op://...` — the *remediated* state — was flagged HIGH. It now runs only when the value verdict was literally `benign`; every other negative reason (`1password_reference`, `$VAR`/`%VAR%` expansion) is exculpatory and short-circuits. Reporting the fixed state would have told everyone who migrated to a secrets manager they were still exposed and inflated the hunt's prevalence with exactly the remediated population.
2. **Coverage-gap noise.** Legacy profile junction points (`My Music`/`My Pictures`/`My Videos`, etc.) deny access to everyone including SYSTEM by design; walking them produced 6 `UnauthorizedAccessException` gaps per user (18 on a 3-profile host). Now pruned by name, plus a general reparse-point skip; gaps are also deduplicated. A gap list that is mostly noise hides the real gaps.
3. **Docker registry captured as `auths`** (`[^}]*` spanned the nested object → `[^{}]*`), and **PSReadLine findings doubled** (`PSReadLine`/`PSReadline` are the same file on NTFS → dedupe on lowercased path).

Two PowerShell traps also worth recording: `$Home` is a read-only automatic variable (so the scan parameter is `$HomeDir`), and `R`/`W` are built-in aliases that silently shadow single-letter helper functions.

## Validation record — real RTR, 2026-08-27

Host `THG-B2P16M2` (AID `8b34684983b64144ac9a77395a2cbfb8`), executed as `NT AUTHORITY\SYSTEM`, Windows PowerShell 5.1.26100.

| check | result |
|---|---|
| `runscript -Raw=` delivery | works |
| Multi-user as SYSTEM | 3 profiles enumerated (`Kebab`, `proffittj`, `StaffTechnology`) — a user-context run saw only 1 |
| `-AllUsers` full scan | rc=0, ~3s, 0 findings, 0 errors, **0 coverage gaps** |
| Live positive control | planted `.env` marker → detected, correct owner + classification, **no secret value in output**, rc=1 |
| Metadata-only invariant | finding carried key name / reason / path / owner only |
| Teardown | marker + all temp JSON removed, removal verified, rescan back to 0/0/0 |

Synthetic fixture validation (local, two users): 14/14 positive controls fired at correct severity; all negative controls held — encrypted SSH key and loopback kubeconfig became observations not findings, and the `op://` reference produced nothing.

## AntiVenom (`antivenom.ps1`)

The Windows remediation-pack generator, sibling of `antivenom.py`. Operator-side (runs on the analyst's workstation against a collected scan JSON, not over RTR), metadata-only (the scanner already stripped values). It groups findings into work units by owner + work area, emits `index.md` / `metadata.md` / `tasks/<id>.md` / PowerShell launchers, and words every remediation for Windows (Credential Manager, DPAPI, `icacls`, `aws sso`, PSReadLine clearing, the `windows_native` set).

**Rotation gate.** Preserved from the Python: a `malware_persistence` finding gates the whole pack (no launchers; every task carries a stop notice; the incident-response task lists Windows shutdown steps — disable scheduled task / Run key / service, then delete, then re-scan — before any rotation). The Windows scanner v1 emits no persistence categories, so the gate is dormant but conservative. **It does not replicate the six edge-case invariants of antivenom.py's gate** (mixed-unit predicate, launcher-clearing on reuse, `--combined` gating, etc.) because the Windows scanner cannot yet produce the inputs those address; when the v2 supply-chain categories land, the gate should be hardened to match.

### AntiVenom validation (local, 2026-08-27)

Against a 14-finding scan of the synthetic fixture: 14 findings → 9 work units, worst-first, correct owner+area grouping; task files render Windows-correct remediation; launchers generated for launchable units only. Rotation-gate test (a `malware_persistence` finding injected into the report): pack correctly gated — `[ROTATION GATED]`, rc=1, **0 launchers written**, stop notice on `index.md` and on every task file, incident-response task carrying the Windows shutdown-before-rotate steps.

## Open items

- **Single-shot inline delivery at ~54 KB is unverified.** Perl proved ~35 KB; Python failed at ~167 KB. For fleet use, prefer chunked write → `Invoke-Expression`, or Falcon Response Files staging, until confirmed.
- **Supply-chain-compromise categories** (`npm_supply_chain`, `agent_autostart_hooks`, `repo_worm_artifacts`, `malware_persistence`) are v2, pending their own approval.
- **A Windows remediation generator** (the `antivenom.py` equivalent) is not yet built.
- **Fleet run** needs its own CSO/SecOps approval — a new ~3,000-host population, ~10× the Mac estate.
