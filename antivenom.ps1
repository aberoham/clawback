<#
    antivenom.ps1 - Windows remediation-pack generator for rattlesnake.ps1
    scan output. The Windows sibling of antivenom.py.

    Consumes a rattlesnake JSON report (findings + observations + scan_scope)
    and writes a remediation pack: index.md, metadata.md, tasks/<id>.md, and
    PowerShell launchers under launch/. Findings are grouped into work units
    by owner + work area (project root, or a config area like .aws / .ssh).

    OPERATOR-SIDE, not endpoint-side. This runs on the analyst's Windows
    workstation against a collected scan JSON. It is NOT delivered over RTR,
    so the no-backtick rule that governs rattlesnake.ps1 does not apply here -
    though the file avoids continuation backticks anyway for house style.

    METADATA-ONLY throughout: the scanner already stripped every secret value,
    so this tool only ever handles paths, key names, owners and reasons. It
    never sees or emits a credential.

    SAFETY - the rotation gate. A malware_persistence finding means a watcher
    may be live whose handler fires the moment a stolen token is revoked
    (the Shai-Hulud pattern deleted the user's home directory). Rotating first
    is the trigger. So any such finding GATES THE WHOLE PACK: no launchers are
    written, every task carries a stop notice, and the shutdown steps come
    before any rotation. The Windows scanner v1 does not emit persistence
    categories yet, so the gate is dormant - but it is implemented in the
    conservative direction so that when the v2 supply-chain categories land,
    the safe ordering already holds. This mirrors antivenom.py's gate; the
    Windows scanner cannot yet produce the mixed-unit edge cases the Python
    gate's six invariants address, and that limitation is stated in the README.

    v0.1 - 2026-08-27
#>

[CmdletBinding()]
param(
    [Alias('i')]
    [string] $InputPath = '',
    [string] $OutputDir = '',
    [switch] $Preview,
    [switch] $Combined,
    [switch] $Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ANTIVENOM_VERSION = '0.1-win'

# category -> remediation fix-type. Same mapping as antivenom.py, plus the
# Windows-only windows_native category. Persistence/supply-chain categories
# are human-first incident response, never agent-automatable config fixes.
$FIX_TYPE_MAP = @{
    'env_files'              = 'env_rewrite'
    'shell_profiles'         = 'profile_rewrite'
    'environment_variables'  = 'env_var_trace'
    'ssh_keys'               = 'ssh_harden'
    'git_credentials'        = 'git_credential_store'
    'package_manager_tokens' = 'token_migrate'
    'cloud_credentials'      = 'cloud_migrate'
    'kubernetes'             = 'kubeconfig_migrate'
    'secrets_manager_status' = 'posture'
    'windows_native'         = 'windows_native_fix'
    'teampcp_ioc'            = 'incident_response'
    'npm_supply_chain'       = 'incident_response'
    'agent_autostart_hooks'  = 'incident_response'
    'repo_worm_artifacts'    = 'incident_response'
    'malware_persistence'    = 'incident_response'
}

# Categories whose watcher fires on revocation - these gate the pack.
$LIVE_PERSISTENCE_CATEGORIES = @('malware_persistence')

# Fix-types that are human-only (no launcher).
$INCIDENT_FIX_TYPES = @('incident_response')

$SEVERITY_RANK = @{ 'critical' = 0; 'high' = 1; 'medium' = 2; 'low' = 3 }

function Write-Note {
    param([string]$Message)
    if (-not $Quiet) { [Console]::Error.WriteLine('[antivenom] ' + $Message) }
}

# ------------------------------------------------------------------ input

function Read-Report {
    if ($InputPath -ne '') {
        if (-not (Test-Path -LiteralPath $InputPath)) {
            [Console]::Error.WriteLine('[antivenom] input not found: ' + $InputPath)
            exit 2
        }
        $raw = [System.IO.File]::ReadAllText($InputPath)
    }
    else {
        $raw = [Console]::In.ReadToEnd()
    }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        [Console]::Error.WriteLine('[antivenom] empty input')
        exit 2
    }
    try {
        return ($raw | ConvertFrom-Json)
    }
    catch {
        [Console]::Error.WriteLine('[antivenom] input is not valid JSON: ' + $_.Exception.Message)
        exit 2
    }
}

# ---------------------------------------------------------------- helpers

function Get-Detail {
    param($Finding, [string]$Key, $Default = $null)
    if ($null -eq $Finding.details) { return $Default }
    $p = $Finding.details.PSObject.Properties[$Key]
    if ($null -eq $p) { return $Default }
    return $p.Value
}

function Get-Basename {
    param([string]$Path)
    if ($Path -match '^HK(LM|CU|CR|U|CC)[:\\]') { return $Path }
    return (Split-Path $Path -Leaf)
}

function Get-FixType {
    param([string]$Category)
    if ($FIX_TYPE_MAP.ContainsKey($Category)) { return $FIX_TYPE_MAP[$Category] }
    return 'generic'
}

# Work area for a finding: a project root if the path sits under one, else a
# per-category config area. Registry and host artifacts group under the host.
function Get-WorkArea {
    param($Finding)
    $path = [string]$Finding.path
    $owner = [string]$Finding.owner
    $cat = [string]$Finding.category

    if ($cat -eq 'windows_native') {
        return @{ Root = '(host)'; Type = 'standalone'; Slug = 'windows-native' }
    }
    if ($path -match '^HK(LM|CU|CR|U|CC)[:\\]') {
        return @{ Root = '(host)'; Type = 'standalone'; Slug = 'registry' }
    }

    # env_files / repo work: find a project root by walking up for a .git,
    # package.json, pyproject.toml, .csproj or a Desktop/Documents/source
    # project directory.
    if ($cat -eq 'env_files') {
        $root = Get-ProjectRoot $path
        if ($root) {
            return @{ Root = $root; Type = 'repo'; Slug = (Split-Path $root -Leaf) }
        }
    }

    # Config-area grouping by the credential's home-relative directory.
    $leafDir = Split-Path $path -Parent
    $slug = switch -Regex ($path) {
        '\\\.aws\\'    { '.aws';    break }
        '\\\.ssh\\'    { '.ssh';    break }
        '\\\.kube\\'   { '.kube';   break }
        '\\\.docker\\' { '.docker'; break }
        '\\\.azure\\'  { '.azure';  break }
        '\\gcloud\\'   { 'gcloud';  break }
        'WindowsPowerShell|PowerShell|PSReadLine' { 'shell-profiles'; break }
        '\.npmrc|\.pypirc|\.cargo|\.gem|pip\.ini|NuGet' { 'package-managers'; break }
        '\.git-credentials|\.gitconfig|_netrc|\.netrc' { 'git-credentials'; break }
        default { (Split-Path $leafDir -Leaf) }
    }
    # Scope config areas to the owning user so two users' .aws do not merge.
    $areaRoot = $owner + ':' + $slug
    return @{ Root = $areaRoot; Type = 'standalone'; Slug = $slug }
}

function Get-ProjectRoot {
    param([string]$Path)
    $dir = Split-Path $Path -Parent
    $markers = @('.git', 'package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml')
    $guard = 0
    while ($dir -and $guard -lt 40) {
        $guard = $guard + 1
        foreach ($m in $markers) {
            if (Test-Path -LiteralPath (Join-Path $dir $m)) { return $dir }
        }
        $parent = Split-Path $dir -Parent
        if ($parent -eq $dir -or [string]::IsNullOrEmpty($parent)) { break }
        # Stop at a user profile root - do not walk into C:\Users.
        if ($dir -match '(?i)\\Users\\[^\\]+$') { break }
        $dir = $parent
    }
    return $null
}

function Get-WorstSeverity {
    param([System.Object[]]$Findings)
    $worst = 3
    foreach ($f in $Findings) {
        $r = 3
        if ($SEVERITY_RANK.ContainsKey([string]$f.severity)) { $r = $SEVERITY_RANK[[string]$f.severity] }
        if ($r -lt $worst) { $worst = $r }
    }
    return ($SEVERITY_RANK.GetEnumerator() | Where-Object { $_.Value -eq $worst } | Select-Object -First 1).Key
}

# ------------------------------------------------------------- grouping

function Group-WorkUnits {
    param([System.Object[]]$Findings)
    $buckets = [ordered]@{}
    foreach ($f in $Findings) {
        $area = Get-WorkArea $f
        $owner = [string]$f.owner
        if ([string]::IsNullOrEmpty($owner)) { $owner = '(host)' }
        $key = $owner + '||' + $area.Root + '||' + $area.Slug
        if (-not $buckets.Contains($key)) {
            $buckets[$key] = @{
                Owner = $owner; Root = $area.Root; Slug = $area.Slug
                Type = $area.Type; Findings = New-Object System.Collections.ArrayList
            }
        }
        [void]$buckets[$key].Findings.Add($f)
    }

    $units = New-Object System.Collections.ArrayList
    foreach ($k in $buckets.Keys) {
        $b = $buckets[$k]
        [void]$units.Add([ordered]@{
            Owner    = $b.Owner
            Root     = $b.Root
            Slug     = $b.Slug
            Type     = $b.Type
            Severity = (Get-WorstSeverity ($b.Findings.ToArray()))
            Findings = $b.Findings.ToArray()
        })
    }

    # Sort worst-first, then assign stable ids.
    $sorted = @($units | Sort-Object `
        @{ Expression = { $SEVERITY_RANK[[string]$_.Severity] } }, `
        @{ Expression = { -1 * $_.Findings.Count } }, `
        @{ Expression = { $_.Owner } }, `
        @{ Expression = { $_.Slug } })
    $i = 0
    foreach ($u in $sorted) {
        $i = $i + 1
        $u['Id'] = ('unit-{0:D2}' -f $i)
        $u['Label'] = ($u.Owner + ' / ' + $u.Slug)
    }
    return $sorted
}

function Test-IncidentUnit {
    param($Unit)
    foreach ($f in $Unit.Findings) {
        if ((Get-FixType ([string]$f.category)) -eq 'incident_response') { return $true }
    }
    return $false
}

function Test-RotationGated {
    param([System.Object[]]$AllFindings)
    foreach ($f in $AllFindings) {
        if ($LIVE_PERSISTENCE_CATEGORIES -contains [string]$f.category) { return $true }
    }
    return $false
}

# ===================================================== remediation sections
# One builder per fix-type, Windows-worded. Each returns an array of markdown
# lines. The target state everywhere is the same: rotate at the provider, then
# stop persisting the literal - Windows Credential Manager, DPAPI-protected
# storage, or a secrets manager (op:// references) - never move plaintext to
# another plaintext file.

function Section-Header {
    param([int]$Num, [string]$Title)
    return @("### $Num. $Title", "")
}

function Paths-Of {
    param([System.Object[]]$Findings)
    return @($Findings | ForEach-Object { '`' + $_.path + '`' } | Sort-Object -Unique)
}

function Sec-EnvRewrite {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Remove literal secrets from .env files'
    $lines += 'For each variable flagged below, the value is a literal secret committed to a `.env` on disk.'
    $lines += ''
    foreach ($f in $Findings) {
        $lines += ('- `' + $f.path + '` - `' + (Get-Detail $f 'key_name' '(name)') + '` (line ' + (Get-Detail $f 'line' '?') + ', ' + (Get-Detail $f 'reason' '') + ')')
    }
    $lines += @(
        ''
        '1. **Rotate first.** Revoke the credential at its provider and issue a replacement - the on-disk value must be treated as compromised.'
        '2. **Replace the literal with a reference.** Prefer a 1Password `op://` reference resolved at runtime (`op run -- <cmd>`), or read it from Windows Credential Manager at startup. A `${ENV}` / `op://` reference is the target state and is not a finding.'
        '3. **Confirm `.env` is git-ignored** so the replacement is not committed, and purge the secret from history if it ever was (`git filter-repo` or BFG).'
        '4. **Delete any stale copy** (`.env.bak`, `.env.local~`) that still holds the plaintext.'
    )
    return $lines
}

function Sec-ProfileRewrite {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Remove secrets from PowerShell profiles and console history'
    $hasHistory = @($Findings | Where-Object { (Get-Detail $_ 'artifact' '') -eq 'psreadline_history' }).Count -gt 0
    foreach ($f in $Findings) {
        $art = Get-Detail $f 'artifact' 'profile'
        $lines += ('- `' + $f.path + '` (' + $art + ', line ' + (Get-Detail $f 'line' '?') + ')')
    }
    $lines += @(
        ''
        '1. **Rotate first** - anything typed at a prompt or exported from a profile must be treated as exposed.'
        '2. **Profiles:** remove the `$env:NAME = ''...''` / `setx` literal from `Microsoft.PowerShell_profile.ps1`; set the variable at startup from Windows Credential Manager (`Get-StoredCredential`) or an `op read` call instead.'
    )
    if ($hasHistory) {
        $lines += @(
            '3. **PSReadLine history is the higher-risk artifact.** It persists every secret ever pasted at a prompt, across sessions, and OneDrive backs it up. Clear it:'
            '   ```'
            '   Remove-Item (Get-PSReadLineOption).HistorySavePath -Force'
            '   ```'
            '   For privileged shells, stop persisting history entirely:'
            '   ```'
            '   Set-PSReadLineOption -HistorySaveStyle SaveNothing'
            '   ```'
        )
    }
    return $lines
}

function Sec-EnvVarTrace {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Machine/user environment variables holding secrets'
    foreach ($f in $Findings) {
        $lines += ('- `' + (Get-Detail $f 'key_name' '(name)') + '` in `' + $f.path + '`')
    }
    $lines += @(
        ''
        '1. **Rotate first.** A machine-scope variable is readable by every process on the host.'
        '2. **Remove the variable** and inject the secret at process start from Credential Manager or a secrets manager instead of persisting it in the environment block.'
        '   ```'
        '   [Environment]::SetEnvironmentVariable(''NAME'', $null, ''Machine'')'
        '   ```'
    )
    return $lines
}

function Sec-SshHarden {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Protect SSH private keys'
    foreach ($f in $Findings) {
        $enc = Get-Detail $f 'encrypted' $false
        $lines += ('- `' + $f.path + '` (' + (Get-Detail $f 'key_type' 'key') + ', encrypted=' + $enc + ')')
    }
    $lines += @(
        ''
        '1. **If the key is unencrypted, treat it as compromised** - rotate it: generate a new keypair, replace the public key in every `authorized_keys` / provider it unlocks, then remove the old key.'
        '2. **Add a passphrase** to the replacement (`ssh-keygen -p -f <key>`).'
        '3. **Lock the file down** - on Windows, remove inherited ACLs and grant only the owning user:'
        '   ```'
        '   icacls <key> /inheritance:r /grant:r "$($env:USERNAME):(R)"'
        '   ```'
        '4. **Load it through the OpenSSH agent** rather than leaving it readable on disk (`Start-Service ssh-agent; ssh-add <key>`).'
    )
    return $lines
}

function Sec-GitCredentialStore {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Move git credentials into Windows Credential Manager'
    foreach ($f in $Findings) {
        $h = Get-Detail $f 'host' ''
        $lines += ('- `' + $f.path + '`' + $(if ($h) { ' (' + $h + ')' } else { '' }))
    }
    $lines += @(
        ''
        '1. **Revoke the token/password** at the provider - a plaintext `.git-credentials` or `_netrc` entry is exposed to every process that can read the profile.'
        '2. **Switch the helper to the Windows Credential Manager backend:**'
        '   ```'
        '   git config --global credential.helper manager'
        '   ```'
        '3. **Delete the plaintext store** (`.git-credentials`, `_netrc`) once the manager holds the new credential.'
        '4. The next `git` operation against the host will prompt once and store it encrypted in Credential Manager.'
    )
    return $lines
}

function Sec-TokenMigrate {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Rotate package-manager and registry tokens'
    foreach ($f in $Findings) {
        $svc = Get-Detail $f 'service' 'registry'
        $lines += ('- `' + $f.path + '` (' + $svc + ')')
    }
    $lines += @(
        ''
        '1. **Revoke each token** at its registry (npm, PyPI, cargo, Docker, NuGet) and issue a scoped, short-lived replacement.'
        '2. **Do not persist the replacement in the rc file.** Prefer a CI-scoped token injected at build time, or `op run` to resolve it at runtime.'
        '3. **Docker specifically:** `docker logout`, then configure the Windows credential store so `~/.docker/config.json` stops holding a base64 `auth`:'
        '   ```'
        '   docker-credential-wincred'
        '   ```'
    )
    return $lines
}

function Sec-CloudMigrate {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Rotate and de-persist cloud credentials'
    foreach ($f in $Findings) {
        $prov = Get-Detail $f 'provider' 'cloud'
        $lines += ('- `' + $f.path + '` (' + $prov + ')')
    }
    $lines += @(
        ''
        '1. **Rotate first** - a static long-lived cloud key on disk is the highest-value target here.'
        '   - **AWS:** deactivate then delete the access key in IAM; move to `aws sso login` (short-lived) or an instance/role credential.'
        '   - **GCP:** `gcloud auth application-default revoke`; delete any downloaded service-account JSON and move the workload to Workload Identity Federation or an attached service account.'
        '   - **Azure:** `az logout` on shared/decommissioned hosts; prefer managed identity or device-code auth.'
        '2. **Remove the file from disk** once the workload uses keyless auth.'
    )
    return $lines
}

function Sec-KubeconfigMigrate {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Move kubeconfig off embedded credentials'
    foreach ($f in $Findings) {
        $tier = Get-Detail $f 'endpoint_tier' ''
        $lines += ('- `' + $f.path + '` (' + $tier + ')')
    }
    $lines += @(
        ''
        '1. **A remote-cluster token or client key embedded in kubeconfig is a live credential.** Rotate it in-cluster - for a ServiceAccount token: `kubectl -n <ns> delete secret <name>` and re-issue.'
        '2. **Switch to exec-based short-lived auth** (`exec` credential plugin / OIDC) so no static material sits in `~/.kube/config`.'
        '3. Local-only clusters (Docker Desktop / kind / rancher-desktop) are reported as observations, not findings - no action.'
    )
    return $lines
}

function Sec-WindowsNative {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Windows-native credential artifacts'
    foreach ($f in $Findings) {
        $art = Get-Detail $f 'artifact' 'artifact'
        $lines += ('- **' + $art + '**: `' + $f.path + '`')
    }
    $lines += @(
        ''
        '**These are host-level and several are trivially reversible - treat as urgent.**'
        ''
        '- **`gpp_cpassword`**: reset the named account''s password immediately (the GPP AES key is public), delete the GPP item, and audit SYSVOL for other `cpassword` occurrences. MS14-025 stopped new ones but did not remove existing.'
        '- **`unattend`**: delete the answer file from the image and the host, and rotate any account it names. Base64 (`PlainText=false`) is not encryption.'
        '- **`winlogon_autologon`**: remove `DefaultPassword`, set `AutoAdminLogon`=0, rotate the account. Use LAPS or a managed service account if unattended logon is genuinely required.'
        '- **`machine_env_var`**: rotate and remove the variable - machine-scope env vars are readable by every process.'
        '- **`iis_connection_string`**: rotate the DB credential and encrypt the config section (`aspnet_regiis -pe "connectionStrings"`) or move to a managed identity.'
    )
    return $lines
}

function Sec-Generic {
    param([int]$Num, [System.Object[]]$Findings)
    $lines = Section-Header $Num 'Remediate flagged secrets'
    foreach ($f in $Findings) {
        $lines += ('- `' + $f.path + '` - ' + $f.description)
        $lines += ('  - ' + $f.remediation)
    }
    return $lines
}

$SECTION_BUILDERS = @{
    'env_rewrite'          = 'Sec-EnvRewrite'
    'profile_rewrite'      = 'Sec-ProfileRewrite'
    'env_var_trace'        = 'Sec-EnvVarTrace'
    'ssh_harden'           = 'Sec-SshHarden'
    'git_credential_store' = 'Sec-GitCredentialStore'
    'token_migrate'        = 'Sec-TokenMigrate'
    'cloud_migrate'        = 'Sec-CloudMigrate'
    'kubeconfig_migrate'   = 'Sec-KubeconfigMigrate'
    'windows_native_fix'   = 'Sec-WindowsNative'
    'generic'              = 'Sec-Generic'
    'posture'              = 'Sec-Generic'
}

# ============================================================ gate notices

function Get-GateNotice {
    return @(
        '> ## STOP - malware persistence was found on this host'
        '>'
        '> A finding in this scan indicates a watcher whose handler fires the moment a stolen token stops working. Any credential rotation or revocation below MUST wait until that watcher is removed - revoking first is the trigger. See the incident-response task and the shutdown steps below, then re-scan before acting on any other file.'
        ''
    )
}

function Get-WindowsShutdownSteps {
    param([System.Object[]]$PersistenceFindings)
    $lines = @(
        ''
        '## STOP - do this before ANY credential rotation'
        ''
        'A watcher planted by this campaign polls for its stolen token and executes a remote-supplied command the moment that token stops working. Revoking first is the trigger.'
        ''
        '1. **Disable the persistence mechanism (do not delete yet):**'
        '   - Scheduled task: `schtasks /change /tn "<name>" /disable`'
        '   - Run key: remove the value under `HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (note it first).'
        '   - Service: `Stop-Service <name>; Set-Service <name> -StartupType Disabled`'
        '2. **Then delete the payload and its state** - each path this scan flagged under `malware_persistence`:'
    )
    foreach ($f in $PersistenceFindings) { $lines += ('   - `' + $f.path + '`') }
    $lines += @(
        '3. **Re-scan** with rattlesnake.ps1 and confirm no `malware_persistence` finding remains.'
        ''
        'Only once that is clean should you proceed to rotation.'
        ''
    )
    return $lines
}

# ============================================================ task files

function Compile-Task {
    param($Unit, [bool]$Gated)
    $isIR = Test-IncidentUnit $Unit

    if ($isIR) {
        $lines = @(
            ('# Task ' + $Unit.Id + ' (CRITICAL) - ' + $Unit.Label)
            ''
            '**THIS TASK REQUIRES IMMEDIATE HUMAN ACTION. Do not use automated remediation.**'
            ''
            '## Indicators'
            ''
        )
        foreach ($f in $Unit.Findings) { $lines += ('- `' + $f.path + '`: ' + $f.description) }
        $persist = @($Unit.Findings | Where-Object { $LIVE_PERSISTENCE_CATEGORIES -contains [string]$_.category })
        if ($persist.Count -gt 0) { $lines += (Get-WindowsShutdownSteps $persist) }
        $lines += @('', '## Then', '', '1. Isolate the host from the network.', '2. Preserve forensic evidence before cleanup.', '3. Only after the watcher is confirmed gone, rotate every credential this scan flagged.')
        return ($lines -join [char]10)
    }

    $lines = @()
    if ($Gated) { $lines += (Get-GateNotice) }
    $lines += @(
        ('# Task ' + $Unit.Id + ' (' + $Unit.Severity + ' severity) - ' + $Unit.Label)
        ''
        ('Owner: `' + $Unit.Owner + '`  |  Area: `' + $Unit.Root + '`')
        ''
        'Metadata-only: no secret values appear below or in the scan - only locations, key names and reasons.'
        ''
        '## Findings'
        ''
    )
    $byCat = @{}
    foreach ($f in $Unit.Findings) {
        $c = [string]$f.category
        if (-not $byCat.ContainsKey($c)) { $byCat[$c] = New-Object System.Collections.ArrayList }
        [void]$byCat[$c].Add($f)
    }
    foreach ($c in ($byCat.Keys | Sort-Object)) {
        $paths = (Paths-Of ($byCat[$c].ToArray())) -join ', '
        $lines += ('- **' + $c + '**: ' + $byCat[$c].Count + ' finding(s) in ' + $paths)
    }
    $lines += @('', '## Remediation', '')

    # Group by fix-type, one section each, worst categories first.
    $byFix = [ordered]@{}
    foreach ($f in $Unit.Findings) {
        $ft = Get-FixType ([string]$f.category)
        if (-not $byFix.Contains($ft)) { $byFix[$ft] = New-Object System.Collections.ArrayList }
        [void]$byFix[$ft].Add($f)
    }
    $n = 0
    foreach ($ft in $byFix.Keys) {
        $n = $n + 1
        $builder = 'Sec-Generic'
        if ($SECTION_BUILDERS.ContainsKey($ft)) { $builder = $SECTION_BUILDERS[$ft] }
        $lines += (& $builder -Num $n -Findings ($byFix[$ft].ToArray()))
        $lines += ''
    }

    $lines += @(
        '## Constraints'
        ''
        '- Do not relocate plaintext secrets to another plaintext file.'
        '- Delete or neutralise the orphaned credential file after migration.'
        '- Preserve comments and formatting in edited files; prefer targeted edits.'
        ''
        '## Verification'
        ''
        '- Re-run `rattlesnake.ps1` scoped to this area and confirm the finding is gone.'
        '- Confirm the replacement resolves from Credential Manager / `op://`, not from a file.'
    )
    return ($lines -join [char]10)
}

# ============================================================ index / meta

function Compile-Index {
    param([System.Object[]]$Units, $Report, [bool]$Gated)
    $lines = @(
        '# Remediation pack'
        ''
        ('Generated by antivenom.ps1 ' + $ANTIVENOM_VERSION + ' from a rattlesnake scan of `' + $Report.hostname + '`.')
        ''
    )
    if ($Gated) {
        $lines += (Get-GateNotice)
        $lines += '**Launchers are withheld while the pack is gated.** Clear the persistence finding and regenerate.'
        $lines += ''
    }
    $lines += @(
        ('Host: `' + $Report.hostname + '`  |  Scan mode: `' + $Report.scan_mode + '`  |  Users: ' + (@($Report.users_scanned) -join ', '))
        ('Findings: ' + $Report.total_findings + '  (critical ' + $Report.summary.critical + ', high ' + $Report.summary.high + ', medium ' + $Report.summary.medium + ', low ' + $Report.summary.low + ')')
        ''
        '## Work units'
        ''
        '| Unit | Severity | Owner | Area | Findings | Launcher |'
        '|---|---|---|---|---|---|'
    )
    foreach ($u in $Units) {
        $ir = Test-IncidentUnit $u
        $launch = if ($Gated -or $ir) { 'human-only' } else { ('`launch/' + $u.Id + '-claude.ps1`') }
        $lines += ('| [' + $u.Id + '](tasks/' + $u.Id + '.md) | ' + $u.Severity + ' | `' + $u.Owner + '` | `' + $u.Slug + '` | ' + $u.Findings.Count + ' | ' + $launch + ' |')
    }
    $lines += @(
        ''
        '## How to use'
        ''
        '1. Open each `tasks/<id>.md` - it is a self-contained, agent-ready prompt.'
        '2. For a launchable unit, run its launcher to open Claude Code in plan mode against that task:'
        '   ```'
        '   powershell -NoProfile -File launch\<id>-claude.ps1'
        '   ```'
        '3. Incident-response and gated units are human-only and carry no launcher.'
        ''
        '_No tmux on Windows: launch units individually, or open several in Windows Terminal tabs._'
    )
    return ($lines -join [char]10)
}

function Compile-Metadata {
    param($Report, [System.Object[]]$Units, [bool]$Gated)
    $gaps = @($Report.scan_scope.coverage_gaps).Count
    return (@(
        '# Pack metadata'
        ''
        ('- antivenom: ' + $ANTIVENOM_VERSION)
        ('- scanner: ' + $Report.scanner_version + ' (schema ' + $Report.schema_version + ')')
        ('- host: ' + $Report.hostname)
        ('- scan timestamp: ' + $Report.timestamp)
        ('- scan mode: ' + $Report.scan_mode)
        ('- users scanned: ' + (@($Report.users_scanned) -join ', '))
        ('- categories scanned: ' + (@($Report.scan_scope.categories_scanned) -join ', '))
        ('- coverage gaps: ' + $gaps)
        ('- total findings: ' + $Report.total_findings)
        ('- work units: ' + $Units.Count)
        ('- rotation gated: ' + $Gated)
        ''
        'Metadata-only: this pack was generated from a report that contains no secret values, and antivenom handled only paths, key names and reasons.'
    ) -join [char]10)
}

# ============================================================ launchers

function Compile-Launcher {
    param($Unit, [string]$PackPath)
    $taskPath = Join-Path $PackPath ('tasks\' + $Unit.Id + '.md')
    return (@(
        '# Claude Code launcher for ' + $Unit.Id + ' - review the task, then start plan mode.'
        '$ErrorActionPreference = ''Stop'''
        ('$task = ' + "'" + $taskPath + "'")
        'Get-Content -LiteralPath $task | Write-Host'
        'Write-Host '''''
        'Read-Host ''Press Enter to start Claude Code in plan mode (Ctrl+C to cancel)'''
        'claude --permission-mode plan (Get-Content -LiteralPath $task -Raw)'
    ) -join [char]10)
}

# ============================================================ pack write

function Write-Pack {
    param([System.Object[]]$Units, $Report, [bool]$Gated, [string]$Dest)
    New-Item -ItemType Directory -Path $Dest -Force | Out-Null
    $tasksDir = Join-Path $Dest 'tasks'
    $launchDir = Join-Path $Dest 'launch'
    New-Item -ItemType Directory -Path $tasksDir -Force | Out-Null
    New-Item -ItemType Directory -Path $launchDir -Force | Out-Null

    foreach ($u in $Units) {
        [System.IO.File]::WriteAllText((Join-Path $tasksDir ($u.Id + '.md')), (Compile-Task $u $Gated) + [char]10)
        $ir = Test-IncidentUnit $u
        if ($Gated -or $ir) { continue }
        [System.IO.File]::WriteAllText((Join-Path $launchDir ($u.Id + '-claude.ps1')), (Compile-Launcher $u $Dest) + [char]10)
    }
    [System.IO.File]::WriteAllText((Join-Path $Dest 'index.md'), (Compile-Index $Units $Report $Gated) + [char]10)
    [System.IO.File]::WriteAllText((Join-Path $Dest 'metadata.md'), (Compile-Metadata $Report $Units $Gated) + [char]10)
}

# ================================================================== main

$report = Read-Report
$findings = @()
if ($report.PSObject.Properties['findings']) { $findings = @($report.findings) }

if ($findings.Count -eq 0) {
    Write-Note 'no findings in report - nothing to remediate'
    if ($Preview) { [Console]::Out.WriteLine('No findings.') }
    exit 0
}

$gated = Test-RotationGated $findings
$units = @(Group-WorkUnits $findings)
Write-Note ('grouped ' + $findings.Count + ' finding(s) into ' + $units.Count + ' work unit(s)' + $(if ($gated) { ' [ROTATION GATED]' } else { '' }))

if ($Preview) {
    $out = New-Object System.Text.StringBuilder
    [void]$out.AppendLine('Remediation preview - ' + $report.hostname + ($(if ($gated) { '  [ROTATION GATED]' } else { '' })))
    foreach ($u in $units) {
        $ir = Test-IncidentUnit $u
        $tag = if ($gated -or $ir) { 'human-only' } else { 'launchable' }
        [void]$out.AppendLine(('  ' + $u.Id + '  [' + $u.Severity + ']  ' + $u.Label + '  (' + $u.Findings.Count + ' finding(s), ' + $tag + ')'))
        foreach ($f in $u.Findings) {
            [void]$out.AppendLine(('      - ' + $f.category + '  ' + $f.path))
        }
    }
    [Console]::Out.WriteLine($out.ToString())
    exit $(if ($gated) { 1 } else { 0 })
}

if ($Combined) {
    $doc = New-Object System.Text.StringBuilder
    [void]$doc.AppendLine((Compile-Index $units $report $gated))
    foreach ($u in $units) {
        [void]$doc.AppendLine('')
        [void]$doc.AppendLine('---')
        [void]$doc.AppendLine('')
        [void]$doc.AppendLine((Compile-Task $u $gated))
    }
    [Console]::Out.WriteLine($doc.ToString())
    exit $(if ($gated) { 1 } else { 0 })
}

if ($OutputDir -eq '') {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $OutputDir = Join-Path (Join-Path (Get-Location) 'antivenom-packs') $stamp
}
Write-Pack $units $report $gated $OutputDir
Write-Note ('pack written to ' + $OutputDir)
[Console]::Out.WriteLine($OutputDir)
exit $(if ($gated) { 1 } else { 0 })
