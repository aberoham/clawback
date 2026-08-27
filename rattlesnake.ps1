<#
    rattlesnake.ps1 - Windows port of the THG fork's secret-at-rest scanner.
    DISCOVERY ONLY. READ-ONLY. METADATA-ONLY OUTPUT - never emits a secret
    value; only paths, key names, an owner, and a classification reason.

    Runtime: Windows PowerShell 5.1 (System.Management.Automation, .NET
    Framework). Measured 2026-08-27 across the estate: powershell.exe present
    on 2,999 of 3,037 Windows hosts (98.7%); pwsh.exe on 30 (1.0%). 5.1 is
    therefore the only viable target - the inverse of the macOS problem, where
    ~41% of Macs lacked /usr/bin/python3 and forced the Perl port.

    DELIVERY - read this before editing:

    1. NO BACKTICKS ANYWHERE IN THIS FILE. RTR delivers inline payloads with
       runscript -Raw= wrapped in a triple-backtick delimiter, and a stray
       backtick in the payload can close that delimiter early. (This comment
       deliberately does not spell the delimiter out, for the same reason.)
       The macOS Perl port carries the same rule. It is harder here
       because the backtick IS PowerShell's escape character, so every escape
       must be spelled out: [char]10 for newline, [char]34 for a quote, and so
       on. There is no linting for this - it is a discipline. Check before you
       commit:  Select-String -Path rattlesnake.ps1 -Pattern ([char]96)

    2. RUN INLINE. DO NOT WRITE THIS TO DISK AND EXECUTE IT. Managed builds
       run ExecutionPolicy Restricted in every scope, so a dropped .ps1 will
       not run. Falcon's runscript host executes the payload directly and
       bypasses the policy entirely. This is a deliberate divergence from
       rattlesnake.pl, which wrote a temp file and self-deleted; the inline
       path writes nothing at all, which is a strictly better read-only story.

    3. Output goes to stdout as one JSON object. -OutputFile is provided for
       parity but writing to disk on a managed endpoint is discouraged.

    Contract: schema-compatible with rattlesnake.py so antivenom.py and the
    hunt findings register consume it unchanged. Exit 0 clean / 1 findings /
    2 scan error.

    Scope v1: the secrets-at-rest equivalents
    plus the Windows-native surface that has no macOS analogue. The four
    supply-chain-compromise categories are deliberately NOT ported yet - they
    carry a bigger blast radius and the macOS case requires their own separate
    CSO/SecOps approval.

    v0.1 - 2026-08-27
#>

[CmdletBinding()]
param(
    [string]   $Category      = '',
    [switch]   $AllUsers,
    [switch]   $CurrentUserOnly,
    [string]   $UsersRoot     = '',
    [int]      $MaxSeconds    = 0,
    [switch]   $Pretty,
    [switch]   $Quiet,
    [string]   $OutputFile    = '',
    [switch]   $Ndjson,
    [string]   $HostId        = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$SCANNER_VERSION = '0.1-win'
$SCHEMA_VERSION  = '1'

# Read caps. Each exists so an oversize artifact becomes a recorded coverage
# gap rather than a silent skip - the macOS scanner learned this the hard way
# when a 64 KiB cap hid credentials at byte ~261k of a real kubeconfig.
$MAX_FILE_BYTES     = 1000000
$MAX_KUBECFG_BYTES  = 4194304
$MAX_HISTORY_BYTES  = 2000000
$ENV_MAX_DEPTH      = 4

# ---------------------------------------------------------------- constants

# Highest-confidence signal: a value that starts with one of these is a
# credential by construction. Kept byte-identical to rattlesnake.py.
$KNOWN_SECRET_PREFIXES = @(
    'sk-', 'sk_live_', 'sk_test_', 'pk_live_', 'pk_test_',
    'ghp_', 'gho_', 'ghs_', 'github_pat_',
    'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-',
    'AKIA', 'glpat-', 'pypi-', 'npm_', 'whsec_',
    'sq0atp-', 'sq0csp-', 'SG.', 'key-', 'rk_live_',
    'eyJ', '-----BEGIN', 'AIZA', 'AIza', 'ya29.',
    'AGE-SECRET-KEY-', 'lsv2_pt_'
)

# Tier 1 names: exact match means HIGH severity.
$NAMED_SECRET_VARS = @(
    'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN',
    'AZURE_CLIENT_SECRET','AZURE_TENANT_ID','ANTHROPIC_API_KEY',
    'CLOUDFLARE_API_TOKEN','DATABASE_URL','DATADOG_API_KEY','DOCKER_PASSWORD',
    'GH_TOKEN','GITHUB_TOKEN','GITLAB_TOKEN','GOOGLE_APPLICATION_CREDENTIALS',
    'HOMEBREW_GITHUB_API_TOKEN','MONGO_URI','NODE_AUTH_TOKEN','NPM_TOKEN',
    'OPENAI_API_KEY','REDIS_URL','SENDGRID_API_KEY','SLACK_TOKEN',
    'STRIPE_SECRET_KEY','TWINE_PASSWORD','TWINE_USERNAME',
    'VAULT_TOKEN','VAULT_ADDR',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN','ACTIONS_ID_TOKEN_REQUEST_URL'
)

# Tier 2 names: pattern match means MEDIUM severity.
$GENERIC_SECRET_RE = [regex]'^[A-Z_]*(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH_KEY|API_KEY|PRIVATE_KEY)[A-Z_]*$'

# Values that are plainly configuration, not credentials.
$INNOCUOUS_RES = @(
    [regex]'(?i)^(true|false|yes|no|on|off|none|null|nil)$',
    [regex]'^\d+$',
    [regex]'^\d+\.\d+(\.\d+)?',
    [regex]'^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$',
    [regex]'(?i)^(development|production|staging|test|testing|debug|info|warn|error|verbose|local)$',
    [regex]'^https?://[^:@]*(?::\d+)?(?:/\S*)?$',
    [regex]'^/[\w/.@+-]+$',
    [regex]'^(/[\w/.@+-]+)(:/[\w/.@+-]+)+$',
    [regex]'^[\w.-]+@[\w.-]+\.\w+$',
    [regex]'^[\w.-]+\.[a-z]{2,10}$',
    [regex]'^\d+[smhd]$',
    [regex]'^[a-z]{2}(-[A-Z]{2})?$',
    [regex]'^#[0-9a-fA-F]{3,8}$',
    [regex]'^\d+(\.\d+)?(px|em|rem|pt|%)$',
    [regex]'^\w{1,5}$',
    # Windows-only additions: a bare drive path or registry path is config.
    [regex]'^[A-Za-z]:\\[^\\]*(\\[^\\]*)*$',
    [regex]'(?i)^HK(LM|CU|CR|U|CC)[:\\].*$'
)

$ENV_IGNORE_SUFFIXES = @('.swp','.swo','.bak','.orig','.tmp')

# Profile directories that are not real users.
$SKIP_PROFILES = @('Public','Default','Default User','All Users','defaultuser0','WDAGUtilityAccount')

# Directories never worth walking for .env files.
$PRUNE_DIRS = @('node_modules','.git','AppData','Library','.vscode-server','venv','.venv','__pycache__','dist','build','.next','target','Packages')

# Legacy profile junction points. These are reparse points Windows keeps for
# pre-Vista compatibility and they deny access to everyone, including SYSTEM,
# by design. Walking them produced 6 UnauthorizedAccessException gaps per user
# on the first real RTR run - 18 on a 3-profile host, all noise. A gap list
# that is mostly noise is worse than no gap list, because the real gaps stop
# being visible in it.
$JUNCTION_DIRS = @(
    'My Music','My Pictures','My Videos','My Documents','Application Data',
    'Local Settings','NetHood','PrintHood','Recent','SendTo','Start Menu',
    'Templates','Cookies','History','3D Objects'
)

# ------------------------------------------------------------------- state

$script:Findings      = New-Object System.Collections.ArrayList
$script:Observations  = New-Object System.Collections.ArrayList
$script:Errors        = New-Object System.Collections.ArrayList
$script:CoverageGaps  = New-Object System.Collections.ArrayList
$script:CategoriesRun = New-Object System.Collections.ArrayList
$script:StartTime     = Get-Date

# Coverage counters. These exist because a zero-finding result was previously
# indistinguishable from a zero-traversal one - the single most important
# lesson from the macOS fleet run. Positive proof of work, independent of
# whether anything was found.
$script:Coverage = [ordered]@{
    users_enumerated        = 0
    wsl_distros_examined    = 0
    home_dirs_examined      = 0
    files_examined          = 0
    env_files_examined      = 0
    project_dirs_walked     = 0
    ssh_keys_examined       = 0
    kubeconfigs_examined    = 0
    ps_profiles_examined    = 0
    history_files_examined  = 0
    registry_keys_examined  = 0
    webconfigs_examined     = 0
}

function Write-Progress-Line {
    param([string]$Message)
    if (-not $Quiet) { [Console]::Error.WriteLine('[rattlesnake] ' + $Message) }
}

$script:GapSeen = @{}
function Add-Gap {
    param([string]$Message)
    # Deduplicated: the same directory is reached from more than one env root
    # (Documents and OneDrive\Documents resolve to overlapping trees), which
    # double-counted every gap on the first real run.
    if ($script:GapSeen.ContainsKey($Message)) { return }
    $script:GapSeen[$Message] = $true
    [void]$script:CoverageGaps.Add($Message)
}

function Add-ScanError {
    param([string]$Message)
    [void]$script:Errors.Add($Message)
}

# --------------------------------------------------------------- classifier

function Get-ShannonEntropy {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0.0 }
    $counts = @{}
    foreach ($ch in $Text.ToCharArray()) {
        if ($counts.ContainsKey($ch)) { $counts[$ch] = $counts[$ch] + 1 }
        else { $counts[$ch] = 1 }
    }
    $len = [double]$Text.Length
    $ent = 0.0
    foreach ($c in $counts.Values) {
        $p = $c / $len
        $ent = $ent - ($p * [Math]::Log($p, 2))
    }
    return $ent
}

function Remove-SurroundingQuotes {
    param([string]$Value)
    $v = $Value.Trim()
    if ($v.Length -ge 2) {
        $first = $v[0]; $last = $v[$v.Length - 1]
        if ($first -eq $last -and ($first -eq [char]34 -or $first -eq [char]39)) {
            return $v.Substring(1, $v.Length - 2)
        }
    }
    return $v
}

# Purely value-based. Never sees the variable name - that is what keeps it
# reusable across .env, shell profiles, registry values and web.config.
# Returns a hashtable: IsSecret (bool), Reason (string).
function Test-SecretValue {
    param([string]$Value)

    $s = Remove-SurroundingQuotes $Value

    if ([string]::IsNullOrWhiteSpace($s)) {
        return @{ IsSecret = $false; Reason = 'empty_or_variable_reference' }
    }
    if ($s.StartsWith('${') -or $s -eq '$') {
        return @{ IsSecret = $false; Reason = 'empty_or_variable_reference' }
    }
    # A secrets-manager reference is the TARGET state, not a finding.
    if ($s.StartsWith('op://')) {
        return @{ IsSecret = $false; Reason = '1password_reference' }
    }
    # PowerShell / cmd / shell expansion is configuration.
    if ($s -match '\$[A-Za-z_{]') {
        return @{ IsSecret = $false; Reason = 'shell_variable_expansion' }
    }
    if ($s -match '%[A-Za-z_][A-Za-z0-9_]*%') {
        return @{ IsSecret = $false; Reason = 'windows_env_expansion' }
    }

    foreach ($p in $KNOWN_SECRET_PREFIXES) {
        if ($s.StartsWith($p)) {
            return @{ IsSecret = $true; Reason = 'known_prefix:' + $p }
        }
    }

    foreach ($re in $INNOCUOUS_RES) {
        if ($re.IsMatch($s)) { return @{ IsSecret = $false; Reason = 'innocuous' } }
    }

    if ($s -match '^\w+://[^:]+:[^@]+@') {
        return @{ IsSecret = $true; Reason = 'url_with_credentials' }
    }

    if ($s.Length -ge 20) {
        $e = Get-ShannonEntropy $s
        if ($e -gt 4.5) {
            return @{ IsSecret = $true; Reason = ('high_entropy:' + $e.ToString('0.0')) }
        }
    }

    if ($s.Length -ge 32 -and $s -match '^[0-9a-fA-F]+$') {
        return @{ IsSecret = $true; Reason = 'long_hex' }
    }

    if ($s.Length -ge 32 -and $s -match '^[A-Za-z0-9+/=_-]+$') {
        $e = Get-ShannonEntropy $s
        if ($e -gt 4.0) {
            return @{ IsSecret = $true; Reason = ('likely_base64:' + $e.ToString('0.0')) }
        }
    }

    return @{ IsSecret = $false; Reason = 'benign' }
}

# Relaxed second look, used ONLY when the name already indicates a secret.
function Test-NameValueSuspicious {
    param([string]$Value)
    $s = Remove-SurroundingQuotes $Value
    if ($s.Length -lt 20) { return @{ IsSecret = $false; Reason = 'too_short' } }
    if ($s -match '^https?://') { return @{ IsSecret = $false; Reason = 'url' } }
    # Placeholders: xxx, changeme, your-key-here, <redacted>, ...
    if ($s -match '(?i)^(x{3,}|changeme|placeholder|your[-_].*|<.*>|\.\.\.|todo|redacted|example)$') {
        return @{ IsSecret = $false; Reason = 'placeholder' }
    }
    # Word-like values (sentences, kebab/snake English) are config.
    if ($s -match '^[A-Za-z][A-Za-z0-9 _-]*$' -and $s -notmatch '\d{4,}') {
        return @{ IsSecret = $false; Reason = 'word_like' }
    }
    $e = Get-ShannonEntropy $s
    if ($e -ge 3.5) {
        return @{ IsSecret = $true; Reason = ('name_and_entropy:' + $e.ToString('0.0')) }
    }
    return @{ IsSecret = $false; Reason = 'low_entropy' }
}

# The name-based second look must run ONLY when the value check reached
# "benign" - i.e. it had nothing to say. Every other negative reason is
# EXCULPATORY and must short-circuit.
#
# This existed as a real false positive: OPENAI_API_KEY=op://Employee/openai/
# credential is the REMEDIATED state, and the relaxed name+entropy path fired
# on it because op:// has no spaces, is over 20 chars and scores above 3.5
# entropy. Reporting that tells everyone who migrated to a secrets manager
# that they are still exposed, and inflates the hunt's prevalence figure with
# exactly the population that already did the right thing.
#
# Same applies to $VAR / %VAR% expansion: a reference is configuration.
function Test-ReasonIsBenign {
    param([string]$Reason)
    return ($Reason -eq 'benign')
}

function Get-NameTier {
    param([string]$Name)
    $n = $Name.Trim().ToUpperInvariant()
    if ($NAMED_SECRET_VARS -contains $n) { return 'tier1' }
    if ($GENERIC_SECRET_RE.IsMatch($n))  { return 'tier2' }
    return 'none'
}

# ----------------------------------------------------------------- findings

function New-Finding {
    param(
        [string]$Category,
        [string]$Path,
        [string]$Severity,
        [string]$Description,
        [string]$Remediation,
        [hashtable]$Details,
        [string]$Owner
    )
    if ($null -eq $Details) { $Details = @{} }
    return [ordered]@{
        category    = $Category
        path        = $Path
        severity    = $Severity
        description = $Description
        remediation = $Remediation
        details     = $Details
        owner       = $Owner
    }
}

function Add-Finding {
    param([System.Object]$Finding)
    [void]$script:Findings.Add($Finding)
}

function Add-Observation {
    param([System.Object]$Finding)
    [void]$script:Observations.Add($Finding)
}

# -------------------------------------------------------------- file access

# Every read goes through here so that unreadable / oversize files become
# recorded gaps instead of exceptions or silent zeroes.
function Read-TextFileSafe {
    param([string]$Path, [int]$MaxBytes = 0)
    if ($MaxBytes -le 0) { $MaxBytes = $MAX_FILE_BYTES }
    try {
        $fi = New-Object System.IO.FileInfo($Path)
        if (-not $fi.Exists) { return $null }
        if ($fi.Length -gt $MaxBytes) {
            Add-Gap ('oversize:' + $Path + ':' + $fi.Length)
            return $null
        }
        $script:Coverage.files_examined = $script:Coverage.files_examined + 1
        return [System.IO.File]::ReadAllText($Path)
    }
    catch [System.UnauthorizedAccessException] {
        Add-Gap ('unreadable:' + $Path)
        return $null
    }
    catch {
        Add-Gap ('read_error:' + $Path + ':' + $_.Exception.GetType().Name)
        return $null
    }
}

function Test-PathSafe {
    param([string]$Path)
    try { return (Test-Path -LiteralPath $Path) } catch { return $false }
}

function Get-ChildItemSafe {
    param([string]$Path, [switch]$Directory, [switch]$File, [string]$Filter = '*')
    try {
        if ($Directory) {
            return @(Get-ChildItem -LiteralPath $Path -Directory -Force -Filter $Filter -ErrorAction Stop)
        }
        if ($File) {
            return @(Get-ChildItem -LiteralPath $Path -File -Force -Filter $Filter -ErrorAction Stop)
        }
        return @(Get-ChildItem -LiteralPath $Path -Force -Filter $Filter -ErrorAction Stop)
    }
    catch {
        Add-Gap ('list_error:' + $Path + ':' + $_.Exception.GetType().Name)
        return @()
    }
}

# ----------------------------------------------------------- key/value scan

# Shared by .env files, PowerShell profiles and any other KEY=VALUE surface.
# Emits at most one finding per line and NEVER the value.
function Invoke-KeyValueScan {
    param(
        [string]$Text,
        [string]$Path,
        [string]$Owner,
        [string]$Category,
        [regex]$LineRe
    )
    if ($null -eq $Text) { return }
    $lineNo = 0
    foreach ($line in ($Text -split '\r?\n')) {
        $lineNo = $lineNo + 1
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
        $m = $LineRe.Match($t)
        if (-not $m.Success) { continue }

        $name  = $m.Groups['name'].Value
        $value = $m.Groups['value'].Value
        if ([string]::IsNullOrWhiteSpace($value)) { continue }

        $tier = Get-NameTier $name
        $cls  = Test-SecretValue $value

        $hit = $false; $reason = ''; $sev = 'medium'
        if ($cls.IsSecret) {
            $hit = $true; $reason = $cls.Reason
            if ($tier -eq 'tier1') { $sev = 'high' }
            elseif ($reason.StartsWith('known_prefix:')) { $sev = 'high' }
            else { $sev = 'medium' }
        }
        elseif ($tier -ne 'none' -and (Test-ReasonIsBenign $cls.Reason)) {
            $nv = Test-NameValueSuspicious $value
            if ($nv.IsSecret) {
                $hit = $true; $reason = $nv.Reason
                if ($tier -eq 'tier1') { $sev = 'high' } else { $sev = 'medium' }
            }
        }

        if (-not $hit) { continue }

        # Splatting, not line continuation: continuations need a backtick.
        $fa = @{
            Category    = $Category
            Path        = $Path
            Severity    = $sev
            Description = ('Literal credential value assigned to ' + $name)
            Remediation = 'Rotate the credential, then move it to Windows Credential Manager or a secrets manager and reference it at runtime.'
            Details     = @{ key_name = $name; line = $lineNo; reason = $reason; name_tier = $tier; value_length = (Remove-SurroundingQuotes $value).Length }
            Owner       = $Owner
        }
        Add-Finding (New-Finding @fa)
    }
}

$ENV_LINE_RE  = [regex]'^(?:export\s+)?(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<value>.*)$'
# PowerShell assignment: $env:NAME = 'value'  or  $NAME = 'value'
$PS_LINE_RE   = [regex]'^\$(?:env:)?(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<value>.+)$'
# setx / set NAME=value inside a profile or batch fragment
$SETX_LINE_RE = [regex]'(?i)^set(?:x)?\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(?<value>.+)$'

# =========================================================== PER-USER SCANS
# Every scanner takes the home directory and the owner name. Each is wrapped
# individually by the orchestrator so one failure cannot abandon the rest -
# the macOS scanner lost whole categories to a single unhandled type error.

function Scan-CloudCredentials {
    param([string]$HomeDir, [string]$Owner)

    # --- AWS: shared credentials + config
    foreach ($leaf in @('.aws\credentials', '.aws\config')) {
        $p = Join-Path $HomeDir $leaf
        if (-not (Test-PathSafe $p)) { continue }
        $txt = Read-TextFileSafe $p
        if ($null -eq $txt) { continue }
        $lineNo = 0
        foreach ($line in ($txt -split '\r?\n')) {
            $lineNo = $lineNo + 1
            $t = $line.Trim()
            if ($t.Length -eq 0 -or $t.StartsWith('#') -or $t.StartsWith(';')) { continue }
            $m = [regex]::Match($t, '^(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<value>.+)$')
            if (-not $m.Success) { continue }
            $name = $m.Groups['name'].Value.ToLowerInvariant()
            if ($name -ne 'aws_access_key_id' -and $name -ne 'aws_secret_access_key' -and $name -ne 'aws_session_token') { continue }
            $val = Remove-SurroundingQuotes $m.Groups['value'].Value
            if ($val.Length -eq 0) { continue }
            # Presence of a long-lived key id/secret in a file IS the finding.
            $sev = 'high'
            if ($name -eq 'aws_secret_access_key') { $sev = 'critical' }
            $fa = @{
                Category = 'cloud_credentials'; Path = $p; Severity = $sev
                Description = ('AWS static credential ' + $name + ' stored in plaintext')
                Remediation = 'Rotate the access key in IAM, then move to SSO / short-lived credentials (aws sso login) or an instance role.'
                Details = @{ key_name = $name; line = $lineNo; value_length = $val.Length; provider = 'aws' }
                Owner = $Owner
            }
            Add-Finding (New-Finding @fa)
        }
    }

    # --- Azure: token cache and service principal files
    $azDir = Join-Path $HomeDir '.azure'
    if (Test-PathSafe $azDir) {
        foreach ($leaf in @('accessTokens.json','msal_token_cache.json','service_principal_entries.json','azureProfile.json')) {
            $p = Join-Path $azDir $leaf
            if (-not (Test-PathSafe $p)) { continue }
            $sev = 'high'
            if ($leaf -eq 'azureProfile.json') { $sev = 'low' }
            $fa = @{
                Category = 'cloud_credentials'; Path = $p; Severity = $sev
                Description = ('Azure CLI credential store present (' + $leaf + ')')
                Remediation = 'Run az logout on shared or decommissioned hosts; prefer managed identity or device-code auth with short lifetimes.'
                Details = @{ provider = 'azure'; artifact = $leaf }
                Owner = $Owner
            }
            if ($sev -eq 'low') { Add-Observation (New-Finding @fa) } else { Add-Finding (New-Finding @fa) }
        }
    }

    # --- GCP: ADC + legacy service-account JSON keys under AppData
    $gcloudDirs = @(
        (Join-Path $HomeDir 'AppData\Roaming\gcloud'),
        (Join-Path $HomeDir '.config\gcloud')
    )
    foreach ($gd in $gcloudDirs) {
        if (-not (Test-PathSafe $gd)) { continue }
        $adc = Join-Path $gd 'application_default_credentials.json'
        if (Test-PathSafe $adc) {
            $txt = Read-TextFileSafe $adc
            $isSa = $false
            if ($null -ne $txt -and $txt -match '"type"\s*:\s*"service_account"') { $isSa = $true }
            $sev = 'high'
            if ($isSa) { $sev = 'critical' }
            $fa = @{
                Category = 'cloud_credentials'; Path = $adc; Severity = $sev
                Description = 'GCP application default credentials on disk'
                Remediation = 'gcloud auth application-default revoke, then re-auth interactively or attach a service account to the workload instead of downloading a key.'
                Details = @{ provider = 'gcp'; service_account_key = $isSa }
                Owner = $Owner
            }
            Add-Finding (New-Finding @fa)
        }
        # Downloaded SA keys are the higher-value target and land anywhere.
        foreach ($f in (Get-ChildItemSafe -Path $gd -File -Filter '*.json')) {
            if ($f.Name -eq 'application_default_credentials.json') { continue }
            $txt = Read-TextFileSafe $f.FullName
            if ($null -eq $txt) { continue }
            if ($txt -match '"type"\s*:\s*"service_account"' -and $txt -match '"private_key"') {
                $proj = ''
                $pm = [regex]::Match($txt, '"project_id"\s*:\s*"([^"]{1,120})"')
                if ($pm.Success) { $proj = $pm.Groups[1].Value }
                $fa = @{
                    Category = 'cloud_credentials'; Path = $f.FullName; Severity = 'critical'
                    Description = 'Downloadable GCP service-account key (private_key present)'
                    Remediation = 'Delete the key in IAM and on disk, then move the workload to Workload Identity Federation or an attached service account.'
                    Details = @{ provider = 'gcp'; project_id = $proj; artifact = 'service_account_key' }
                    Owner = $Owner
                }
                Add-Finding (New-Finding @fa)
            }
        }
    }
}

function Scan-SshKeys {
    param([string]$HomeDir, [string]$Owner)
    $ssh = Join-Path $HomeDir '.ssh'
    if (-not (Test-PathSafe $ssh)) { return }

    foreach ($f in (Get-ChildItemSafe -Path $ssh -File)) {
        $n = $f.Name
        if ($n -eq 'known_hosts' -or $n -eq 'config' -or $n -eq 'authorized_keys') { continue }
        if ($n.EndsWith('.pub')) { continue }
        $txt = Read-TextFileSafe $f.FullName 200000
        if ($null -eq $txt) { continue }
        if ($txt -notmatch '-----BEGIN [A-Z ]*PRIVATE KEY-----') { continue }

        $script:Coverage.ssh_keys_examined = $script:Coverage.ssh_keys_examined + 1

        # Encrypted keys carry either a Proc-Type header (PEM) or an explicit
        # cipher name in the OpenSSH format. An unencrypted key is the finding;
        # an encrypted one is materially weaker evidence and drops to low.
        $encrypted = $false
        if ($txt -match 'Proc-Type:\s*4,ENCRYPTED') { $encrypted = $true }
        elseif ($txt -match 'BEGIN OPENSSH PRIVATE KEY') {
            # Base64 body encodes the cipher name near the start when encrypted.
            $body = ($txt -replace '-----[A-Z ]+-----','').Trim()
            $head = $body.Substring(0, [Math]::Min(120, $body.Length))
            try {
                $raw = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(($head -replace '\s','')))
                if ($raw -match 'aes|3des|chacha') { $encrypted = $true }
            } catch { }
        }

        $kind = 'unknown'
        if     ($txt -match 'BEGIN OPENSSH PRIVATE KEY') { $kind = 'openssh' }
        elseif ($txt -match 'BEGIN RSA PRIVATE KEY')     { $kind = 'rsa_pem' }
        elseif ($txt -match 'BEGIN EC PRIVATE KEY')      { $kind = 'ec_pem' }
        elseif ($txt -match 'BEGIN DSA PRIVATE KEY')     { $kind = 'dsa_pem' }

        $sev = 'high'
        $desc = 'Unencrypted SSH private key on disk'
        if ($encrypted) { $sev = 'low'; $desc = 'Passphrase-protected SSH private key on disk' }

        $fa = @{
            Category = 'ssh_keys'; Path = $f.FullName; Severity = $sev
            Description = $desc
            Remediation = 'Confirm the key is still needed. If so, protect it with a passphrase and move to a hardware-backed or agent-held key; rotate the authorized_keys entries it unlocks.'
            Details = @{ key_type = $kind; encrypted = $encrypted; size_bytes = $f.Length }
            Owner = $Owner
        }
        if ($encrypted) { Add-Observation (New-Finding @fa) } else { Add-Finding (New-Finding @fa) }
    }
}

function Scan-GitCredentials {
    param([string]$HomeDir, [string]$Owner)

    # ~/.git-credentials stores https://user:token@host verbatim.
    foreach ($leaf in @('.git-credentials', '.config\git\credentials')) {
        $p = Join-Path $HomeDir $leaf
        if (-not (Test-PathSafe $p)) { continue }
        $txt = Read-TextFileSafe $p
        if ($null -eq $txt) { continue }
        $n = 0
        foreach ($line in ($txt -split '\r?\n')) {
            $t = $line.Trim()
            if ($t.Length -eq 0) { continue }
            $m = [regex]::Match($t, '^(?<scheme>\w+)://(?<user>[^:@/]+):(?<secret>[^@]+)@(?<host>[^/]+)')
            if (-not $m.Success) { continue }
            $n = $n + 1
            $fa = @{
                Category = 'git_credentials'; Path = $p; Severity = 'high'
                Description = ('Git credential stored in plaintext for ' + $m.Groups['host'].Value)
                Remediation = 'Revoke the token at the provider, delete the store, and switch credential.helper to manager (Windows Credential Manager) or use SSH keys.'
                Details = @{ host = $m.Groups['host'].Value; username = $m.Groups['user'].Value; secret_length = $m.Groups['secret'].Value.Length }
                Owner = $Owner
            }
            Add-Finding (New-Finding @fa)
        }
    }

    # Windows uses _netrc; some tools still read .netrc.
    foreach ($leaf in @('_netrc', '.netrc')) {
        $p = Join-Path $HomeDir $leaf
        if (-not (Test-PathSafe $p)) { continue }
        $txt = Read-TextFileSafe $p
        if ($null -eq $txt) { continue }
        foreach ($m in [regex]::Matches($txt, '(?im)^\s*machine\s+(?<host>\S+)')) {
            $hasPw = ($txt -match '(?im)^\s*password\s+\S+')
            if (-not $hasPw) { continue }
            $fa = @{
                Category = 'git_credentials'; Path = $p; Severity = 'high'
                Description = ('netrc password entry for ' + $m.Groups['host'].Value)
                Remediation = 'Rotate the credential and replace netrc with Windows Credential Manager or a token helper.'
                Details = @{ host = $m.Groups['host'].Value; artifact = 'netrc' }
                Owner = $Owner
            }
            Add-Finding (New-Finding @fa)
        }
    }

    # Posture: which credential helper is configured.
    $gitcfg = Join-Path $HomeDir '.gitconfig'
    if (Test-PathSafe $gitcfg) {
        $txt = Read-TextFileSafe $gitcfg
        if ($null -ne $txt) {
            $hm = [regex]::Match($txt, '(?im)^\s*helper\s*=\s*(?<h>.+)$')
            $helper = 'none'
            if ($hm.Success) { $helper = $hm.Groups['h'].Value.Trim() }
            $fa = @{
                Category = 'git_credentials'; Path = $gitcfg; Severity = 'low'
                Description = ('git credential.helper = ' + $helper)
                Remediation = 'manager / manager-core (Windows Credential Manager) is the target state; store is plaintext.'
                Details = @{ helper = $helper; posture = $true }
                Owner = $Owner
            }
            if ($helper -match '(?i)^store') { Add-Finding (New-Finding @fa) }
            else { Add-Observation (New-Finding @fa) }
        }
    }
}

function Scan-PackageManagerTokens {
    param([string]$HomeDir, [string]$Owner)

    $targets = @(
        @{ leaf = '.npmrc';                       re = '(?im)^\s*(?<name>[^=\s]*_authToken|_auth|_password)\s*=\s*(?<value>.+)$'; svc = 'npm' },
        @{ leaf = '.pypirc';                      re = '(?im)^\s*(?<name>password|username)\s*[:=]\s*(?<value>.+)$';               svc = 'pypi' },
        @{ leaf = '.cargo\credentials';           re = '(?im)^\s*(?<name>token)\s*=\s*(?<value>.+)$';                              svc = 'cargo' },
        @{ leaf = '.cargo\credentials.toml';      re = '(?im)^\s*(?<name>token)\s*=\s*(?<value>.+)$';                              svc = 'cargo' },
        @{ leaf = '.gem\credentials';             re = '(?im)^\s*(?<name>:?[a-z_]*api_key)\s*:\s*(?<value>.+)$';                   svc = 'rubygems' },
        @{ leaf = 'pip\pip.ini';                  re = '(?im)^\s*(?<name>password)\s*=\s*(?<value>.+)$';                           svc = 'pip' },
        @{ leaf = 'AppData\Roaming\pip\pip.ini';  re = '(?im)^\s*(?<name>password)\s*=\s*(?<value>.+)$';                           svc = 'pip' }
    )

    foreach ($t in $targets) {
        $p = Join-Path $HomeDir $t.leaf
        if (-not (Test-PathSafe $p)) { continue }
        $txt = Read-TextFileSafe $p
        if ($null -eq $txt) { continue }
        foreach ($m in [regex]::Matches($txt, $t.re)) {
            $val = Remove-SurroundingQuotes $m.Groups['value'].Value
            if ($val.Length -eq 0) { continue }
            $cls = Test-SecretValue $val
            # A username line is context, not a credential.
            if ($m.Groups['name'].Value -match '(?i)^username$') { continue }
            $sev = 'high'
            if (-not $cls.IsSecret -and $val.Length -lt 20) { $sev = 'medium' }
            $fa = @{
                Category = 'package_manager_tokens'; Path = $p; Severity = $sev
                Description = ($t.svc + ' registry credential stored in plaintext')
                Remediation = 'Revoke the token at the registry and use a short-lived or CI-scoped token; do not persist it in a user rc file.'
                Details = @{ service = $t.svc; key_name = $m.Groups['name'].Value; reason = $cls.Reason; value_length = $val.Length }
                Owner = $Owner
            }
            Add-Finding (New-Finding @fa)
        }
    }

    # Docker: config.json auths[].auth is base64 user:password, not a hash.
    $dcfg = Join-Path $HomeDir '.docker\config.json'
    if (Test-PathSafe $dcfg) {
        $txt = Read-TextFileSafe $dcfg
        if ($null -ne $txt) {
            # [^{}]* not [^}]* : the loose form let the engine span the nested
            # object and capture the outer "auths" key as the registry name.
            foreach ($m in [regex]::Matches($txt, '"(?<reg>[^"]+)"\s*:\s*\{[^{}]*"auth"\s*:\s*"(?<auth>[A-Za-z0-9+/=]{8,})"')) {
                $fa = @{
                    Category = 'package_manager_tokens'; Path = $dcfg; Severity = 'high'
                    Description = ('Docker registry auth stored for ' + $m.Groups['reg'].Value)
                    Remediation = 'docker logout, then use a credential store (docker-credential-wincred) or a short-lived registry token.'
                    Details = @{ service = 'docker'; registry = $m.Groups['reg'].Value; encoded_length = $m.Groups['auth'].Value.Length }
                    Owner = $Owner
                }
                Add-Finding (New-Finding @fa)
            }
            if ($txt -match '"credsStore"\s*:\s*"(?<s>[^"]+)"') {
                $fa = @{
                    Category = 'package_manager_tokens'; Path = $dcfg; Severity = 'low'
                    Description = 'Docker configured to use an external credential store'
                    Remediation = 'This is the target state - no action.'
                    Details = @{ service = 'docker'; creds_store = $Matches['s']; posture = $true }
                    Owner = $Owner
                }
                Add-Observation (New-Finding @fa)
            }
        }
    }

    # NuGet: clear-text package source credentials.
    $nuget = Join-Path $HomeDir 'AppData\Roaming\NuGet\NuGet.Config'
    if (Test-PathSafe $nuget) {
        $txt = Read-TextFileSafe $nuget
        if ($null -ne $txt) {
            foreach ($m in [regex]::Matches($txt, '(?i)<add\s+key="(?<k>ClearTextPassword|Password)"\s+value="(?<v>[^"]+)"')) {
                $sev = 'high'
                if ($m.Groups['k'].Value -match '(?i)^password$') { $sev = 'medium' }
                $fa = @{
                    Category = 'package_manager_tokens'; Path = $nuget; Severity = $sev
                    Description = ('NuGet source credential stored (' + $m.Groups['k'].Value + ')')
                    Remediation = 'Rotate the feed credential and store it encrypted, or use an Azure Artifacts credential provider.'
                    Details = @{ service = 'nuget'; key_name = $m.Groups['k'].Value; value_length = $m.Groups['v'].Value.Length }
                    Owner = $Owner
                }
                Add-Finding (New-Finding @fa)
            }
        }
    }
}

function Scan-Kubernetes {
    param([string]$HomeDir, [string]$Owner)
    $kube = Join-Path $HomeDir '.kube'
    if (-not (Test-PathSafe $kube)) { return }

    $cands = New-Object System.Collections.ArrayList
    $cfg = Join-Path $kube 'config'
    if (Test-PathSafe $cfg) { [void]$cands.Add($cfg) }
    foreach ($f in (Get-ChildItemSafe -Path $kube -File)) {
        if ($f.FullName -eq $cfg) { continue }
        if ($f.Name -match '(?i)(^config\.|\.kubeconfig$|kubeconfig)') { [void]$cands.Add($f.FullName) }
    }

    foreach ($p in $cands) {
        $txt = Read-TextFileSafe $p $MAX_KUBECFG_BYTES
        if ($null -eq $txt) { continue }
        $script:Coverage.kubeconfigs_examined = $script:Coverage.kubeconfigs_examined + 1

        # Locality gate FIRST, exactly as the Python does. Docker Desktop and
        # kind ship certificates whose subject is literally system:masters, so
        # judging the credential before the endpoint makes every dev laptop
        # report a critical cluster-admin credential.
        $servers = @()
        foreach ($m in [regex]::Matches($txt, '(?im)^\s*server:\s*(?<s>\S+)')) { $servers = $servers + $m.Groups['s'].Value }
        foreach ($m in [regex]::Matches($txt, '"server"\s*:\s*"(?<s>[^"]+)"'))  { $servers = $servers + $m.Groups['s'].Value }

        $isLocalOnly = $true
        if ($servers.Count -eq 0) { $isLocalOnly = $false }
        foreach ($s in $servers) {
            if ($s -notmatch '(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|docker.internal|orb\.local|rancher-desktop|kubernetes\.docker\.internal)') {
                $isLocalOnly = $false
            }
        }

        $kinds = New-Object System.Collections.ArrayList
        if ($txt -match '(?im)^\s*token:\s*\S' -or $txt -match '"token"\s*:\s*"')                                 { [void]$kinds.Add('token') }
        if ($txt -match '(?im)^\s*client-key-data:\s*\S' -or $txt -match '"client-key-data"\s*:\s*"')             { [void]$kinds.Add('client_key') }
        if ($txt -match '(?im)^\s*password:\s*\S' -or $txt -match '"password"\s*:\s*"')                           { [void]$kinds.Add('password') }
        if ($txt -match '(?im)^\s*client-secret:\s*\S')                                                          { [void]$kinds.Add('oidc_client_secret') }

        if ($kinds.Count -eq 0) {
            $fa = @{
                Category = 'kubernetes'; Path = $p; Severity = 'low'
                Description = 'Kubeconfig present with no embedded credential material'
                Remediation = 'Target state - external auth (exec / oidc). No action.'
                Details = @{ servers = $servers.Count; posture = $true }
                Owner = $Owner
            }
            Add-Observation (New-Finding @fa)
            continue
        }

        if ($isLocalOnly) {
            $fa = @{
                Category = 'kubernetes'; Path = $p; Severity = 'low'
                Description = 'Local development cluster credential (loopback endpoint only)'
                Remediation = 'No action - Docker Desktop / kind / rancher-desktop credentials are local by construction.'
                Details = @{ credentials = @($kinds); endpoint_tier = 'local' }
                Owner = $Owner
            }
            Add-Observation (New-Finding @fa)
            continue
        }

        $sev = 'high'
        if ($kinds -contains 'token' -or $kinds -contains 'client_key') { $sev = 'critical' }
        $fa = @{
            Category = 'kubernetes'; Path = $p; Severity = $sev
            Description = 'Kubeconfig embeds credential material for a non-local cluster'
            Remediation = 'Rotate the credential in-cluster (kubectl delete secret for a ServiceAccount token), then move to exec-based short-lived auth.'
            Details = @{ credentials = @($kinds); endpoint_tier = 'remote'; servers = $servers.Count }
            Owner = $Owner
        }
        Add-Finding (New-Finding @fa)
    }
}

function Scan-EnvFiles {
    param([string]$HomeDir, [string]$Owner)

    $roots = @('Desktop','Documents','source','source\repos','repos','Projects','dev','src','git','code','OneDrive - THG')
    foreach ($r in $roots) {
        $root = Join-Path $HomeDir $r
        if (-not (Test-PathSafe $root)) { continue }
        Walk-EnvDir -Dir $root -Depth 0 -Owner $Owner
    }
    # Home itself, non-recursive.
    Walk-EnvDir -Dir $HomeDir -Depth $ENV_MAX_DEPTH -Owner $Owner
}

function Walk-EnvDir {
    param([string]$Dir, [int]$Depth, [string]$Owner)
    if ($Depth -gt $ENV_MAX_DEPTH) { return }
    if (Test-BudgetExceeded) { return }

    $script:Coverage.project_dirs_walked = $script:Coverage.project_dirs_walked + 1

    foreach ($f in (Get-ChildItemSafe -Path $Dir -File)) {
        $n = $f.Name
        if ($n -ne '.env' -and -not $n.StartsWith('.env.')) { continue }
        $skip = $false
        foreach ($sfx in $ENV_IGNORE_SUFFIXES) { if ($n.EndsWith($sfx)) { $skip = $true } }
        if ($skip) { continue }
        $txt = Read-TextFileSafe $f.FullName
        if ($null -eq $txt) { continue }
        $script:Coverage.env_files_examined = $script:Coverage.env_files_examined + 1
        Invoke-KeyValueScan -Text $txt -Path $f.FullName -Owner $Owner -Category 'env_files' -LineRe $ENV_LINE_RE
    }

    if ($Depth -ge $ENV_MAX_DEPTH) { return }
    foreach ($d in (Get-ChildItemSafe -Path $Dir -Directory)) {
        if ($PRUNE_DIRS -contains $d.Name) { continue }
        if ($JUNCTION_DIRS -contains $d.Name) { continue }
        # Reparse points are junctions/symlinks: following them risks both
        # access errors and walking the same tree twice.
        if (($d.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        if ($d.Name.StartsWith('.') -and $d.Name -ne '.config') { continue }
        Walk-EnvDir -Dir $d.FullName -Depth ($Depth + 1) -Owner $Owner
    }
}

function Scan-ShellProfiles {
    param([string]$HomeDir, [string]$Owner)

    # PowerShell profiles - the direct analogue of .zshrc / .bashrc.
    $profiles = @(
        'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1',
        'Documents\WindowsPowerShell\profile.ps1',
        'Documents\PowerShell\Microsoft.PowerShell_profile.ps1',
        'Documents\PowerShell\profile.ps1',
        'OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1',
        'OneDrive - THG\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
    )
    foreach ($leaf in $profiles) {
        $p = Join-Path $HomeDir $leaf
        if (-not (Test-PathSafe $p)) { continue }
        $txt = Read-TextFileSafe $p
        if ($null -eq $txt) { continue }
        $script:Coverage.ps_profiles_examined = $script:Coverage.ps_profiles_examined + 1
        Invoke-KeyValueScan -Text $txt -Path $p -Owner $Owner -Category 'shell_profiles' -LineRe $PS_LINE_RE
        Invoke-KeyValueScan -Text $txt -Path $p -Owner $Owner -Category 'shell_profiles' -LineRe $SETX_LINE_RE
    }

    # Git Bash / WSL-adjacent profiles that exist on developer Windows boxes.
    foreach ($leaf in @('.bashrc','.bash_profile','.profile','.zshrc')) {
        $p = Join-Path $HomeDir $leaf
        if (-not (Test-PathSafe $p)) { continue }
        $txt = Read-TextFileSafe $p
        if ($null -eq $txt) { continue }
        $script:Coverage.ps_profiles_examined = $script:Coverage.ps_profiles_examined + 1
        Invoke-KeyValueScan -Text $txt -Path $p -Owner $Owner -Category 'shell_profiles' -LineRe $ENV_LINE_RE
    }

    # --- PSReadLine console history. No macOS analogue and consistently the
    # highest-yield Windows artifact: every secret ever typed at a prompt is
    # here in plaintext, retained across sessions, and backed up by OneDrive.
    # NTFS is case-insensitive, so PSReadLine and PSReadline are the SAME file.
    # Listing both spellings double-counted every history finding. Dedupe on
    # the lowercased resolved path rather than assuming either spelling.
    $histPaths = @(
        (Join-Path $HomeDir 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
        (Join-Path $HomeDir 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')
    )
    $seenHist = @{}
    foreach ($hp in $histPaths) {
        if (-not (Test-PathSafe $hp)) { continue }
        $keyH = $hp.ToLowerInvariant()
        if ($seenHist.ContainsKey($keyH)) { continue }
        $seenHist[$keyH] = $true
        $txt = Read-TextFileSafe $hp $MAX_HISTORY_BYTES
        if ($null -eq $txt) { continue }
        $script:Coverage.history_files_examined = $script:Coverage.history_files_examined + 1

        $lineNo = 0
        $hits = 0
        foreach ($line in ($txt -split '\r?\n')) {
            $lineNo = $lineNo + 1
            $t = $line.Trim()
            if ($t.Length -lt 12) { continue }

            # Two independent signals, both name-anchored so an ordinary
            # command line does not trip on entropy alone.
            $m = [regex]::Match($t, '(?i)(?<name>[A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|TOKEN|SECRET|APIKEY|API_KEY|CREDENTIAL|PASSWD|PWD))\s*[:=]\s*(?<value>\S+)')
            if (-not $m.Success) {
                $m = [regex]::Match($t, '(?i)(?<name>--?(?:password|token|secret|api-?key|credential)[A-Za-z-]*)[= ]\s*(?<value>\S+)')
            }
            if ($m.Success) {
                $val = Remove-SurroundingQuotes $m.Groups['value'].Value
                $cls = Test-SecretValue $val
                $nv  = Test-NameValueSuspicious $val
                if ($cls.IsSecret -or $nv.IsSecret) {
                    $reason = $cls.Reason
                    if (-not $cls.IsSecret) { $reason = $nv.Reason }
                    $hits = $hits + 1
                    $fa = @{
                        Category = 'shell_profiles'; Path = $hp; Severity = 'high'
                        Description = 'Credential typed at a PowerShell prompt and retained in console history'
                        Remediation = 'Rotate the credential, then clear ConsoleHost_history.txt. Consider Set-PSReadLineOption -HistorySaveStyle SaveNothing for privileged sessions.'
                        Details = @{ key_name = $m.Groups['name'].Value; line = $lineNo; reason = $reason; artifact = 'psreadline_history'; value_length = $val.Length }
                        Owner = $Owner
                    }
                    Add-Finding (New-Finding @fa)
                }
            }

            # A bare high-confidence token anywhere on the line, name or not.
            foreach ($pfx in $KNOWN_SECRET_PREFIXES) {
                if ($pfx -eq 'key-' -or $pfx -eq 'sk-' -or $pfx -eq 'SG.' -or $pfx -eq 'eyJ') { continue }
                if ($t.Contains($pfx)) {
                    $hits = $hits + 1
                    $fa = @{
                        Category = 'shell_profiles'; Path = $hp; Severity = 'critical'
                        Description = 'Provider credential literal present in PowerShell console history'
                        Remediation = 'Rotate immediately at the provider, then clear the history file.'
                        Details = @{ line = $lineNo; reason = ('known_prefix:' + $pfx); artifact = 'psreadline_history' }
                        Owner = $Owner
                    }
                    Add-Finding (New-Finding @fa)
                    break
                }
            }
            if ($hits -gt 200) {
                Add-Gap ('history_truncated:' + $hp)
                break
            }
        }
    }
}

function Scan-SecretsManagerStatus {
    param([string]$HomeDir, [string]$Owner)
    # Posture only. Drives the target-state remediation story; never a finding.
    $opPaths = @(
        (Join-Path $HomeDir 'AppData\Local\Microsoft\WindowsApps\op.exe'),
        'C:\Program Files\1Password CLI\op.exe',
        (Join-Path $HomeDir 'scoop\shims\op.exe')
    )
    $found = ''
    foreach ($p in $opPaths) { if (Test-PathSafe $p) { $found = $p; break } }
    if ($found -ne '') {
        $fa = @{
            Category = 'secrets_manager_status'; Path = $found; Severity = 'low'
            Description = '1Password CLI available on this host'
            Remediation = 'Target state - op run / op:// references replace literals.'
            Details = @{ tool = '1password'; posture = $true }
            Owner = $Owner
        }
        Add-Observation (New-Finding @fa)
    }
}

# ====================================================== WINDOWS-NATIVE SCANS
# Host-context, not per-user. These have no macOS analogue and are the reason
# a straight port of rattlesnake.py would have under-covered this estate.

function Scan-WindowsNative {
    param([string]$Owner)

    # --- Group Policy Preferences cpassword. Microsoft published the AES key
    # in MSDN, so any surviving cpassword is trivially reversible. Cached
    # copies persist locally long after SYSVOL is cleaned up.
    $gpRoots = @(
        (Join-Path $env:SystemRoot 'SYSVOL'),
        (Join-Path $env:ProgramData 'Microsoft\Group Policy\History'),
        (Join-Path $env:SystemRoot 'System32\GroupPolicy'),
        (Join-Path $env:SystemRoot 'SysWOW64\GroupPolicy')
    )
    foreach ($root in $gpRoots) {
        if (-not (Test-PathSafe $root)) { continue }
        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.xml' -Force -ErrorAction SilentlyContinue | Select-Object -First 400)
        } catch { Add-Gap ('gpp_walk_error:' + $root) }
        foreach ($f in $files) {
            $txt = Read-TextFileSafe $f.FullName 500000
            if ($null -eq $txt) { continue }
            $m = [regex]::Match($txt, 'cpassword\s*=\s*"(?<c>[^"]+)"')
            if (-not $m.Success) { continue }
            $un = ''
            $um = [regex]::Match($txt, '(?:userName|runAs|accountName)\s*=\s*"(?<u>[^"]{1,120})"')
            if ($um.Success) { $un = $um.Groups['u'].Value }
            $fa = @{
                Category = 'windows_native'; Path = $f.FullName; Severity = 'critical'
                Description = 'Group Policy Preferences cpassword present (reversible with the published AES key)'
                Remediation = 'Reset the affected account password immediately, delete the GPP item, and audit SYSVOL for other cpassword occurrences. MS14-025 removed the ability to create these but did not remove existing ones.'
                Details = @{ artifact = 'gpp_cpassword'; account = $un; encoded_length = $m.Groups['c'].Value.Length }
                Owner = $Owner
            }
            Add-Finding (New-Finding @fa)
        }
    }

    # --- Unattend / sysprep answer files. Plaintext or trivially-encoded
    # local admin passwords survive imaging far more often than anyone expects.
    $unattendPaths = @(
        (Join-Path $env:SystemRoot 'Panther\Unattend.xml'),
        (Join-Path $env:SystemRoot 'Panther\Unattend\Unattend.xml'),
        (Join-Path $env:SystemRoot 'System32\Sysprep\unattend.xml'),
        (Join-Path $env:SystemRoot 'System32\Sysprep\Panther\unattend.xml'),
        'C:\unattend.xml',
        'C:\sysprep.inf',
        'C:\sysprep\sysprep.xml'
    )
    foreach ($p in $unattendPaths) {
        if (-not (Test-PathSafe $p)) { continue }
        $txt = Read-TextFileSafe $p 500000
        if ($null -eq $txt) { continue }
        $hasPw = ($txt -match '(?i)<Password>' -or $txt -match '(?i)<AdministratorPassword>' -or $txt -match '(?i)AdminPassword')
        if (-not $hasPw) { continue }
        # PlainText=false means base64, which is encoding, not protection.
        $plain = $true
        if ($txt -match '(?i)<PlainText>false</PlainText>') { $plain = $false }
        $fa = @{
            Category = 'windows_native'; Path = $p; Severity = 'critical'
            Description = 'Sysprep/unattend answer file retains an account password'
            Remediation = 'Delete the answer file from the image and the host, and rotate any account it names. Base64 (PlainText=false) is not encryption.'
            Details = @{ artifact = 'unattend'; plaintext = $plain }
            Owner = $Owner
        }
        Add-Finding (New-Finding @fa)
    }

    # --- Winlogon autologon. DefaultPassword is stored in the clear.
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    try {
        $script:Coverage.registry_keys_examined = $script:Coverage.registry_keys_examined + 1
        $k = Get-ItemProperty -LiteralPath $wl -ErrorAction Stop
        $autoOn = $false
        if ($k.PSObject.Properties.Name -contains 'AutoAdminLogon') {
            if ([string]$k.AutoAdminLogon -eq '1') { $autoOn = $true }
        }
        if ($k.PSObject.Properties.Name -contains 'DefaultPassword') {
            $dp = [string]$k.DefaultPassword
            if ($dp.Length -gt 0) {
                $du = ''
                if ($k.PSObject.Properties.Name -contains 'DefaultUserName') { $du = [string]$k.DefaultUserName }
                $fa = @{
                    Category = 'windows_native'; Path = $wl; Severity = 'critical'
                    Description = 'Winlogon DefaultPassword set (autologon credential in cleartext registry value)'
                    Remediation = 'Remove DefaultPassword, set AutoAdminLogon to 0, and rotate the account. Use LAPS or a managed service account if unattended logon is genuinely required.'
                    Details = @{ artifact = 'winlogon_autologon'; auto_admin_logon = $autoOn; account = $du; value_length = $dp.Length }
                    Owner = $Owner
                }
                Add-Finding (New-Finding @fa)
            }
        }
    }
    catch { Add-Gap ('registry_unreadable:' + $wl) }

    # --- Machine-scope environment variables holding credential-shaped values.
    $envKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    try {
        $script:Coverage.registry_keys_examined = $script:Coverage.registry_keys_examined + 1
        $k = Get-ItemProperty -LiteralPath $envKey -ErrorAction Stop
        foreach ($prop in $k.PSObject.Properties) {
            if ($prop.Name.StartsWith('PS')) { continue }
            $tier = Get-NameTier $prop.Name
            if ($tier -eq 'none') { continue }
            $val = [string]$prop.Value
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            $cls = Test-SecretValue $val
            $nv  = Test-NameValueSuspicious $val
            if (-not ($cls.IsSecret -or $nv.IsSecret)) { continue }
            $reason = $cls.Reason
            if (-not $cls.IsSecret) { $reason = $nv.Reason }
            $sev = 'medium'
            if ($tier -eq 'tier1') { $sev = 'high' }
            $fa = @{
                Category = 'windows_native'; Path = $envKey; Severity = $sev
                Description = ('Machine-scope environment variable ' + $prop.Name + ' holds a credential-shaped value')
                Remediation = 'Rotate and remove the variable; machine-scope env vars are readable by every process on the host.'
                Details = @{ artifact = 'machine_env_var'; key_name = $prop.Name; reason = $reason; name_tier = $tier; value_length = $val.Length }
                Owner = $Owner
            }
            Add-Finding (New-Finding @fa)
        }
    }
    catch { Add-Gap ('registry_unreadable:' + $envKey) }

    # --- IIS web.config connection strings. Only on hosts that actually run
    # IIS, so the walk is gated on inetpub existing.
    $inetpub = 'C:\inetpub\wwwroot'
    if (Test-PathSafe $inetpub) {
        $files = @()
        try {
            $files = @(Get-ChildItem -LiteralPath $inetpub -Recurse -File -Filter 'web.config' -Force -ErrorAction SilentlyContinue | Select-Object -First 200)
        } catch { Add-Gap ('iis_walk_error:' + $inetpub) }
        foreach ($f in $files) {
            $txt = Read-TextFileSafe $f.FullName 500000
            if ($null -eq $txt) { continue }
            $script:Coverage.webconfigs_examined = $script:Coverage.webconfigs_examined + 1
            foreach ($m in [regex]::Matches($txt, '(?i)connectionString\s*=\s*"(?<v>[^"]+)"')) {
                $v = $m.Groups['v'].Value
                if ($v -notmatch '(?i)(password|pwd)\s*=') { continue }
                $nm = ''
                $nmm = [regex]::Match($txt, '(?i)<add\s+name\s*=\s*"(?<n>[^"]+)"[^>]*connectionString')
                if ($nmm.Success) { $nm = $nmm.Groups['n'].Value }
                $fa = @{
                    Category = 'windows_native'; Path = $f.FullName; Severity = 'high'
                    Description = 'IIS connection string contains an inline password'
                    Remediation = 'Rotate the database credential and move the connection string to an encrypted configuration section (aspnet_regiis -pe) or a managed identity.'
                    Details = @{ artifact = 'iis_connection_string'; name = $nm; value_length = $v.Length }
                    Owner = $Owner
                }
                Add-Finding (New-Finding @fa)
            }
        }
    }
}

# =============================================================== WSL HOMES
# A second POSIX filesystem on the same endpoint, carrying its own .aws,
# .ssh and .config. Invisible to any Windows-path-only scan.

function Get-WslHomes {
    param([string]$WinHome)
    $out = New-Object System.Collections.ArrayList
    $pkgRoot = Join-Path $WinHome 'AppData\Local\Packages'
    if (-not (Test-PathSafe $pkgRoot)) { return $out }
    foreach ($d in (Get-ChildItemSafe -Path $pkgRoot -Directory)) {
        if ($d.Name -notmatch '(?i)(Ubuntu|Debian|kali|SUSE|Oracle|Fedora|WindowsSubsystemForLinux)') { continue }
        $wslHome = Join-Path $d.FullName 'LocalState\rootfs\home'
        if (-not (Test-PathSafe $wslHome)) { continue }
        $script:Coverage.wsl_distros_examined = $script:Coverage.wsl_distros_examined + 1
        foreach ($u in (Get-ChildItemSafe -Path $wslHome -Directory)) { [void]$out.Add($u.FullName) }
        $rootHome = Join-Path $d.FullName 'LocalState\rootfs\root'
        if (Test-PathSafe $rootHome) { [void]$out.Add($rootHome) }
    }
    return $out
}

# ============================================================ ORCHESTRATION

function Test-BudgetExceeded {
    if ($MaxSeconds -le 0) { return $false }
    return ((New-TimeSpan -Start $script:StartTime -End (Get-Date)).TotalSeconds -gt $MaxSeconds)
}

# name -> per-user scanner. Registered in one place so scan_scope can report
# categories_available honestly.
$PER_HOME_SCANS = [ordered]@{
    'cloud_credentials'      = 'Scan-CloudCredentials'
    'ssh_keys'               = 'Scan-SshKeys'
    'git_credentials'        = 'Scan-GitCredentials'
    'package_manager_tokens' = 'Scan-PackageManagerTokens'
    'kubernetes'             = 'Scan-Kubernetes'
    'env_files'              = 'Scan-EnvFiles'
    'shell_profiles'         = 'Scan-ShellProfiles'
    'secrets_manager_status' = 'Scan-SecretsManagerStatus'
}
$HOST_SCANS = [ordered]@{
    'windows_native' = 'Scan-WindowsNative'
}
$ALL_CATEGORY_NAMES = @($PER_HOME_SCANS.Keys) + @($HOST_SCANS.Keys) + @('wsl_homes')

function Get-SelectedCategories {
    if ([string]::IsNullOrWhiteSpace($Category)) { return $ALL_CATEGORY_NAMES }
    $sel = @()
    foreach ($c in ($Category -split ',')) {
        $c = $c.Trim()
        if ($c.Length -eq 0) { continue }
        if ($ALL_CATEGORY_NAMES -contains $c) { $sel = $sel + $c }
        else { Add-ScanError ('unknown_category:' + $c) }
    }
    return $sel
}

function Invoke-HomeScans {
    param([string]$HomeDir, [string]$Owner, [string[]]$Selected, [string]$Kind)
    $script:Coverage.home_dirs_examined = $script:Coverage.home_dirs_examined + 1
    foreach ($name in $PER_HOME_SCANS.Keys) {
        if ($Selected -notcontains $name) { continue }
        if (Test-BudgetExceeded) { Add-Gap ('budget_exceeded_before:' + $name + ':' + $Owner); return }
        try {
            & $PER_HOME_SCANS[$name] -HomeDir $HomeDir -Owner $Owner
            if ($script:CategoriesRun -notcontains $name) { [void]$script:CategoriesRun.Add($name) }
        }
        catch {
            # Per-category isolation: one bad artifact must not abandon the
            # remaining categories or the remaining users.
            Add-ScanError ($name + ':' + $Owner + ':' + $_.Exception.GetType().Name + ':' + $_.Exception.Message)
        }
    }
}

function Get-UserHomes {
    $homes = New-Object System.Collections.ArrayList
    if ($UsersRoot -ne '') {
        foreach ($d in (Get-ChildItemSafe -Path $UsersRoot -Directory)) {
            [void]$homes.Add(@{ Path = $d.FullName; Owner = $d.Name })
        }
        return $homes
    }
    $root = Join-Path $env:SystemDrive '\Users'
    if (-not (Test-PathSafe $root)) { $root = 'C:\Users' }
    foreach ($d in (Get-ChildItemSafe -Path $root -Directory)) {
        if ($SKIP_PROFILES -contains $d.Name) { continue }
        [void]$homes.Add(@{ Path = $d.FullName; Owner = $d.Name })
    }
    return $homes
}

function Test-IsElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object Security.Principal.WindowsPrincipal($id)
        if ($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return $true }
        if ($id.Name -match '(?i)NT AUTHORITY.SYSTEM') { return $true }
        return $false
    } catch { return $false }
}

# ================================================================== REPORT

function Build-Report {
    param([string]$ScanMode, [string[]]$UsersScanned)

    $summary = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0 }
    foreach ($f in $script:Findings) {
        $s = [string]$f.severity
        if ($summary.Contains($s)) { $summary[$s] = $summary[$s] + 1 }
        else { $summary[$s] = 1 }
    }

    $opAvail = $false
    foreach ($o in $script:Observations) {
        if ($o.category -eq 'secrets_manager_status' -and $o.details.ContainsKey('tool') -and $o.details['tool'] -eq '1password') { $opAvail = $true }
    }

    $elapsed = (New-TimeSpan -Start $script:StartTime -End (Get-Date)).TotalSeconds

    $hostName = ''
    try { $hostName = [System.Net.Dns]::GetHostName() } catch { $hostName = $env:COMPUTERNAME }

    return [ordered]@{
        scanner_version        = $SCANNER_VERSION
        schema_version         = $SCHEMA_VERSION
        host_id                = $HostId
        hostname               = $hostName
        username               = $env:USERNAME
        scan_mode              = $ScanMode
        users_scanned          = @($UsersScanned)
        platform               = ([string][System.Environment]::OSVersion.VersionString)
        powershell_version     = ([string]$PSVersionTable.PSVersion)
        timestamp              = ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
        scan_duration_seconds  = ([Math]::Round($elapsed, 2))
        findings               = @($script:Findings)
        observations           = @($script:Observations)
        summary                = $summary
        total_findings         = $script:Findings.Count
        op_cli_available       = $opAvail
        scan_scope             = [ordered]@{
            categories_scanned   = @($script:CategoriesRun)
            categories_available = @($ALL_CATEGORY_NAMES)
            complete             = ($script:CategoriesRun.Count -eq $ALL_CATEGORY_NAMES.Count)
            coverage_gaps        = @($script:CoverageGaps)
            coverage_counters    = $script:Coverage
        }
        errors                 = @($script:Errors)
    }
}

# ==================================================================== MAIN

$exitCode = 0
try {
    $selected = Get-SelectedCategories
    if ($selected.Count -eq 0) {
        [Console]::Error.WriteLine('[rattlesnake] no valid categories selected')
        exit 2
    }

    $elevated = Test-IsElevated
    $multi = $false
    if ($UsersRoot -ne '')        { $multi = $true }
    elseif ($CurrentUserOnly)     { $multi = $false }
    elseif ($AllUsers)            { $multi = $true }
    elseif ($elevated)            { $multi = $true }

    $usersScanned = New-Object System.Collections.ArrayList
    $scanMode = 'current-user'

    if ($multi) {
        $scanMode = 'all-users'
        $homes = Get-UserHomes
        $script:Coverage.users_enumerated = $homes.Count
        Write-Progress-Line ('scanning ' + $homes.Count + ' user profile(s)')
        foreach ($h in $homes) {
            if (Test-BudgetExceeded) { Add-Gap ('budget_exceeded_user:' + $h.Owner); break }
            Write-Progress-Line ('user ' + $h.Owner)
            Invoke-HomeScans -HomeDir $h.Path -Owner $h.Owner -Selected $selected -Kind 'windows'
            [void]$usersScanned.Add($h.Owner)

            if ($selected -contains 'wsl_homes') {
                foreach ($wh in (Get-WslHomes -WinHome $h.Path)) {
                    if (Test-BudgetExceeded) { break }
                    $wslOwner = $h.Owner + '/wsl:' + (Split-Path $wh -Leaf)
                    Invoke-HomeScans -HomeDir $wh -Owner $wslOwner -Selected $selected -Kind 'wsl'
                    if ($script:CategoriesRun -notcontains 'wsl_homes') { [void]$script:CategoriesRun.Add('wsl_homes') }
                }
            }
        }
    }
    else {
        $me = $env:USERPROFILE
        if ([string]::IsNullOrWhiteSpace($me)) { $me = (Join-Path 'C:\Users' $env:USERNAME) }
        $script:Coverage.users_enumerated = 1
        Invoke-HomeScans -HomeDir $me -Owner $env:USERNAME -Selected $selected -Kind 'windows'
        [void]$usersScanned.Add($env:USERNAME)
        if ($selected -contains 'wsl_homes') {
            foreach ($wh in (Get-WslHomes -WinHome $me)) {
                $wslOwner = $env:USERNAME + '/wsl:' + (Split-Path $wh -Leaf)
                Invoke-HomeScans -HomeDir $wh -Owner $wslOwner -Selected $selected -Kind 'wsl'
                if ($script:CategoriesRun -notcontains 'wsl_homes') { [void]$script:CategoriesRun.Add('wsl_homes') }
            }
        }
    }

    # Host-context categories run once, owner "(host)".
    foreach ($name in $HOST_SCANS.Keys) {
        if ($selected -notcontains $name) { continue }
        if (Test-BudgetExceeded) { Add-Gap ('budget_exceeded_before:' + $name); break }
        try {
            & $HOST_SCANS[$name] -Owner '(host)'
            if ($script:CategoriesRun -notcontains $name) { [void]$script:CategoriesRun.Add($name) }
        }
        catch { Add-ScanError ($name + ':(host):' + $_.Exception.GetType().Name + ':' + $_.Exception.Message) }
    }

    $report = Build-Report -ScanMode $scanMode -UsersScanned @($usersScanned)

    if ($Ndjson) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($f in $script:Findings) {
            [void]$sb.AppendLine((ConvertTo-Json $f -Depth 12 -Compress))
        }
        foreach ($o in $script:Observations) {
            [void]$sb.AppendLine((ConvertTo-Json $o -Depth 12 -Compress))
        }
        $out = $sb.ToString()
    }
    elseif ($Pretty) {
        $out = ConvertTo-Json $report -Depth 12
    }
    else {
        $out = ConvertTo-Json $report -Depth 12 -Compress
    }

    if ($OutputFile -ne '') {
        [System.IO.File]::WriteAllText($OutputFile, $out)
        Write-Progress-Line ('wrote ' + $OutputFile)
    }
    else {
        [Console]::Out.WriteLine($out)
    }

    Write-Progress-Line ('done: ' + $script:Findings.Count + ' finding(s), ' + $script:Observations.Count + ' observation(s), ' + $script:Errors.Count + ' error(s)')

    if ($script:Errors.Count -gt 0) { $exitCode = 2 }
    elseif ($script:Findings.Count -gt 0) { $exitCode = 1 }
    else { $exitCode = 0 }
}
catch {
    [Console]::Error.WriteLine('[rattlesnake] fatal: ' + $_.Exception.Message)
    $exitCode = 2
}

exit $exitCode

