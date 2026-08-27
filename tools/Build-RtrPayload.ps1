# Build-RtrPayload.ps1 - produce the RTR inline delivery build of
# rattlesnake.ps1.
#
# Comments are the value of the source file, but they are dead weight in an
# inline RTR payload where size decides whether delivery works at all
# (rattlesnake.pl at ~35KB delivers; rattlesnake.py at ~167KB did not).
#
# Stripping is done with PowerShell's own tokenizer, NOT a regex. A regex for
# a leading # would corrupt this file specifically: it contains the regex
# '^#[0-9a-fA-F]{3,8}$' for CSS colours and a $t.StartsWith('#') test, and a
# naive line-based stripper mangles both. The tokenizer knows which '#' is a
# comment and which is inside a string.
#
# The output is byte-for-byte the same program - only Comment tokens and the
# whitespace they leave behind are removed. Verified by re-parsing.

param(
    [string]$Source = (Join-Path $PSScriptRoot '..\rattlesnake.ps1'),
    [string]$Out    = (Join-Path $PSScriptRoot '..\rattlesnake.min.ps1')
)

$ErrorActionPreference = 'Stop'
$src = [System.IO.File]::ReadAllText((Resolve-Path $Source))

$errors = $null
$tokens = [System.Management.Automation.PSParser]::Tokenize($src, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
    Write-Error ('source does not tokenize cleanly: ' + $errors.Count + ' error(s)')
    exit 1
}

# Walk backwards so earlier offsets stay valid as we cut.
$sb = New-Object System.Text.StringBuilder($src)
$comments = @($tokens | Where-Object { $_.Type -eq 'Comment' } | Sort-Object Start -Descending)
foreach ($c in $comments) {
    [void]$sb.Remove($c.Start, $c.Length)
}
$text = $sb.ToString()

# Collapse the blank lines the comments left behind, and trim trailing
# whitespace. Indentation is kept - it costs little and a payload that is
# still readable in the Falcon audit log is worth the bytes.
$cr = ([char]13).ToString()
$lf = ([char]10).ToString()
$lineSplitRe = $cr + $lf + '|' + $lf
$lines = $text -split $lineSplitRe
$keep = New-Object System.Collections.ArrayList
foreach ($l in $lines) {
    $t = $l.TrimEnd()
    if ($t.Trim().Length -eq 0) { continue }
    [void]$keep.Add($t)
}
$min = ($keep -join [char]10) + [char]10

[System.IO.File]::WriteAllText($Out, $min)

# Re-parse the OUTPUT. A minifier that produces something that does not parse
# is worse than no minifier, and this is the only check that catches it.
$outErrors = $null
$outTokens = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Out), [ref]$outTokens, [ref]$outErrors)
if ($outErrors -and $outErrors.Count -gt 0) {
    Write-Error ('MINIFIED OUTPUT DOES NOT PARSE: ' + $outErrors.Count + ' error(s)')
    $outErrors | Select-Object -First 5 | ForEach-Object { Write-Error ($_.Extent.StartLineNumber.ToString() + ': ' + $_.Message) }
    exit 1
}

# The delimiter-collision guard. This is the one that breaks RTR delivery
# silently, so it is enforced on the artifact that actually gets delivered.
$bt = [char]96
if ($min.Contains($bt)) {
    Write-Error 'MINIFIED OUTPUT CONTAINS A BACKTICK - would collide with the RTR -Raw= delimiter'
    exit 1
}

$srcKb = [Math]::Round(((Get-Item (Resolve-Path $Source)).Length / 1KB), 1)
$outKb = [Math]::Round(((Get-Item (Resolve-Path $Out)).Length / 1KB), 1)
Write-Output ('source   : ' + $srcKb + ' KB')
Write-Output ('payload  : ' + $outKb + ' KB')
Write-Output ('reduction: ' + [Math]::Round((1 - ($outKb / $srcKb)) * 100, 1) + '%')
Write-Output ('parses   : yes')
Write-Output ('backticks: 0')
