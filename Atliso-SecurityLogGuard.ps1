<#
.SYNOPSIS
    Atliso-SecurityLogGuard.ps1 - Detect and fix the Windows Security log "only admins can log on" lockout.

.DESCRIPTION
    When the Security event log is set to Do Not Overwrite (LogMode=Retain) and fills
    up, Windows can flip CrashOnAuditFail to 2, which locks out every non-administrator
    until the log is cleared. This script catches the condition early and remediates it:
    it resizes the log, sets it to overwrite as needed, and - if the lockout has already
    tripped - archives and clears the log and resets CrashOnAuditFail from 2 to 1.

    Runs audit-only by default (-WhatIf $true). Set -WhatIf $false to apply changes.

    Intune usage: deploy as a Remediation. The detection half exits 1 when the log is
    on Do Not Overwrite, at/over the warn threshold, full, or the lockout has tripped.
    Run as SYSTEM, 64-bit.

.NOTES
    MIT licensed. Free to use and modify.
    Reconstructed from the published Atliso article spec - lab-test before fleet rollout.
    Tested target: Windows 10/11, PowerShell 5.1+.
#>

[CmdletBinding()]
param(
    # Trigger remediation once the log is at or above this percent full.
    [int]$WarnThresholdPercent = 90,

    # Target max size for the Security log, in bytes. 256MB covers most fleets even
    # with advanced audit policy turned on. Raise it if your baseline logs more.
    [long]$TargetMaxSizeBytes = 256MB,

    # $true reports only. $false resizes the log, sets it to overwrite, and
    # archives + clears it if the lockout has already tripped.
    [bool]$WhatIf = $true,

    [string]$LogPath = (Join-Path $env:LOCALAPPDATA "Atliso\SecurityLogGuard.log")
)

# ── Logging ───────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    try {
        $dir = Split-Path -Parent $LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -ErrorAction Stop
    } catch { }
    Write-Output $line
}

$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

# ── Detection ───────────────────────────────────────────────────────────────────
$log = Get-WinEvent -ListLog Security
$crashOnAuditFail = (Get-ItemProperty $lsaPath -Name CrashOnAuditFail -ErrorAction SilentlyContinue).CrashOnAuditFail
$pctFull = if ($log.MaximumSizeInBytes -gt 0) {
    [math]::Round(($log.FileSize / $log.MaximumSizeInBytes) * 100, 1)
} else { 0 }

$needsRemediation = $false
$lockoutTripped   = $false

if ($crashOnAuditFail -eq 2) {
    Write-Log "CrashOnAuditFail=2: the lockout has already tripped. Non-admins are locked out." "ERROR"
    $needsRemediation = $true
    $lockoutTripped   = $true
}
# The root cause. 'Retain' means Do Not Overwrite, so the log stops the machine
# when it fills instead of wrapping. Catch it before it locks anyone out.
elseif ($log.LogMode -eq 'Retain') {
    Write-Log "Security log set to Do Not Overwrite (LogMode=Retain), $pctFull% full." "WARN"
    $needsRemediation = $true
}
elseif ($log.IsLogFull -or $pctFull -ge $WarnThresholdPercent) {
    Write-Log "Security log at $pctFull% full (IsLogFull=$($log.IsLogFull))." "WARN"
    $needsRemediation = $true
}
else {
    Write-Log "Security log healthy: LogMode=$($log.LogMode), $pctFull% full."
}

if (-not $needsRemediation) { exit 0 }

# Audit-only: report non-compliant, which is exactly the shape an Intune
# detection script wants.
if ($WhatIf) {
    Write-Log "WhatIf is on - reporting only, no changes made. Re-run with -WhatIf `$false to fix it."
    exit 1
}

# ── Remediation ─────────────────────────────────────────────────────────────────
if ($lockoutTripped) {
    $stamp   = Get-Date -Format yyyyMMdd-HHmmss
    $archive = Join-Path (Split-Path -Parent $LogPath) "Security-archive-$stamp.evtx"
    wevtutil epl Security "$archive"
    wevtutil cl Security
    Set-ItemProperty $lsaPath -Name CrashOnAuditFail -Value 1
    Write-Log "Lockout cleared: log archived to $archive, cleared, CrashOnAuditFail reset from 2 to 1."
}

# Set the log to overwrite as needed at the target size so this can't recur.
wevtutil sl Security "/ms:$TargetMaxSizeBytes" /rt:false
Write-Log "Security log set to overwrite as needed, max size $TargetMaxSizeBytes bytes."

exit 0
