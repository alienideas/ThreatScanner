#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Automated Windows 10/11 Threat Scanner & Selective Remover
.DESCRIPTION
    Fully automated scan. Shows all findings ONCE at the end with reasons.
    User chooses: remove all, specific numbers, or none.
#>

$ErrorActionPreference = "Continue"
$script:Findings = @()
$LogPath = "$env:TEMP\ThreatScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
    if ($Level -eq "ERROR") { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq "WARN") { Write-Host $line -ForegroundColor Yellow }
    else { Write-Host $line -ForegroundColor Cyan }
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Details,
        [string]$Reason,
        [string]$Severity = "Medium",
        [string]$ActionType,
        [string]$Target,
        [hashtable]$Extra = @{}
    )
    $script:Findings += [PSCustomObject]@{
        ID          = $script:Findings.Count + 1
        Category    = $Category
        Name        = $Name
        Details     = $Details
        Reason      = $Reason
        Severity    = $Severity
        ActionType  = $ActionType
        Target      = $Target
        Extra       = $Extra
    }
}

function Scan-SuspiciousProcesses {
    Write-Log "Scanning running processes for anomalies..."
    
    $suspiciousPaths = @("\Temp\", "\AppData\Local\Temp\", "\Downloads\", "\AppData\Roaming\", "\ProgramData\")
    $lolbins = @("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe")
    
    Get-CimInstance Win32_Process | ForEach-Object {
        $proc = $_
        $path = $proc.ExecutablePath
        $cmd  = $proc.CommandLine
        $name = $proc.Name
        $pid  = $proc.ProcessId
        
        if (-not $path -and $name -notin @("System", "Idle", "Registry")) {
            Add-Finding -Category "Process" -Name $name -Details "PID: $pid | No executable path" `
                -Reason "Legitimate Windows process appears to have no image path on disk. This is a strong indicator of process hollowing or reflective injection (common in fileless malware and APTs)." `
                -Severity "High" -ActionType "Process" -Target $pid
        }
        
        if ($path) {
            foreach ($sp in $suspiciousPaths) {
                if ($path -like "*$sp*") {
                    Add-Finding -Category "Process" -Name $name -Details "PID: $pid | Path: $path" `
                        -Reason "Process is executing from a temporary or user-writable folder. Legitimate Windows system processes almost never run from Temp/Downloads. Highly suspicious for malware droppers and spyware." `
                        -Severity "High" -ActionType "Process" -Target $pid -Extra @{Path = $path}
                    break
                }
            }
        }
        
        if ($name -match "powershell|pwsh" -and $cmd) {
            if ($cmd -match "-enc|-encodedcommand|-e | -w hidden|-windowstyle hidden|-nop|-noni") {
                $shortCmd = $cmd.Substring(0, [Math]::Min(120, $cmd.Length))
                Add-Finding -Category "Process" -Name $name -Details "PID: $pid | CMD: $shortCmd..." `
                    -Reason "PowerShell launched with encoded command or hidden window flags. This is a hallmark of fileless malware and living-off-the-land attacks." `
                    -Severity "Critical" -ActionType "Process" -Target $pid
            }
        }
        
        if ($lolbins -contains $name.ToLower() -and $cmd -match "http|download|iex|invoke-expression|frombase64") {
            Add-Finding -Category "Process" -Name $name -Details "PID: $pid | Suspicious args detected" `
                -Reason "Living-off-the-land binary ($name) used with download or code-execution arguments. Frequently abused by malware to avoid dropping files." `
                -Severity "High" -ActionType "Process" -Target $pid
        }
    }
}

function Scan-NetworkC2 {
    Write-Log "Scanning active network connections for C2 indicators..."
    
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        
        $remote = "$($conn.RemoteAddress):$($conn.RemotePort)"
        
        $suspiciousProc = $proc.ProcessName -match "powershell|wscript|mshta|rundll32|svchost|explorer"
        $highPort = $conn.RemotePort -gt 10000
        
        if ($suspiciousProc -or $highPort) {
            if ($conn.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)" -and
                $conn.RemoteAddress -notlike "*.microsoft.com" -and
                $conn.RemoteAddress -notlike "*.windows.com") {
                
                Add-Finding -Category "Network/C2" -Name $proc.ProcessName `
                    -Details "PID: $($proc.Id) -> $remote" `
                    -Reason "Process is making an established outbound connection that may indicate Command-and-Control (C2) beaconing or data exfiltration. Combined with process name, this is a strong behavioral indicator of malware/spyware." `
                    -Severity "High" -ActionType "Network" -Target $proc.Id `
                    -Extra @{Remote = $remote; LocalPort = $conn.LocalPort}
            }
        }
    }
}

function Scan-Persistence {
    Write-Log "Scanning common persistence locations..."
    
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty $key -ErrorAction SilentlyContinue | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") } | ForEach-Object {
                    $val = $_.Value
                    if ($val -match "Temp|AppData\\Local\\Temp|Downloads|http|powershell|mshta|wscript|rundll32") {
                        Add-Finding -Category "Persistence" -Name $_.Name -Details "Key: $key | Value: $val" `
                            -Reason "Suspicious entry in Run/RunOnce key pointing to temporary location or scripting engine. Classic malware persistence method." `
                            -Severity "High" -ActionType "Registry" -Target "$key\$($_.Name)"
                    }
                }
            }
        }
    }
    
    Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
        $actions = $_.Actions.Execute + " " + $_.Actions.Arguments
        if ($actions -match "Temp|AppData\\Local\\Temp|powershell -|mshta|wscript|http") {
            Add-Finding -Category "Persistence" -Name $_.TaskName -Details "Path: $($_.TaskPath) | Action: $actions" `
                -Reason "Scheduled task executes content from temporary location or uses scripting engines with suspicious arguments. Frequently used by spyware and APTs for persistence." `
                -Severity "High" -ActionType "ScheduledTask" -Target $_.TaskName
        }
    }
}

function Scan-DefenderThreats {
    Write-Log "Querying Windows Defender for existing detections..."
    try {
        $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue
        foreach ($t in $threats) {
            Add-Finding -Category "Defender" -Name $t.Resources -Details "Threat ID: $($t.ThreatID) | Domain: $($t.Domain)" `
                -Reason "Windows Defender has already classified this as a threat ($($t.ThreatName)). Severity reported by Defender engine." `
                -Severity "Critical" -ActionType "Defender" -Target $t.ThreatID
        }
    } catch {
        Write-Log "Could not query Defender detections (may require newer Windows or Defender running)." "WARN"
    }
}

function Remove-SelectedFindings {
    param([int[]]$IDs)
    
    foreach ($id in $IDs) {
        $f = $script:Findings | Where-Object { $_.ID -eq $id }
        if (-not $f) { continue }
        
        Write-Host ""
        Write-Host "Removing [$id] $($f.Name) ..." -ForegroundColor Yellow
        
        try {
            switch ($f.ActionType) {
                "Process" {
                    Stop-Process -Id $f.Target -Force -ErrorAction Stop
                    Write-Log "Killed process PID $($f.Target)"
                    if ($f.Extra.Path -and (Test-Path $f.Extra.Path)) {
                        Remove-Item $f.Extra.Path -Force -ErrorAction SilentlyContinue
                        Write-Log "Deleted file $($f.Extra.Path)"
                    }
                }
                "Registry" {
                    $regPath = $f.Target.Substring(0, $f.Target.LastIndexOf('\'))
                    $regName = $f.Target.Split('\')[-1]
                    Remove-ItemProperty -Path $regPath -Name $regName -Force -ErrorAction Stop
                    Write-Log "Removed registry value $($f.Target)"
                }
                "ScheduledTask" {
                    Unregister-ScheduledTask -TaskName $f.Target -Confirm:$false -ErrorAction Stop
                    Write-Log "Removed scheduled task $($f.Target)"
                }
                "Defender" {
                    Write-Log "Defender threat $($f.Target) - recommend running full Defender scan afterward"
                }
                default {
                    Write-Log "No automated removal defined for ActionType $($f.ActionType)" "WARN"
                }
            }
            Write-Host "  -> Successfully processed." -ForegroundColor Green
        }
        catch {
            Write-Host "  -> Failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Removal failed for ID $id : $($_.Exception.Message)" "ERROR"
        }
    }
}

# ==================== MAIN ====================

Clear-Host
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Windows 10/11 Automated Threat Scanner & Remover" -ForegroundColor Cyan
Write-Host "  Focus: Processes | Network/C2 | Persistence | Fileless" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Log file: $LogPath"
Write-Host ""

$createRP = Read-Host "Create a System Restore Point before scanning? (Y/N)"
if ($createRP -match '^[Yy]') {
    try {
        Checkpoint-Computer -Description "Before ThreatScan $(Get-Date -Format g)" -RestorePointType MODIFY_SETTINGS
        Write-Log "System Restore Point created."
    } catch {
        Write-Log "Could not create restore point: $($_.Exception.Message)" "WARN"
    }
}

Write-Host ""
Write-Host "Starting automated scan... This may take 1-3 minutes." -ForegroundColor Green
Write-Host ""

Scan-SuspiciousProcesses
Scan-NetworkC2
Scan-Persistence
Scan-DefenderThreats

if ($script:Findings.Count -eq 0) {
    Write-Host ""
    Write-Host "No suspicious items found matching the detection rules." -ForegroundColor Green
    Write-Log "Scan completed - no findings."
    exit 0
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Yellow
Write-Host " SCAN COMPLETE - $($script:Findings.Count) SUSPICIOUS ITEM(S) FOUND" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Yellow

$script:Findings | Sort-Object Severity -Descending | Format-Table -AutoSize ID, Severity, Category, Name, Details -Wrap

Write-Host ""
Write-Host "DETAILED REASONS:" -ForegroundColor Cyan
foreach ($f in ($script:Findings | Sort-Object ID)) {
    Write-Host ""
    Write-Host "[$($f.ID)] $($f.Name)  ($($f.Severity))" -ForegroundColor White
    Write-Host "    Category : $($f.Category)"
    Write-Host "    Details  : $($f.Details)"
    Write-Host "    Why threat: $($f.Reason)" -ForegroundColor Magenta
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Yellow
Write-Host "REMOVAL OPTIONS" -ForegroundColor Yellow
Write-Host "  A  = Remove ALL listed items"
Write-Host "  N  = Remove NONE (exit)"
Write-Host "  Or type specific numbers separated by commas / spaces (e.g. 1 3 7  or  1,3,7)"
Write-Host "================================================================================" -ForegroundColor Yellow

$choice = Read-Host "Your choice"

if ($choice -match '^[Nn]') {
    Write-Host "No changes made. Exiting." -ForegroundColor Cyan
    exit 0
}

$toRemove = @()
if ($choice -match '^[Aa]') {
    $toRemove = $script:Findings.ID
}
else {
    $toRemove = $choice -split '[, ]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
}

if ($toRemove.Count -eq 0) {
    Write-Host "No valid IDs selected. Exiting." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "You selected $($toRemove.Count) item(s) for removal. Proceeding..." -ForegroundColor Red
Start-Sleep -Seconds 2

Remove-SelectedFindings -IDs $toRemove

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  Done. Review the log file for details:" -ForegroundColor Green
Write-Host "  $LogPath" -ForegroundColor Green
Write-Host "  Strongly recommended: Run a full Windows Defender Offline scan now." -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
```

The clean script file is ready.