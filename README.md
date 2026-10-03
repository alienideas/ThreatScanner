# ThreatScanner
# Windows Threat Scanner & Selective Remover

A fully automated PowerShell script for **Windows 10 / 11** that scans for common malware, spyware, fileless threats, process injection indicators, suspicious network/C2 activity, and persistence mechanisms.  

At the end of the scan it presents **all findings once** (with clear explanations of *why* each item is considered a threat) and lets you choose exactly what to remove.

---

## Features

- **Automated multi-layer scan**
  - Suspicious / injected / hollowed processes
  - Processes running from temporary or user-writable locations
  - Encoded / hidden PowerShell and living-off-the-land binary (LOLBin) abuse
  - Active network connections that may indicate Command-and-Control (C2)
  - Common persistence locations (Run keys, Scheduled Tasks)
  - Existing Windows Defender detections

- **User-controlled removal**
  - All findings are shown **only once** at the end of the scan
  - You can remove **all**, **none**, or **specific items by number**
  - Each finding includes a plain-English reason (e.g. “legitimate process appears hollowed”, “running from Temp folder”, “classic fileless PowerShell pattern”, etc.)

- **Safety features**
  - Requires Administrator privileges
  - Optional System Restore Point creation before any changes
  - Detailed log file generated for every run
  - Conservative detection rules to reduce false positives on critical system processes

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later (built-in)
- Administrator rights

---

## Quick Start

1. Download `ThreatScanner.ps1`
2. Right-click **Windows PowerShell** → **Run as Administrator**
3. (Optional but recommended) Allow the script for the current session:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

   Run the script:
   ```powershell
   .\ThreatScanner.ps1
