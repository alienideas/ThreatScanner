# Windows Threat Scanner & Selective Remover

**A fully automated PowerShell tool for detecting and selectively removing malware, spyware, fileless threats, and suspicious activity on Windows 10 and Windows 11.**

This script performs a multi-layered scan focused on real-world attack techniques (process injection, living-off-the-land binaries, C2 beaconing, and persistence).  
It collects all findings silently, shows them **once** at the end with clear explanations, and gives you full control over what gets removed.

---

## Description

Modern malware (especially fileless malware, spyware, and advanced persistent threats) often avoids dropping traditional files on disk. Instead, it:

- Injects code into legitimate Windows processes
- Abuses built-in tools (PowerShell, mshta, rundll32, etc.)
- Communicates with remote Command-and-Control (C2) servers
- Creates stealthy persistence via registry or scheduled tasks

This tool is designed to detect these behaviors using native Windows capabilities and present the results in a simple, actionable way — without overwhelming the user with individual alerts during the scan.

**Key principle:** Fully automated scanning + human-controlled removal.

---

## Features

- **Automated multi-layer detection**
  - Suspicious, injected, or hollowed processes
  - Processes running from Temp, Downloads, or other user-writable locations
  - Encoded / hidden PowerShell commands (classic fileless technique)
  - Living-off-the-land binary (LOLBin) abuse
  - Active network connections that may indicate C2 activity
  - Common persistence mechanisms (Run keys, Scheduled Tasks)
  - Existing Windows Defender detections

- **Clear threat explanations**
  - Every finding includes a plain-English reason (e.g. “legitimate process appears hollowed”, “running from Temp folder”, “classic fileless PowerShell pattern”)

- **Selective & safe removal**
  - All results are shown **only once** at the end of the scan
  - Choose to remove **all**, **none**, or **specific items by number**
  - Conservative rules to avoid breaking critical system processes

- **Safety & usability**
  - Requires Administrator privileges
  - Optional System Restore Point creation
  - Detailed timestamped log file for every run
  - Simple interactive menu

---

## Installation

1. Download the script file `ThreatScanner.ps1`
2. (Recommended) Place it in a dedicated folder, for example:
   ```
   C:\Tools\ThreatScanner\
   ```
3. No additional software installation is required — the script uses only built-in Windows PowerShell features.

> **Note:** You may need to adjust the PowerShell execution policy the first time you run it (see Usage section below).

---

## Usage

### 1. Run PowerShell as Administrator
Right-click on **Windows PowerShell** or **Terminal** → **Run as administrator**.

### 2. Allow the script to run (one-time per session)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 3. Navigate to the script location and execute it
```powershell
cd C:\Tools\ThreatScanner
.\ThreatScanner.ps1
```

### 4. Follow the on-screen prompts
- The script will offer to create a **System Restore Point** (recommended).
- It then runs a fully automated scan (usually takes 1–3 minutes).
- When finished, it displays a numbered list of all findings with severity and explanations.
- You will be asked:
  - `A` → Remove **all** findings
  - `N` → Remove **nothing**
  - Or enter specific numbers (example: `1 3 5` or `1,3,5`)

### 5. After removal
- Review the log file created in your Temp folder.
- It is strongly recommended to run a **Windows Defender Offline scan** afterward.

---

## Example Output

```
 SCAN COMPLETE – 4 SUSPICIOUS ITEM(S) FOUND
--------------------------------------------------------------------------------
ID Severity Category   Name            Details
1  Critical Process    powershell.exe  PID: 4820 | CMD: -enc JABz...
2  High     Process    svchost.exe     PID: 3192 | No executable path
3  High     Network/C2 mshta.exe       PID: 5104 → 185.234.xx.xx:443
4  High     Persistence UpdateCheck    Key: HKCU\...\Run | Value: ...

DETAILED REASONS:
[1] powershell.exe (Critical)
    Why threat: PowerShell launched with encoded command or hidden window flags.
                This is a hallmark of fileless malware...

[2] svchost.exe (High)
    Why threat: Legitimate Windows process appears to have no image path on disk.
                Strong indicator of process hollowing or reflective injection...
```

---

## Log File

Every run creates a detailed log, for example:

```
%TEMP%\ThreatScan_20261003_152700.log
```

---

## Limitations

- Pure PowerShell cannot perform full physical-memory forensics or detect all advanced kernel-mode rootkits.
- Network C2 detection is behavioral only (it does not query external threat-intelligence databases).
- Some injected threats may require a reboot or additional tools after removal.

---

## Disclaimer

This tool is provided **as-is** for educational and defensive security purposes.  
The author assumes no responsibility for any damage caused by misuse or false-positive removals.

**Always** create a System Restore Point (and preferably a full backup) before running the script.  
Use only on systems you own or are authorized to scan.

---

## License

MIT License – free to use, modify, and distribute.
