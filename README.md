# Windows Security Audit Tool

A lightweight Windows security audit and incident-response reporting tool. It runs locally, collects endpoint evidence, calculates a 0-100 risk score, and writes a professional HTML report plus a JSON artifact.

## Quick Start

Double-click `run_audit.cmd` for the easiest local run. If a packaged executable is present, the launcher uses it; otherwise it falls back to the installed Python runtime.

```powershell
.\run_audit.cmd
```

The tool automatically asks for Administrator rights when possible. Running as Administrator gives better coverage for Security event logs, BitLocker, Defender, protected registry keys, and firewall data.

Reports are written to:

```text
reports\SecurityReport_<host>_<timestamp>.html
reports\SecurityReport_<host>_<timestamp>.json
```

## What It Checks

- System and Windows version
- Local users, groups, and Administrators membership
- Installed applications
- Running processes, command lines, services, and drivers
- Startup folders and Run/RunOnce registry autoruns
- Scheduled tasks
- Network connections with owning process
- Microsoft Defender status
- Windows Firewall profiles and inbound allow rules
- BitLocker status
- USB and related system indicators through runtime inventory
- Remote access software indicators
- Suspicious executables/scripts under AppData, Temp, and Startup
- SHA256 hashes and Authenticode signatures for suspicious files
- WMI persistence
- PowerShell profile files
- Hosts file entries
- Proxy settings
- Recent Security/System event logs
- Common dual-use/security tool indicators such as Mimikatz, PsExec, Netcat, Rubeus, SharpHound, and similar tools
- Optional Sysinternals Autoruns/Sigcheck integration

## Optional Sysinternals Integration

Download the official Microsoft Sysinternals tools yourself and place these files here:

```text
tools\sysinternals\autorunsc.exe
tools\sysinternals\sigcheck.exe
```

If present, their output is folded into the same HTML report. The project does not redistribute Sysinternals binaries.

## Build a Standalone EXE

```powershell
.\build.ps1
```

This creates:

```text
dist\SecurityAudit.exe
release\SecurityAuditTool.zip
```

The EXE is built with PyInstaller and does not require Python on the target machine.

## Command Line

```powershell
py -3 -m win_security_audit --output-dir reports
py -3 -m win_security_audit --quick --max-file-scan 800
py -3 -m win_security_audit --no-elevate --no-open
```

Useful options:

- `--quick`: faster run with lower scan limits.
- `--max-file-scan N`: cap filesystem candidate inspection.
- `--no-open`: do not open the HTML report automatically.
- `--no-elevate`: do not request Administrator rights.
- `--no-sysinternals`: skip optional Sysinternals execution.

## Safety and Privacy

The tool is read-only except for writing report files under the selected output directory and temporary files needed for signature checks. It does not upload data or call external services.

Some findings are intentionally conservative. For example, remote access tools and executables under AppData can be legitimate, so the report marks many of these as "Needs review" rather than automatically malicious.

## Development

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s tests
python -m win_security_audit --quick --no-elevate --no-open
```

## License

MIT
