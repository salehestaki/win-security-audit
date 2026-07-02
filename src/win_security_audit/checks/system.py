from __future__ import annotations

from datetime import datetime, timezone

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="system",
        title="System",
        summary="Windows version, hardware, uptime, disks, and privilege context.",
    )
    if not utils.is_windows():
        section.add_finding(
            "Unsupported operating system",
            Status.REVIEW,
            severity=5,
            description="This tool is designed for Windows endpoints. Only a limited report can be generated here.",
        )
        return section

    data = powershell.run_powershell_json(
        """
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$tpm = $null
try { $tpm = Get-Tpm } catch {}
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
  [pscustomobject]@{
    Drive = $_.DeviceID
    SizeGB = [math]::Round($_.Size / 1GB, 1)
    FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
    FreePercent = if ($_.Size) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { 0 }
    FileSystem = $_.FileSystem
  }
}
[pscustomobject]@{
  HostName = $env:COMPUTERNAME
  UserName = [Environment]::UserName
  Windows = $os.Caption
  Version = $os.Version
  Build = $os.BuildNumber
  Architecture = $os.OSArchitecture
  InstallDate = $os.InstallDate
  LastBoot = $os.LastBootUpTime
  Domain = $cs.Domain
  DomainJoined = $cs.PartOfDomain
  Manufacturer = $cs.Manufacturer
  Model = $cs.Model
  TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
  Processor = $cpu.Name
  BIOSSerial = $bios.SerialNumber
  TimeZone = (Get-TimeZone).Id
  TPMReady = if ($tpm) { $tpm.TpmReady } else { $null }
  TPMPresent = if ($tpm) { $tpm.TpmPresent } else { $null }
  Disks = @($disks)
}
""",
        timeout=45,
    )

    if isinstance(data, dict) and data.get("__error"):
        section.add_finding("System collection error", Status.REVIEW, severity=4, description=str(data.get("__error")))
        return section

    ctx.facts["system"] = data
    info_rows = []
    for key in [
        "HostName",
        "UserName",
        "Windows",
        "Version",
        "Build",
        "Architecture",
        "Domain",
        "DomainJoined",
        "Manufacturer",
        "Model",
        "TotalMemoryGB",
        "Processor",
        "TPMPresent",
        "TPMReady",
        "TimeZone",
        "LastBoot",
    ]:
        info_rows.append({"Property": key, "Value": utils.trim(data.get(key) if isinstance(data, dict) else "")})
    section.add_table("System information", info_rows, ["Property", "Value"], max_rows=40)

    disks = utils.coerce_list(data.get("Disks") if isinstance(data, dict) else [])
    section.add_table("Fixed disks", utils.limited_rows(disks), ["Drive", "SizeGB", "FreeGB", "FreePercent", "FileSystem"], max_rows=20)

    if ctx.is_admin:
        section.add_finding("Running with Administrator rights", Status.HEALTHY, severity=0)
    else:
        section.add_finding(
            "Not running as Administrator",
            Status.REVIEW,
            severity=3,
            description="Some checks such as Security event logs, BitLocker, Defender, and protected registry locations may be incomplete.",
            recommendation="Run the tool as Administrator for a complete audit.",
        )

    for disk in disks:
        try:
            free_percent = float(disk.get("FreePercent", 100))
        except Exception:
            free_percent = 100
        if free_percent < 10:
            section.add_finding(
                f"Low disk space on {disk.get('Drive', 'drive')}",
                Status.REVIEW,
                severity=3,
                evidence=[f"{disk.get('FreeGB')} GB free ({free_percent}%)"],
                recommendation="Free space or expand the volume. Low space can break updates, logging, and forensic acquisition.",
            )

    last_boot = data.get("LastBoot") if isinstance(data, dict) else None
    if last_boot:
        try:
            boot_time = datetime.fromisoformat(str(last_boot).replace("Z", "+00:00"))
            uptime_days = (datetime.now(timezone.utc).astimezone() - boot_time).days
            if uptime_days > 30:
                section.add_finding(
                    "Long system uptime",
                    Status.REVIEW,
                    severity=2,
                    description=f"The system appears to have been running for about {uptime_days} days.",
                    recommendation="Confirm Windows Updates and security patches are not waiting for a restart.",
                )
        except Exception:
            pass

    if not section.findings:
        section.add_finding("System baseline collected", Status.HEALTHY, severity=0)
    return section
