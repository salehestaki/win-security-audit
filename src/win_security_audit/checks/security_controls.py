from __future__ import annotations

import os
from pathlib import Path

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


SECURITY_DOMAINS = [
    "microsoft.com",
    "windowsupdate.com",
    "update.microsoft.com",
    "download.microsoft.com",
    "virustotal.com",
    "malwarebytes.com",
    "crowdstrike.com",
    "sentinelone.net",
    "sophos.com",
]


CRITICAL_INBOUND_PORTS = {"22", "135", "139", "445", "3389", "5985", "5986", "5900", "5938"}


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="security-controls",
        title="Security Controls",
        summary="Microsoft Defender, Firewall, BitLocker, proxy, hosts file, and inbound firewall rules.",
    )
    if not utils.is_windows():
        return section

    defender = _collect_defender(section)
    firewall_profiles = _collect_firewall_profiles(section)
    bitlocker = _collect_bitlocker(section)
    proxy = _collect_proxy(section)
    hosts_rows = _collect_hosts(section)
    firewall_rules = _collect_firewall_rules(section, quick=ctx.quick)

    ctx.facts["defender"] = defender
    ctx.facts["firewall_profiles"] = firewall_profiles
    ctx.facts["bitlocker"] = bitlocker
    ctx.facts["proxy"] = proxy
    ctx.facts["hosts"] = hosts_rows
    ctx.facts["firewall_rules"] = firewall_rules

    _analyze_defender(section, defender)
    _analyze_firewall_profiles(section, firewall_profiles)
    _analyze_bitlocker(section, bitlocker)
    _analyze_proxy(section, proxy)
    _analyze_hosts(section, hosts_rows)
    _analyze_firewall_rules(section, firewall_rules)

    if not section.findings:
        section.add_finding("Security controls collected", Status.HEALTHY, severity=0)
    return section


def _collect_defender(section: Section) -> dict:
    data = powershell.run_powershell_json(
        """
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
  $d = Get-MpComputerStatus
  [pscustomobject]@{
    AMServiceEnabled = $d.AMServiceEnabled
    AntispywareEnabled = $d.AntispywareEnabled
    AntivirusEnabled = $d.AntivirusEnabled
    BehaviorMonitorEnabled = $d.BehaviorMonitorEnabled
    IoavProtectionEnabled = $d.IoavProtectionEnabled
    NISEnabled = $d.NISEnabled
    OnAccessProtectionEnabled = $d.OnAccessProtectionEnabled
    RealTimeProtectionEnabled = $d.RealTimeProtectionEnabled
    TamperProtection = $d.TamperProtection
    AntivirusSignatureLastUpdated = $d.AntivirusSignatureLastUpdated
    AntispywareSignatureLastUpdated = $d.AntispywareSignatureLastUpdated
    FullScanAge = $d.FullScanAge
    QuickScanAge = $d.QuickScanAge
  }
}
""",
        timeout=60,
    )
    row = data if isinstance(data, dict) else {}
    section.add_table("Microsoft Defender status", [utils.flatten_row(row)] if row else [], list(row.keys()) if row else [], max_rows=1)
    return row


def _collect_firewall_profiles(section: Section) -> list[dict]:
    data = powershell.run_powershell_json(
        """
if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
  Get-NetFirewallProfile | ForEach-Object {
    [pscustomobject]@{
      Name = $_.Name
      Enabled = $_.Enabled
      DefaultInboundAction = $_.DefaultInboundAction
      DefaultOutboundAction = $_.DefaultOutboundAction
      AllowInboundRules = $_.AllowInboundRules
      NotifyOnListen = $_.NotifyOnListen
      LogFileName = $_.LogFileName
      LogAllowed = $_.LogAllowed
      LogBlocked = $_.LogBlocked
    }
  }
}
""",
        timeout=45,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    section.add_table("Firewall profiles", utils.limited_rows(rows), ["Name", "Enabled", "DefaultInboundAction", "DefaultOutboundAction", "AllowInboundRules", "LogAllowed", "LogBlocked"], max_rows=10)
    return rows


def _collect_bitlocker(section: Section) -> list[dict]:
    data = powershell.run_powershell_json(
        """
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
  Get-BitLockerVolume | ForEach-Object {
    [pscustomobject]@{
      MountPoint = $_.MountPoint
      VolumeStatus = $_.VolumeStatus
      ProtectionStatus = $_.ProtectionStatus
      EncryptionPercentage = $_.EncryptionPercentage
      EncryptionMethod = $_.EncryptionMethod
      LockStatus = $_.LockStatus
      KeyProtector = (@($_.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', ')
    }
  }
}
""",
        timeout=60,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    section.add_table("BitLocker volumes", utils.limited_rows(rows), ["MountPoint", "VolumeStatus", "ProtectionStatus", "EncryptionPercentage", "EncryptionMethod", "LockStatus", "KeyProtector"], max_rows=20)
    return rows


def _collect_proxy(section: Section) -> dict:
    data = powershell.run_powershell_json(
        """
$inet = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue
$machine = Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue
$winhttp = ''
try { $winhttp = (netsh winhttp show proxy | Out-String).Trim() } catch {}
[pscustomobject]@{
  UserProxyEnable = $inet.ProxyEnable
  UserProxyServer = $inet.ProxyServer
  UserAutoConfigURL = $inet.AutoConfigURL
  MachineProxyEnable = $machine.ProxyEnable
  MachineProxyServer = $machine.ProxyServer
  MachineAutoConfigURL = $machine.AutoConfigURL
  WinHttpProxy = $winhttp
}
""",
        timeout=45,
    )
    row = data if isinstance(data, dict) else {}
    section.add_table("Proxy configuration", [utils.flatten_row(row)] if row else [], list(row.keys()) if row else [], max_rows=1)
    return row


def _collect_hosts(section: Section) -> list[dict]:
    hosts_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    rows: list[dict] = []
    try:
        content = utils.read_text_limited(hosts_path, limit=200_000)
    except Exception:
        section.notes.append(f"Could not read hosts file at {hosts_path}.")
        return rows
    for number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            rows.append({"Line": number, "Address": parts[0], "Names": " ".join(parts[1:]), "Raw": stripped})
    section.add_table("Hosts file entries", rows, ["Line", "Address", "Names", "Raw"], max_rows=120)
    return rows


def _collect_firewall_rules(section: Section, quick: bool) -> list[dict]:
    if quick:
        max_rules = 250
    else:
        max_rules = 800
    data = powershell.run_powershell_json(
        f"""
$rules = Get-NetFirewallRule -Enabled True -Action Allow -Direction Inbound -ErrorAction SilentlyContinue | Select-Object -First {max_rules}
foreach ($rule in $rules) {{
  $port = $rule | Get-NetFirewallPortFilter
  $app = $rule | Get-NetFirewallApplicationFilter
  $addr = $rule | Get-NetFirewallAddressFilter
  [pscustomobject]@{{
    DisplayName = $rule.DisplayName
    Profile = $rule.Profile
    Program = $app.Program
    Service = ($rule | Get-NetFirewallServiceFilter).Service
    Protocol = $port.Protocol
    LocalPort = $port.LocalPort
    RemoteAddress = $addr.RemoteAddress
    EdgeTraversalPolicy = $rule.EdgeTraversalPolicy
    Group = $rule.Group
  }}
}}
""",
        timeout=110,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    section.add_table("Enabled inbound allow firewall rules", utils.limited_rows(rows, 800), ["DisplayName", "Profile", "Program", "Service", "Protocol", "LocalPort", "RemoteAddress"], max_rows=220)
    return rows


def _analyze_defender(section: Section, defender: dict) -> None:
    if not defender:
        section.add_finding(
            "Defender status unavailable",
            Status.REVIEW,
            severity=4,
            description="Microsoft Defender cmdlets did not return status. This may happen if another AV is installed or access is limited.",
            recommendation="Confirm endpoint protection status manually.",
        )
        return
    critical_false = []
    for key in ["AMServiceEnabled", "AntivirusEnabled", "AntispywareEnabled", "RealTimeProtectionEnabled", "OnAccessProtectionEnabled"]:
        if str(defender.get(key)).lower() == "false":
            critical_false.append(key)
    if critical_false:
        section.add_finding(
            "Defender protection is disabled or degraded",
            Status.SUSPICIOUS,
            severity=9,
            evidence=critical_false,
            recommendation="Re-enable Microsoft Defender or verify another managed endpoint protection product is active.",
        )
    else:
        section.add_finding("Defender core protections appear enabled", Status.HEALTHY, severity=0)

    if str(defender.get("BehaviorMonitorEnabled")).lower() == "false":
        section.add_finding("Defender behavior monitoring is disabled", Status.REVIEW, severity=6)
    if str(defender.get("TamperProtection")).lower() in {"false", "off", "disabled"}:
        section.add_finding("Defender tamper protection is disabled", Status.REVIEW, severity=5)


def _analyze_firewall_profiles(section: Section, rows: list[dict]) -> None:
    disabled = [row for row in rows if str(row.get("Enabled")).lower() == "false"]
    inbound_allow = [row for row in rows if str(row.get("DefaultInboundAction")).lower() == "allow"]
    if disabled:
        section.add_finding(
            "Windows Firewall profile disabled",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[str(row.get("Name")) for row in disabled],
            recommendation="Enable Firewall profiles unless a centrally managed alternative is documented.",
        )
    if inbound_allow:
        section.add_finding(
            "Firewall default inbound action is Allow",
            Status.REVIEW,
            severity=6,
            evidence=[str(row.get("Name")) for row in inbound_allow],
            recommendation="Use default inbound block and create scoped allow rules only where needed.",
        )
    if rows and not disabled and not inbound_allow:
        section.add_finding("Firewall profiles appear enabled with default inbound blocking", Status.HEALTHY, severity=0)


def _analyze_bitlocker(section: Section, rows: list[dict]) -> None:
    if not rows:
        section.add_finding(
            "BitLocker status unavailable",
            Status.REVIEW,
            severity=3,
            description="BitLocker cmdlets returned no volume data. This can happen on unsupported Windows editions or without administrative access.",
        )
        return
    unprotected = []
    for row in rows:
        mount = str(row.get("MountPoint", ""))
        if mount.upper().startswith("C") and str(row.get("ProtectionStatus")).lower() not in {"on", "1"}:
            unprotected.append(row)
    if unprotected:
        section.add_finding(
            "OS volume BitLocker protection is not on",
            Status.REVIEW,
            severity=6,
            evidence=[f"{row.get('MountPoint')}: {row.get('ProtectionStatus')}" for row in unprotected],
            recommendation="Enable BitLocker for portable systems or document the compensating control.",
        )
    else:
        section.add_finding("BitLocker status collected", Status.HEALTHY, severity=0)


def _analyze_proxy(section: Section, proxy: dict) -> None:
    if not proxy:
        return
    enabled = str(proxy.get("UserProxyEnable")).lower() in {"1", "true"}
    machine_enabled = str(proxy.get("MachineProxyEnable")).lower() in {"1", "true"}
    auto_config = bool(proxy.get("UserAutoConfigURL") or proxy.get("MachineAutoConfigURL"))
    if enabled or machine_enabled or auto_config:
        section.add_finding(
            "Proxy configuration is enabled",
            Status.REVIEW,
            severity=5,
            evidence=[utils.trim(proxy.get("UserProxyServer")), utils.trim(proxy.get("UserAutoConfigURL")), utils.trim(proxy.get("MachineProxyServer"))],
            recommendation="Confirm the proxy/PAC URL is approved. Unexpected proxies can intercept or redirect traffic.",
        )


def _analyze_hosts(section: Section, rows: list[dict]) -> None:
    if not rows:
        section.add_finding("Hosts file has no active entries", Status.HEALTHY, severity=0)
        return
    suspicious = []
    for row in rows:
        names = str(row.get("Names", "")).lower()
        if any(domain in names for domain in SECURITY_DOMAINS):
            suspicious.append(row)
    if suspicious:
        section.add_finding(
            "Hosts file redirects security or update domains",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[utils.trim(row.get("Raw")) for row in suspicious[:8]],
            recommendation="Remove unauthorized hosts entries and check for malware persistence.",
        )
    else:
        section.add_finding("Hosts file has active custom entries", Status.INFO, severity=1)


def _analyze_firewall_rules(section: Section, rows: list[dict]) -> None:
    risky = []
    broad = []
    for row in rows:
        port = str(row.get("LocalPort", ""))
        remote = str(row.get("RemoteAddress", ""))
        if any(p in CRITICAL_INBOUND_PORTS for p in port.replace(",", " ").split()):
            risky.append(row)
        if remote in {"Any", "0.0.0.0/0", "::/0", ""} and port not in {"RPC", "RPC-EPMap"}:
            broad.append(row)
    if risky:
        section.add_finding(
            "Inbound firewall rules allow sensitive ports",
            Status.REVIEW,
            severity=6,
            evidence=[f"{row.get('DisplayName')}: {row.get('LocalPort')} from {row.get('RemoteAddress')}" for row in risky[:8]],
            recommendation="Scope sensitive inbound ports to trusted addresses or disable unused services.",
        )
    if len(broad) > 25:
        section.add_finding(
            "Many broad inbound allow rules",
            Status.INFO,
            severity=2,
            description=f"{len(broad)} enabled inbound allow rules appear broadly scoped.",
            recommendation="Review broad rules and reduce scope where practical.",
        )
