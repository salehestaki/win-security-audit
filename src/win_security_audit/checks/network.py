from __future__ import annotations

import ipaddress

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


SENSITIVE_LISTEN_PORTS = {
    22: "SSH",
    135: "RPC Endpoint Mapper",
    139: "NetBIOS",
    445: "SMB",
    3389: "Remote Desktop",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    5900: "VNC",
    5938: "TeamViewer",
    7070: "AnyDesk",
}


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="network",
        title="Network",
        summary="TCP and UDP endpoints with owning processes and sensitive listening ports.",
    )
    if not utils.is_windows():
        return section

    data = powershell.run_powershell_json(
        """
$proc = @{}
Get-Process | ForEach-Object {
  $proc[[int]$_.Id] = [pscustomobject]@{ Name = $_.ProcessName; Path = $_.Path }
}
$tcp = @()
try {
  $tcp = Get-NetTCPConnection | ForEach-Object {
    $p = $proc[[int]$_.OwningProcess]
    [pscustomobject]@{
      Protocol = 'TCP'
      LocalAddress = $_.LocalAddress
      LocalPort = $_.LocalPort
      RemoteAddress = $_.RemoteAddress
      RemotePort = $_.RemotePort
      State = $_.State
      PID = $_.OwningProcess
      Process = if ($p) { $p.Name } else { '' }
      Path = if ($p) { $p.Path } else { '' }
    }
  }
} catch {}
$udp = @()
try {
  $udp = Get-NetUDPEndpoint | ForEach-Object {
    $p = $proc[[int]$_.OwningProcess]
    [pscustomobject]@{
      Protocol = 'UDP'
      LocalAddress = $_.LocalAddress
      LocalPort = $_.LocalPort
      RemoteAddress = ''
      RemotePort = ''
      State = 'Bound'
      PID = $_.OwningProcess
      Process = if ($p) { $p.Name } else { '' }
      Path = if ($p) { $p.Path } else { '' }
    }
  }
} catch {}
$tcp + $udp
""",
        timeout=80,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    rows.sort(key=lambda row: (str(row.get("Protocol")), str(row.get("State")), int(row.get("LocalPort") or 0)))
    ctx.facts["network_connections"] = rows
    section.add_table(
        "Network endpoints",
        utils.limited_rows(rows, 900),
        ["Protocol", "LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "State", "PID", "Process", "Path"],
        max_rows=300,
    )

    _analyze(section, rows)
    if not section.findings:
        section.add_finding("Network endpoint inventory collected", Status.HEALTHY, severity=0)
    return section


def _analyze(section: Section, rows: list[dict]) -> None:
    listening_sensitive = []
    user_path_connections = []
    external_established = []
    remote_hits = []
    tool_hits = []
    for row in rows:
        state = str(row.get("State", "")).lower()
        try:
            local_port = int(row.get("LocalPort") or 0)
        except Exception:
            local_port = 0
        searchable = f"{row.get('Process')} {row.get('Path')} {row.get('LocalPort')} {row.get('RemotePort')}"
        if row.get("Protocol") == "TCP" and state == "listen" and local_port in SENSITIVE_LISTEN_PORTS:
            listening_sensitive.append({"ServiceHint": SENSITIVE_LISTEN_PORTS[local_port], **row})
        if utils.user_writable_path(utils.trim(row.get("Path"))):
            user_path_connections.append(row)
        if row.get("Protocol") == "TCP" and state == "established" and _is_external(row.get("RemoteAddress")):
            external_established.append(row)
        remote = utils.remote_access_name(searchable)
        tool = utils.known_tool_name(searchable)
        if remote:
            remote_hits.append({"Indicator": remote, **row})
        if tool:
            tool_hits.append({"Indicator": tool, **row})

    if listening_sensitive:
        section.add_finding(
            "Sensitive services are listening",
            Status.REVIEW,
            severity=5,
            description="Open administrative services may be expected, but they increase exposure if reachable from untrusted networks.",
            evidence=[f"{hit.get('ServiceHint')} on {hit.get('LocalAddress')}:{hit.get('LocalPort')} ({hit.get('Process')})" for hit in listening_sensitive[:8]],
            recommendation="Confirm firewall scope and disable services that are not required.",
        )
        section.add_table(
            "Sensitive listening ports",
            utils.limited_rows(listening_sensitive, 100),
            ["ServiceHint", "Protocol", "LocalAddress", "LocalPort", "PID", "Process", "Path"],
            max_rows=100,
        )

    if user_path_connections:
        section.add_finding(
            "Network process runs from a user-writable path",
            Status.REVIEW,
            severity=6,
            evidence=[f"{row.get('Process')} {row.get('LocalPort')}->{row.get('RemoteAddress')}:{row.get('RemotePort')} {row.get('Path')}" for row in user_path_connections[:8]],
            recommendation="Check whether the executable is signed and expected.",
        )

    if len(external_established) > 60:
        section.add_finding(
            "High number of established external TCP connections",
            Status.INFO,
            severity=2,
            description=f"{len(external_established)} established external TCP connections were observed.",
            recommendation="Review the connection table if unusual outbound traffic is suspected.",
        )

    if remote_hits:
        section.add_finding(
            "Remote access indicator in network endpoints",
            Status.REVIEW,
            severity=6,
            evidence=[f"{hit.get('Indicator')}: {hit.get('Process')} {hit.get('LocalPort')}->{hit.get('RemoteAddress')}:{hit.get('RemotePort')}" for hit in remote_hits[:8]],
            recommendation="Confirm the remote access channel is approved.",
        )
    if tool_hits:
        section.add_finding(
            "Dual-use tool indicator in network endpoints",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[f"{hit.get('Indicator')}: {hit.get('Process')} {hit.get('Path')}" for hit in tool_hits[:8]],
            recommendation="Investigate the process, binary hash, and parent process.",
        )


def _is_external(value: object) -> bool:
    text = str(value or "")
    if not text or text in {"0.0.0.0", "::", "::1", "127.0.0.1"}:
        return False
    try:
        ip = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)
