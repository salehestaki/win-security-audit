from __future__ import annotations

import re

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="runtime",
        title="Runtime",
        summary="Running processes, services, drivers, command lines, and dual-use indicators.",
    )
    if not utils.is_windows():
        return section

    process_rows = _collect_processes(section)
    service_rows = _collect_services(section)
    driver_rows = _collect_drivers(section)
    ctx.facts["processes"] = process_rows
    ctx.facts["services"] = service_rows
    ctx.facts["drivers"] = driver_rows

    _analyze_processes(section, process_rows)
    _analyze_services(section, service_rows)
    _analyze_drivers(section, driver_rows)

    if not section.findings:
        section.add_finding("Runtime inventory collected", Status.HEALTHY, severity=0)
    return section


def _collect_processes(section: Section) -> list[dict]:
    data = powershell.run_powershell_json(
        """
Get-CimInstance Win32_Process | ForEach-Object {
  [pscustomobject]@{
    Name = $_.Name
    PID = $_.ProcessId
    ParentPID = $_.ParentProcessId
    Path = $_.ExecutablePath
    CommandLine = $_.CommandLine
    CreationDate = $_.CreationDate
  }
}
""",
        timeout=80,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    rows.sort(key=lambda row: str(row.get("Name", "")).lower())
    section.add_table(
        "Running processes",
        utils.limited_rows(rows, 500),
        ["Name", "PID", "ParentPID", "Path", "CommandLine", "CreationDate"],
        max_rows=250,
    )
    return rows


def _collect_services(section: Section) -> list[dict]:
    data = powershell.run_powershell_json(
        """
Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{
    Name = $_.Name
    DisplayName = $_.DisplayName
    State = $_.State
    StartMode = $_.StartMode
    StartName = $_.StartName
    PathName = $_.PathName
  }
}
""",
        timeout=80,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    rows.sort(key=lambda row: (str(row.get("State", "")), str(row.get("Name", "")).lower()))
    section.add_table(
        "Services",
        utils.limited_rows(rows, 600),
        ["Name", "DisplayName", "State", "StartMode", "StartName", "PathName"],
        max_rows=250,
    )
    return rows


def _collect_drivers(section: Section) -> list[dict]:
    data = powershell.run_powershell_json(
        """
Get-CimInstance Win32_SystemDriver | ForEach-Object {
  [pscustomobject]@{
    Name = $_.Name
    DisplayName = $_.DisplayName
    State = $_.State
    StartMode = $_.StartMode
    PathName = $_.PathName
  }
}
""",
        timeout=80,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    rows.sort(key=lambda row: str(row.get("Name", "")).lower())
    section.add_table("System drivers", utils.limited_rows(rows, 600), ["Name", "DisplayName", "State", "StartMode", "PathName"], max_rows=200)
    return rows


def _analyze_processes(section: Section, rows: list[dict]) -> None:
    user_path_hits = []
    suspicious_cmd_hits = []
    tool_hits = []
    remote_hits = []
    for row in rows:
        name = utils.trim(row.get("Name"))
        path = utils.trim(row.get("Path"))
        cmd = utils.trim(row.get("CommandLine"), 1200)
        searchable = f"{name} {path} {cmd}"
        if utils.user_writable_path(path) and path:
            user_path_hits.append(row)
        if utils.suspicious_command(cmd):
            suspicious_cmd_hits.append(row)
        tool = utils.known_tool_name(searchable)
        if tool:
            tool_hits.append({"Indicator": tool, **row})
        remote = utils.remote_access_name(searchable)
        if remote:
            remote_hits.append({"Indicator": remote, **row})

    if user_path_hits:
        section.add_finding(
            "Processes are running from user-writable locations",
            Status.REVIEW,
            severity=5,
            description="Malware often executes from AppData, Temp, Downloads, Desktop, or Startup. Some legitimate user-installed apps also do this.",
            evidence=[utils.trim(hit.get("Path")) for hit in user_path_hits[:8]],
            recommendation="Check file signatures and whether each process is expected for this user.",
        )
        section.add_table(
            "Processes from user-writable locations",
            utils.limited_rows(user_path_hits, 120),
            ["Name", "PID", "Path", "CommandLine"],
            max_rows=120,
        )

    if suspicious_cmd_hits:
        section.add_finding(
            "Suspicious process command lines",
            Status.SUSPICIOUS,
            severity=8,
            description="Command lines include patterns such as encoded PowerShell, script hosts, download-and-execute, or LOLBin usage.",
            evidence=[utils.trim(hit.get("CommandLine"), 500) for hit in suspicious_cmd_hits[:6]],
            recommendation="Inspect parent processes, hashes, signatures, and the originating user session.",
        )
        section.add_table(
            "Suspicious command lines",
            utils.limited_rows(suspicious_cmd_hits, 80),
            ["Name", "PID", "ParentPID", "Path", "CommandLine"],
            max_rows=80,
        )

    if tool_hits:
        section.add_finding(
            "Dual-use or credential-access tool names in running processes",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[f"{hit.get('Indicator')}: {hit.get('Name')} ({hit.get('Path')})" for hit in tool_hits[:8]],
            recommendation="Validate whether the process belongs to approved administrative or security testing activity.",
        )
        section.add_table("Running dual-use tool indicators", utils.limited_rows(tool_hits, 80), ["Indicator", "Name", "PID", "Path", "CommandLine"], max_rows=80)

    if remote_hits:
        section.add_finding(
            "Remote access process is running",
            Status.REVIEW,
            severity=6,
            evidence=[f"{hit.get('Indicator')}: {hit.get('Name')}" for hit in remote_hits[:8]],
            recommendation="Confirm the session/tool is approved and not an attacker persistence channel.",
        )
        section.add_table("Running remote access indicators", utils.limited_rows(remote_hits, 80), ["Indicator", "Name", "PID", "Path"], max_rows=80)


def _analyze_services(section: Section, rows: list[dict]) -> None:
    user_path = []
    unquoted = []
    suspicious_cmd = []
    remote_hits = []
    tool_hits = []
    for row in rows:
        path = utils.trim(row.get("PathName"), 1200)
        searchable = f"{row.get('Name')} {row.get('DisplayName')} {path}"
        if str(row.get("StartMode", "")).lower() == "auto" and utils.user_writable_path(path):
            user_path.append(row)
        if _unquoted_service_path(path):
            unquoted.append(row)
        if utils.suspicious_command(path):
            suspicious_cmd.append(row)
        remote = utils.remote_access_name(searchable)
        tool = utils.known_tool_name(searchable)
        if remote:
            remote_hits.append({"Indicator": remote, **row})
        if tool:
            tool_hits.append({"Indicator": tool, **row})

    if user_path:
        section.add_finding(
            "Auto-start services run from user-writable locations",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[utils.trim(hit.get("PathName")) for hit in user_path[:8]],
            recommendation="Move approved services to protected locations and remove unknown services.",
        )
        section.add_table("Auto services in user-writable paths", utils.limited_rows(user_path, 80), ["Name", "DisplayName", "State", "StartMode", "PathName"], max_rows=80)

    if unquoted:
        section.add_finding(
            "Unquoted service paths",
            Status.REVIEW,
            severity=4,
            description="Unquoted service paths with spaces can sometimes allow local privilege escalation if parent folders are writable.",
            evidence=[utils.trim(hit.get("PathName")) for hit in unquoted[:8]],
            recommendation="Quote the service ImagePath and verify folder permissions.",
        )
        section.add_table("Unquoted service paths", utils.limited_rows(unquoted, 100), ["Name", "DisplayName", "StartMode", "PathName"], max_rows=100)

    if suspicious_cmd:
        section.add_finding(
            "Suspicious service command lines",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[utils.trim(hit.get("PathName")) for hit in suspicious_cmd[:8]],
            recommendation="Investigate the service binary, creator, and install time.",
        )

    if remote_hits:
        section.add_finding(
            "Remote access service installed or running",
            Status.REVIEW,
            severity=6,
            evidence=[f"{hit.get('Indicator')}: {hit.get('DisplayName')}" for hit in remote_hits[:8]],
            recommendation="Confirm it is authorized and protected with strong access controls.",
        )
    if tool_hits:
        section.add_finding(
            "Dual-use tool indicator in service list",
            Status.REVIEW,
            severity=6,
            evidence=[f"{hit.get('Indicator')}: {hit.get('DisplayName')}" for hit in tool_hits[:8]],
            recommendation="Validate the service source and business justification.",
        )


def _analyze_drivers(section: Section, rows: list[dict]) -> None:
    user_path = [row for row in rows if utils.user_writable_path(utils.trim(row.get("PathName")))]
    if user_path:
        section.add_finding(
            "Driver path is in a user-writable location",
            Status.SUSPICIOUS,
            severity=9,
            evidence=[utils.trim(hit.get("PathName")) for hit in user_path[:8]],
            recommendation="Investigate immediately. Kernel drivers should not load from user-writable paths.",
        )


def _unquoted_service_path(value: str) -> bool:
    text = (value or "").strip()
    if not text or text.startswith('"'):
        return False
    exe_match = re.search(r"\.exe(\s|$)", text, flags=re.IGNORECASE)
    if not exe_match:
        return False
    exe_part = text[: exe_match.end()].strip()
    return " " in exe_part
