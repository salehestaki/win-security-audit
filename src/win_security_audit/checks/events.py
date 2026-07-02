from __future__ import annotations

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


SECURITY_EVENT_MEANINGS = {
    "4624": "Successful logon",
    "4625": "Failed logon",
    "4672": "Special privileges assigned",
    "4688": "Process creation",
    "4720": "User account created",
    "4726": "User account deleted",
    "4732": "Member added to local group",
    "4740": "Account locked out",
}


SYSTEM_EVENT_MEANINGS = {
    "7045": "Service installed",
    "7036": "Service state changed",
}


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="event-logs",
        title="Event Logs",
        summary="Recent Security and System event log highlights from the last 72 hours.",
    )
    if not utils.is_windows():
        return section

    data = powershell.run_powershell_json(
        """
$since = (Get-Date).AddHours(-72)
$securityIds = 4624,4625,4672,4688,4720,4726,4732,4740
$systemIds = 7045,7036
$security = @()
$system = @()
try {
  $security = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=$securityIds} -MaxEvents 700 | ForEach-Object {
    $msg = ($_.Message -replace '\\s+', ' ')
    [pscustomobject]@{
      Log = 'Security'
      TimeCreated = $_.TimeCreated
      Id = $_.Id
      Provider = $_.ProviderName
      Level = $_.LevelDisplayName
      Message = $msg.Substring(0, [Math]::Min(700, $msg.Length))
    }
  }
} catch {
  $security = @([pscustomobject]@{ Log='Security'; TimeCreated=''; Id='Error'; Provider=''; Level=''; Message=$_.Exception.Message })
}
try {
  $system = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since; Id=$systemIds} -MaxEvents 300 | ForEach-Object {
    $msg = ($_.Message -replace '\\s+', ' ')
    [pscustomobject]@{
      Log = 'System'
      TimeCreated = $_.TimeCreated
      Id = $_.Id
      Provider = $_.ProviderName
      Level = $_.LevelDisplayName
      Message = $msg.Substring(0, [Math]::Min(700, $msg.Length))
    }
  }
} catch {
  $system = @([pscustomobject]@{ Log='System'; TimeCreated=''; Id='Error'; Provider=''; Level=''; Message=$_.Exception.Message })
}
$all = @($security + $system)
$summary = $all | Group-Object Log, Id | ForEach-Object {
  [pscustomobject]@{ Key = $_.Name; Count = $_.Count }
}
[pscustomobject]@{ Summary = @($summary); Events = @($all | Select-Object -First 250) }
""",
        timeout=100,
    )

    if not isinstance(data, dict):
        section.add_finding("Event log collection returned no structured data", Status.REVIEW, severity=3)
        return section

    summary = [row for row in utils.coerce_list(data.get("Summary")) if isinstance(row, dict)]
    events = [row for row in utils.coerce_list(data.get("Events")) if isinstance(row, dict)]
    ctx.facts["events_summary"] = summary
    ctx.facts["events"] = events

    section.add_table("Event summary", _with_meanings(summary), ["Key", "Meaning", "Count"], max_rows=80)
    section.add_table("Recent event details", utils.limited_rows(events, 250), ["Log", "TimeCreated", "Id", "Provider", "Level", "Message"], max_rows=160)

    _analyze(section, summary, events)
    return section


def _with_meanings(summary: list[dict]) -> list[dict]:
    rows = []
    for row in summary:
        key = str(row.get("Key", ""))
        event_id = key.split(",")[-1].strip()
        meaning = SECURITY_EVENT_MEANINGS.get(event_id) or SYSTEM_EVENT_MEANINGS.get(event_id) or ""
        rows.append({"Key": key, "Meaning": meaning, "Count": row.get("Count", "")})
    return rows


def _count(summary: list[dict], event_id: int | str) -> int:
    wanted = str(event_id)
    total = 0
    for row in summary:
        key = str(row.get("Key", ""))
        if key.endswith(f", {wanted}") or key.endswith(wanted):
            try:
                total += int(row.get("Count") or 0)
            except Exception:
                pass
    return total


def _analyze(section: Section, summary: list[dict], events: list[dict]) -> None:
    error_events = [event for event in events if str(event.get("Id")).lower() == "error"]
    if error_events:
        section.add_finding(
            "Some event logs could not be read",
            Status.REVIEW,
            severity=3,
            evidence=[utils.trim(event.get("Message")) for event in error_events[:3]],
            recommendation="Run as Administrator to read Security events.",
        )
        return

    failed = _count(summary, 4625)
    lockouts = _count(summary, 4740)
    users_created = _count(summary, 4720)
    group_adds = _count(summary, 4732)
    services_installed = _count(summary, 7045)

    if failed > 50:
        section.add_finding(
            "High failed-logon volume",
            Status.REVIEW,
            severity=6,
            description=f"{failed} failed logon events were found in the last 72 hours.",
            recommendation="Review source hosts and usernames for brute-force or stale credential activity.",
        )
    elif failed > 0:
        section.add_finding("Failed logons present", Status.INFO, severity=1, description=f"{failed} failed logon events were found.")

    if lockouts:
        section.add_finding(
            "Account lockout events present",
            Status.REVIEW,
            severity=5,
            description=f"{lockouts} account lockout events were found.",
            recommendation="Identify locked accounts and source hosts.",
        )
    if users_created or group_adds:
        section.add_finding(
            "Account or group membership changes",
            Status.REVIEW,
            severity=6,
            evidence=[f"4720 user created: {users_created}", f"4732 group additions: {group_adds}"],
            recommendation="Verify the changes were authorized.",
        )
    if services_installed:
        section.add_finding(
            "Service installation events found",
            Status.REVIEW,
            severity=6,
            description=f"{services_installed} service installation events were found in System log.",
            recommendation="Review service names and binary paths in the event details.",
        )
    if not section.findings:
        section.add_finding("No high-signal recent event log findings", Status.HEALTHY, severity=0)
