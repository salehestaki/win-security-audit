from __future__ import annotations

from pathlib import Path

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="persistence",
        title="Persistence",
        summary="Autoruns, startup folders, scheduled tasks, WMI event subscriptions, and PowerShell profiles.",
    )
    if not utils.is_windows():
        return section

    autoruns = _collect_registry_and_startup(section)
    tasks = _collect_scheduled_tasks(section, quick=ctx.quick)
    wmi = _collect_wmi(section)
    profiles = _collect_powershell_profiles(section)

    ctx.facts["autoruns"] = autoruns
    ctx.facts["scheduled_tasks"] = tasks
    ctx.facts["wmi_persistence"] = wmi
    ctx.facts["powershell_profiles"] = profiles

    _analyze_autoruns(section, autoruns)
    _analyze_tasks(section, tasks)
    _analyze_wmi(section, wmi)
    _analyze_profiles(section, profiles)

    if not section.findings:
        section.add_finding("No notable persistence indicators found", Status.HEALTHY, severity=0)
    return section


def _collect_registry_and_startup(section: Section) -> list[dict]:
    data = powershell.run_powershell_json(
        """
$items = @()
$runKeys = @(
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
foreach ($key in $runKeys) {
  if (Test-Path $key) {
    $props = Get-ItemProperty -Path $key
    foreach ($prop in $props.PSObject.Properties) {
      if ($prop.Name -notmatch '^PS') {
        $items += [pscustomobject]@{
          Source = 'Registry'
          Location = $key
          Name = $prop.Name
          Command = [string]$prop.Value
          LastWriteTime = ''
        }
      }
    }
  }
}
$startupFolders = @(
  [Environment]::GetFolderPath('Startup'),
  "$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
)
foreach ($folder in $startupFolders) {
  if (Test-Path $folder) {
    Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | ForEach-Object {
      $target = ''
      if ($_.Extension -eq '.lnk') {
        try {
          $shell = New-Object -ComObject WScript.Shell
          $shortcut = $shell.CreateShortcut($_.FullName)
          $target = ($shortcut.TargetPath + ' ' + $shortcut.Arguments).Trim()
        } catch {}
      }
      if ($_.Name -ne 'desktop.ini') {
        if (-not $target) { $target = $_.FullName }
        $items += [pscustomobject]@{
          Source = 'StartupFolder'
          Location = $folder
          Name = $_.Name
          Command = $target
          LastWriteTime = $_.LastWriteTimeUtc
        }
      }
    }
  }
}
$items
""",
        timeout=70,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    section.add_table("Registry and startup-folder autoruns", utils.limited_rows(rows, 300), ["Source", "Location", "Name", "Command", "LastWriteTime"], max_rows=180)
    return rows


def _collect_scheduled_tasks(section: Section, quick: bool) -> list[dict]:
    timeout = 80 if quick else 130
    data = powershell.run_powershell_json(
        """
Get-ScheduledTask | ForEach-Object {
  $actions = @($_.Actions | ForEach-Object { (($_.Execute + ' ' + $_.Arguments).Trim()) }) -join '; '
  $triggers = @($_.Triggers | ForEach-Object { if ($_) { [string]$_ } }) -join '; '
  [pscustomobject]@{
    TaskPath = $_.TaskPath
    TaskName = $_.TaskName
    State = $_.State
    Author = $_.Author
    UserId = $_.Principal.UserId
    RunLevel = $_.Principal.RunLevel
    Actions = $actions
    Triggers = $triggers
  }
}
""",
        timeout=timeout,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    rows.sort(key=lambda row: (str(row.get("TaskPath", "")).lower(), str(row.get("TaskName", "")).lower()))
    section.add_table("Scheduled tasks", utils.limited_rows(rows, 800), ["TaskPath", "TaskName", "State", "Author", "UserId", "RunLevel", "Actions"], max_rows=260)
    return rows


def _collect_wmi(section: Section) -> list[dict]:
    data = powershell.run_powershell_json(
        """
$filters = @(Get-WmiObject -Namespace root\\subscription -Class __EventFilter | ForEach-Object {
  [pscustomobject]@{ Type = 'Filter'; Name = $_.Name; Query = $_.Query; Consumer = ''; Command = '' }
})
$cmdConsumers = @(Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | ForEach-Object {
  [pscustomobject]@{ Type = 'CommandLineConsumer'; Name = $_.Name; Query = ''; Consumer = $_.Name; Command = ($_.ExecutablePath + ' ' + $_.CommandLineTemplate).Trim() }
})
$scriptConsumers = @(Get-WmiObject -Namespace root\\subscription -Class ActiveScriptEventConsumer | ForEach-Object {
  [pscustomobject]@{ Type = 'ActiveScriptConsumer'; Name = $_.Name; Query = ''; Consumer = $_.ScriptingEngine; Command = ($_.ScriptText -replace '\\s+', ' ') }
})
$bindings = @(Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding | ForEach-Object {
  [pscustomobject]@{ Type = 'Binding'; Name = ''; Query = [string]$_.Filter; Consumer = [string]$_.Consumer; Command = '' }
})
$filters + $cmdConsumers + $scriptConsumers + $bindings
""",
        timeout=90,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    section.add_table("WMI event subscriptions", utils.limited_rows(rows, 120), ["Type", "Name", "Query", "Consumer", "Command"], max_rows=120)
    return rows


def _collect_powershell_profiles(section: Section) -> list[dict]:
    data = powershell.run_powershell_json(
        """
$profilePaths = @(
  $PROFILE.AllUsersAllHosts,
  $PROFILE.AllUsersCurrentHost,
  $PROFILE.CurrentUserAllHosts,
  $PROFILE.CurrentUserCurrentHost
) | Select-Object -Unique
foreach ($path in $profilePaths) {
  if ($path -and (Test-Path -LiteralPath $path)) {
    $item = Get-Item -LiteralPath $path
    $content = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
    $flat = if ($content) { $content -replace '\\s+', ' ' } else { '' }
    [pscustomobject]@{
      Path = $path
      Length = $item.Length
      LastWriteTime = $item.LastWriteTimeUtc
      Preview = $flat.Substring(0, [Math]::Min(500, $flat.Length))
    }
  }
}
""",
        timeout=45,
    )
    rows = [row for row in utils.coerce_list(data) if isinstance(row, dict)]
    section.add_table("PowerShell profiles", utils.limited_rows(rows, 20), ["Path", "Length", "LastWriteTime", "Preview"], max_rows=20)
    return rows


def _analyze_autoruns(section: Section, rows: list[dict]) -> None:
    if not rows:
        section.add_finding("No Run/Startup autoruns returned", Status.HEALTHY, severity=0)
        return
    user_path = []
    suspicious_cmd = []
    startup_scripts = []
    tool_hits = []
    for row in rows:
        command = utils.trim(row.get("Command"), 1200)
        name = utils.trim(row.get("Name"))
    if _is_meaningful_autorun(command) and utils.user_writable_path(command):
        user_path.append(row)
        if utils.suspicious_command(command):
            suspicious_cmd.append(row)
        if utils.startup_path(utils.trim(row.get("Location"))) and Path(name).suffix.lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf"}:
            startup_scripts.append(row)
        tool = utils.known_tool_name(f"{name} {command}")
        if tool:
            tool_hits.append({"Indicator": tool, **row})

    if user_path:
        section.add_finding(
            "Autoruns point to user-writable locations",
            Status.REVIEW,
            severity=6,
            evidence=[utils.trim(row.get("Command")) for row in user_path[:8]],
            recommendation="Validate each autorun and remove unknown entries.",
        )
    if suspicious_cmd:
        section.add_finding(
            "Suspicious autorun command",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[utils.trim(row.get("Command")) for row in suspicious_cmd[:8]],
            recommendation="Investigate the command, parent install source, and referenced files.",
        )
    if startup_scripts:
        section.add_finding(
            "Script files in Startup folder",
            Status.REVIEW,
            severity=6,
            evidence=[utils.trim(row.get("Name")) for row in startup_scripts[:8]],
            recommendation="Startup scripts should be rare on end-user systems. Confirm they are approved.",
        )
    if tool_hits:
        section.add_finding(
            "Dual-use tool indicator in autoruns",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[f"{hit.get('Indicator')}: {hit.get('Command')}" for hit in tool_hits[:8]],
            recommendation="Remove unauthorized persistence and preserve evidence before cleanup.",
        )


def _analyze_tasks(section: Section, rows: list[dict]) -> None:
    suspicious = []
    user_path = []
    remote_hits = []
    tool_hits = []
    for row in rows:
        actions = utils.trim(row.get("Actions"), 1500)
        searchable = f"{row.get('TaskPath')} {row.get('TaskName')} {actions}"
        if utils.suspicious_command(actions):
            suspicious.append(row)
        if utils.user_writable_path(actions):
            user_path.append(row)
        remote = utils.remote_access_name(searchable)
        tool = utils.known_tool_name(searchable)
        if remote:
            remote_hits.append({"Indicator": remote, **row})
        if tool:
            tool_hits.append({"Indicator": tool, **row})

    if suspicious:
        section.add_finding(
            "Scheduled tasks with suspicious commands",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[f"{row.get('TaskPath')}{row.get('TaskName')}: {utils.trim(row.get('Actions'), 400)}" for row in suspicious[:8]],
            recommendation="Inspect task author, creation time, action target, and trigger history.",
        )
        section.add_table("Suspicious scheduled tasks", utils.limited_rows(suspicious, 80), ["TaskPath", "TaskName", "State", "Author", "UserId", "Actions"], max_rows=80)

    if user_path:
        section.add_finding(
            "Scheduled tasks run from user-writable paths",
            Status.REVIEW,
            severity=6,
            evidence=[f"{row.get('TaskPath')}{row.get('TaskName')}: {utils.trim(row.get('Actions'), 400)}" for row in user_path[:8]],
            recommendation="Confirm whether these tasks belong to legitimate user-installed applications.",
        )
    if remote_hits:
        section.add_finding(
            "Remote access indicator in scheduled tasks",
            Status.REVIEW,
            severity=6,
            evidence=[f"{hit.get('Indicator')}: {hit.get('TaskName')}" for hit in remote_hits[:8]],
            recommendation="Validate the task is expected and not being used as remote-access persistence.",
        )
    if tool_hits:
        section.add_finding(
            "Dual-use tool indicator in scheduled tasks",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[f"{hit.get('Indicator')}: {hit.get('TaskName')}" for hit in tool_hits[:8]],
            recommendation="Treat as suspicious unless explicitly approved.",
        )


def _analyze_wmi(section: Section, rows: list[dict]) -> None:
    meaningful_rows = [row for row in rows if not _known_benign_wmi_subscription(row)]
    if meaningful_rows:
        section.add_finding(
            "WMI event subscription persistence present",
            Status.SUSPICIOUS,
            severity=8,
            description="Permanent WMI event subscriptions are uncommon on normal workstations and are often used for stealthy persistence.",
            evidence=[f"{row.get('Type')}: {utils.trim(row.get('Name') or row.get('Command') or row.get('Query'), 400)}" for row in meaningful_rows[:8]],
            recommendation="Validate each subscription. Export evidence before deleting unknown filters, consumers, or bindings.",
        )
    elif rows:
        section.add_finding(
            "Only known Windows WMI subscriptions found",
            Status.HEALTHY,
            severity=0,
            evidence=[f"{row.get('Type')}: {utils.trim(row.get('Name') or row.get('Query') or row.get('Consumer'), 200)}" for row in rows[:4]],
        )


def _analyze_profiles(section: Section, rows: list[dict]) -> None:
    suspicious = []
    for row in rows:
        preview = utils.trim(row.get("Preview"), 1000)
        if utils.suspicious_command(preview):
            suspicious.append(row)
    if suspicious:
        section.add_finding(
            "Suspicious PowerShell profile content",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[utils.trim(row.get("Path")) for row in suspicious],
            recommendation="Review the profile content and remove unauthorized commands.",
        )
    elif rows:
        section.add_finding(
            "PowerShell profile files exist",
            Status.INFO,
            severity=1,
            evidence=[utils.trim(row.get("Path")) for row in rows],
            recommendation="Review profiles if PowerShell abuse is suspected.",
        )


def _is_meaningful_autorun(command: str) -> bool:
    suffix = Path(utils.extract_path_from_command(command)).suffix.lower()
    return suffix in {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".scr", ".lnk"}


def _known_benign_wmi_subscription(row: dict) -> bool:
    text = " ".join(str(row.get(key, "")) for key in ["Type", "Name", "Query", "Consumer", "Command"]).lower()
    known = [
        "scm event log filter",
        "msft_scmeventlogevent",
        "scm event log consumer",
    ]
    return any(item in text for item in known) and not utils.suspicious_command(text) and not utils.known_tool_name(text)
