from __future__ import annotations

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="software",
        title="Software",
        summary="Installed applications and remote-access software indicators.",
    )
    if not utils.is_windows():
        return section

    rows = powershell.run_powershell_json(
        """
$paths = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
foreach ($path in $paths) {
  Get-ItemProperty -Path $path | Where-Object { $_.DisplayName } | ForEach-Object {
    [pscustomobject]@{
      DisplayName = $_.DisplayName
      DisplayVersion = $_.DisplayVersion
      Publisher = $_.Publisher
      InstallDate = $_.InstallDate
      InstallLocation = $_.InstallLocation
      UninstallString = $_.UninstallString
      RegistryPath = $_.PSPath
    }
  }
}
""",
        timeout=80,
    )
    apps = [row for row in utils.coerce_list(rows) if isinstance(row, dict)]
    apps.sort(key=lambda item: str(item.get("DisplayName", "")).lower())
    ctx.facts["installed_apps"] = apps
    section.add_table(
        "Installed applications",
        utils.limited_rows(apps, 500),
        ["DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation"],
        max_rows=250,
    )

    remote_hits = []
    tool_hits = []
    for app in apps:
        searchable = " ".join(
            utils.trim(app.get(key), 300)
            for key in ["DisplayName", "Publisher", "InstallLocation", "UninstallString"]
        )
        remote = utils.remote_access_name(searchable)
        tool = utils.known_tool_name(searchable)
        if remote:
            remote_hits.append({"Indicator": remote, **app})
        if tool:
            tool_hits.append({"Indicator": tool, **app})

    if remote_hits:
        section.add_finding(
            "Remote access software installed",
            Status.REVIEW,
            severity=5,
            description="Remote access tools can be legitimate, but they are also frequently abused in intrusions.",
            evidence=[utils.trim(hit.get("DisplayName")) for hit in remote_hits[:8]],
            recommendation="Confirm each remote access tool is approved, patched, and protected with MFA where possible.",
        )
        section.add_table(
            "Remote access software",
            utils.limited_rows(remote_hits, 80),
            ["Indicator", "DisplayName", "DisplayVersion", "Publisher", "InstallLocation"],
            max_rows=80,
        )
    else:
        section.add_finding("No common remote access products found in installed apps", Status.HEALTHY, severity=0)

    if tool_hits:
        section.add_finding(
            "Security or dual-use tools appear in installed software",
            Status.REVIEW,
            severity=6,
            evidence=[utils.trim(hit.get("DisplayName")) for hit in tool_hits[:8]],
            recommendation="Validate whether these tools are part of approved administration or security testing activity.",
        )
        section.add_table(
            "Dual-use tool indicators",
            utils.limited_rows(tool_hits, 80),
            ["Indicator", "DisplayName", "DisplayVersion", "Publisher", "InstallLocation"],
            max_rows=80,
        )

    if not apps:
        section.add_finding("No installed application inventory returned", Status.REVIEW, severity=2)
    return section
