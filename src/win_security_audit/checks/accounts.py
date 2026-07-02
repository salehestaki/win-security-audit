from __future__ import annotations

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="accounts",
        title="Accounts",
        summary="Local users, local groups, and Administrators membership.",
    )
    if not utils.is_windows():
        return section

    data = powershell.run_powershell_json(
        """
$users = @()
$admins = @()
$groups = @()
try {
  $users = Get-LocalUser | ForEach-Object {
    [pscustomobject]@{
      Name = $_.Name
      Enabled = $_.Enabled
      LastLogon = $_.LastLogon
      PasswordLastSet = $_.PasswordLastSet
      PasswordRequired = $_.PasswordRequired
      PasswordExpires = $_.PasswordExpires
      SID = [string]$_.SID
      Description = $_.Description
    }
  }
  $admins = Get-LocalGroupMember -Group Administrators | ForEach-Object {
    [pscustomobject]@{
      Name = $_.Name
      ObjectClass = $_.ObjectClass
      PrincipalSource = $_.PrincipalSource
      SID = [string]$_.SID
    }
  }
  $groups = Get-LocalGroup | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; Description = $_.Description }
  }
} catch {
  $netAdmins = net localgroup administrators
  $admins = $netAdmins | ForEach-Object { [pscustomobject]@{ Name = $_; ObjectClass = ''; PrincipalSource = ''; SID = '' } }
}
[pscustomobject]@{ Users = @($users); Administrators = @($admins); Groups = @($groups) }
""",
        timeout=60,
    )

    if isinstance(data, dict) and data.get("__error"):
        section.add_finding("Account collection error", Status.REVIEW, severity=4, description=str(data.get("__error")))
        return section

    users = utils.coerce_list(data.get("Users") if isinstance(data, dict) else [])
    admins = utils.coerce_list(data.get("Administrators") if isinstance(data, dict) else [])
    groups = utils.coerce_list(data.get("Groups") if isinstance(data, dict) else [])
    ctx.facts["users"] = users
    ctx.facts["admins"] = admins

    section.add_table(
        "Local users",
        utils.limited_rows(users),
        ["Name", "Enabled", "LastLogon", "PasswordLastSet", "PasswordRequired", "PasswordExpires", "SID", "Description"],
        max_rows=80,
    )
    section.add_table("Administrators", utils.limited_rows(admins), ["Name", "ObjectClass", "PrincipalSource", "SID"], max_rows=60)
    section.add_table("Local groups", utils.limited_rows(groups), ["Name", "Description"], max_rows=120)

    enabled_users = [u for u in users if str(u.get("Enabled")).lower() == "true"]
    if len(admins) > 5:
        section.add_finding(
            "Large Administrators group",
            Status.REVIEW,
            severity=5,
            description=f"{len(admins)} principals are listed in the local Administrators group.",
            evidence=[utils.trim(a.get("Name")) for a in admins[:8]],
            recommendation="Remove stale accounts and require named, accountable administrator access.",
        )
    else:
        section.add_finding("Administrators membership collected", Status.HEALTHY, severity=0)

    for user in users:
        sid = str(user.get("SID", ""))
        name = str(user.get("Name", ""))
        enabled = str(user.get("Enabled")).lower() == "true"
        if sid.endswith("-501") and enabled:
            section.add_finding(
                "Guest account is enabled",
                Status.SUSPICIOUS,
                severity=7,
                evidence=[name, sid],
                recommendation="Disable the Guest account unless there is a documented business requirement.",
            )
        if sid.endswith("-500") and enabled:
            section.add_finding(
                "Built-in Administrator account is enabled",
                Status.REVIEW,
                severity=5,
                evidence=[name, sid],
                recommendation="Prefer named admin accounts and keep the built-in Administrator disabled when possible.",
            )
        if enabled and str(user.get("PasswordRequired")).lower() == "false":
            section.add_finding(
                "Enabled account does not require a password",
                Status.SUSPICIOUS,
                severity=8,
                evidence=[name],
                recommendation="Require a strong password or disable the account.",
            )

    if not enabled_users:
        section.add_finding("No enabled local users found", Status.REVIEW, severity=2)
    return section
