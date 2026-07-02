from __future__ import annotations

import csv
import io
from pathlib import Path

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="sysinternals",
        title="Sysinternals",
        summary="Optional Autoruns and Sigcheck integration when official Sysinternals tools are placed beside this project.",
    )
    if not utils.is_windows():
        return section
    if not ctx.include_sysinternals:
        section.add_finding("Sysinternals integration skipped by option", Status.INFO, severity=0)
        return section

    tools_dir = _tools_dir(ctx.project_root)
    autorunsc = _find_tool(tools_dir, "autorunsc.exe")
    sigcheck = _find_tool(tools_dir, "sigcheck.exe")
    rows = []

    if autorunsc:
        rows.extend(_run_autorunsc(section, autorunsc))
    else:
        section.add_finding(
            "Autorunsc not present",
            Status.INFO,
            severity=0,
            description=f"Optional tool not found under {tools_dir}.",
            recommendation="Place official Sysinternals autorunsc.exe in tools/sysinternals to enrich autorun data.",
        )

    if sigcheck:
        _run_sigcheck(section, sigcheck, ctx)
    else:
        section.add_finding(
            "Sigcheck not present",
            Status.INFO,
            severity=0,
            description=f"Optional tool not found under {tools_dir}.",
            recommendation="Place official Sysinternals sigcheck.exe in tools/sysinternals to enrich file signature data.",
        )

    if rows:
        section.add_table("Autorunsc results", utils.limited_rows(rows, 500), list(rows[0].keys()), max_rows=180)
    return section


def _tools_dir(project_root: Path) -> Path:
    candidates = [
        project_root / "tools" / "sysinternals",
        Path.cwd() / "tools" / "sysinternals",
        Path.cwd(),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return project_root / "tools" / "sysinternals"


def _find_tool(tools_dir: Path, name: str) -> Path | None:
    direct = tools_dir / name
    if direct.exists():
        return direct
    for path in tools_dir.glob(f"**/{name}"):
        if path.is_file():
            return path
    return None


def _run_autorunsc(section: Section, autorunsc: Path) -> list[dict]:
    command = [str(autorunsc), "-accepteula", "-a", "*", "-ct", "-nobanner"]
    code, stdout, stderr = powershell.run_command(command, timeout=130, cwd=autorunsc.parent)
    if code != 0:
        section.add_finding(
            "Autorunsc execution failed",
            Status.REVIEW,
            severity=3,
            description=utils.trim(stderr or stdout, 800),
        )
        return []

    rows: list[dict] = []
    reader = csv.reader(io.StringIO(stdout), delimiter="\t")
    headers: list[str] | None = None
    for parsed in reader:
        if not parsed:
            continue
        if headers is None:
            headers = [cell.strip() or f"Column{idx}" for idx, cell in enumerate(parsed)]
            continue
        row = {headers[idx] if idx < len(headers) else f"Column{idx}": utils.trim(value, 700) for idx, value in enumerate(parsed)}
        rows.append(row)

    unsigned = []
    suspicious = []
    for row in rows:
        joined = " ".join(str(value) for value in row.values())
        if "not verified" in joined.lower() or "unsigned" in joined.lower():
            unsigned.append(row)
        if utils.suspicious_command(joined) or utils.known_tool_name(joined) or utils.user_writable_path(joined):
            suspicious.append(row)

    section.add_finding("Autorunsc executed successfully", Status.HEALTHY, severity=0, evidence=[str(autorunsc)])
    if unsigned:
        section.add_finding(
            "Autorunsc reports unsigned or unverified entries",
            Status.REVIEW,
            severity=6,
            evidence=[utils.trim(" | ".join(str(v) for v in row.values()), 500) for row in unsigned[:6]],
            recommendation="Verify unsigned autoruns and remove entries that are not approved.",
        )
    if suspicious:
        section.add_finding(
            "Autorunsc high-signal entries",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[utils.trim(" | ".join(str(v) for v in row.values()), 500) for row in suspicious[:6]],
            recommendation="Investigate matching autoruns with file hashes and timestamps.",
        )
    return rows[:500]


def _run_sigcheck(section: Section, sigcheck: Path, ctx: AuditContext) -> None:
    suspicious_files = ctx.facts.get("suspicious_files", [])
    paths = []
    if isinstance(suspicious_files, list):
        for row in suspicious_files[:20]:
            if isinstance(row, dict) and row.get("Path"):
                paths.append(str(row.get("Path")))
    if not paths:
        section.add_finding("Sigcheck present but no suspicious files selected", Status.INFO, severity=0, evidence=[str(sigcheck)])
        return

    rows = []
    for path in paths:
        command = [str(sigcheck), "-accepteula", "-nobanner", "-q", "-h", path]
        code, stdout, stderr = powershell.run_command(command, timeout=25, cwd=sigcheck.parent)
        rows.append({"Path": path, "ExitCode": code, "Output": utils.trim(stdout or stderr, 1200)})
    section.add_table("Sigcheck output for suspicious files", rows, ["Path", "ExitCode", "Output"], max_rows=20)
    section.add_finding("Sigcheck executed for suspicious files", Status.HEALTHY, severity=0, evidence=[str(sigcheck)])
