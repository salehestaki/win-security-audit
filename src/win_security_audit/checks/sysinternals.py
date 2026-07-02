from __future__ import annotations

import csv
import io
import platform
import tempfile
import zipfile
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

    tools_dirs = _tools_dirs(ctx.project_root)
    autorunsc = _find_sysinternals_tool(tools_dirs, "autorunsc")
    sigcheck = _find_sysinternals_tool(tools_dirs, "sigcheck")
    rows = []

    if autorunsc:
        section.notes.append(f"Using Autorunsc: {autorunsc}")
        rows.extend(_run_autorunsc(section, autorunsc))
    else:
        section.add_finding(
            "Autorunsc not present",
            Status.INFO,
            severity=0,
            description=f"Optional tool not found under: {', '.join(str(path) for path in tools_dirs)}.",
            recommendation="Download Autoruns from Microsoft Sysinternals and extract autorunsc.exe, autorunsc64.exe, or autorunsc64a.exe under Sysinternals or tools/sysinternals.",
        )

    if sigcheck:
        section.notes.append(f"Using Sigcheck: {sigcheck}")
        _run_sigcheck(section, sigcheck, ctx)
    else:
        section.add_finding(
            "Sigcheck not present",
            Status.INFO,
            severity=0,
            description=f"Optional tool not found under: {', '.join(str(path) for path in tools_dirs)}.",
            recommendation="Download Sigcheck from Microsoft Sysinternals and extract sigcheck.exe under Sysinternals or tools/sysinternals.",
        )

    if rows:
        section.add_table("Autorunsc results", utils.limited_rows(rows, 500), list(rows[0].keys()), max_rows=180)
    return section


def _tools_dirs(project_root: Path) -> list[Path]:
    candidates = [
        Path.cwd() / "Sysinternals",
        Path.cwd() / "sysinternals",
        project_root / "tools" / "sysinternals",
        project_root / "tools" / "Sysinternals",
        project_root / "Sysinternals",
        project_root / "sysinternals",
        Path.cwd() / "tools" / "sysinternals",
        Path.cwd() / "tools" / "Sysinternals",
    ]
    results = []
    seen = set()
    for candidate in candidates:
        try:
            key = str(candidate.resolve()).lower()
        except Exception:
            key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists():
            results.append(candidate)
    if not results:
        results.append(project_root / "tools" / "sysinternals")
    return results


def _find_sysinternals_tool(tools_dirs: list[Path], base_name: str) -> Path | None:
    names = _preferred_tool_names(base_name)
    wanted_stems = {Path(name).stem.lower() for name in names}
    for tools_dir in tools_dirs:
        for name in names:
            direct = tools_dir / name
            if direct.is_file():
                return direct
        matches = []
        for path in tools_dir.glob("**/*.exe"):
            if path.is_file() and path.stem.lower() in wanted_stems:
                matches.append(path)
        if matches:
            matches.sort(key=lambda path: names.index(path.name.lower()) if path.name.lower() in names else 99)
            return matches[0]
        zip_match = _extract_tool_from_zip(tools_dir, names)
        if zip_match:
            return zip_match
    return None


def _extract_tool_from_zip(tools_dir: Path, names: list[str]) -> Path | None:
    zip_paths = sorted(tools_dir.glob("**/*.zip"), key=lambda path: str(path).lower())
    for zip_path in zip_paths:
        try:
            with zipfile.ZipFile(zip_path) as archive:
                members = [member for member in archive.infolist() if not member.is_dir()]
                for name in names:
                    member = _find_zip_member(members, name)
                    if not member:
                        continue
                    target = _zip_extract_target(zip_path, name)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists() and target.stat().st_size == member.file_size:
                        return target
                    with archive.open(member) as source, target.open("wb") as destination:
                        destination.write(source.read())
                    return target
        except (OSError, zipfile.BadZipFile):
            continue
    return None


def _find_zip_member(members: list[zipfile.ZipInfo], name: str) -> zipfile.ZipInfo | None:
    lowered = name.lower()
    for member in members:
        member_name = Path(member.filename.replace("\\", "/")).name.lower()
        if member_name == lowered:
            return member
    return None


def _zip_extract_target(zip_path: Path, name: str) -> Path:
    safe_zip_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in zip_path.stem)
    return Path(tempfile.gettempdir()) / "WinSecurityAudit" / "Sysinternals" / safe_zip_name / name


def _preferred_tool_names(base_name: str) -> list[str]:
    machine = platform.machine().lower()
    is_arm64 = "arm64" in machine or machine in {"aarch64", "arm"}
    is_64bit = platform.architecture()[0] == "64bit"
    base = base_name.lower()
    if base == "sigcheck":
        # Sysinternals currently ships Sigcheck as sigcheck.exe.
        return ["sigcheck.exe"]
    if is_arm64:
        return [f"{base}64a.exe", f"{base}64.exe", f"{base}.exe"]
    if is_64bit:
        return [f"{base}64.exe", f"{base}.exe", f"{base}64a.exe"]
    return [f"{base}.exe", f"{base}64.exe", f"{base}64a.exe"]


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
