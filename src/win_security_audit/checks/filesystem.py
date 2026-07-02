from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from win_security_audit import powershell, utils
from win_security_audit.audit import AuditContext
from win_security_audit.models import Section, Status


INTERESTING_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"}
SIGNED_EXTENSIONS = {".exe", ".dll", ".scr", ".com"}
SKIP_DIR_NAMES = {
    "cache",
    "code cache",
    "gpucache",
    "shadercache",
    "__pycache__",
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "site-packages",
}


def collect(ctx: AuditContext) -> Section:
    section = Section(
        key="suspicious-files",
        title="Suspicious Files",
        summary="Executable and script files in AppData, Temp, and Startup with hashes and signature status.",
    )
    if not utils.is_windows():
        return section

    roots = _scan_roots()
    candidates = _iter_candidates(roots, max_files=ctx.max_file_scan)
    suspicious = [_score_candidate(item) for item in candidates]
    suspicious = [item for item in suspicious if item["Score"] > 0]
    suspicious.sort(key=lambda row: (-int(row.get("Score", 0)), str(row.get("Path", "")).lower()))

    enriched = _enrich_files(suspicious[:120])
    ctx.facts["suspicious_files"] = enriched

    section.add_table(
        "Suspicious executable and script candidates",
        utils.limited_rows(enriched, 250),
        ["Score", "Reason", "Path", "Size", "ModifiedUtc", "SHA256", "SignatureStatus", "Signer"],
        max_rows=180,
    )

    _analyze(section, enriched, len(candidates), len(roots), ctx.max_file_scan)
    return section


def _scan_roots() -> list[Path]:
    roots = []
    for env_name in ["APPDATA", "LOCALAPPDATA", "TEMP", "TMP"]:
        value = os.environ.get(env_name)
        if value:
            roots.append(Path(value))
    program_data = os.environ.get("ProgramData")
    if program_data:
        roots.append(Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    unique = []
    seen = set()
    for root in roots:
        try:
            resolved = str(root.resolve())
        except Exception:
            resolved = str(root)
        if resolved.lower() not in seen and root.exists():
            unique.append(root)
            seen.add(resolved.lower())
    return unique


def _iter_candidates(roots: list[Path], max_files: int) -> list[dict]:
    rows: list[dict] = []
    if max_files <= 0:
        return rows
    seen = set()
    for root in roots:
        if len(rows) >= max_files:
            break
        for current, dirs, files in os.walk(root, topdown=True):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIR_NAMES and not d.startswith(".")]
            for name in files:
                if len(rows) >= max_files:
                    break
                path = Path(current) / name
                suffix = path.suffix.lower()
                if suffix not in INTERESTING_EXTENSIONS:
                    continue
                key = str(path).lower()
                if key in seen:
                    continue
                seen.add(key)
                try:
                    stat = path.stat()
                except OSError:
                    continue
                rows.append(
                    {
                        "Path": str(path),
                        "Extension": suffix,
                        "Size": stat.st_size,
                        "ModifiedUtc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds"),
                        "Root": str(root),
                    }
                )
    return rows


def _score_candidate(row: dict) -> dict:
    path = str(row.get("Path", ""))
    lower = path.lower().replace("/", "\\")
    ext = str(row.get("Extension", "")).lower()
    if _known_low_signal_file(lower, ext):
        row = dict(row)
        row["Score"] = 0
        row["Reason"] = ""
        return row
    score = 0
    reasons = []
    if "\\temp\\" in lower or "\\tmp\\" in lower:
        score += 4
        reasons.append("Temp path")
    if "\\startup\\" in lower:
        score += 5
        reasons.append("Startup path")
    if ext in SCRIPT_EXTENSIONS:
        score += 2
        reasons.append("Script")
    if ext in {".scr", ".hta", ".com"}:
        score += 4
        reasons.append("Risky extension")
    if utils.looks_random_name(path):
        score += 4
        reasons.append("Random-looking name")
    if utils.known_tool_name(path):
        score += 7
        reasons.append(f"Tool indicator: {utils.known_tool_name(path)}")
    if path.endswith(".lnk") and ("\\startup\\" in lower or "\\temp\\" in lower):
        score += 4
        reasons.append("Shortcut in sensitive location")
    if "\\appdata\\" in lower and ext in SIGNED_EXTENSIONS:
        score += 1
        reasons.append("Executable under AppData")
    row = dict(row)
    row["Score"] = score
    row["Reason"] = ", ".join(reasons)
    return row


def _known_low_signal_file(lower_path: str, ext: str) -> bool:
    if ext in {".js", ".jse"} and "\\appdata\\local\\microsoft\\office\\solutionpackages\\" in lower_path:
        return True
    if lower_path.endswith("\\desktop.ini"):
        return True
    return False


def _enrich_files(rows: list[dict]) -> list[dict]:
    if not rows:
        return []
    for row in rows:
        path = Path(str(row.get("Path", "")))
        row["SHA256"] = ""
        if path.exists() and path.is_file():
            try:
                row["SHA256"] = utils.sha256_file(path)
            except Exception as exc:
                row["SHA256"] = f"hash-error: {exc}"
    signable = [str(row.get("Path")) for row in rows if Path(str(row.get("Path", ""))).suffix.lower() in SIGNED_EXTENSIONS][:90]
    signatures = powershell.get_authenticode_signatures(signable, timeout=160)
    for row in rows:
        sig = signatures.get(str(row.get("Path")), {})
        row["SignatureStatus"] = sig.get("Status", "")
        row["Signer"] = sig.get("Signer", "")
        row["SignatureMessage"] = sig.get("StatusMessage", "")
        if row.get("SignatureStatus") in {"NotSigned", "UnknownError", "HashMismatch"}:
            try:
                row["Score"] = int(row.get("Score", 0)) + 3
            except Exception:
                pass
            row["Reason"] = (str(row.get("Reason") or "") + ", unsigned or invalid signature").strip(", ")
    rows.sort(key=lambda row: (-int(row.get("Score", 0) or 0), str(row.get("Path", "")).lower()))
    return rows


def _analyze(section: Section, rows: list[dict], candidate_count: int, root_count: int, max_file_scan: int) -> None:
    section.notes.append(f"Scanned {candidate_count} candidate files from {root_count} roots with max-file-scan={max_file_scan}.")
    if not rows:
        section.add_finding("No suspicious file candidates found in scanned locations", Status.HEALTHY, severity=0)
        return
    high = [row for row in rows if int(row.get("Score", 0) or 0) >= 8]
    unsigned_startup = [
        row
        for row in rows
        if "\\startup\\" in str(row.get("Path", "")).lower().replace("/", "\\")
        and str(row.get("SignatureStatus", "")).lower() in {"notsigned", "hashmismatch", "unknownerror", ""}
    ]
    tool_hits = [row for row in rows if utils.known_tool_name(str(row.get("Path")))]

    if high:
        section.add_finding(
            "High-scoring suspicious files found",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[f"{row.get('Score')}: {row.get('Path')} [{row.get('Reason')}]" for row in high[:8]],
            recommendation="Inspect hashes, signatures, timestamps, and autorun references before deleting. Preserve evidence if this may be an incident.",
        )
    else:
        section.add_finding(
            "Low-to-medium suspicious file candidates found",
            Status.REVIEW,
            severity=4,
            evidence=[f"{row.get('Score')}: {row.get('Path')}" for row in rows[:8]],
            recommendation="Review the candidate table and validate unexpected files.",
        )

    if unsigned_startup:
        section.add_finding(
            "Unsigned or unknown startup file",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[utils.trim(row.get("Path")) for row in unsigned_startup[:8]],
            recommendation="Disable unknown Startup entries and investigate the file origin.",
        )

    if tool_hits:
        section.add_finding(
            "Known dual-use tool filename found in scanned paths",
            Status.SUSPICIOUS,
            severity=8,
            evidence=[utils.trim(row.get("Path")) for row in tool_hits[:8]],
            recommendation="Validate authorization. Tools like PsExec, Netcat, Mimikatz, and credential dumpers are high-signal.",
        )
