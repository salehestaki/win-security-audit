from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


SUSPICIOUS_COMMAND_PATTERNS = [
    "encodedcommand",
    "-enc ",
    "frombase64string",
    "downloadstring",
    "downloadfile",
    "iex ",
    "invoke-expression",
    "invoke-webrequest",
    "bitsadmin",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "certutil",
    "add-mppreference",
]

KNOWN_TOOL_PATTERNS = [
    "mimikatz",
    "sekurlsa",
    "psexec",
    "paexec",
    "procdump",
    "rubeus",
    "sharphound",
    "bloodhound",
    "lazagne",
    "winpeas",
    "seatbelt",
    "ncat",
    "netcat",
    "nc.exe",
    "plink",
    "chisel",
    "cobaltstrike",
    "beacon",
]

REMOTE_ACCESS_PATTERNS = [
    "anydesk",
    "teamviewer",
    "rustdesk",
    "ultraviewer",
    "tightvnc",
    "realvnc",
    "vnc",
    "chrome remote desktop",
    "screenconnect",
    "connectwise",
    "splashtop",
    "logmein",
    "gotoassist",
    "zoho assist",
    "dwservice",
    "mesh agent",
    "tacticalrmm",
    "ngrok",
    "tailscale",
    "zerotier",
]


def is_windows() -> bool:
    return os.name == "nt"


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return os.environ.get("COMPUTERNAME", "unknown-host")


def is_admin() -> bool:
    if not is_windows():
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(args: list[str]) -> bool:
    if not is_windows():
        return False
    try:
        executable = sys.executable
        if getattr(sys, "frozen", False):
            parameters = " ".join(quote_windows_arg(arg) for arg in args)
        else:
            parameters = "-m win_security_audit " + " ".join(quote_windows_arg(arg) for arg in args)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parameters, os.getcwd(), 1)
        return int(rc) > 32
    except Exception:
        return False


class RunGuard:
    """Prevent accidental concurrent or immediate duplicate audits."""

    def __init__(self, output_dir: Path, cooldown_seconds: int = 120) -> None:
        self.output_dir = output_dir
        self.cooldown_seconds = cooldown_seconds
        self.lock_path = output_dir / ".security_audit.lock"
        self.stamp_path = output_dir / ".security_audit_last_run"
        self._handle = None

    def __enter__(self) -> "RunGuard":
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._check_cooldown()
        self._handle = self.lock_path.open("a+b")
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError("Another audit is already running for this output directory.") from exc
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._handle:
            if exc_type is None:
                self.stamp_path.write_text(str(time.time()), encoding="ascii")
            if os.name == "nt":
                import msvcrt

                try:
                    self._handle.seek(0)
                    msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            self._handle.close()

    def _check_cooldown(self) -> None:
        try:
            last_run = float(self.stamp_path.read_text(encoding="ascii").strip())
        except Exception:
            return
        age = time.time() - last_run
        if age < self.cooldown_seconds:
            raise RuntimeError(
                f"An audit completed {int(age)} seconds ago. Use --force to run another audit immediately."
            )


def quote_windows_arg(value: str) -> str:
    if not value:
        return '""'
    if not re.search(r'\s|"', value):
        return value
    return '"' + value.replace('"', r'\"') + '"'


def ps_quote(value: str | os.PathLike[str]) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def trim(value: Any, limit: int = 500) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def flatten_row(row: dict[str, Any], limit: int = 350) -> dict[str, str]:
    return {str(k): trim(v, limit) for k, v in row.items()}


def limited_rows(rows: Iterable[dict[str, Any]], limit: int = 300) -> list[dict[str, str]]:
    return [flatten_row(row) for row in list(rows)[:limit]]


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text_limited(path: Path, limit: int = 250_000) -> str:
    data = path.read_bytes()[:limit]
    for encoding in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return data.decode(encoding, errors="replace")
        except Exception:
            continue
    return data.decode(errors="replace")


def user_writable_path(path: str | None) -> bool:
    if not path:
        return False
    lower = path.lower().replace("/", "\\")
    markers = [
        "\\appdata\\",
        "\\temp\\",
        "\\tmp\\",
        "\\users\\public\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\startup\\",
    ]
    return any(marker in lower for marker in markers)


def startup_path(path: str | None) -> bool:
    if not path:
        return False
    return "\\startup\\" in path.lower().replace("/", "\\")


def suspicious_command(text: str | None) -> bool:
    if not text:
        return False
    normalized = " ".join(text.lower().split())
    return any(pattern in normalized for pattern in SUSPICIOUS_COMMAND_PATTERNS)


def known_tool_name(text: str | None) -> str | None:
    if not text:
        return None
    normalized = text.lower()
    for pattern in KNOWN_TOOL_PATTERNS:
        if pattern in normalized:
            return pattern
    return None


def remote_access_name(text: str | None) -> str | None:
    if not text:
        return None
    normalized = text.lower()
    for pattern in REMOTE_ACCESS_PATTERNS:
        if pattern in normalized:
            return pattern
    return None


def looks_random_name(path: str | None) -> bool:
    if not path:
        return False
    stem = Path(path).stem
    if len(stem) < 10:
        return False
    if re.fullmatch(r"[a-f0-9]{12,}", stem.lower()):
        return True
    consonants = len(re.findall(r"[bcdfghjklmnpqrstvwxyz]", stem.lower()))
    vowels = len(re.findall(r"[aeiou]", stem.lower()))
    digits = len(re.findall(r"\d", stem))
    return consonants >= 7 and vowels <= 2 and digits >= 2


def extract_path_from_command(command: str | None) -> str:
    if not command:
        return ""
    text = command.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 1 else text.strip('"')
    match = re.search(r"([a-zA-Z]:\\[^\s]+?\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr))", text)
    if match:
        return match.group(1)
    return text.split(" ")[0]


def json_default(value: Any) -> str:
    if isinstance(value, (datetime, Path)):
        return str(value)
    return trim(value, 1000)


def dump_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=json_default)


def timestamp_for_filename() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def resource_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[2]
