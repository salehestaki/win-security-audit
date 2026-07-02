from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from win_security_audit import utils


def _startupinfo() -> subprocess.STARTUPINFO | None:
    if os.name != "nt":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return info


def run_command(command: list[str], timeout: int = 60, cwd: Path | None = None) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            startupinfo=_startupinfo(),
        )
        return completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", f"Command timed out after {timeout}s"
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def run_powershell(script: str, timeout: int = 60) -> tuple[int, str, str]:
    executable = "powershell.exe" if os.name == "nt" else "pwsh"
    command = [
        executable,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    return run_command(command, timeout=timeout)


def run_powershell_json(script: str, timeout: int = 60) -> Any:
    wrapped = f"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
try {{
  $result = & {{
{script}
  }}
  if ($null -eq $result) {{
    @() | ConvertTo-Json -Depth 8 -Compress
  }} else {{
    $result | ConvertTo-Json -Depth 8 -Compress
  }}
}} catch {{
  [pscustomobject]@{{ __error = $_.Exception.Message }} | ConvertTo-Json -Depth 4 -Compress
}}
"""
    code, stdout, stderr = run_powershell(wrapped, timeout=timeout)
    output = stdout.strip()
    if code != 0 and not output:
        return {"__error": stderr.strip() or f"PowerShell exited with {code}"}
    if not output:
        return []
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"__raw": output[:5000], "__error": stderr.strip()}


def get_authenticode_signatures(paths: list[str], timeout: int = 120) -> dict[str, dict[str, str]]:
    if not utils.is_windows() or not paths:
        return {}
    unique_paths = []
    seen = set()
    for path in paths:
        if path and path not in seen:
            unique_paths.append(path)
            seen.add(path)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
            json.dump(unique_paths, handle, ensure_ascii=False)
            temp_path = Path(handle.name)
        script = f"""
$paths = @(Get-Content -Raw -LiteralPath {utils.ps_quote(temp_path)} | ConvertFrom-Json)
foreach ($p in $paths) {{
  try {{
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    [pscustomobject]@{{
      Path = [string]$p
      Status = [string]$sig.Status
      StatusMessage = [string]$sig.StatusMessage
      Signer = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.Subject }} else {{ '' }}
      Issuer = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.Issuer }} else {{ '' }}
    }}
  }} catch {{
    [pscustomobject]@{{ Path = [string]$p; Status = 'Error'; StatusMessage = $_.Exception.Message; Signer = ''; Issuer = '' }}
  }}
}}
"""
        raw = run_powershell_json(script, timeout=timeout)
        rows = utils.coerce_list(raw)
        return {str(row.get("Path", "")): {str(k): utils.trim(v, 500) for k, v in row.items()} for row in rows if isinstance(row, dict)}
    finally:
        if temp_path:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
