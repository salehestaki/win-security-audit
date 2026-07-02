from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from win_security_audit import __version__, utils
from win_security_audit.models import AuditReport, Section, Status
from win_security_audit.report import render_html
from win_security_audit.scoring import calculate_risk_score


@dataclass
class AuditContext:
    output_dir: Path
    project_root: Path
    is_admin: bool
    quick: bool = False
    max_file_scan: int = 4000
    include_sysinternals: bool = True
    facts: dict[str, object] = field(default_factory=dict)


Collector = Callable[[AuditContext], Section]


def get_collectors() -> list[Collector]:
    from win_security_audit.checks import (
        accounts,
        events,
        filesystem,
        network,
        persistence,
        runtime,
        security_controls,
        software,
        system,
        sysinternals,
    )

    collectors: list[Collector] = [
        system.collect,
        accounts.collect,
        software.collect,
        runtime.collect,
        persistence.collect,
        network.collect,
        security_controls.collect,
        filesystem.collect,
        events.collect,
    ]
    collectors.append(sysinternals.collect)
    return collectors


def run_audit(
    output_dir: Path,
    quick: bool = False,
    max_file_scan: int = 4000,
    include_sysinternals: bool = True,
) -> tuple[AuditReport, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    context = AuditContext(
        output_dir=output_dir,
        project_root=utils.resource_root(),
        is_admin=utils.is_admin(),
        quick=quick,
        max_file_scan=max_file_scan,
        include_sysinternals=include_sysinternals,
    )
    report = AuditReport.create(
        version=__version__,
        host=utils.get_hostname(),
        user=os.environ.get("USERNAME") or os.environ.get("USER") or "unknown-user",
        is_admin=context.is_admin,
        command_line=" ".join(utils.quote_windows_arg(arg) for arg in sys.argv),
    )
    report.metadata.update(
        {
            "python": sys.version,
            "executable": sys.executable,
            "frozen": bool(getattr(sys, "frozen", False)),
            "quick": quick,
            "max_file_scan": max_file_scan,
        }
    )

    for collector in get_collectors():
        start = time.perf_counter()
        try:
            section = collector(context)
        except Exception as exc:
            section = Section(
                key=getattr(collector, "__module__", "collector").split(".")[-1],
                title=getattr(collector, "__module__", "Collector").split(".")[-1].replace("_", " ").title(),
                summary="This collector failed before it could complete.",
                status=Status.REVIEW,
            )
            section.add_finding(
                "Collector failed",
                Status.REVIEW,
                severity=4,
                description=str(exc),
                recommendation="Run again as Administrator and check the JSON output for troubleshooting details.",
            )
        section.elapsed_seconds = time.perf_counter() - start
        section.finalize_status()
        report.sections.append(section)

    report.risk_score = calculate_risk_score(report)
    base_name = f"SecurityReport_{report.host}_{utils.timestamp_for_filename()}"
    html_path = output_dir / f"{base_name}.html"
    json_path = output_dir / f"{base_name}.json"
    html_path.write_text(render_html(report), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=utils.json_default), encoding="utf-8")
    return report, html_path, json_path
