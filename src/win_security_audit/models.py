from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


class Status:
    HEALTHY = "healthy"
    REVIEW = "review"
    SUSPICIOUS = "suspicious"
    INFO = "info"


STATUS_META = {
    Status.HEALTHY: {"icon": "🟢", "label": "Healthy", "rank": 0},
    Status.INFO: {"icon": "⚪", "label": "Info", "rank": 1},
    Status.REVIEW: {"icon": "🟡", "label": "Needs review", "rank": 2},
    Status.SUSPICIOUS: {"icon": "🔴", "label": "Suspicious", "rank": 3},
}


def normalize_status(status: str) -> str:
    return status if status in STATUS_META else Status.INFO


def worst_status(statuses: list[str]) -> str:
    if not statuses:
        return Status.HEALTHY
    return max((normalize_status(s) for s in statuses), key=lambda s: STATUS_META[s]["rank"])


@dataclass
class Finding:
    title: str
    status: str
    category: str
    severity: int = 1
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""

    def __post_init__(self) -> None:
        self.status = normalize_status(self.status)
        self.severity = max(0, min(10, int(self.severity)))


@dataclass
class ReportTable:
    title: str
    columns: list[str]
    rows: list[dict[str, Any]] = field(default_factory=list)
    max_rows: int = 150

    @property
    def shown_rows(self) -> list[dict[str, Any]]:
        return self.rows[: self.max_rows]

    @property
    def hidden_count(self) -> int:
        return max(0, len(self.rows) - self.max_rows)


@dataclass
class Section:
    key: str
    title: str
    summary: str = ""
    status: str = Status.HEALTHY
    findings: list[Finding] = field(default_factory=list)
    tables: list[ReportTable] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def add_finding(
        self,
        title: str,
        status: str,
        severity: int = 1,
        description: str = "",
        evidence: list[str] | None = None,
        recommendation: str = "",
        category: str | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                title=title,
                status=status,
                severity=severity,
                description=description,
                evidence=evidence or [],
                recommendation=recommendation,
                category=category or self.title,
            )
        )
        self.status = worst_status([self.status, status])

    def add_table(
        self,
        title: str,
        rows: list[dict[str, Any]],
        columns: list[str] | None = None,
        max_rows: int = 150,
    ) -> None:
        if columns is None:
            columns = list(rows[0].keys()) if rows else []
        self.tables.append(ReportTable(title=title, columns=columns, rows=rows, max_rows=max_rows))

    def finalize_status(self) -> None:
        self.status = worst_status([f.status for f in self.findings] or [self.status])


@dataclass
class AuditReport:
    tool_name: str
    version: str
    generated_at: str
    host: str
    user: str
    is_admin: bool
    command_line: str
    metadata: dict[str, Any] = field(default_factory=dict)
    sections: list[Section] = field(default_factory=list)
    risk_score: int = 0

    @classmethod
    def create(cls, version: str, host: str, user: str, is_admin: bool, command_line: str) -> "AuditReport":
        return cls(
            tool_name="Windows Security Audit Tool",
            version=version,
            generated_at=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            host=host,
            user=user,
            is_admin=is_admin,
            command_line=command_line,
        )

    @property
    def findings(self) -> list[Finding]:
        items: list[Finding] = []
        for section in self.sections:
            items.extend(section.findings)
        return items

    @property
    def status_counts(self) -> dict[str, int]:
        counts = {status: 0 for status in STATUS_META}
        for finding in self.findings:
            counts[finding.status] = counts.get(finding.status, 0) + 1
        return counts

    @property
    def overall_status(self) -> str:
        if self.risk_score >= 70:
            return Status.SUSPICIOUS
        if self.risk_score >= 35:
            return Status.REVIEW
        return Status.HEALTHY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
