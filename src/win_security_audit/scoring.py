from __future__ import annotations

import math

from win_security_audit.models import AuditReport, Status


STATUS_FACTORS = {
    Status.SUSPICIOUS: 3.4,
    Status.REVIEW: 1.55,
    Status.INFO: 0.25,
    Status.HEALTHY: 0.0,
}

CATEGORY_CAPS = {
    "Accounts": 18,
    "Persistence": 24,
    "Security Controls": 24,
    "Network": 16,
    "Suspicious Files": 22,
    "Event Logs": 15,
    "Runtime": 18,
    "Sysinternals": 8,
    "System": 10,
    "Software": 12,
}


def calculate_risk_score(report: AuditReport) -> int:
    """Return a stable 0-100 score from weighted findings.

    The formula intentionally saturates: one critical issue matters, but many
    medium signals also accumulate into a high score.
    """

    by_category: dict[str, float] = {}
    for finding in report.findings:
        factor = STATUS_FACTORS.get(finding.status, 0.25)
        points = finding.severity * factor
        by_category[finding.category] = by_category.get(finding.category, 0.0) + points

    capped_total = 0.0
    for category, points in by_category.items():
        capped_total += min(points, CATEGORY_CAPS.get(category, 16))

    score = 100.0 * (1.0 - math.exp(-capped_total / 58.0))
    return max(0, min(100, int(round(score))))
