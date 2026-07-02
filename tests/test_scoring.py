import unittest

from win_security_audit.models import AuditReport, Section, Status
from win_security_audit.scoring import calculate_risk_score


class ScoringTests(unittest.TestCase):
    def test_healthy_report_scores_zero(self):
        report = AuditReport.create("1", "host", "user", True, "cmd")
        section = Section(key="system", title="System")
        section.add_finding("ok", Status.HEALTHY, severity=0)
        report.sections.append(section)
        self.assertEqual(calculate_risk_score(report), 0)

    def test_suspicious_finding_increases_score(self):
        report = AuditReport.create("1", "host", "user", True, "cmd")
        section = Section(key="persistence", title="Persistence")
        section.add_finding("bad", Status.SUSPICIOUS, severity=9)
        report.sections.append(section)
        self.assertGreaterEqual(calculate_risk_score(report), 30)


if __name__ == "__main__":
    unittest.main()
