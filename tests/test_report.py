import unittest

from win_security_audit.models import AuditReport, Section, Status
from win_security_audit.report import render_html


class ReportRenderingTests(unittest.TestCase):
    def test_sections_are_collapsible(self):
        report = AuditReport.create("1", "host", "user", True, "cmd")
        section = Section("system", "System", "System summary", Status.REVIEW)
        section.add_finding("Finding", Status.REVIEW, severity=3)
        report.sections.append(section)
        report.risk_score = 40

        html = render_html(report)

        self.assertIn('<nav class="section-grid"', html)
        self.assertIn('<details class="section"', html)
        self.assertIn("Open flagged", html)
        self.assertIn("setSections", html)


if __name__ == "__main__":
    unittest.main()
