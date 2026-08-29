from datetime import date

from assureops.access_review import DORMANT_DAYS, PRIVILEGED_DORMANT_DAYS, review
from assureops.models import Entitlement, Severity


def titles(summary):
    return [f.title for f in summary.findings]


class TestDormancy:
    def test_dormant_standard_account_is_flagged(self):
        summary = review([Entitlement("a@example.com", "CRM", "user",
                                      days_since_login=DORMANT_DAYS + 1)])
        assert "Dormant account" in titles(summary)

    def test_active_account_is_not_flagged(self):
        summary = review([Entitlement("a@example.com", "CRM", "user", days_since_login=5)])
        assert summary.clean

    def test_privileged_dormancy_uses_a_tighter_threshold(self):
        days = PRIVILEGED_DORMANT_DAYS + 1
        assert days < DORMANT_DAYS  # the point of the rule
        summary = review([Entitlement("a@example.com", "ERP", "iam.admin",
                                      privileged=True, days_since_login=days)])
        assert "Dormant privileged access" in titles(summary)

    def test_unknown_login_date_is_not_flagged(self):
        summary = review([Entitlement("a@example.com", "CRM", "user", days_since_login=None)])
        assert summary.clean


class TestMfa:
    def test_missing_mfa_on_privileged_is_critical(self):
        summary = review([Entitlement("a@example.com", "ERP", "iam.admin",
                                      privileged=True, mfa_enrolled=False)])
        assert summary.findings[0].severity is Severity.CRITICAL

    def test_missing_mfa_on_standard_is_high(self):
        summary = review([Entitlement("a@example.com", "CRM", "user", mfa_enrolled=False)])
        assert summary.findings[0].severity is Severity.HIGH


class TestOrphanedAccess:
    def test_disabled_account_holding_access_is_flagged(self):
        summary = review([Entitlement("a@example.com", "ERP", "user", enabled=False)])
        assert "Entitlement retained on a disabled account" in titles(summary)


class TestRecertification:
    def test_overdue_review_is_flagged(self):
        summary = review([Entitlement("a@example.com", "CRM", "user", last_reviewed_days=400)])
        assert "Access not recertified within policy" in titles(summary)

    def test_recent_review_is_not_flagged(self):
        summary = review([Entitlement("a@example.com", "CRM", "user", last_reviewed_days=30)])
        assert summary.clean


class TestSegregationOfDuties:
    def test_conflicting_roles_on_one_principal_are_flagged(self):
        summary = review([
            Entitlement("a@example.com", "ERP", "payments.initiator"),
            Entitlement("a@example.com", "ERP", "payments.approver"),
        ])
        assert "Segregation of duties conflict" in titles(summary)
        assert summary.findings[0].severity is Severity.CRITICAL

    def test_conflict_detected_across_different_systems(self):
        summary = review([
            Entitlement("a@example.com", "ERP", "payments.initiator"),
            Entitlement("a@example.com", "ClaimsHub", "payments.approver"),
        ])
        assert "Segregation of duties conflict" in titles(summary)

    def test_roles_split_between_people_are_fine(self):
        summary = review([
            Entitlement("a@example.com", "ERP", "payments.initiator"),
            Entitlement("b@example.com", "ERP", "payments.approver"),
        ])
        assert summary.clean


class TestSummary:
    def test_counts_are_reported(self, entitlements):
        summary = review(entitlements)
        assert summary.total == len(entitlements)
        assert summary.privileged == 2

    def test_findings_sorted_by_severity(self, entitlements):
        summary = review(entitlements)
        ranks = [f.severity.rank for f in summary.findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_severity_breakdown(self, entitlements):
        assert review(entitlements).by_severity()["critical"] >= 1

    def test_finding_ids_are_unique(self, entitlements):
        ids = [f.finding_id for f in review(entitlements).findings]
        assert len(ids) == len(set(ids))

    def test_findings_carry_control_references(self, entitlements):
        from assureops.frameworks import resolve
        for finding in review(entitlements).findings:
            for control in finding.controls:
                resolve(control)

    def test_as_of_date_is_stamped(self, entitlements):
        stamp = date(2026, 8, 22)
        assert all(f.raised_on == stamp for f in review(entitlements, stamp).findings)

    def test_empty_input_is_clean(self):
        assert review([]).clean
