from datetime import date

from assureops.models import DataClass, Severity, Vendor
from assureops.pipeline import assess_portfolio, assess_vendor
from assureops.posture import make_static_prober


class TestAssessVendor:
    def test_clean_vendor_raises_no_questionnaire_findings(self, vendor, all_yes, guard, prober):
        result = assess_vendor(vendor, all_yes, guard, prober)
        assert not [f for f in result.findings if f.source == "questionnaire"]

    def test_gaps_become_findings(self, vendor, all_yes, guard, prober):
        answers = dict(all_yes, **{"IAM-01": "no", "GOV-01": "partial"})
        result = assess_vendor(vendor, answers, guard, prober)
        sources = [f for f in result.findings if f.source == "questionnaire"]
        assert len(sources) == 2

    def test_critical_gap_produces_critical_finding(self, vendor, all_yes, guard, prober):
        result = assess_vendor(vendor, dict(all_yes, **{"IAM-01": "no"}), guard, prober)
        assert result.worst_severity is Severity.CRITICAL

    def test_posture_issues_become_findings(self, vendor, all_yes, guard, weak_observation):
        prober = make_static_prober({"vendor-a.example": weak_observation})
        result = assess_vendor(vendor, all_yes, guard, prober)
        assert any(f.source == "posture" for f in result.findings)

    def test_findings_sorted_by_severity(self, vendor, all_no, guard, prober):
        result = assess_vendor(vendor, all_no, guard, prober)
        ranks = [f.severity.rank for f in result.findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_finding_ids_are_unique(self, vendor, all_no, guard, weak_observation):
        prober = make_static_prober({"vendor-a.example": weak_observation})
        result = assess_vendor(vendor, all_no, guard, prober)
        ids = [f.finding_id for f in result.findings]
        assert len(ids) == len(set(ids))

    def test_every_finding_maps_to_a_real_control(self, vendor, all_no, guard, prober):
        from assureops.frameworks import resolve
        for finding in assess_vendor(vendor, all_no, guard, prober).findings:
            for control in finding.controls:
                resolve(control)

    def test_weak_controls_drive_a_worse_tier(self, vendor, all_yes, all_no, guard, prober):
        strong = assess_vendor(vendor, all_yes, guard, prober)
        weak = assess_vendor(vendor, all_no, guard, prober)
        assert weak.risk.residual_score > strong.risk.residual_score


class TestPostureScoping:
    def test_out_of_scope_host_is_skipped_not_fatal(self, all_yes, guard, prober):
        """An out of scope domain is a recorded outcome, not a crash."""
        vendor = Vendor("vendor-z", "Zed", "svc", DataClass.INTERNAL, False,
                        domain="not-allowed.example")
        result = assess_vendor(vendor, all_yes, guard, prober)
        assert result.posture is None
        assert result.risk is not None

    def test_vendor_without_domain_has_no_posture(self, all_yes, guard, prober):
        vendor = Vendor("vendor-y", "Why", "svc", DataClass.INTERNAL, False)
        assert assess_vendor(vendor, all_yes, guard, prober).posture is None

    def test_no_prober_means_no_posture(self, vendor, all_yes, guard):
        assert assess_vendor(vendor, all_yes, guard, None).posture is None

    def test_suppression_is_audited(self, tmp_path, all_yes, guard, prober):
        from assureops.audit import AuditLog
        log = AuditLog(tmp_path / "audit.jsonl")
        vendor = Vendor("vendor-z", "Zed", "svc", DataClass.INTERNAL, False,
                        domain="not-allowed.example")
        assess_vendor(vendor, all_yes, guard, prober, audit=log)
        outcomes = [r["outcome"] for r in log.records() if r["action"] == "posture_check"]
        assert "suppressed" in outcomes


class TestAuditIntegration:
    def test_assessment_is_recorded(self, tmp_path, vendor, all_yes, guard, prober):
        from assureops.audit import AuditLog
        log = AuditLog(tmp_path / "audit.jsonl")
        assess_vendor(vendor, all_yes, guard, prober, audit=log)
        actions = {r["action"] for r in log.records()}
        assert {"posture_check", "vendor_assessed"} <= actions

    def test_audit_chain_stays_valid(self, tmp_path, vendor, all_yes, guard, prober):
        from assureops.audit import AuditLog
        log = AuditLog(tmp_path / "audit.jsonl")
        for _ in range(5):
            assess_vendor(vendor, all_yes, guard, prober, audit=log)
        assert log.verify().ok


class TestPortfolio:
    def _portfolio(self, guard, prober, all_yes, all_no):
        vendors = [
            Vendor("vendor-a", "A", "svc", DataClass.RESTRICTED, True, domain="vendor-a.example"),
            Vendor("vendor-b", "B", "svc", DataClass.PUBLIC, False),
        ]
        answers = {"vendor-a": all_no, "vendor-b": all_yes}
        return assess_portfolio(vendors, answers, guard, prober, date(2026, 8, 22))

    def test_sorted_by_descending_residual_risk(self, guard, prober, all_yes, all_no):
        result = self._portfolio(guard, prober, all_yes, all_no)
        scores = [a.risk.residual_score for a in result.assessments]
        assert scores == sorted(scores, reverse=True)

    def test_tier_counts_sum_to_vendor_count(self, guard, prober, all_yes, all_no):
        result = self._portfolio(guard, prober, all_yes, all_no)
        assert sum(result.tier_counts().values()) == len(result.assessments)

    def test_severity_counts_sum_to_finding_count(self, guard, prober, all_yes, all_no):
        result = self._portfolio(guard, prober, all_yes, all_no)
        assert sum(result.severity_counts().values()) == len(result.findings)

    def test_missing_answers_do_not_crash(self, guard, prober):
        vendors = [Vendor("vendor-x", "X", "svc", DataClass.INTERNAL, False)]
        result = assess_portfolio(vendors, {}, guard, prober)
        assert len(result.assessments) == 1

    def test_domain_averages_cover_every_domain(self, guard, prober, all_yes, all_no):
        from assureops.questionnaire import DOMAINS
        result = self._portfolio(guard, prober, all_yes, all_no)
        assert set(result.domain_averages()) == set(DOMAINS)

    def test_empty_portfolio_is_handled(self, guard, prober):
        result = assess_portfolio([], {}, guard, prober)
        assert result.findings == [] and result.worst_severity() is Severity.INFO
