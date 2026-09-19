"""Tests for continuous monitoring: snapshots, storage, and change detection."""

from __future__ import annotations

from datetime import date

import pytest

from assureops.audit import AuditLog
from assureops.errors import ValidationError
from assureops.models import DataClass, RiskTier, Severity, Vendor
from assureops.pipeline import assess_portfolio
from assureops.trend import (
    FindingRef,
    Snapshot,
    build_trend_report,
    compute_trends,
    load_snapshots,
    record_snapshot,
)


def snap(vendor_id="vendor-a", as_of=date(2026, 8, 1), residual=10.0, tier=RiskTier.MEDIUM, findings=()):
    return Snapshot(vendor_id=vendor_id, as_of=as_of, residual_score=residual, tier=tier, findings=findings)


class TestSnapshot:
    def test_round_trips_through_a_record(self):
        original = snap(findings=(FindingRef("F1", Severity.HIGH), FindingRef("F2", Severity.LOW)))
        restored = Snapshot.from_record(original.to_record())
        assert restored == original

    def test_finding_ids_is_a_frozenset(self):
        s = snap(findings=(FindingRef("F1", Severity.HIGH),))
        assert s.finding_ids == frozenset({"F1"})

    def test_rejects_an_empty_vendor_id(self):
        with pytest.raises(ValidationError):
            snap(vendor_id="  ")

    def test_rejects_a_negative_residual_score(self):
        with pytest.raises(ValidationError):
            snap(residual=-1.0)

    def test_is_immutable(self):
        s = snap()
        with pytest.raises(AttributeError):
            s.residual_score = 99.0  # type: ignore[misc]


class TestRecordAndLoad:
    def test_recording_writes_one_audit_record_per_vendor(self, guard, prober, all_yes, as_of, tmp_path):
        vendors = [
            Vendor("vendor-a", "Alpha", "Claims", DataClass.RESTRICTED, True, domain="vendor-a.example"),
            Vendor("vendor-b", "Beta", "Print", DataClass.INTERNAL, False),
        ]
        portfolio = assess_portfolio(vendors, {"vendor-a": all_yes, "vendor-b": all_yes}, guard, prober, as_of)
        audit = AuditLog(tmp_path / "audit.jsonl")

        written = record_snapshot(audit, portfolio)

        assert len(written) == 2
        actions = [r["action"] for r in audit.records()]
        assert actions.count("trend_snapshot") == 2
        assert audit.verify().ok

    def test_load_snapshots_ignores_other_audit_actions(self, tmp_path):
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.append("vendor_assessed", "completed", vendor="vendor-a")
        audit.append("trend_snapshot", "recorded", **snap().to_record())
        loaded = load_snapshots(audit)
        assert len(loaded) == 1
        assert loaded[0].vendor_id == "vendor-a"

    def test_load_snapshots_is_empty_for_a_fresh_log(self, tmp_path):
        audit = AuditLog(tmp_path / "audit.jsonl")
        assert load_snapshots(audit) == []

    def test_tampering_with_a_recorded_snapshot_breaks_the_chain(self, tmp_path):
        import json

        path = tmp_path / "audit.jsonl"
        audit = AuditLog(path)
        record_snapshot_direct = audit.append("trend_snapshot", "recorded", **snap(residual=5.0).to_record())
        audit.append("trend_snapshot", "recorded", **snap(as_of=date(2026, 8, 2), residual=6.0).to_record())

        lines = path.read_text().splitlines()
        first = json.loads(lines[0])
        assert first["seq"] == record_snapshot_direct["seq"]
        first["residual_score"] = 500.0
        lines[0] = json.dumps(first, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")

        assert not AuditLog(path).verify().ok


class TestComputeTrends:
    def test_a_single_snapshot_produces_no_trend(self):
        assert compute_trends([snap()]) == []

    def test_two_snapshots_produce_one_trend_with_the_correct_delta(self):
        history = [snap(as_of=date(2026, 7, 1), residual=10.0), snap(as_of=date(2026, 8, 1), residual=16.0)]
        trends = compute_trends(history)
        assert len(trends) == 1
        assert trends[0].residual_delta == 6.0
        assert trends[0].days_between == 31

    def test_only_the_two_most_recent_snapshots_are_compared(self):
        history = [
            snap(as_of=date(2026, 6, 1), residual=2.0),
            snap(as_of=date(2026, 7, 1), residual=20.0),
            snap(as_of=date(2026, 8, 1), residual=21.0),
        ]
        trends = compute_trends(history)
        assert trends[0].residual_delta == 1.0

    def test_multiple_vendors_each_get_their_own_trend(self):
        history = [
            snap("vendor-a", date(2026, 7, 1), 5.0),
            snap("vendor-a", date(2026, 8, 1), 8.0),
            snap("vendor-b", date(2026, 7, 1), 12.0),
            snap("vendor-b", date(2026, 8, 1), 9.0),
        ]
        trends = {t.vendor_id: t for t in compute_trends(history)}
        assert trends["vendor-a"].residual_delta == 3.0
        assert trends["vendor-b"].residual_delta == -3.0

    def test_snapshots_out_of_chronological_order_are_still_compared_correctly(self):
        """The store is append only; nothing guarantees insertion order."""
        history = [snap(as_of=date(2026, 8, 1), residual=16.0), snap(as_of=date(2026, 7, 1), residual=10.0)]
        trends = compute_trends(history)
        assert trends[0].residual_delta == 6.0
        assert trends[0].previous.as_of == date(2026, 7, 1)

    def test_tier_worsened_uses_the_explicit_rank_not_alphabetical_order(self):
        """critical sorts before high alphabetically; the rank table must disagree."""
        history = [snap(as_of=date(2026, 7, 1), tier=RiskTier.HIGH), snap(as_of=date(2026, 8, 1), tier=RiskTier.CRITICAL)]
        trend = compute_trends(history)[0]
        assert str(RiskTier.CRITICAL.value) < str(RiskTier.HIGH.value)
        assert trend.tier_worsened is True
        assert trend.tier_improved is False

    def test_tier_improved_is_detected_the_same_way(self):
        history = [snap(as_of=date(2026, 7, 1), tier=RiskTier.CRITICAL), snap(as_of=date(2026, 8, 1), tier=RiskTier.LOW)]
        trend = compute_trends(history)[0]
        assert trend.tier_improved is True
        assert trend.tier_worsened is False

    def test_an_unchanged_tier_is_neither_worsened_nor_improved(self):
        history = [snap(as_of=date(2026, 7, 1), tier=RiskTier.HIGH), snap(as_of=date(2026, 8, 1), tier=RiskTier.HIGH)]
        trend = compute_trends(history)[0]
        assert trend.tier_worsened is False
        assert trend.tier_improved is False

    def test_new_and_resolved_findings_are_computed_by_id(self):
        history = [
            snap(as_of=date(2026, 7, 1), findings=(FindingRef("F1", Severity.HIGH), FindingRef("F2", Severity.LOW))),
            snap(as_of=date(2026, 8, 1), findings=(FindingRef("F2", Severity.LOW), FindingRef("F3", Severity.CRITICAL))),
        ]
        trend = compute_trends(history)[0]
        assert [f.finding_id for f in trend.new_findings] == ["F3"]
        assert [f.finding_id for f in trend.resolved_findings] == ["F1"]

    def test_identical_findings_produce_no_new_or_resolved_entries(self):
        shared = (FindingRef("F1", Severity.HIGH),)
        history = [snap(as_of=date(2026, 7, 1), findings=shared), snap(as_of=date(2026, 8, 1), findings=shared)]
        trend = compute_trends(history)[0]
        assert trend.new_findings == ()
        assert trend.resolved_findings == ()

    def test_velocity_is_delta_per_day(self):
        history = [snap(as_of=date(2026, 7, 1), residual=10.0), snap(as_of=date(2026, 7, 11), residual=15.0)]
        trend = compute_trends(history)[0]
        assert trend.velocity == 0.5

    def test_velocity_is_zero_when_snapshots_share_a_date(self):
        history = [snap(as_of=date(2026, 7, 1), residual=10.0), snap(as_of=date(2026, 7, 1), residual=15.0)]
        trend = compute_trends(history)[0]
        assert trend.days_between == 0
        assert trend.velocity == 0.0

    def test_empty_input_produces_no_trends(self):
        assert compute_trends([]) == []


class TestTrendReport:
    def test_regressed_flags_a_worsened_tier_regardless_of_the_delta_threshold(self):
        history = [
            snap(as_of=date(2026, 7, 1), residual=10.0, tier=RiskTier.MEDIUM),
            snap(as_of=date(2026, 8, 1), residual=10.5, tier=RiskTier.HIGH),
        ]
        report = build_trend_report(history)
        assert len(report.regressed(threshold=100.0)) == 1

    def test_regressed_flags_a_large_delta_even_without_a_tier_change(self):
        history = [snap(as_of=date(2026, 7, 1), residual=5.0), snap(as_of=date(2026, 8, 1), residual=12.0)]
        report = build_trend_report(history)
        assert len(report.regressed(threshold=2.0)) == 1
        assert len(report.regressed(threshold=50.0)) == 0

    def test_improved_flags_a_falling_residual_score(self):
        history = [snap(as_of=date(2026, 7, 1), residual=12.0), snap(as_of=date(2026, 8, 1), residual=5.0)]
        report = build_trend_report(history)
        assert len(report.improved()) == 1

    def test_new_findings_by_severity_aggregates_across_vendors(self):
        history = [
            snap("vendor-a", date(2026, 7, 1), findings=()),
            snap("vendor-a", date(2026, 8, 1), findings=(FindingRef("F1", Severity.CRITICAL),)),
            snap("vendor-b", date(2026, 7, 1), findings=()),
            snap("vendor-b", date(2026, 8, 1), findings=(FindingRef("F2", Severity.CRITICAL), FindingRef("F3", Severity.LOW))),
        ]
        report = build_trend_report(history)
        assert report.new_findings_by_severity() == {"critical": 2, "low": 1}

    def test_resolved_count_sums_across_every_vendor_trend(self):
        history = [
            snap("vendor-a", date(2026, 7, 1), findings=(FindingRef("F1", Severity.LOW),)),
            snap("vendor-a", date(2026, 8, 1), findings=()),
        ]
        report = build_trend_report(history)
        assert report.resolved_count() == 1

    def test_default_as_of_is_todays_date(self):
        report = build_trend_report([])
        assert report.as_of == date.today()

    def test_empty_history_produces_an_empty_report(self):
        report = build_trend_report([])
        assert report.trends == []
        assert report.regressed(0.0) == []
        assert report.improved() == []
        assert report.resolved_count() == 0
