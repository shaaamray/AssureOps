from datetime import timedelta

import pytest

from assureops.errors import ValidationError
from assureops.models import Finding, Severity
from assureops.sla import APPROACHING, BREACHED, DEFAULT_SLA_DAYS, WITHIN, evaluate


def finding(severity, days_ago, as_of, fid="F-1"):
    return Finding(fid, "vendor-a", "t", severity, "test",
                   raised_on=as_of - timedelta(days=days_ago))


class TestStatus:
    def test_fresh_finding_is_within_sla(self, as_of):
        report = evaluate([finding(Severity.HIGH, 1, as_of)], as_of)
        assert report.records[0].status == WITHIN

    def test_overdue_finding_is_breached(self, as_of):
        report = evaluate([finding(Severity.CRITICAL, 30, as_of)], as_of)
        assert report.records[0].status == BREACHED

    def test_finding_near_the_limit_is_approaching(self, as_of):
        # 80% of the 30 day high window is 24 days.
        report = evaluate([finding(Severity.HIGH, 25, as_of)], as_of)
        assert report.records[0].status == APPROACHING

    def test_due_today_is_not_yet_breached(self, as_of):
        report = evaluate([finding(Severity.HIGH, DEFAULT_SLA_DAYS[Severity.HIGH], as_of)], as_of)
        assert report.records[0].status != BREACHED

    def test_windows_differ_by_severity(self, as_of):
        """The same age is breached for critical but fine for medium."""
        age = 20
        crit = evaluate([finding(Severity.CRITICAL, age, as_of)], as_of).records[0]
        med = evaluate([finding(Severity.MEDIUM, age, as_of)], as_of).records[0]
        assert crit.status == BREACHED and med.status == WITHIN


class TestDates:
    def test_due_date_derives_from_severity_window(self, as_of):
        record = evaluate([finding(Severity.CRITICAL, 0, as_of)], as_of).records[0]
        assert record.due_on == as_of + timedelta(days=DEFAULT_SLA_DAYS[Severity.CRITICAL])

    def test_days_open_counts_from_raised_date(self, as_of):
        assert evaluate([finding(Severity.LOW, 12, as_of)], as_of).records[0].days_open == 12

    def test_days_remaining_is_negative_when_overdue(self, as_of):
        assert evaluate([finding(Severity.CRITICAL, 10, as_of)], as_of).records[0].days_remaining < 0

    def test_missing_raised_date_is_rejected(self, as_of):
        bad = Finding("F-X", "v", "t", Severity.HIGH, "test", raised_on=None)
        with pytest.raises(ValidationError, match="raised_on"):
            evaluate([bad], as_of)


class TestMetrics:
    def test_compliance_rate(self, as_of):
        items = [finding(Severity.CRITICAL, 30, as_of, "F-1"),   # breached
                 finding(Severity.HIGH, 1, as_of, "F-2"),
                 finding(Severity.LOW, 1, as_of, "F-3"),
                 finding(Severity.LOW, 2, as_of, "F-4")]
        assert evaluate(items, as_of).compliance_rate == 0.75

    def test_empty_report_is_fully_compliant(self, as_of):
        assert evaluate([], as_of).compliance_rate == 1.0

    def test_aging_buckets(self, as_of):
        items = [finding(Severity.LOW, 3, as_of, "F-1"),
                 finding(Severity.LOW, 20, as_of, "F-2"),
                 finding(Severity.LOW, 60, as_of, "F-3"),
                 finding(Severity.LOW, 150, as_of, "F-4")]
        assert evaluate(items, as_of).aging_buckets() == {"0-7": 1, "8-30": 1, "31-90": 1, "90+": 1}

    def test_mean_days_open(self, as_of):
        items = [finding(Severity.LOW, 10, as_of, "F-1"), finding(Severity.LOW, 20, as_of, "F-2")]
        assert evaluate(items, as_of).mean_days_open() == 15.0

    def test_mean_of_empty_report_is_zero(self, as_of):
        assert evaluate([], as_of).mean_days_open() == 0.0

    def test_severity_breakdown(self, findings, as_of):
        assert evaluate(findings, as_of).by_severity()["high"] == 2


class TestOrdering:
    def test_most_urgent_first(self, findings, as_of):
        report = evaluate(findings, as_of)
        remaining = [r.days_remaining for r in report.records]
        assert remaining == sorted(remaining)

    def test_breached_and_approaching_are_separable(self, findings, as_of):
        report = evaluate(findings, as_of)
        assert len(report.breached) == 1
        assert all(r.breached for r in report.breached)


class TestCustomWindows:
    def test_custom_table_overrides_defaults(self, as_of):
        tight = dict(DEFAULT_SLA_DAYS, **{Severity.LOW: 1})
        report = evaluate([finding(Severity.LOW, 5, as_of)], as_of, tight)
        assert report.records[0].status == BREACHED
