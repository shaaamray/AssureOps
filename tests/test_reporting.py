from datetime import date

import pytest

from assureops.models import DataClass, Vendor
from assureops.pipeline import assess_portfolio
from assureops.reporting import render_markdown, write_report
from assureops.sla import evaluate as evaluate_sla


@pytest.fixture
def portfolio(guard, prober, all_yes, all_no):
    vendors = [
        Vendor("vendor-a", "Alpha Ltd", "Claims", DataClass.RESTRICTED, True, domain="vendor-a.example"),
        Vendor("vendor-b", "Beta Ltd", "Print", DataClass.INTERNAL, False),
    ]
    answers = {"vendor-a": all_no, "vendor-b": all_yes}
    return assess_portfolio(vendors, answers, guard, prober, date(2026, 8, 22))


@pytest.fixture
def sla(portfolio, as_of):
    return evaluate_sla(portfolio.findings, as_of)


class TestMarkdown:
    def test_includes_organisation_and_date(self, portfolio, sla):
        md = render_markdown(portfolio, sla, "Example Insurance Group")
        assert "Example Insurance Group" in md
        assert "2026-08-22" in md

    def test_lists_every_vendor(self, portfolio, sla):
        md = render_markdown(portfolio, sla, "Org")
        assert "Alpha Ltd" in md and "Beta Ltd" in md

    def test_reports_no_breaches_when_all_fresh(self, portfolio, sla):
        md = render_markdown(portfolio, sla, "Org")
        assert "No findings are currently outside" in md

    def test_renders_valid_markdown_tables(self, portfolio, sla):
        md = render_markdown(portfolio, sla, "Org")
        assert md.count("| --- |") >= 1


class TestChartGeneration:
    def test_writes_report_and_charts(self, portfolio, sla, tmp_path):
        written = write_report(portfolio, sla, tmp_path, "Org")
        assert written["report"].exists()
        assert len(written["charts"]) == 5
        for chart in written["charts"]:
            assert chart.exists() and chart.stat().st_size > 1000

    def test_charts_can_be_skipped(self, portfolio, sla, tmp_path):
        written = write_report(portfolio, sla, tmp_path, "Org", charts=False)
        assert "charts" not in written

    def test_creates_output_directory(self, portfolio, sla, tmp_path):
        target = tmp_path / "nested" / "reports"
        write_report(portfolio, sla, target, "Org")
        assert (target / "assurance_report.md").exists()

    def test_charts_are_png(self, portfolio, sla, tmp_path):
        written = write_report(portfolio, sla, tmp_path, "Org")
        for chart in written["charts"]:
            assert chart.read_bytes()[:4] == b"\x89PNG"


class TestRiskTrendChart:
    def _history(self):
        from assureops.models import RiskTier
        from assureops.trend import Snapshot

        return [
            Snapshot("vendor-a", date(2026, 7, 1), 8.0, RiskTier.MEDIUM),
            Snapshot("vendor-a", date(2026, 8, 1), 14.0, RiskTier.HIGH),
            Snapshot("vendor-b", date(2026, 7, 1), 20.0, RiskTier.CRITICAL),
            Snapshot("vendor-b", date(2026, 8, 1), 12.0, RiskTier.HIGH),
        ]

    def test_writes_a_png(self, tmp_path):
        from assureops.reporting import chart_risk_trend

        out = chart_risk_trend(self._history(), tmp_path)
        assert out.exists()
        assert out.read_bytes()[:4] == b"\x89PNG"

    def test_vendors_with_only_one_snapshot_are_excluded_not_crashed_on(self, tmp_path):
        from assureops.models import RiskTier
        from assureops.reporting import chart_risk_trend
        from assureops.trend import Snapshot

        history = self._history() + [Snapshot("vendor-c", date(2026, 7, 1), 3.0, RiskTier.LOW)]
        out = chart_risk_trend(history, tmp_path)
        assert out.exists()

    def test_raises_a_clear_error_when_nothing_is_plottable(self, tmp_path):
        from assureops.models import RiskTier
        from assureops.reporting import chart_risk_trend
        from assureops.trend import Snapshot

        with pytest.raises(ValueError, match="no vendor has at least two snapshots"):
            chart_risk_trend([Snapshot("vendor-a", date(2026, 7, 1), 3.0, RiskTier.LOW)], tmp_path)

    def test_respects_the_configured_dpi(self, tmp_path):
        from assureops.reporting import chart_risk_trend

        low = chart_risk_trend(self._history(), tmp_path / "low", dpi=60)
        high = chart_risk_trend(self._history(), tmp_path / "high", dpi=220)
        assert high.stat().st_size > low.stat().st_size
