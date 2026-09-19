"""Report and chart generation.

Charts are rendered with matplotlib through a non interactive backend so they
work in CI. Every chart function returns the path it wrote, and the markdown
report references them relatively so it renders on GitHub.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # no display in CI
import matplotlib.pyplot as plt  # noqa: E402

from .frameworks import coverage_by_function  # noqa: E402
from .pipeline import PortfolioResult  # noqa: E402
from .sla import SLAReport  # noqa: E402

SEVERITY_COLOURS = {
    "critical": "#8b1a1a", "high": "#c0392b", "medium": "#d68910",
    "low": "#2e86c1", "info": "#7f8c8d",
}
TIER_COLOURS = {"critical": "#8b1a1a", "high": "#c0392b", "medium": "#d68910", "low": "#1e8449"}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
TIER_ORDER = ["critical", "high", "medium", "low"]


def _style(ax) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", alpha=0.25, linewidth=0.7)
    ax.set_axisbelow(True)


def _save(fig, out_dir: Path, name: str, dpi: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / name
    fig.tight_layout()
    fig.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)
    return path


def chart_risk_tiers(portfolio: PortfolioResult, out_dir: Path, dpi: int = 140) -> Path:
    counts = portfolio.tier_counts()
    labels = [t for t in TIER_ORDER if counts.get(t)]
    values = [counts[t] for t in labels]
    fig, ax = plt.subplots(figsize=(6, 3.4))
    bars = ax.bar(labels, values, color=[TIER_COLOURS[t] for t in labels], width=0.6)
    ax.bar_label(bars, padding=2, fontsize=9)
    ax.set_title("Vendor portfolio by residual risk tier", fontsize=11, fontweight="bold")
    ax.set_ylabel("Vendors")
    ax.set_ylim(0, max(values) * 1.25 if values else 1)
    _style(ax)
    return _save(fig, out_dir, "risk_tiers.png", dpi)


def chart_findings_by_severity(portfolio: PortfolioResult, out_dir: Path, dpi: int = 140) -> Path:
    counts = portfolio.severity_counts()
    labels = [s for s in SEVERITY_ORDER if counts.get(s)]
    values = [counts[s] for s in labels]
    fig, ax = plt.subplots(figsize=(6, 3.4))
    bars = ax.barh(labels[::-1], values[::-1], color=[SEVERITY_COLOURS[s] for s in labels[::-1]], height=0.6)
    ax.bar_label(bars, padding=3, fontsize=9)
    ax.set_title("Open findings by severity", fontsize=11, fontweight="bold")
    ax.set_xlabel("Findings")
    ax.set_xlim(0, max(values) * 1.2 if values else 1)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="x", alpha=0.25, linewidth=0.7)
    ax.set_axisbelow(True)
    return _save(fig, out_dir, "findings_by_severity.png", dpi)


def chart_control_domains(portfolio: PortfolioResult, out_dir: Path, dpi: int = 140) -> Path:
    """Portfolio mean score per questionnaire domain, as a radar chart."""
    import math

    averages = portfolio.domain_averages()
    if not averages:
        raise ValueError("no domain scores to plot")

    labels = list(averages)
    values = [averages[k] for k in labels]
    angles = [n / len(labels) * 2 * math.pi for n in range(len(labels))]
    values += values[:1]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(5.6, 5.2), subplot_kw={"polar": True})
    ax.plot(angles, values, color="#1f4e79", linewidth=2)
    ax.fill(angles, values, color="#1f4e79", alpha=0.22)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["25%", "50%", "75%", "100%"], fontsize=7)
    ax.set_ylim(0, 1)
    ax.set_title("Control domain maturity across the portfolio", fontsize=11, fontweight="bold", pad=18)
    return _save(fig, out_dir, "control_domains.png", dpi)


def chart_sla_aging(report: SLAReport, out_dir: Path, dpi: int = 140) -> Path:
    buckets = report.aging_buckets()
    labels = list(buckets)
    values = [buckets[k] for k in labels]
    colours = ["#1e8449", "#d68910", "#c0392b", "#8b1a1a"]
    fig, ax = plt.subplots(figsize=(6, 3.4))
    bars = ax.bar(labels, values, color=colours[: len(labels)], width=0.6)
    ax.bar_label(bars, padding=2, fontsize=9)
    ax.set_title(
        f"Finding age in days (SLA compliance {report.compliance_rate:.0%})",
        fontsize=11, fontweight="bold",
    )
    ax.set_ylabel("Findings")
    ax.set_xlabel("Days open")
    ax.set_ylim(0, max(values) * 1.25 if values and max(values) else 1)
    _style(ax)
    return _save(fig, out_dir, "sla_aging.png", dpi)


def chart_csf_coverage(portfolio: PortfolioResult, out_dir: Path, dpi: int = 140) -> Path:
    """How findings distribute across NIST CSF 2.0 functions."""
    control_ids = [c for f in portfolio.findings for c in f.controls]
    counts = coverage_by_function(control_ids)
    labels = list(counts)
    values = [counts[k] for k in labels]
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    bars = ax.bar(labels, values, color="#1f4e79", width=0.6)
    ax.bar_label(bars, padding=2, fontsize=9)
    ax.set_title("Findings mapped to NIST CSF 2.0 functions", fontsize=11, fontweight="bold")
    ax.set_ylabel("Control references")
    ax.set_ylim(0, max(values) * 1.25 if values and max(values) else 1)
    _style(ax)
    return _save(fig, out_dir, "csf_coverage.png", dpi)


def chart_risk_trend(snapshots: list, out_dir: Path, dpi: int = 140) -> Path:
    """Residual score over time, one line per vendor with at least two cycles.

    Takes the raw snapshot history rather than a TrendReport, since the point
    of the chart is the whole trajectory, not just the delta between the two
    most recent points that drives the pass or fail gate.
    """
    from collections import defaultdict

    by_vendor: dict[str, list] = defaultdict(list)
    for snap in snapshots:
        by_vendor[snap.vendor_id].append(snap)

    plottable = {
        vid: sorted(points, key=lambda s: s.as_of)
        for vid, points in by_vendor.items()
        if len(points) >= 2
    }
    if not plottable:
        raise ValueError("no vendor has at least two snapshots to plot a trend")

    fig, ax = plt.subplots(figsize=(7, 4))
    palette = ["#1f4e79", "#c0392b", "#1e8449", "#d68910", "#6c3483", "#117864", "#8b1a1a", "#2e86c1"]
    for idx, (vendor_id, points) in enumerate(sorted(plottable.items())):
        ax.plot(
            [p.as_of for p in points],
            [p.residual_score for p in points],
            marker="o",
            linewidth=2,
            color=palette[idx % len(palette)],
            label=vendor_id,
        )
    ax.set_title("Residual risk over time", fontsize=11, fontweight="bold")
    ax.set_ylabel("Residual score")
    ax.legend(fontsize=8, ncol=2, frameon=False)
    fig.autofmt_xdate()
    _style(ax)
    return _save(fig, out_dir, "risk_trend.png", dpi)


def render_markdown(portfolio: PortfolioResult, sla: SLAReport, org: str) -> str:
    """Assurance summary as markdown."""
    lines: list[str] = []
    a = lines.append
    a(f"# Third party assurance report: {org}")
    a("")
    a(f"Assessment date: {portfolio.as_of.isoformat()}")
    a("")
    a("## Portfolio summary")
    a("")
    a("| Metric | Value |")
    a("| --- | --- |")
    a(f"| Vendors assessed | {len(portfolio.assessments)} |")
    a(f"| Open findings | {len(portfolio.findings)} |")
    a(f"| Highest severity | {portfolio.worst_severity().value} |")
    a(f"| SLA compliance | {sla.compliance_rate:.1%} |")
    a(f"| Breached remediations | {len(sla.breached)} |")
    a(f"| Mean days open | {sla.mean_days_open()} |")
    a("")
    a("## Residual risk by vendor")
    a("")
    a("| Vendor | Service | Data class | Inherent | Effectiveness | Residual | Tier |")
    a("| --- | --- | --- | ---: | ---: | ---: | --- |")
    for item in portfolio.assessments:
        v, r = item.vendor, item.risk
        a(
            f"| {v.name} | {v.service} | {v.data_class.value} | {r.inherent_score:.1f} | "
            f"{r.control_effectiveness:.0%} | {r.residual_score:.2f} | {r.tier.value} |"
        )
    a("")
    a("## Findings breaching remediation SLA")
    a("")
    if sla.breached:
        a("| Finding | Subject | Severity | Raised | Due | Days overdue |")
        a("| --- | --- | --- | --- | --- | ---: |")
        for rec in sla.breached:
            a(
                f"| {rec.finding_id} | {rec.subject} | {rec.severity.value} | "
                f"{rec.raised_on.isoformat()} | {rec.due_on.isoformat()} | {abs(rec.days_remaining)} |"
            )
    else:
        a("No findings are currently outside their remediation window.")
    a("")
    return "\n".join(lines)


def write_report(
    portfolio: PortfolioResult,
    sla: SLAReport,
    out_dir: str | Path,
    org: str = "Example Organisation",
    dpi: int = 140,
    charts: bool = True,
) -> dict[str, Any]:
    """Write the markdown report and every chart. Returns the paths written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Any] = {}

    report_path = out / "assurance_report.md"
    report_path.write_text(render_markdown(portfolio, sla, org), encoding="utf-8")
    written["report"] = report_path

    if charts:
        images = out / "images"
        written["charts"] = [
            chart_risk_tiers(portfolio, images, dpi),
            chart_findings_by_severity(portfolio, images, dpi),
            chart_control_domains(portfolio, images, dpi),
            chart_sla_aging(sla, images, dpi),
            chart_csf_coverage(portfolio, images, dpi),
        ]
    return written
