"""Continuous monitoring: change detection between assessment cycles.

A single assessment is a photograph. What a real assurance programme needs is
the film reel: is this vendor's residual risk actually going up or down, and
how fast, since the last time anyone looked? This module answers that without
inventing a second storage format for the history it needs.

Every assessment cycle already writes to the hash chained audit log through
`AuditLog`. Rather than keep a parallel snapshot file that would need its own
integrity guarantees, a snapshot is written as an ordinary audit record with
action "trend_snapshot". That means the trend history inherits the same
tamper evidence as every other decision this tool makes: quietly editing last
month's residual score to hide a regression breaks the chain exactly like
editing any other record would.

Grouping snapshots by vendor is a single sort by (vendor_id, as_of) followed
by one linear pass, which is O(n log n). The tempting alternative — filter
the full snapshot list once per distinct vendor — is O(n * v) for v vendors
and degrades badly once both the portfolio and its history grow, which is
exactly the shape a continuous monitoring history takes over time.

Tier comparisons use an explicit rank table rather than RiskTier's inherited
string ordering, for the same reason Severity's comparison operators were
overridden in models.py: "critical" sorts before "high" alphabetically, which
would make a regression from high to critical register as an improvement.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from .audit import AuditLog
from .errors import ValidationError
from .models import RiskTier, Severity
from .pipeline import PortfolioResult

_TRIGGER_ACTION = "trend_snapshot"
_TRIGGER_OUTCOME = "recorded"

# Explicit, not inherited from RiskTier's string ordering. See module docstring.
_TIER_RANK: dict[RiskTier, int] = {
    RiskTier.LOW: 0,
    RiskTier.MEDIUM: 1,
    RiskTier.HIGH: 2,
    RiskTier.CRITICAL: 3,
}


@dataclass(frozen=True)
class FindingRef:
    """Just enough of a Finding to diff two cycles: identity and severity."""

    finding_id: str
    severity: Severity


@dataclass(frozen=True)
class Snapshot:
    """One vendor's risk position as at one assessment cycle."""

    vendor_id: str
    as_of: date
    residual_score: float
    tier: RiskTier
    findings: tuple[FindingRef, ...] = ()

    def __post_init__(self) -> None:
        if not self.vendor_id.strip():
            raise ValidationError("vendor_id must not be empty")
        if self.residual_score < 0:
            raise ValidationError("residual_score must not be negative")

    @property
    def finding_ids(self) -> frozenset[str]:
        return frozenset(f.finding_id for f in self.findings)

    def to_record(self) -> dict[str, Any]:
        """Shape written into an audit record's fields."""
        return {
            "vendor_id": self.vendor_id,
            "as_of": self.as_of.isoformat(),
            "residual_score": self.residual_score,
            "tier": self.tier.value,
            "findings": [{"finding_id": f.finding_id, "severity": f.severity.value} for f in self.findings],
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> Snapshot:
        """Reconstruct a snapshot from an audit record's fields."""
        return cls(
            vendor_id=record["vendor_id"],
            as_of=date.fromisoformat(record["as_of"]),
            residual_score=float(record["residual_score"]),
            tier=RiskTier(record["tier"]),
            findings=tuple(
                FindingRef(f["finding_id"], Severity(f["severity"]))
                for f in record.get("findings", [])
            ),
        )


def record_snapshot(audit: AuditLog, portfolio: PortfolioResult) -> list[Snapshot]:
    """Write one snapshot per assessed vendor into the audit trail.

    Returns the snapshots written, in portfolio order. Safe to call every
    cycle: a repeated call for the same as_of date simply adds another
    record, which compute_trends treats as the newest observation for that
    date and does not double count, since it only ever compares the two most
    recent snapshots per vendor.
    """
    written: list[Snapshot] = []
    for item in portfolio.assessments:
        snapshot = Snapshot(
            vendor_id=item.vendor.vendor_id,
            as_of=portfolio.as_of,
            residual_score=item.risk.residual_score,
            tier=item.risk.tier,
            findings=tuple(FindingRef(f.finding_id, f.severity) for f in item.findings),
        )
        audit.append(_TRIGGER_ACTION, _TRIGGER_OUTCOME, **snapshot.to_record())
        written.append(snapshot)
    return written


def load_snapshots(audit: AuditLog) -> list[Snapshot]:
    """Reconstruct every recorded snapshot from the audit trail, in file order."""
    return [
        Snapshot.from_record(rec)
        for rec in audit.records()
        if rec.get("action") == _TRIGGER_ACTION and rec.get("outcome") == _TRIGGER_OUTCOME
    ]


@dataclass(frozen=True)
class VendorTrend:
    """What changed for one vendor between its two most recent snapshots."""

    vendor_id: str
    previous: Snapshot
    current: Snapshot
    residual_delta: float
    new_findings: tuple[FindingRef, ...] = ()
    resolved_findings: tuple[FindingRef, ...] = ()
    days_between: int = 0

    @property
    def tier_previous(self) -> RiskTier:
        return self.previous.tier

    @property
    def tier_current(self) -> RiskTier:
        return self.current.tier

    @property
    def tier_worsened(self) -> bool:
        return _TIER_RANK[self.tier_current] > _TIER_RANK[self.tier_previous]

    @property
    def tier_improved(self) -> bool:
        return _TIER_RANK[self.tier_current] < _TIER_RANK[self.tier_previous]

    @property
    def velocity(self) -> float:
        """Residual score change per day. Positive means the vendor is getting worse.

        Turns "residual risk went up by 6.4" into "residual risk is rising at
        0.8 a day", which is the number that actually helps decide which of
        several worsening vendors to chase first.
        """
        if self.days_between <= 0:
            return 0.0
        return round(self.residual_delta / self.days_between, 4)


def compute_trends(snapshots: Iterable[Snapshot]) -> list[VendorTrend]:
    """Build one VendorTrend per vendor that has at least two snapshots.

    See the module docstring for why grouping is a single sort followed by
    one linear pass rather than a per vendor filter.
    """
    ordered = sorted(snapshots, key=lambda s: (s.vendor_id, s.as_of))
    grouped: dict[str, list[Snapshot]] = {}
    for snap in ordered:
        grouped.setdefault(snap.vendor_id, []).append(snap)

    trends: list[VendorTrend] = []
    for history in grouped.values():
        if len(history) < 2:
            continue
        previous, current = history[-2], history[-1]
        prev_by_id = {f.finding_id: f for f in previous.findings}
        curr_by_id = {f.finding_id: f for f in current.findings}
        new_ids = curr_by_id.keys() - prev_by_id.keys()
        resolved_ids = prev_by_id.keys() - curr_by_id.keys()
        trends.append(
            VendorTrend(
                vendor_id=current.vendor_id,
                previous=previous,
                current=current,
                residual_delta=round(current.residual_score - previous.residual_score, 2),
                new_findings=tuple(curr_by_id[i] for i in sorted(new_ids)),
                resolved_findings=tuple(prev_by_id[i] for i in sorted(resolved_ids)),
                days_between=(current.as_of - previous.as_of).days,
            )
        )
    return trends


@dataclass
class TrendReport:
    """Trend results for a whole portfolio as at one review date."""

    trends: list[VendorTrend] = field(default_factory=list)
    as_of: date = field(default_factory=date.today)

    def regressed(self, threshold: float) -> list[VendorTrend]:
        """Vendors whose tier got worse, or whose residual score rose past threshold."""
        return [t for t in self.trends if t.tier_worsened or t.residual_delta > threshold]

    def improved(self) -> list[VendorTrend]:
        """Vendors whose tier got better, or whose residual score fell."""
        return [t for t in self.trends if t.tier_improved or t.residual_delta < 0]

    def new_findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for trend in self.trends:
            for finding in trend.new_findings:
                counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    def resolved_count(self) -> int:
        return sum(len(t.resolved_findings) for t in self.trends)


def build_trend_report(snapshots: Iterable[Snapshot], as_of: date | None = None) -> TrendReport:
    return TrendReport(trends=compute_trends(snapshots), as_of=as_of or date.today())
