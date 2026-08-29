"""Remediation SLA governance.

Findings get a remediation deadline based on severity. This module tracks
which are inside SLA, which are approaching breach and which have already
breached, and computes the metrics an assurance report needs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from .errors import ValidationError
from .models import Finding, Severity

# Working days allowed for remediation, by severity.
DEFAULT_SLA_DAYS: dict[Severity, int] = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFO: 365,
}

APPROACHING_RATIO = 0.8  # flagged once 80% of the window has elapsed


class SLAStatus(str):
    pass


WITHIN = "within_sla"
APPROACHING = "approaching_breach"
BREACHED = "breached"


@dataclass
class SLARecord:
    finding_id: str
    subject: str
    severity: Severity
    raised_on: date
    due_on: date
    days_open: int
    days_remaining: int
    status: str

    @property
    def breached(self) -> bool:
        return self.status == BREACHED


@dataclass
class SLAReport:
    records: list[SLARecord]
    as_of: date

    @property
    def breached(self) -> list[SLARecord]:
        return [r for r in self.records if r.status == BREACHED]

    @property
    def approaching(self) -> list[SLARecord]:
        return [r for r in self.records if r.status == APPROACHING]

    @property
    def compliance_rate(self) -> float:
        if not self.records:
            return 1.0
        return round(1 - len(self.breached) / len(self.records), 4)

    def aging_buckets(self) -> dict[str, int]:
        buckets = {"0-7": 0, "8-30": 0, "31-90": 0, "90+": 0}
        for r in self.records:
            if r.days_open <= 7:
                buckets["0-7"] += 1
            elif r.days_open <= 30:
                buckets["8-30"] += 1
            elif r.days_open <= 90:
                buckets["31-90"] += 1
            else:
                buckets["90+"] += 1
        return buckets

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.records:
            counts[r.severity.value] = counts.get(r.severity.value, 0) + 1
        return counts

    def mean_days_open(self) -> float:
        if not self.records:
            return 0.0
        return round(sum(r.days_open for r in self.records) / len(self.records), 2)


def evaluate(
    findings: list[Finding],
    as_of: date,
    sla_days: dict[Severity, int] | None = None,
) -> SLAReport:
    """Build an SLA report for a set of open findings."""
    table = sla_days or DEFAULT_SLA_DAYS
    records: list[SLARecord] = []

    for finding in findings:
        if finding.raised_on is None:
            raise ValidationError(f"finding {finding.finding_id} has no raised_on date")
        window = table[finding.severity]
        due = finding.raised_on + timedelta(days=window)
        days_open = (as_of - finding.raised_on).days
        days_remaining = (due - as_of).days

        if days_remaining < 0:
            status = BREACHED
        elif window and days_open >= window * APPROACHING_RATIO:
            status = APPROACHING
        else:
            status = WITHIN

        records.append(
            SLARecord(
                finding_id=finding.finding_id,
                subject=finding.subject,
                severity=finding.severity,
                raised_on=finding.raised_on,
                due_on=due,
                days_open=days_open,
                days_remaining=days_remaining,
                status=status,
            )
        )

    records.sort(key=lambda r: (r.days_remaining, -r.severity.rank))
    return SLAReport(records=records, as_of=as_of)
