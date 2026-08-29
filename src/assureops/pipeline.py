"""The assurance pipeline.

Ties the pieces together: score the questionnaire, gather posture evidence
where permitted, compute residual risk, raise findings against real controls,
and write every decision to the audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from . import questionnaire as q
from . import risk
from .audit import AuditLog
from .errors import ScopeError
from .models import Finding, RiskResult, Severity, Vendor
from .posture import PostureResult, Prober, assess_host
from .scope import ScopeGuard


@dataclass
class VendorAssessment:
    vendor: Vendor
    questionnaire: q.QuestionnaireResult
    posture: PostureResult | None
    risk: RiskResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)


@dataclass
class PortfolioResult:
    assessments: list[VendorAssessment]
    as_of: date

    @property
    def findings(self) -> list[Finding]:
        return [f for a in self.assessments for f in a.findings]

    def tier_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self.assessments:
            counts[a.risk.tier.value] = counts.get(a.risk.tier.value, 0) + 1
        return counts

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def worst_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def domain_averages(self) -> dict[str, float]:
        """Mean questionnaire ratio per control domain across the portfolio."""
        totals: dict[str, list[float]] = {}
        for a in self.assessments:
            for name, dscore in a.questionnaire.domains.items():
                if dscore.weight:
                    totals.setdefault(name, []).append(dscore.ratio)
        return {k: round(sum(v) / len(v), 4) for k, v in sorted(totals.items())}


def assess_vendor(
    vendor: Vendor,
    answers: dict[str, str],
    guard: ScopeGuard,
    prober: Prober | None = None,
    as_of: date | None = None,
    audit: AuditLog | None = None,
) -> VendorAssessment:
    """Assess a single vendor end to end."""
    as_of = as_of or date.today()
    qresult = q.score(answers)

    posture: PostureResult | None = None
    if prober is not None and vendor.domain:
        try:
            posture = assess_host(vendor.domain, guard, prober)
            if audit:
                audit.append("posture_check", "completed", vendor=vendor.vendor_id,
                             host=vendor.domain, score=posture.score)
        except ScopeError as exc:
            # Out of scope is a normal, recorded outcome, not a crash.
            if audit:
                audit.append("posture_check", "suppressed", vendor=vendor.vendor_id,
                             host=vendor.domain, reason=str(exc))
            posture = None

    findings: list[Finding] = []
    counter = 0

    for question, answer in qresult.gaps:
        counter += 1
        findings.append(
            Finding(
                finding_id=f"{vendor.vendor_id}-Q{counter:03d}",
                subject=vendor.vendor_id,
                title=question.text,
                severity=q.gap_severity(question, answer),
                source="questionnaire",
                controls=question.controls,
                detail=f"{question.qid} answered {answer}",
                raised_on=as_of,
            )
        )

    if posture:
        for idx, issue in enumerate(posture.issues, start=1):
            findings.append(
                Finding(
                    finding_id=f"{vendor.vendor_id}-P{idx:03d}",
                    subject=vendor.vendor_id,
                    title=f"External posture: {issue.check}",
                    severity=issue.severity,
                    source="posture",
                    controls=issue.controls,
                    detail=issue.detail,
                    raised_on=as_of,
                )
            )

    result = risk.assess(
        vendor_id=vendor.vendor_id,
        data_class=vendor.data_class,
        business_critical=vendor.business_critical,
        questionnaire_score=qresult.overall,
        posture_score=posture.score if posture else None,
        open_findings=[f.severity for f in findings],
    )

    if audit:
        audit.append("vendor_assessed", "completed", vendor=vendor.vendor_id,
                     tier=result.tier.value, residual=result.residual_score,
                     findings=len(findings))

    findings.sort(key=lambda f: (-f.severity.rank, f.finding_id))
    return VendorAssessment(vendor, qresult, posture, result, findings)


def assess_portfolio(
    vendors: list[Vendor],
    answers_by_vendor: dict[str, dict[str, str]],
    guard: ScopeGuard,
    prober: Prober | None = None,
    as_of: date | None = None,
    audit: AuditLog | None = None,
) -> PortfolioResult:
    as_of = as_of or date.today()
    assessments = [
        assess_vendor(v, answers_by_vendor.get(v.vendor_id, {}), guard, prober, as_of, audit)
        for v in vendors
    ]
    assessments.sort(key=lambda a: -a.risk.residual_score)
    return PortfolioResult(assessments, as_of)
