"""Risk scoring engine.

The model is deliberately explicit and documented rather than a black box,
because a risk score that cannot be explained to an auditor or a vendor is not
useful. See docs/risk-methodology.md for the reasoning behind each weight.

    inherent  = impact x likelihood, on a 1 to 25 scale
    residual  = inherent x (1 - control_effectiveness)
    tier      = band(residual)

Control effectiveness combines the questionnaire result with observed external
posture, because self attestation alone is the weakest form of assurance.
"""

from __future__ import annotations

from .errors import ValidationError
from .models import DataClass, RiskResult, RiskTier, Severity

# Impact is driven by the sensitivity of data the third party can reach.
IMPACT_BY_DATA_CLASS: dict[DataClass, int] = {
    DataClass.RESTRICTED: 5,
    DataClass.CONFIDENTIAL: 4,
    DataClass.INTERNAL: 2,
    DataClass.PUBLIC: 1,
}

# A vendor supporting a business critical process raises impact by one band,
# capped at the top of the scale.
BUSINESS_CRITICAL_UPLIFT = 1

# Weighting between attested controls and observed posture. Attestation is
# worth more only because it covers far more ground; posture is weighted
# heavily for its size because it is evidence rather than a claim.
QUESTIONNAIRE_WEIGHT = 0.65
POSTURE_WEIGHT = 0.35

# Residual score bands. Lower bound inclusive.
TIER_BANDS: tuple[tuple[float, RiskTier], ...] = (
    (15.0, RiskTier.CRITICAL),
    (9.0, RiskTier.HIGH),
    (4.0, RiskTier.MEDIUM),
    (0.0, RiskTier.LOW),
)

# How much an open finding of each severity suppresses measured effectiveness.
FINDING_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 0.30,
    Severity.HIGH: 0.18,
    Severity.MEDIUM: 0.08,
    Severity.LOW: 0.03,
    Severity.INFO: 0.0,
}
MAX_FINDING_PENALTY = 0.60


def impact_score(data_class: DataClass, business_critical: bool) -> int:
    """Impact on a 1 to 5 scale."""
    base = IMPACT_BY_DATA_CLASS[data_class]
    if business_critical:
        base += BUSINESS_CRITICAL_UPLIFT
    return max(1, min(5, base))


def likelihood_score(control_effectiveness: float) -> float:
    """Likelihood on a 1 to 5 scale, falling as controls improve.

    Perfectly effective controls do not drive likelihood to zero. Residual
    likelihood of 1 reflects that no control set is complete.
    """
    _check_unit_interval(control_effectiveness, "control_effectiveness")
    return 1.0 + 4.0 * (1.0 - control_effectiveness)


def inherent_risk(data_class: DataClass, business_critical: bool) -> float:
    """Risk before any credit for controls: impact x worst case likelihood."""
    return float(impact_score(data_class, business_critical) * 5)


def control_effectiveness(
    questionnaire_score: float,
    posture_score: float | None = None,
    open_findings: list[Severity] | None = None,
) -> float:
    """Blend attested and observed control strength, then penalise open findings.

    Both inputs are unit intervals. When no posture evidence exists the
    questionnaire carries the full weight, but the result is capped so that a
    vendor cannot reach full effectiveness on self attestation alone.
    """
    _check_unit_interval(questionnaire_score, "questionnaire_score")

    if posture_score is None:
        blended = questionnaire_score * 0.85  # attestation only, capped
    else:
        _check_unit_interval(posture_score, "posture_score")
        blended = QUESTIONNAIRE_WEIGHT * questionnaire_score + POSTURE_WEIGHT * posture_score

    penalty = 0.0
    for severity in open_findings or []:
        penalty += FINDING_PENALTY[severity]
    penalty = min(penalty, MAX_FINDING_PENALTY)

    return max(0.0, min(1.0, blended * (1.0 - penalty)))


def residual_risk(inherent: float, effectiveness: float) -> float:
    _check_unit_interval(effectiveness, "effectiveness")
    return round(inherent * (1.0 - effectiveness), 2)


def tier_for(residual: float) -> RiskTier:
    for threshold, tier in TIER_BANDS:
        if residual >= threshold:
            return tier
    return RiskTier.LOW


def assess(
    vendor_id: str,
    data_class: DataClass,
    business_critical: bool,
    questionnaire_score: float,
    posture_score: float | None = None,
    open_findings: list[Severity] | None = None,
) -> RiskResult:
    """Full assessment for one vendor, retaining the drivers behind the score."""
    findings = open_findings or []
    effectiveness = control_effectiveness(questionnaire_score, posture_score, findings)
    impact = impact_score(data_class, business_critical)
    likelihood = likelihood_score(effectiveness)
    residual = round(impact * likelihood, 2)
    inherent = inherent_risk(data_class, business_critical)

    return RiskResult(
        vendor_id=vendor_id,
        inherent_score=inherent,
        control_effectiveness=round(effectiveness, 4),
        residual_score=residual,
        tier=tier_for(residual),
        drivers={
            "impact": impact,
            "likelihood": round(likelihood, 2),
            "questionnaire_score": round(questionnaire_score, 4),
            "posture_score": None if posture_score is None else round(posture_score, 4),
            "open_findings": len(findings),
            "risk_reduction": round(inherent - residual, 2),
        },
    )


def _check_unit_interval(value: float, name: str) -> None:
    if not isinstance(value, (int, float)):
        raise ValidationError(f"{name} must be numeric, got {type(value).__name__}")
    if not 0.0 <= float(value) <= 1.0:
        raise ValidationError(f"{name} must be between 0.0 and 1.0, got {value}")
