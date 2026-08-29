"""Identity governance and access recertification.

Runs a set of rules over an entitlement extract and produces findings that a
reviewer can action: dormant accounts, stale privileged access, missing MFA,
orphaned entitlements and segregation of duties conflicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .models import Entitlement, Finding, Severity

DORMANT_DAYS = 90
STALE_REVIEW_DAYS = 180
PRIVILEGED_DORMANT_DAYS = 45

# Role pairs that should not be held by the same principal. Real programmes
# keep this in policy; it lives here so the rule is testable and explicit.
SOD_CONFLICTS: tuple[tuple[str, str, str], ...] = (
    ("payments.initiator", "payments.approver", "Initiate and approve payments"),
    ("vendor.create", "payments.approver", "Create vendors and approve payments"),
    ("iam.admin", "audit.reviewer", "Administer identities and review the audit trail"),
    ("dev.deploy", "prod.dba", "Deploy code and administer the production database"),
)


@dataclass
class ReviewSummary:
    total: int
    privileged: int
    findings: list[Finding]

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def clean(self) -> bool:
        return not self.findings


def _fid(prefix: str, index: int) -> str:
    return f"{prefix}-{index:04d}"


def review(entitlements: list[Entitlement], as_of: date | None = None) -> ReviewSummary:
    """Apply every recertification rule and collect findings."""
    findings: list[Finding] = []
    counter = 0

    def emit(subject: str, title: str, severity: Severity, controls: tuple[str, ...], detail: str) -> None:
        nonlocal counter
        counter += 1
        findings.append(
            Finding(
                finding_id=_fid("AR", counter),
                subject=subject,
                title=title,
                severity=severity,
                source="access_review",
                controls=controls,
                detail=detail,
                raised_on=as_of,
            )
        )

    by_principal: dict[str, list[Entitlement]] = {}

    for ent in entitlements:
        by_principal.setdefault(ent.principal, []).append(ent)
        subject = f"{ent.principal}:{ent.system}"

        # Disabled accounts that still hold entitlements are orphaned access.
        if not ent.enabled:
            emit(subject, "Entitlement retained on a disabled account", Severity.HIGH,
                 ("A.5.18", "A.5.16"),
                 f"{ent.principal} is disabled but still holds {ent.role} on {ent.system}")

        # Missing MFA is worse on a privileged entitlement.
        if not ent.mfa_enrolled:
            emit(subject,
                 "Privileged account without MFA" if ent.privileged else "Account without MFA",
                 Severity.CRITICAL if ent.privileged else Severity.HIGH,
                 ("A.8.5", "A.5.17"),
                 f"{ent.principal} has no MFA enrolled for {ent.system}")

        # Dormancy, with a tighter threshold for privileged access.
        if ent.days_since_login is not None:
            limit = PRIVILEGED_DORMANT_DAYS if ent.privileged else DORMANT_DAYS
            if ent.days_since_login >= limit:
                emit(subject,
                     "Dormant privileged access" if ent.privileged else "Dormant account",
                     Severity.HIGH if ent.privileged else Severity.MEDIUM,
                     ("A.5.18", "A.8.2") if ent.privileged else ("A.5.18",),
                     f"no sign in for {ent.days_since_login} days, threshold is {limit}")

        # Recertification overdue.
        if ent.last_reviewed_days is not None and ent.last_reviewed_days > STALE_REVIEW_DAYS:
            emit(subject, "Access not recertified within policy", Severity.MEDIUM,
                 ("A.5.18",),
                 f"last reviewed {ent.last_reviewed_days} days ago, policy is {STALE_REVIEW_DAYS}")

    # Segregation of duties is evaluated per principal across all systems.
    for principal, ents in by_principal.items():
        roles = {e.role for e in ents}
        for role_a, role_b, description in SOD_CONFLICTS:
            if role_a in roles and role_b in roles:
                emit(principal, "Segregation of duties conflict", Severity.CRITICAL,
                     ("A.5.15", "A.8.2"),
                     f"{description}: holds both {role_a} and {role_b}")

    privileged = sum(1 for e in entitlements if e.privileged)
    findings.sort(key=lambda f: (-f.severity.rank, f.subject))
    return ReviewSummary(total=len(entitlements), privileged=privileged, findings=findings)
