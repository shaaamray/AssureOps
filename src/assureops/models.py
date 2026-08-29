"""Typed domain objects.

These are deliberately plain dataclasses. Anything that needs validation
validates on construction so an invalid object cannot exist further down
the pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any

from .errors import ValidationError

_VENDOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}$")


class Severity(str, Enum):
    """Finding severity. Ordering matters, so keep the rank table in sync."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    # str is the base class, so the inherited str comparisons would order these
    # alphabetically ("critical" < "low"). Every comparison is overridden to use
    # the rank table instead, because severity ordering drives SLA and gating.
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class RiskTier(str, Enum):
    """Residual risk tier assigned to a vendor or finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataClass(str, Enum):
    """Sensitivity of data the third party can reach."""

    RESTRICTED = "restricted"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"


@dataclass(frozen=True)
class Vendor:
    """A third party in scope for assessment."""

    vendor_id: str
    name: str
    service: str
    data_class: DataClass
    business_critical: bool
    domain: str | None = None
    contract_owner: str | None = None

    def __post_init__(self) -> None:
        if not _VENDOR_ID.match(self.vendor_id):
            raise ValidationError(
                f"vendor_id {self.vendor_id!r} must be 2-64 chars of letters, digits, dot, dash or underscore"
            )
        if not self.name.strip():
            raise ValidationError("vendor name must not be empty")


@dataclass(frozen=True)
class Finding:
    """A single assurance finding raised against a vendor or an identity."""

    finding_id: str
    subject: str
    title: str
    severity: Severity
    source: str
    controls: tuple[str, ...] = ()
    detail: str = ""
    raised_on: date | None = None

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValidationError("finding_id must not be empty")
        if not isinstance(self.severity, Severity):
            raise ValidationError(f"severity must be a Severity, got {type(self.severity).__name__}")


@dataclass(frozen=True)
class Entitlement:
    """One principal's access to one system, as presented for recertification."""

    principal: str
    system: str
    role: str
    privileged: bool = False
    days_since_login: int | None = None
    last_reviewed_days: int | None = None
    enabled: bool = True
    mfa_enrolled: bool = True

    def __post_init__(self) -> None:
        if not _PRINCIPAL.match(self.principal):
            raise ValidationError(f"principal {self.principal!r} is not a valid UPN or email address")
        if self.days_since_login is not None and self.days_since_login < 0:
            raise ValidationError("days_since_login must not be negative")


@dataclass
class RiskResult:
    """Output of the risk engine for one vendor."""

    vendor_id: str
    inherent_score: float
    control_effectiveness: float
    residual_score: float
    tier: RiskTier
    drivers: dict[str, Any] = field(default_factory=dict)
