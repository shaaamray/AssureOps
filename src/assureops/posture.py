"""External posture checks.

Evidence to sit alongside a vendor's self attestation: TLS configuration,
certificate expiry, and HTTP security headers. Every probe goes through the
scope guard first.

The prober is a pluggable callable rather than a hard dependency on a socket
library. In production it wraps a real TLS handshake and HTTP request; in
tests it is a plain function returning a canned observation. That single seam
is what makes this module fully testable without touching the network.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from .models import Severity
from .scope import ScopeGuard

# Header checks, each contributing to the posture score.
SECURITY_HEADERS: dict[str, float] = {
    "strict-transport-security": 2.0,
    "content-security-policy": 2.0,
    "x-content-type-options": 1.0,
    "x-frame-options": 1.0,
    "referrer-policy": 0.5,
    "permissions-policy": 0.5,
}

ACCEPTABLE_TLS = {"TLSv1.2", "TLSv1.3"}
WEAK_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}

CERT_EXPIRY_CRITICAL_DAYS = 7
CERT_EXPIRY_WARN_DAYS = 30


@dataclass
class Observation:
    """Raw facts a prober returns about one host. No judgement applied yet."""

    host: str
    reachable: bool = True
    tls_version: str | None = None
    cert_days_to_expiry: int | None = None
    cert_self_signed: bool = False
    hostname_match: bool = True
    headers: dict[str, str] = field(default_factory=dict)
    open_ports: tuple[int, ...] = ()
    error: str | None = None


class Prober(Protocol):
    def __call__(self, host: str) -> Observation: ...


@dataclass
class PostureIssue:
    check: str
    severity: Severity
    detail: str
    controls: tuple[str, ...]


@dataclass
class PostureResult:
    host: str
    score: float
    issues: list[PostureIssue]
    observation: Observation

    @property
    def worst(self) -> Severity:
        return max((i.severity for i in self.issues), default=Severity.INFO)


def evaluate(obs: Observation) -> PostureResult:
    """Turn a raw observation into a score between 0 and 1 plus typed issues."""
    issues: list[PostureIssue] = []

    if not obs.reachable:
        issues.append(
            PostureIssue("reachability", Severity.HIGH, obs.error or "host was not reachable", ("A.8.16",))
        )
        return PostureResult(obs.host, 0.0, issues, obs)

    earned = 0.0
    possible = 0.0

    # --- TLS version -----------------------------------------------------
    possible += 3.0
    if obs.tls_version in ACCEPTABLE_TLS:
        earned += 3.0
    elif obs.tls_version in WEAK_TLS:
        issues.append(
            PostureIssue("tls_version", Severity.HIGH,
                         f"negotiated {obs.tls_version}, which is deprecated", ("A.8.24",))
        )
    elif obs.tls_version is None:
        issues.append(
            PostureIssue("tls_version", Severity.MEDIUM, "no TLS version observed", ("A.8.24",))
        )

    # --- Certificate -----------------------------------------------------
    possible += 3.0
    days = obs.cert_days_to_expiry
    if days is None:
        issues.append(PostureIssue("cert_expiry", Severity.MEDIUM, "certificate expiry unknown", ("A.8.24",)))
    elif days < 0:
        issues.append(PostureIssue("cert_expiry", Severity.CRITICAL,
                                   f"certificate expired {abs(days)} days ago", ("A.8.24",)))
    elif days < CERT_EXPIRY_CRITICAL_DAYS:
        issues.append(PostureIssue("cert_expiry", Severity.HIGH,
                                   f"certificate expires in {days} days", ("A.8.24",)))
        earned += 1.0
    elif days < CERT_EXPIRY_WARN_DAYS:
        issues.append(PostureIssue("cert_expiry", Severity.MEDIUM,
                                   f"certificate expires in {days} days", ("A.8.24",)))
        earned += 2.0
    else:
        earned += 3.0

    if obs.cert_self_signed:
        issues.append(PostureIssue("cert_trust", Severity.HIGH,
                                   "certificate is self signed", ("A.8.24",)))
    if not obs.hostname_match:
        issues.append(PostureIssue("cert_hostname", Severity.HIGH,
                                   "certificate does not match the hostname", ("A.8.24",)))

    # --- Security headers ------------------------------------------------
    present = {k.lower() for k in obs.headers}
    for header, weight in SECURITY_HEADERS.items():
        possible += weight
        if header in present:
            earned += weight
        else:
            sev = Severity.MEDIUM if weight >= 2.0 else Severity.LOW
            issues.append(PostureIssue(f"header:{header}", sev,
                                       f"{header} is not set", ("A.8.9",)))

    score = round(earned / possible, 4) if possible else 0.0
    return PostureResult(obs.host, score, issues, obs)


def assess_host(host: str, guard: ScopeGuard, prober: Prober) -> PostureResult:
    """Scope check, probe, then evaluate. The guard is never optional."""
    checked = guard.check(host)
    return evaluate(prober(checked))


def null_prober(host: str) -> Observation:
    """Default prober used when posture checking is disabled."""
    return Observation(host=host, reachable=False, error="posture checking disabled")


def make_static_prober(table: dict[str, Observation]) -> Callable[[str], Observation]:
    """Build a prober backed by a fixed table. Used in tests and for demos."""

    def _prober(host: str) -> Observation:
        return table.get(host, Observation(host=host, reachable=False, error="no observation recorded"))

    return _prober
