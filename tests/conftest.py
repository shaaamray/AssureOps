"""Shared fixtures. Everything runs offline: no network, no tenant, no clock dependency."""

from __future__ import annotations

from datetime import date

import pytest

from assureops.models import DataClass, Entitlement, Finding, Severity, Vendor
from assureops.posture import Observation, make_static_prober
from assureops.questionnaire import QUESTION_BANK
from assureops.scope import ScopeGuard

AS_OF = date(2026, 8, 22)


@pytest.fixture
def as_of() -> date:
    return AS_OF


@pytest.fixture
def vendor() -> Vendor:
    return Vendor(
        vendor_id="vendor-a",
        name="Northwind Claims Bureau",
        service="Claims processing",
        data_class=DataClass.RESTRICTED,
        business_critical=True,
        domain="vendor-a.example",
    )


@pytest.fixture
def all_yes() -> dict[str, str]:
    return {q.qid: "yes" for q in QUESTION_BANK}


@pytest.fixture
def all_no() -> dict[str, str]:
    return {q.qid: "no" for q in QUESTION_BANK}


@pytest.fixture
def guard() -> ScopeGuard:
    return ScopeGuard(
        allow=frozenset({"vendor-a.example", "vendor-b.example"}),
        require_authorisation=True,
    ).authorise(True)


@pytest.fixture
def strong_observation() -> Observation:
    return Observation(
        host="vendor-a.example",
        tls_version="TLSv1.3",
        cert_days_to_expiry=200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
        },
    )


@pytest.fixture
def weak_observation() -> Observation:
    return Observation(
        host="vendor-a.example",
        tls_version="TLSv1",
        cert_days_to_expiry=-4,
        cert_self_signed=True,
        hostname_match=False,
        headers={},
    )


@pytest.fixture
def prober(strong_observation):
    return make_static_prober({"vendor-a.example": strong_observation})


@pytest.fixture
def entitlements() -> list[Entitlement]:
    return [
        Entitlement("clean@example.com", "CRM", "sales.user", False, 3, 30),
        Entitlement("dormant@example.com", "CRM", "sales.user", False, 200, 30),
        Entitlement("noMfa@example.com", "ERP", "iam.admin", True, 2, 10, mfa_enrolled=False),
        Entitlement("disabled@example.com", "ERP", "readonly.analyst", False, 400, 30, enabled=False),
        Entitlement("sod@example.com", "ERP", "payments.initiator", False, 5, 20),
        Entitlement("sod@example.com", "ERP", "payments.approver", True, 5, 20),
    ]


@pytest.fixture
def findings(as_of) -> list[Finding]:
    from datetime import timedelta

    return [
        Finding("F-001", "vendor-a", "Overdue critical", Severity.CRITICAL,
                "test", ("A.8.5",), raised_on=as_of - timedelta(days=40)),
        Finding("F-002", "vendor-a", "Fresh high", Severity.HIGH,
                "test", ("A.8.8",), raised_on=as_of - timedelta(days=2)),
        Finding("F-003", "vendor-b", "Approaching high", Severity.HIGH,
                "test", ("A.8.8",), raised_on=as_of - timedelta(days=25)),
        Finding("F-004", "vendor-b", "Fresh low", Severity.LOW,
                "test", ("A.6.3",), raised_on=as_of - timedelta(days=1)),
    ]
