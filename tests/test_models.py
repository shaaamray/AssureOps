import dataclasses

import pytest

from assureops.errors import ValidationError
from assureops.models import DataClass, Entitlement, Finding, Severity, Vendor


class TestSeverityOrdering:
    """str is the base class, so ordering must not fall back to alphabetical."""

    def test_rank_order_not_alphabetical(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_alphabetical_would_disagree(self):
        # "critical" < "low" as plain strings; the enum must not agree.
        assert str(Severity.CRITICAL.value) < str(Severity.LOW.value)
        assert Severity.CRITICAL > Severity.LOW

    def test_all_comparison_operators(self):
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.LOW <= Severity.HIGH
        assert not Severity.LOW > Severity.HIGH

    def test_sorting(self):
        ordered = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM])
        assert ordered == [Severity.LOW, Severity.MEDIUM, Severity.CRITICAL]

    def test_comparison_with_other_type_is_not_implemented(self):
        with pytest.raises(TypeError):
            _ = Severity.HIGH < 3


class TestVendorValidation:
    def test_valid_vendor(self, vendor):
        assert vendor.vendor_id == "vendor-a"

    @pytest.mark.parametrize("bad_id", ["", "a", "-leading", "has space", "x" * 65, "semi;colon"])
    def test_rejects_bad_ids(self, bad_id):
        with pytest.raises(ValidationError):
            Vendor(bad_id, "Name", "svc", DataClass.INTERNAL, False)

    def test_rejects_empty_name(self):
        with pytest.raises(ValidationError):
            Vendor("ok-id", "   ", "svc", DataClass.INTERNAL, False)

    def test_is_frozen(self, vendor):
        with pytest.raises(dataclasses.FrozenInstanceError):
            vendor.name = "changed"


class TestEntitlementValidation:
    @pytest.mark.parametrize("bad", ["notanemail", "@example.com", "a@b", "a b@example.com"])
    def test_rejects_bad_principal(self, bad):
        with pytest.raises(ValidationError):
            Entitlement(bad, "ERP", "role")

    def test_rejects_negative_login_days(self):
        with pytest.raises(ValidationError):
            Entitlement("a@example.com", "ERP", "role", days_since_login=-1)

    def test_accepts_none_login_days(self):
        assert Entitlement("a@example.com", "ERP", "role").days_since_login is None


class TestFindingValidation:
    def test_rejects_empty_id(self):
        with pytest.raises(ValidationError):
            Finding("", "subj", "t", Severity.LOW, "src")

    def test_rejects_non_severity(self):
        with pytest.raises(ValidationError):
            Finding("F-1", "subj", "t", "high", "src")
