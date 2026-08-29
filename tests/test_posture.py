import pytest

from assureops.errors import ScopeError
from assureops.models import Severity
from assureops.posture import (
    SECURITY_HEADERS,
    Observation,
    assess_host,
    evaluate,
    make_static_prober,
    null_prober,
)


class TestReachability:
    def test_unreachable_host_scores_zero(self):
        result = evaluate(Observation("h.example", reachable=False, error="timed out"))
        assert result.score == 0.0
        assert result.issues[0].check == "reachability"

    def test_unreachable_short_circuits_other_checks(self):
        result = evaluate(Observation("h.example", reachable=False))
        assert len(result.issues) == 1


class TestTls:
    @pytest.mark.parametrize("version", ["TLSv1.2", "TLSv1.3"])
    def test_modern_tls_raises_no_issue(self, version, strong_observation):
        obs = Observation("h.example", tls_version=version, cert_days_to_expiry=200,
                          headers=strong_observation.headers)
        assert not any(i.check == "tls_version" for i in evaluate(obs).issues)

    @pytest.mark.parametrize("version", ["SSLv3", "TLSv1", "TLSv1.1"])
    def test_deprecated_tls_is_high(self, version):
        result = evaluate(Observation("h.example", tls_version=version, cert_days_to_expiry=100))
        issue = next(i for i in result.issues if i.check == "tls_version")
        assert issue.severity is Severity.HIGH

    def test_missing_tls_version_is_medium(self):
        result = evaluate(Observation("h.example", tls_version=None, cert_days_to_expiry=100))
        issue = next(i for i in result.issues if i.check == "tls_version")
        assert issue.severity is Severity.MEDIUM


class TestCertificate:
    def test_expired_certificate_is_critical(self):
        result = evaluate(Observation("h.example", tls_version="TLSv1.3", cert_days_to_expiry=-1))
        issue = next(i for i in result.issues if i.check == "cert_expiry")
        assert issue.severity is Severity.CRITICAL

    def test_expiring_within_a_week_is_high(self):
        result = evaluate(Observation("h.example", tls_version="TLSv1.3", cert_days_to_expiry=3))
        assert next(i for i in result.issues if i.check == "cert_expiry").severity is Severity.HIGH

    def test_expiring_within_a_month_is_medium(self):
        result = evaluate(Observation("h.example", tls_version="TLSv1.3", cert_days_to_expiry=20))
        assert next(i for i in result.issues if i.check == "cert_expiry").severity is Severity.MEDIUM

    def test_healthy_certificate_raises_nothing(self):
        result = evaluate(Observation("h.example", tls_version="TLSv1.3", cert_days_to_expiry=300))
        assert not any(i.check == "cert_expiry" for i in result.issues)

    def test_self_signed_is_flagged(self):
        result = evaluate(Observation("h.example", tls_version="TLSv1.3",
                                      cert_days_to_expiry=300, cert_self_signed=True))
        assert any(i.check == "cert_trust" for i in result.issues)

    def test_hostname_mismatch_is_flagged(self):
        result = evaluate(Observation("h.example", tls_version="TLSv1.3",
                                      cert_days_to_expiry=300, hostname_match=False))
        assert any(i.check == "cert_hostname" for i in result.issues)


class TestHeaders:
    def test_all_headers_present_raises_no_header_issues(self, strong_observation):
        result = evaluate(strong_observation)
        assert not any(i.check.startswith("header:") for i in result.issues)

    def test_missing_headers_are_each_flagged(self):
        result = evaluate(Observation("h.example", tls_version="TLSv1.3",
                                      cert_days_to_expiry=300, headers={}))
        flagged = {i.check for i in result.issues if i.check.startswith("header:")}
        assert flagged == {f"header:{h}" for h in SECURITY_HEADERS}

    def test_header_matching_is_case_insensitive(self):
        obs = Observation("h.example", tls_version="TLSv1.3", cert_days_to_expiry=300,
                          headers={"Strict-Transport-Security": "max-age=1"})
        result = evaluate(obs)
        assert not any(i.check == "header:strict-transport-security" for i in result.issues)


class TestScoring:
    def test_strong_host_scores_high(self, strong_observation):
        assert evaluate(strong_observation).score >= 0.95

    def test_weak_host_scores_low(self, weak_observation):
        assert evaluate(weak_observation).score <= 0.1

    def test_score_is_bounded(self, strong_observation, weak_observation):
        for obs in (strong_observation, weak_observation):
            assert 0.0 <= evaluate(obs).score <= 1.0

    def test_worst_severity_reported(self, weak_observation):
        assert evaluate(weak_observation).worst is Severity.CRITICAL

    def test_worst_is_info_when_clean(self, strong_observation):
        assert evaluate(strong_observation).worst is Severity.INFO


class TestAssessHost:
    def test_scope_guard_is_enforced(self, guard, prober):
        with pytest.raises(ScopeError):
            assess_host("facebook.com", guard, prober)

    def test_permitted_host_is_probed(self, guard, prober):
        assert assess_host("vendor-a.example", guard, prober).score > 0

    def test_unknown_host_returns_unreachable(self, guard):
        result = assess_host("vendor-b.example", guard, make_static_prober({}))
        assert not result.observation.reachable

    def test_null_prober_reports_disabled(self):
        assert null_prober("any.example").error == "posture checking disabled"
