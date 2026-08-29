import pytest

from assureops.errors import ScopeError
from assureops.scope import HARD_DENY, ScopeGuard, is_protected_ip, normalise, registrable


class TestNormalise:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("HTTPS://Vendor-A.Example/path?q=1", "vendor-a.example"),
            ("http://host.example:8443", "host.example"),
            ("host.example.", "host.example"),
            ("  Host.Example  ", "host.example"),
        ],
    )
    def test_strips_scheme_port_path_and_case(self, raw, expected):
        assert normalise(raw) == expected

    def test_registrable_takes_last_two_labels(self):
        assert registrable("a.b.c.example.com") == "example.com"
        assert registrable("localhost") == "localhost"


class TestProtectedRanges:
    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1"])
    def test_detects_protected(self, ip):
        assert is_protected_ip(ip)

    def test_public_ip_is_not_protected(self):
        assert not is_protected_ip("93.184.216.34")

    def test_hostname_is_not_an_ip(self):
        assert not is_protected_ip("vendor.example")


class TestHardDenyList:
    """The deny list must win over any configuration, including an allow entry."""

    @pytest.mark.parametrize("domain", ["facebook.com", "google.com", "github.com", "instagram.com"])
    def test_blocks_well_known_domains(self, domain):
        guard = ScopeGuard(allow=frozenset({domain}), require_authorisation=False)
        with pytest.raises(ScopeError, match="deny list"):
            guard.check(domain)

    def test_blocks_subdomain_of_denied_domain(self):
        guard = ScopeGuard(allow=frozenset(), require_authorisation=False)
        with pytest.raises(ScopeError, match="deny list"):
            guard.check("api.facebook.com")

    def test_deny_list_is_not_empty(self):
        assert len(HARD_DENY) >= 15


class TestAuthorisation:
    def test_refuses_without_explicit_authorisation(self):
        guard = ScopeGuard(allow=frozenset({"vendor.example"}), require_authorisation=True)
        with pytest.raises(ScopeError, match="authorisation"):
            guard.check("vendor.example")

    def test_permits_once_authorised(self):
        guard = ScopeGuard(allow=frozenset({"vendor.example"}), require_authorisation=True)
        assert guard.authorise(True).check("vendor.example") == "vendor.example"

    def test_authorisation_can_be_waived_by_config(self):
        guard = ScopeGuard(allow=frozenset({"vendor.example"}), require_authorisation=False)
        assert guard.check("vendor.example") == "vendor.example"


class TestAllowList:
    def test_rejects_host_not_on_allow_list(self, guard):
        with pytest.raises(ScopeError, match="allow list"):
            guard.check("other.example")

    def test_accepts_via_registrable_domain(self):
        guard = ScopeGuard(allow=frozenset({"example.org"}), require_authorisation=False)
        assert guard.check("api.example.org") == "api.example.org"

    def test_empty_allow_list_permits_any_valid_host(self):
        guard = ScopeGuard(allow=frozenset(), require_authorisation=False)
        assert guard.check("anything.example") == "anything.example"


class TestPrivateAddresses:
    def test_blocked_by_default(self, guard):
        with pytest.raises(ScopeError, match="protected address"):
            guard.check("127.0.0.1")

    def test_allowed_when_configured(self):
        guard = ScopeGuard(allow_private=True, require_authorisation=False)
        assert guard.check("127.0.0.1") == "127.0.0.1"


class TestMalformedInput:
    @pytest.mark.parametrize("bad", ["", "   ", "-bad.example", "bad-.example", "a" * 300])
    def test_rejects_invalid_hostnames(self, bad):
        guard = ScopeGuard(require_authorisation=False)
        with pytest.raises(ScopeError):
            guard.check(bad)

    def test_permits_returns_bool_instead_of_raising(self, guard):
        assert guard.permits("vendor-a.example")
        assert not guard.permits("facebook.com")


class TestFromConfig:
    def test_builds_from_config_dict(self):
        cfg = {"scope": {"allow": ["A.Example", "b.example"], "allow_private": True,
                          "require_authorisation": False}}
        guard = ScopeGuard.from_config(cfg)
        assert "a.example" in guard.allow
        assert guard.allow_private is True
        assert guard.require_authorisation is False

    def test_missing_section_uses_defaults(self):
        guard = ScopeGuard.from_config({})
        assert guard.allow == frozenset()
        assert guard.require_authorisation is True
