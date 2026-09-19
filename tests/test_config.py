import pytest

from assureops.config import load
from assureops.errors import ConfigError


def write(tmp_path, text):
    path = tmp_path / "assureops.yaml"
    path.write_text(text, encoding="utf-8")
    return path


class TestDefaults:
    def test_no_path_returns_defaults(self):
        cfg = load(None)
        assert cfg["scope"]["require_authorisation"] is True
        assert cfg["assessment"]["fail_on"] == "high"

    def test_file_overrides_merge_over_defaults(self, tmp_path):
        cfg = load(write(tmp_path, "organisation: Acme\n"))
        assert cfg["organisation"] == "Acme"
        assert cfg["sla"]["critical_days"] == 7  # default retained

    def test_nested_override_keeps_siblings(self, tmp_path):
        cfg = load(write(tmp_path, "sla:\n  critical_days: 3\n"))
        assert cfg["sla"]["critical_days"] == 3
        assert cfg["sla"]["high_days"] == 30


class TestStrictValidation:
    def test_unknown_top_level_key_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="unknown configuration key"):
            load(write(tmp_path, "orgnisation: typo\n"))

    def test_unknown_nested_key_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="scope.allowed"):
            load(write(tmp_path, "scope:\n  allowed: []\n"))

    def test_error_names_the_allowed_keys(self, tmp_path):
        with pytest.raises(ConfigError, match="allowed keys here are"):
            load(write(tmp_path, "nonsense: 1\n"))

    def test_missing_file_is_reported(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load(tmp_path / "absent.yaml")

    def test_malformed_yaml_is_reported(self, tmp_path):
        with pytest.raises(ConfigError, match="could not parse"):
            load(write(tmp_path, "scope:\n  allow: [unclosed\n"))

    def test_non_mapping_document_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="mapping"):
            load(write(tmp_path, "- a\n- b\n"))


class TestEnvironmentInterpolation:
    def test_env_reference_is_resolved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASSUREOPS_ORG", "Resolved Ltd")
        cfg = load(write(tmp_path, "organisation: ${ENV:ASSUREOPS_ORG}\n"))
        assert cfg["organisation"] == "Resolved Ltd"

    def test_default_is_used_when_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASSUREOPS_MISSING", raising=False)
        cfg = load(write(tmp_path, "organisation: ${ENV:ASSUREOPS_MISSING:Fallback}\n"))
        assert cfg["organisation"] == "Fallback"

    def test_unset_without_default_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASSUREOPS_MISSING", raising=False)
        with pytest.raises(ConfigError, match="not set"):
            load(write(tmp_path, "organisation: ${ENV:ASSUREOPS_MISSING}\n"))


class TestSecretRejection:
    """An accidental paste of a credential should fail startup, not leak."""

    @pytest.mark.parametrize(
        "secret",
        ["AKIAIOSFODNN7EXAMPLE", "ghp_016C7869F4B4B1B2C3D4E5F6a7b8c9d0e1f2",
         "xoxb-1234567890-abcdefghij"],
    )
    def test_credential_shaped_literal_is_rejected(self, tmp_path, secret):
        with pytest.raises(ConfigError, match="credential"):
            load(write(tmp_path, f"organisation: {secret}\n"))

    def test_error_names_the_offending_path(self, tmp_path):
        with pytest.raises(ConfigError, match="organisation"):
            load(write(tmp_path, "organisation: AKIAIOSFODNN7EXAMPLE\n"))

    def test_secret_inside_a_list_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError):
            load(write(tmp_path, "scope:\n  allow:\n    - AKIAIOSFODNN7EXAMPLE\n"))

    def test_env_reference_is_not_mistaken_for_a_secret(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TOKEN_NAME", "safe-value")
        cfg = load(write(tmp_path, "organisation: ${ENV:TOKEN_NAME}\n"))
        assert cfg["organisation"] == "safe-value"


class TestTrendSection:
    def test_defaults_are_enabled_with_a_sensible_threshold(self):
        from assureops.config import load
        cfg = load()
        assert cfg["trend"]["enabled"] is True
        assert cfg["trend"]["regression_delta"] == 2.0

    def test_trend_can_be_disabled(self, tmp_path):
        from assureops.config import load
        path = tmp_path / "cfg.yaml"
        path.write_text("trend:\n  enabled: false\n")
        cfg = load(path)
        assert cfg["trend"]["enabled"] is False

    def test_regression_delta_can_be_overridden(self, tmp_path):
        from assureops.config import load
        path = tmp_path / "cfg.yaml"
        path.write_text("trend:\n  regression_delta: 5.0\n")
        cfg = load(path)
        assert cfg["trend"]["regression_delta"] == 5.0

    def test_unknown_key_under_trend_is_rejected(self, tmp_path):
        from assureops.config import load
        from assureops.errors import ConfigError
        path = tmp_path / "cfg.yaml"
        path.write_text("trend:\n  regression_deltaa: 5.0\n")
        with pytest.raises(ConfigError, match="trend.regression_deltaa"):
            load(path)
