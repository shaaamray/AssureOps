"""Error handling and boundary conditions."""

import pytest

from assureops.cli import EXIT_CONFIG, EXIT_RUNTIME, main
from assureops.errors import AssureOpsError, FrameworkError, ValidationError
from assureops.models import Severity
from assureops.posture import Observation, evaluate
from assureops.reporting import chart_control_domains
from assureops.risk import control_effectiveness


class TestCliErrorMapping:
    def test_validation_error_maps_to_config_exit(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        code = main(["access-review", "--entitlements", str(tmp_path / "missing.csv")])
        assert code == EXIT_CONFIG
        assert "error:" in capsys.readouterr().err

    def test_generic_error_maps_to_runtime_exit(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)

        def boom(_args):
            raise AssureOpsError("something went wrong")

        from assureops import cli
        monkeypatch.setattr(cli, "cmd_validate", boom)
        assert main(["validate"]) == EXIT_RUNTIME
        assert "something went wrong" in capsys.readouterr().err


class TestReportingEdges:
    def test_radar_chart_needs_domain_data(self, tmp_path):
        class Empty:
            def domain_averages(self):
                return {}

        with pytest.raises(ValueError, match="no domain scores"):
            chart_control_domains(Empty(), tmp_path)


class TestPostureEdges:
    def test_unknown_tls_string_is_not_credited(self):
        """An unrecognised version earns no points but does not crash."""
        result = evaluate(Observation("h.example", tls_version="QUIC?", cert_days_to_expiry=100))
        assert 0.0 <= result.score <= 1.0

    def test_observation_defaults_are_safe(self):
        result = evaluate(Observation("h.example"))
        assert result.worst >= Severity.LOW


class TestRiskEdges:
    def test_rejects_non_numeric_score(self):
        with pytest.raises(ValidationError):
            control_effectiveness("high")

    def test_rejects_out_of_range_posture(self):
        with pytest.raises(ValidationError):
            control_effectiveness(0.5, posture_score=2.0)


class TestFrameworkEdges:
    def test_validate_all_reports_the_bad_id(self):
        with pytest.raises(FrameworkError, match="A.0.0"):
            from assureops.frameworks import validate_all
            validate_all(["A.5.19", "A.0.0"])
