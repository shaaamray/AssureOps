import pytest

from assureops import risk
from assureops.errors import ValidationError
from assureops.models import DataClass, RiskTier, Severity


class TestImpact:
    def test_scales_with_data_sensitivity(self):
        assert (risk.impact_score(DataClass.RESTRICTED, False)
                > risk.impact_score(DataClass.CONFIDENTIAL, False)
                > risk.impact_score(DataClass.INTERNAL, False)
                > risk.impact_score(DataClass.PUBLIC, False))

    def test_business_criticality_uplifts_impact(self):
        assert (risk.impact_score(DataClass.INTERNAL, True)
                > risk.impact_score(DataClass.INTERNAL, False))

    def test_impact_is_capped_at_five(self):
        assert risk.impact_score(DataClass.RESTRICTED, True) == 5

    def test_impact_has_a_floor_of_one(self):
        assert risk.impact_score(DataClass.PUBLIC, False) >= 1


class TestLikelihood:
    def test_falls_as_controls_improve(self):
        assert risk.likelihood_score(0.9) < risk.likelihood_score(0.2)

    def test_never_reaches_zero(self):
        """No control set is complete, so residual likelihood stays at 1."""
        assert risk.likelihood_score(1.0) == pytest.approx(1.0)

    def test_worst_case_is_five(self):
        assert risk.likelihood_score(0.0) == pytest.approx(5.0)

    @pytest.mark.parametrize("bad", [-0.1, 1.5, "high"])
    def test_rejects_out_of_range(self, bad):
        with pytest.raises(ValidationError):
            risk.likelihood_score(bad)


class TestControlEffectiveness:
    def test_attestation_alone_is_capped(self):
        """A vendor cannot reach full effectiveness on self attestation alone."""
        assert risk.control_effectiveness(1.0) < 1.0
        assert risk.control_effectiveness(1.0) == pytest.approx(0.85)

    def test_posture_evidence_is_blended_in(self):
        strong = risk.control_effectiveness(0.8, posture_score=1.0)
        weak = risk.control_effectiveness(0.8, posture_score=0.0)
        assert strong > weak

    def test_weights_sum_to_one(self):
        assert risk.QUESTIONNAIRE_WEIGHT + risk.POSTURE_WEIGHT == pytest.approx(1.0)

    def test_open_findings_reduce_effectiveness(self):
        base = risk.control_effectiveness(0.9, 0.9)
        penalised = risk.control_effectiveness(0.9, 0.9, [Severity.CRITICAL])
        assert penalised < base

    def test_penalty_is_capped(self):
        """A long tail of findings cannot drive effectiveness to zero on its own."""
        many = [Severity.CRITICAL] * 20
        assert risk.control_effectiveness(1.0, 1.0, many) > 0.0

    def test_severity_penalties_are_ordered(self):
        crit = risk.control_effectiveness(0.9, 0.9, [Severity.CRITICAL])
        high = risk.control_effectiveness(0.9, 0.9, [Severity.HIGH])
        low = risk.control_effectiveness(0.9, 0.9, [Severity.LOW])
        assert crit < high < low

    def test_info_findings_carry_no_penalty(self):
        assert (risk.control_effectiveness(0.8, 0.8, [Severity.INFO])
                == risk.control_effectiveness(0.8, 0.8))

    def test_result_stays_in_unit_interval(self):
        assert 0.0 <= risk.control_effectiveness(0.0, 0.0, [Severity.CRITICAL] * 5) <= 1.0


class TestResidualAndTiers:
    def test_residual_falls_as_effectiveness_rises(self):
        assert risk.residual_risk(25.0, 0.9) < risk.residual_risk(25.0, 0.1)

    def test_perfect_controls_leave_no_residual(self):
        assert risk.residual_risk(25.0, 1.0) == 0.0

    @pytest.mark.parametrize(
        "score,tier",
        [(20.0, RiskTier.CRITICAL), (15.0, RiskTier.CRITICAL), (14.9, RiskTier.HIGH),
         (9.0, RiskTier.HIGH), (8.9, RiskTier.MEDIUM), (4.0, RiskTier.MEDIUM),
         (3.9, RiskTier.LOW), (0.0, RiskTier.LOW)],
    )
    def test_tier_boundaries(self, score, tier):
        assert risk.tier_for(score) is tier


class TestAssess:
    def test_high_sensitivity_weak_controls_is_critical(self):
        result = risk.assess("v1", DataClass.RESTRICTED, True, 0.3)
        assert result.tier is RiskTier.CRITICAL

    def test_low_sensitivity_strong_controls_is_low(self):
        result = risk.assess("v1", DataClass.PUBLIC, False, 0.95, 0.95)
        assert result.tier is RiskTier.LOW

    def test_drivers_explain_the_score(self):
        result = risk.assess("v1", DataClass.CONFIDENTIAL, False, 0.7, 0.6, [Severity.HIGH])
        assert result.drivers["impact"] == 4
        assert result.drivers["open_findings"] == 1
        assert result.drivers["risk_reduction"] > 0

    def test_residual_never_exceeds_inherent(self):
        result = risk.assess("v1", DataClass.RESTRICTED, True, 0.0, 0.0)
        assert result.residual_score <= result.inherent_score

    def test_identical_inputs_are_deterministic(self):
        a = risk.assess("v1", DataClass.INTERNAL, True, 0.6, 0.7)
        b = risk.assess("v1", DataClass.INTERNAL, True, 0.6, 0.7)
        assert a.residual_score == b.residual_score and a.tier == b.tier
