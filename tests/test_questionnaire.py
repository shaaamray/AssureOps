import pytest

from assureops import questionnaire as q
from assureops.errors import ValidationError
from assureops.models import Severity


class TestAnswerNormalisation:
    @pytest.mark.parametrize("raw,expected", [("YES", "yes"), ("y", "yes"), ("Partial", "partial"),
                                              ("p", "partial"), ("N", "no"), ("false", "no")])
    def test_accepts_aliases(self, raw, expected):
        assert q.normalise_answer(raw) == expected

    @pytest.mark.parametrize("bad", ["maybe", "", "1", "unknown"])
    def test_rejects_unknown_answers(self, bad):
        with pytest.raises(ValidationError):
            q.normalise_answer(bad)


class TestScoring:
    def test_all_yes_scores_one(self, all_yes):
        assert q.score(all_yes).overall == 1.0

    def test_all_no_scores_zero(self, all_no):
        assert q.score(all_no).overall == 0.0

    def test_partial_earns_half_credit(self):
        answers = {qq.qid: "partial" for qq in q.QUESTION_BANK}
        assert q.score(answers).overall == pytest.approx(0.5)

    def test_weighting_favours_heavier_questions(self, all_yes):
        """Failing a weight 2.0 question must cost more than a weight 1.0 one."""
        heavy = dict(all_yes, **{"IAM-01": "no"})   # weight 2.0
        light = dict(all_yes, **{"GOV-01": "no"})   # weight 1.0
        assert q.score(heavy).overall < q.score(light).overall

    def test_unknown_question_id_is_rejected(self, all_yes):
        with pytest.raises(ValidationError, match="unknown question"):
            q.score(dict(all_yes, **{"NOPE-99": "yes"}))

    def test_unanswered_questions_are_reported(self):
        result = q.score({"GOV-01": "yes"})
        assert len(result.unanswered) == len(q.QUESTION_BANK) - 1

    def test_partial_submission_scores_only_answered(self):
        assert q.score({"GOV-01": "yes"}).overall == 1.0

    def test_empty_submission_does_not_divide_by_zero(self):
        assert q.score({}).overall == 0.0


class TestDomains:
    def test_every_domain_is_represented(self, all_yes):
        result = q.score(all_yes)
        assert set(result.domains) == set(q.DOMAINS)

    def test_domain_ratio_reflects_answers(self, all_yes):
        answers = dict(all_yes)
        for question in q.QUESTION_BANK:
            if question.domain == "Access Control":
                answers[question.qid] = "no"
        result = q.score(answers)
        assert result.domains["Access Control"].ratio == 0.0
        assert result.domains["Governance"].ratio == 1.0

    def test_answered_count_tracks_submissions(self, all_yes):
        result = q.score(all_yes)
        assert sum(d.answered for d in result.domains.values()) == len(q.QUESTION_BANK)


class TestGaps:
    def test_no_gaps_when_all_yes(self, all_yes):
        assert q.score(all_yes).gaps == []

    def test_partial_counts_as_a_gap(self, all_yes):
        result = q.score(dict(all_yes, **{"GOV-01": "partial"}))
        assert len(result.gaps) == 1

    def test_failed_critical_questions_are_surfaced(self, all_yes):
        result = q.score(dict(all_yes, **{"IAM-01": "no", "GOV-01": "no"}))
        assert [x.qid for x in result.failed_critical] == ["IAM-01"]

    def test_partial_on_critical_is_not_a_hard_failure(self, all_yes):
        result = q.score(dict(all_yes, **{"IAM-01": "partial"}))
        assert result.failed_critical == []


class TestGapSeverity:
    def test_critical_question_answered_no_is_critical(self):
        assert q.gap_severity(q.QUESTIONS_BY_ID["IAM-01"], "no") is Severity.CRITICAL

    def test_critical_question_answered_partial_is_high(self):
        assert q.gap_severity(q.QUESTIONS_BY_ID["IAM-01"], "partial") is Severity.HIGH

    def test_heavy_question_answered_no_is_high(self):
        assert q.gap_severity(q.QUESTIONS_BY_ID["GOV-02"], "no") is Severity.HIGH

    def test_light_question_answered_no_is_medium(self):
        assert q.gap_severity(q.QUESTIONS_BY_ID["GOV-01"], "no") is Severity.MEDIUM


class TestBankIntegrity:
    def test_question_ids_are_unique(self):
        ids = [x.qid for x in q.QUESTION_BANK]
        assert len(ids) == len(set(ids))

    def test_every_question_maps_to_real_controls(self):
        from assureops.frameworks import resolve
        for question in q.QUESTION_BANK:
            assert question.controls
            for control_id in question.controls:
                resolve(control_id)

    def test_weights_are_positive(self):
        assert all(x.weight > 0 for x in q.QUESTION_BANK)
