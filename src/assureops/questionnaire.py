"""Third party security questionnaire.

A weighted assessment across the control domains that matter for supplier
assurance. Every question carries the Annex A control it evidences, so a low
score produces a finding that names a real control rather than a vague theme.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import ValidationError
from .models import Severity


@dataclass(frozen=True)
class Question:
    qid: str
    domain: str
    text: str
    weight: float
    controls: tuple[str, ...]
    critical: bool = False


# Answers are a three point scale. Partial credit matters: "in progress with a
# documented plan" is genuinely different from "no".
ANSWER_VALUES: dict[str, float] = {"yes": 1.0, "partial": 0.5, "no": 0.0}

QUESTION_BANK: tuple[Question, ...] = (
    Question(
        "GOV-01",
        "Governance",
        "Documented information security policy approved by management",
        1.0,
        ("A.5.19",),
    ),
    Question(
        "GOV-02",
        "Governance",
        "Independent certification or attestation held (ISO 27001, SOC 2)",
        1.5,
        ("A.5.19", "A.5.20"),
    ),
    Question(
        "GOV-03",
        "Governance",
        "Security obligations are written into the contract",
        1.0,
        ("A.5.20",),
    ),
    Question(
        "GOV-04",
        "Governance",
        "Fourth party and sub processor risk is managed and disclosed",
        1.0,
        ("A.5.21",),
    ),
    Question(
        "IAM-01",
        "Access Control",
        "Multi factor authentication enforced for all administrative access",
        2.0,
        ("A.8.5", "A.5.17"),
        critical=True,
    ),
    Question(
        "IAM-02",
        "Access Control",
        "Access rights reviewed at least every six months",
        1.5,
        ("A.5.18",),
    ),
    Question(
        "IAM-03",
        "Access Control",
        "Privileged accounts are separate from day to day accounts",
        1.5,
        ("A.8.2",),
    ),
    Question(
        "IAM-04",
        "Access Control",
        "Joiner, mover and leaver process removes access within one business day",
        1.0,
        ("A.5.16", "A.5.18"),
    ),
    Question(
        "DAT-01",
        "Data Protection",
        "Customer data encrypted in transit using TLS 1.2 or above",
        2.0,
        ("A.8.24",),
        critical=True,
    ),
    Question(
        "DAT-02",
        "Data Protection",
        "Customer data encrypted at rest",
        1.5,
        ("A.8.24",),
    ),
    Question(
        "DAT-03",
        "Data Protection",
        "Data residency and retention commitments are documented",
        1.0,
        ("A.8.12",),
    ),
    Question(
        "VUL-01",
        "Vulnerability Management",
        "Documented patching SLAs by severity, with evidence of compliance",
        1.5,
        ("A.8.8",),
    ),
    Question(
        "VUL-02",
        "Vulnerability Management",
        "Independent penetration test within the last twelve months",
        1.5,
        ("A.8.8",),
    ),
    Question(
        "VUL-03",
        "Vulnerability Management",
        "Secure baseline configuration applied and monitored",
        1.0,
        ("A.8.9",),
    ),
    Question(
        "IR-01",
        "Incident Response",
        "Documented incident response plan, tested within the last year",
        1.5,
        ("A.5.24",),
    ),
    Question(
        "IR-02",
        "Incident Response",
        "Contractual breach notification within 72 hours",
        2.0,
        ("A.5.24", "A.5.20"),
        critical=True,
    ),
    Question(
        "IR-03",
        "Incident Response",
        "Security monitoring and logging retained for at least 12 months",
        1.0,
        ("A.8.16",),
    ),
    Question(
        "BCP-01",
        "Resilience",
        "Business continuity and disaster recovery plans tested annually",
        1.5,
        ("A.5.30",),
    ),
    Question(
        "BCP-02",
        "Resilience",
        "Recovery time and recovery point objectives are committed to",
        1.0,
        ("A.5.30",),
    ),
    Question(
        "AWR-01",
        "People",
        "Security awareness training completed by all staff annually",
        1.0,
        ("A.6.3",),
    ),
    Question(
        "TI-01",
        "Threat Intelligence",
        "Threat intelligence is consumed and acted upon",
        1.0,
        ("A.5.7",),
    ),
    Question(
        "CLD-01",
        "Cloud",
        "Cloud service configuration reviewed against a hardening benchmark",
        1.0,
        ("A.5.23",),
    ),
)

QUESTIONS_BY_ID: dict[str, Question] = {q.qid: q for q in QUESTION_BANK}
DOMAINS: tuple[str, ...] = tuple(dict.fromkeys(q.domain for q in QUESTION_BANK))


@dataclass
class DomainScore:
    domain: str
    score: float
    weight: float
    answered: int

    @property
    def ratio(self) -> float:
        return self.score / self.weight if self.weight else 0.0


@dataclass
class QuestionnaireResult:
    overall: float
    domains: dict[str, DomainScore]
    gaps: list[tuple[Question, str]]
    unanswered: tuple[str, ...]

    @property
    def failed_critical(self) -> list[Question]:
        return [q for q, ans in self.gaps if q.critical and ans == "no"]


def normalise_answer(raw: str) -> str:
    value = str(raw).strip().lower()
    aliases = {"y": "yes", "n": "no", "p": "partial", "true": "yes", "false": "no", "partially": "partial"}
    value = aliases.get(value, value)
    if value not in ANSWER_VALUES:
        raise ValidationError(f"answer {raw!r} must be one of yes, partial or no")
    return value


def score(answers: dict[str, str]) -> QuestionnaireResult:
    """Score a completed questionnaire, weighted, with per domain breakdown."""
    unknown = set(answers) - set(QUESTIONS_BY_ID)
    if unknown:
        raise ValidationError(f"unknown question ids: {', '.join(sorted(unknown))}")

    domains = {d: DomainScore(d, 0.0, 0.0, 0) for d in DOMAINS}
    gaps: list[tuple[Question, str]] = []

    for question in QUESTION_BANK:
        bucket = domains[question.domain]
        if question.qid not in answers:
            continue
        answer = normalise_answer(answers[question.qid])
        bucket.weight += question.weight
        bucket.score += question.weight * ANSWER_VALUES[answer]
        bucket.answered += 1
        if answer != "yes":
            gaps.append((question, answer))

    total_weight = sum(d.weight for d in domains.values())
    total_score = sum(d.score for d in domains.values())
    overall = total_score / total_weight if total_weight else 0.0

    unanswered = tuple(sorted(set(QUESTIONS_BY_ID) - set(answers)))
    return QuestionnaireResult(round(overall, 4), domains, gaps, unanswered)


def gap_severity(question: Question, answer: str) -> Severity:
    """Severity of a gap: critical questions answered no are the worst case."""
    if question.critical:
        return Severity.CRITICAL if answer == "no" else Severity.HIGH
    if answer == "no":
        return Severity.HIGH if question.weight >= 1.5 else Severity.MEDIUM
    return Severity.MEDIUM if question.weight >= 1.5 else Severity.LOW
