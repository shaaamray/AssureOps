"""Loading vendors, answers and entitlements from CSV or JSON."""

from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .models import DataClass, Entitlement, Finding, Severity, Vendor


def _bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _optional(value: Any) -> str | None:
    """Blank cells become None rather than empty strings."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int_or_none(value: Any) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        raise ValidationError(f"expected an integer, got {value!r}") from None


def _rows(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise ValidationError(f"input file not found: {p}")
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValidationError(f"{p} must contain a JSON array")
        return data
    with p.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_vendors(path: str | Path) -> list[Vendor]:
    vendors = []
    for idx, row in enumerate(_rows(path), start=1):
        try:
            vendors.append(
                Vendor(
                    vendor_id=str(row["vendor_id"]).strip(),
                    name=str(row["name"]).strip(),
                    service=str(row.get("service", "")).strip(),
                    data_class=DataClass(str(row["data_class"]).strip().lower()),
                    business_critical=_bool(row.get("business_critical")),
                    domain=_optional(row.get("domain")),
                    contract_owner=_optional(row.get("contract_owner")),
                )
            )
        except KeyError as exc:
            raise ValidationError(f"row {idx} is missing required column {exc}") from None
        except ValueError as exc:
            raise ValidationError(f"row {idx}: {exc}") from None
    return vendors


def load_entitlements(path: str | Path) -> list[Entitlement]:
    entitlements = []
    for idx, row in enumerate(_rows(path), start=1):
        try:
            entitlements.append(
                Entitlement(
                    principal=str(row["principal"]).strip(),
                    system=str(row["system"]).strip(),
                    role=str(row["role"]).strip(),
                    privileged=_bool(row.get("privileged")),
                    days_since_login=_int_or_none(row.get("days_since_login")),
                    last_reviewed_days=_int_or_none(row.get("last_reviewed_days")),
                    enabled=_bool(row.get("enabled"), default=True),
                    mfa_enrolled=_bool(row.get("mfa_enrolled"), default=True),
                )
            )
        except KeyError as exc:
            raise ValidationError(f"row {idx} is missing required column {exc}") from None
    return entitlements


def load_answers(path: str | Path) -> dict[str, dict[str, str]]:
    """Questionnaire answers keyed by vendor_id then question id."""
    p = Path(path)
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValidationError(f"{p} must contain a JSON object keyed by vendor_id")
        return data

    answers: dict[str, dict[str, str]] = {}
    for row in _rows(p):
        vendor_id = str(row["vendor_id"]).strip()
        answers.setdefault(vendor_id, {})[str(row["question_id"]).strip()] = str(row["answer"]).strip()
    return answers


def load_findings(path: str | Path) -> list[Finding]:
    findings = []
    for row in _rows(path):
        raised = str(row.get("raised_on", "")).strip()
        findings.append(
            Finding(
                finding_id=str(row["finding_id"]).strip(),
                subject=str(row["subject"]).strip(),
                title=str(row.get("title", "")).strip(),
                severity=Severity(str(row["severity"]).strip().lower()),
                source=str(row.get("source", "import")).strip(),
                controls=tuple(c.strip() for c in str(row.get("controls", "")).split(";") if c.strip()),
                detail=str(row.get("detail", "")).strip(),
                raised_on=date.fromisoformat(raised) if raised else None,
            )
        )
    return findings
