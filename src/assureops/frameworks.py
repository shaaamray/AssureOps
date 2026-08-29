"""Control framework mapping.

Assessment questions and findings are mapped onto ISO/IEC 27001:2022 Annex A
controls and NIST CSF 2.0 functions, so a result can be expressed in the
language an auditor already uses rather than in tool specific jargon.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import FrameworkError


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    theme: str
    framework: str = "ISO27001:2022"


# A working subset of ISO/IEC 27001:2022 Annex A, chosen for the controls that
# actually come up in third party assurance and access governance.
ISO_27001_ANNEX_A: dict[str, Control] = {
    c.control_id: c
    for c in (
        Control("A.5.7", "Threat intelligence", "Organisational"),
        Control("A.5.15", "Access control", "Organisational"),
        Control("A.5.16", "Identity management", "Organisational"),
        Control("A.5.17", "Authentication information", "Organisational"),
        Control("A.5.18", "Access rights", "Organisational"),
        Control("A.5.19", "Information security in supplier relationships", "Organisational"),
        Control("A.5.20", "Addressing information security within supplier agreements", "Organisational"),
        Control("A.5.21", "Managing information security in the ICT supply chain", "Organisational"),
        Control("A.5.22", "Monitoring, review and change management of supplier services", "Organisational"),
        Control("A.5.23", "Information security for use of cloud services", "Organisational"),
        Control("A.5.24", "Information security incident management planning", "Organisational"),
        Control("A.5.30", "ICT readiness for business continuity", "Organisational"),
        Control("A.6.3", "Information security awareness, education and training", "People"),
        Control("A.8.2", "Privileged access rights", "Technological"),
        Control("A.8.5", "Secure authentication", "Technological"),
        Control("A.8.8", "Management of technical vulnerabilities", "Technological"),
        Control("A.8.9", "Configuration management", "Technological"),
        Control("A.8.12", "Data leakage prevention", "Technological"),
        Control("A.8.16", "Monitoring activities", "Technological"),
        Control("A.8.24", "Use of cryptography", "Technological"),
    )
}

# NIST CSF 2.0 functions, including GOVERN which was added in 2.0.
NIST_CSF_FUNCTIONS: dict[str, str] = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}

# Each Annex A control above is attributed to the CSF function it most
# directly supports. One to one is a simplification, but a defensible one for
# reporting coverage by function.
ISO_TO_CSF: dict[str, str] = {
    "A.5.7": "DE", "A.5.15": "PR", "A.5.16": "PR", "A.5.17": "PR", "A.5.18": "PR",
    "A.5.19": "GV", "A.5.20": "GV", "A.5.21": "GV", "A.5.22": "GV", "A.5.23": "GV",
    "A.5.24": "RS", "A.5.30": "RC", "A.6.3": "PR", "A.8.2": "PR", "A.8.5": "PR",
    "A.8.8": "ID", "A.8.9": "PR", "A.8.12": "PR", "A.8.16": "DE", "A.8.24": "PR",
}


def resolve(control_id: str) -> Control:
    """Look up an Annex A control, or fail loudly with the offending id."""
    try:
        return ISO_27001_ANNEX_A[control_id]
    except KeyError:
        raise FrameworkError(f"unknown ISO 27001 Annex A control {control_id!r}") from None


def csf_function(control_id: str) -> str:
    """Return the CSF function name a control maps to."""
    code = ISO_TO_CSF.get(control_id)
    if code is None:
        raise FrameworkError(f"no NIST CSF mapping for control {control_id!r}")
    return NIST_CSF_FUNCTIONS[code]


def validate_all(control_ids) -> tuple[str, ...]:
    """Validate a collection of control ids, returning them sorted and deduplicated."""
    resolved = {resolve(cid).control_id for cid in control_ids}
    return tuple(sorted(resolved))


def coverage_by_function(control_ids) -> dict[str, int]:
    """Count how many of the supplied controls sit under each CSF function."""
    counts = {name: 0 for name in NIST_CSF_FUNCTIONS.values()}
    for cid in control_ids:
        counts[csf_function(cid)] += 1
    return counts


def coverage_by_theme(control_ids) -> dict[str, int]:
    counts: dict[str, int] = {}
    for cid in control_ids:
        theme = resolve(cid).theme
        counts[theme] = counts.get(theme, 0) + 1
    return counts
