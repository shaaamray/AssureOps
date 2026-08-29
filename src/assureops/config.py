"""Strict configuration loading.

Unknown keys are rejected rather than ignored, and every error names the exact
dotted path. A silently swallowed typo in an assurance tool means a control
you believe is enforced is not.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError
from .redaction import looks_like_secret

_ENV_REF = re.compile(r"\$\{ENV:([A-Z0-9_]+)(?::([^}]*))?\}")

SCHEMA: dict[str, set[str]] = {
    "": {"organisation", "scope", "assessment", "sla", "audit", "reporting"},
    "scope": {"allow", "allow_private", "require_authorisation"},
    "assessment": {"posture_enabled", "minimum_questionnaire_score", "fail_on"},
    "sla": {"critical_days", "high_days", "medium_days", "low_days"},
    "audit": {"path", "hmac_key_env"},
    "reporting": {"output_dir", "chart_dpi"},
}

DEFAULTS: dict[str, Any] = {
    "organisation": "Example Organisation",
    "scope": {"allow": [], "allow_private": False, "require_authorisation": True},
    "assessment": {"posture_enabled": True, "minimum_questionnaire_score": 0.7, "fail_on": "high"},
    "sla": {"critical_days": 7, "high_days": 30, "medium_days": 90, "low_days": 180},
    "audit": {"path": "var/audit/assureops_audit.jsonl", "hmac_key_env": "ASSUREOPS_AUDIT_HMAC_KEY"},
    "reporting": {"output_dir": "var/reports", "chart_dpi": 140},
}


def _interpolate(value: Any) -> Any:
    """Replace ${ENV:NAME} and ${ENV:NAME:default} references."""
    if isinstance(value, str):
        def sub(match: re.Match) -> str:
            name, default = match.group(1), match.group(2)
            resolved = os.environ.get(name, default)
            if resolved is None:
                raise ConfigError(f"environment variable {name} is referenced but not set")
            return resolved
        return _ENV_REF.sub(sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def _reject_secrets(data: Any, path: str = "") -> None:
    """Refuse to start if a credential shaped literal is pasted into the file."""
    if isinstance(data, dict):
        for key, val in data.items():
            _reject_secrets(val, f"{path}.{key}" if path else key)
    elif isinstance(data, list):
        for idx, val in enumerate(data):
            _reject_secrets(val, f"{path}[{idx}]")
    elif isinstance(data, str) and looks_like_secret(data):
        raise ConfigError(
            f"{path or 'config'} looks like a credential. Reference an environment "
            f"variable with ${{ENV:NAME}} instead of pasting secrets into the file."
        )


def _validate(section: dict[str, Any], prefix: str = "") -> None:
    allowed = SCHEMA.get(prefix)
    if allowed is None:
        return
    for key, value in section.items():
        dotted = f"{prefix}.{key}" if prefix else key
        if key not in allowed:
            suggestions = ", ".join(sorted(allowed))
            raise ConfigError(f"unknown configuration key {dotted!r}; allowed keys here are: {suggestions}")
        if isinstance(value, dict):
            _validate(value, key if not prefix else f"{prefix}.{key}")


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load(path: str | Path | None = None) -> dict[str, Any]:
    """Load, interpolate, validate and merge a configuration file over defaults."""
    if path is None:
        return _merge(DEFAULTS, {})

    file_path = Path(path)
    if not file_path.exists():
        raise ConfigError(f"configuration file not found: {file_path}")

    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse {file_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{file_path} must contain a YAML mapping at the top level")

    _reject_secrets(raw)
    _validate(raw)
    return _merge(DEFAULTS, _interpolate(raw))
