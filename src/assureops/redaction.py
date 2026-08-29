"""Secret redaction.

Matching on value shape alone misses anything that does not look like a
token, so this redacts by key name as well. A random looking password matches
no pattern, but any value under a key called password, secret or token is
redacted regardless of what it contains.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(pass(word|phrase)?|secret|token|api[_-]?key|client[_-]?secret|credential|authorization|cookie|private[_-]?key)",
    re.IGNORECASE,
)

_VALUE_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),                      # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),            # GitHub token
    re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}"),         # Slack token
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),    # PEM private key
)


def looks_like_secret(value: str) -> bool:
    """True when a bare string matches a known credential shape."""
    return any(p.search(value) for p in _VALUE_PATTERNS)


def redact_value(value: str) -> str:
    out = value
    for pattern in _VALUE_PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


def redact(obj: Any) -> Any:
    """Recursively redact by key name and by value shape."""
    if isinstance(obj, dict):
        result = {}
        for key, val in obj.items():
            if isinstance(key, str) and _SENSITIVE_KEY.search(key):
                result[key] = REDACTED
            else:
                result[key] = redact(val)
        return result
    if isinstance(obj, (list, tuple)):
        rendered = [redact(item) for item in obj]
        return type(obj)(rendered) if isinstance(obj, tuple) else rendered
    if isinstance(obj, str):
        return redact_value(obj)
    return obj
