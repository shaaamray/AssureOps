"""Tamper evident audit log.

Every record carries the digest of the record before it. Editing, deleting or
reordering any line breaks the chain, and verification reports the exact
sequence number where it broke. Supplying an HMAC key through the environment
makes the chain keyed, so an attacker who can write to the file still cannot
forge a record that verifies.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import AuditChainError

GENESIS = "0" * 64
_HMAC_ENV = "ASSUREOPS_AUDIT_HMAC_KEY"


def _canonical(payload: dict[str, Any]) -> str:
    """Serialise deterministically so the same record always hashes the same."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_digest(record: dict[str, Any], key: bytes | None = None) -> str:
    """Digest of a record, excluding its own digest field."""
    body = {k: v for k, v in record.items() if k != "digest"}
    material = _canonical(body).encode("utf-8")
    if key:
        return hmac.new(key, material, hashlib.sha256).hexdigest()
    return hashlib.sha256(material).hexdigest()


@dataclass
class VerificationResult:
    """Outcome of verifying a chain end to end."""

    ok: bool
    records: int
    broken_at: int | None = None
    reason: str | None = None


class AuditLog:
    """Append only, hash chained JSONL log."""

    def __init__(self, path: str | Path, hmac_key: bytes | None = None) -> None:
        self.path = Path(path)
        if hmac_key is None:
            env_key = os.environ.get(_HMAC_ENV)
            hmac_key = env_key.encode("utf-8") if env_key else None
        self._key = hmac_key

    @property
    def keyed(self) -> bool:
        return self._key is not None

    def append(self, action: str, outcome: str, **fields: Any) -> dict[str, Any]:
        """Append one record and return it, including its digest."""
        prev = self._last_digest()
        record: dict[str, Any] = {
            "seq": self._next_seq(),
            "ts": datetime.now(UTC).isoformat(),
            "action": action,
            "outcome": outcome,
            "prev": prev,
        }
        record.update({k: v for k, v in fields.items() if k not in record})
        record["digest"] = compute_digest(record, self._key)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical(record) + "\n")
        return record

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def _last_digest(self) -> str:
        last = GENESIS
        for rec in self.records():
            last = rec.get("digest", GENESIS)
        return last

    def _next_seq(self) -> int:
        n = 0
        for _ in self.records():
            n += 1
        return n

    def verify(self) -> VerificationResult:
        """Walk the chain and report the first record that does not line up."""
        expected_prev = GENESIS
        count = 0
        for idx, rec in enumerate(self.records()):
            count += 1
            if rec.get("seq") != idx:
                return VerificationResult(False, count, idx, "sequence number out of order")
            if rec.get("prev") != expected_prev:
                return VerificationResult(False, count, idx, "previous digest does not match")
            recomputed = compute_digest(rec, self._key)
            if not hmac.compare_digest(recomputed, rec.get("digest", "")):
                return VerificationResult(False, count, idx, "record digest does not match contents")
            expected_prev = rec["digest"]
        return VerificationResult(True, count)

    def tail(self, count: int = 5) -> list[dict[str, Any]]:
        return list(self.records())[-count:]

    def require_valid(self) -> None:
        result = self.verify()
        if not result.ok:
            raise AuditChainError(f"audit chain broken at record {result.broken_at}: {result.reason}")
