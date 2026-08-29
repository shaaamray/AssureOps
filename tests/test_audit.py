import json

import pytest

from assureops.audit import GENESIS, AuditLog, compute_digest
from assureops.errors import AuditChainError


@pytest.fixture
def log(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


class TestAppend:
    def test_first_record_links_to_genesis(self, log):
        rec = log.append("vendor_assessed", "completed", vendor="v1")
        assert rec["prev"] == GENESIS
        assert rec["seq"] == 0

    def test_records_chain_together(self, log):
        first = log.append("a", "ok")
        second = log.append("b", "ok")
        assert second["prev"] == first["digest"]
        assert second["seq"] == 1

    def test_extra_fields_are_persisted(self, log):
        log.append("posture_check", "completed", host="v.example", score=0.82)
        rec = next(iter(log.records()))
        assert rec["host"] == "v.example"
        assert rec["score"] == 0.82

    def test_reserved_fields_cannot_be_overridden(self, log):
        rec = log.append("a", "ok", seq=999, prev="deadbeef")
        assert rec["seq"] == 0
        assert rec["prev"] == GENESIS

    def test_creates_parent_directory(self, tmp_path):
        nested = AuditLog(tmp_path / "deep" / "nested" / "audit.jsonl")
        nested.append("a", "ok")
        assert nested.path.exists()


class TestVerification:
    def test_empty_log_verifies(self, log):
        result = log.verify()
        assert result.ok and result.records == 0

    def test_intact_chain_verifies(self, log):
        for i in range(6):
            log.append("action", "ok", index=i)
        result = log.verify()
        assert result.ok
        assert result.records == 6

    def test_detects_edited_content(self, log):
        log.append("a", "ok", amount=100)
        log.append("b", "ok", amount=200)
        lines = log.path.read_text().splitlines()
        tampered = json.loads(lines[0])
        tampered["amount"] = 999
        lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        log.path.write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert not result.ok
        assert result.broken_at == 0
        assert "digest" in result.reason

    def test_detects_deleted_record(self, log):
        for i in range(4):
            log.append("a", "ok", index=i)
        lines = log.path.read_text().splitlines()
        del lines[1]
        log.path.write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert not result.ok
        assert result.broken_at == 1

    def test_detects_reordered_records(self, log):
        for i in range(3):
            log.append("a", "ok", index=i)
        lines = log.path.read_text().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        log.path.write_text("\n".join(lines) + "\n")
        assert not log.verify().ok

    def test_detects_appended_forgery(self, log):
        log.append("a", "ok")
        forged = {"seq": 1, "ts": "2026-01-01T00:00:00+00:00", "action": "x",
                  "outcome": "ok", "prev": GENESIS, "digest": "0" * 64}
        with log.path.open("a") as fh:
            fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
        result = log.verify()
        assert not result.ok
        assert result.broken_at == 1

    def test_require_valid_raises_on_broken_chain(self, log):
        log.append("a", "ok")
        log.path.write_text(log.path.read_text().replace('"ok"', '"tampered"'))
        with pytest.raises(AuditChainError):
            log.require_valid()


class TestKeyedChain:
    def test_keyed_digest_differs_from_unkeyed(self):
        record = {"seq": 0, "action": "a", "outcome": "ok", "prev": GENESIS}
        assert compute_digest(record) != compute_digest(record, b"secret-key")

    def test_forged_record_fails_without_the_key(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        keyed = AuditLog(path, hmac_key=b"correct-key")
        keyed.append("a", "ok")
        assert keyed.verify().ok

        # An attacker who can write the file but does not hold the key cannot
        # produce a record that verifies.
        attacker = AuditLog(path, hmac_key=b"wrong-key")
        attacker.append("evil", "ok")
        assert not keyed.verify().ok

    def test_keyed_flag_reports_correctly(self, tmp_path):
        assert AuditLog(tmp_path / "a.jsonl", hmac_key=b"k").keyed
        assert not AuditLog(tmp_path / "b.jsonl").keyed

    def test_key_read_from_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASSUREOPS_AUDIT_HMAC_KEY", "from-env")
        assert AuditLog(tmp_path / "a.jsonl").keyed


class TestTail:
    def test_returns_last_n(self, log):
        for i in range(10):
            log.append("a", "ok", index=i)
        tail = log.tail(3)
        assert [r["index"] for r in tail] == [7, 8, 9]

    def test_tail_of_missing_file_is_empty(self, tmp_path):
        assert AuditLog(tmp_path / "absent.jsonl").tail() == []
