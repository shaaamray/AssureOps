"""End to end CLI tests, including the exit code contract."""

import json
from pathlib import Path

import pytest

from assureops.cli import EXIT_AUDIT, EXIT_CONFIG, EXIT_FINDINGS, EXIT_OK, main

SAMPLES = Path(__file__).resolve().parents[1] / "config" / "samples"
CONFIG = Path(__file__).resolve().parents[1] / "config" / "assureops.example.yaml"


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Run each CLI test in an isolated directory so audit paths do not collide."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestValidate:
    def test_valid_config_exits_zero(self, workdir, capsys):
        assert main(["validate", "--config", str(CONFIG)]) == EXIT_OK
        assert "Configuration valid" in capsys.readouterr().out

    def test_unknown_key_exits_config_error(self, workdir, capsys):
        bad = workdir / "bad.yaml"
        bad.write_text("nonsense: true\n")
        assert main(["validate", "--config", str(bad)]) == EXIT_CONFIG
        assert "unknown configuration key" in capsys.readouterr().err

    def test_missing_file_exits_config_error(self, workdir):
        assert main(["validate", "--config", str(workdir / "absent.yaml")]) == EXIT_CONFIG


class TestAssess:
    def _args(self, extra=None):
        args = ["assess", "--config", str(CONFIG),
                "--vendors", str(SAMPLES / "vendors.csv"),
                "--answers", str(SAMPLES / "answers.csv"),
                "--observations", str(SAMPLES / "observations.json"),
                "--as-of", "2026-08-22", "--i-am-authorised"]
        return args + (extra or [])

    def test_reports_findings_with_exit_code_two(self, workdir, capsys):
        """The sample portfolio has high findings, so the gate must trip."""
        assert main(self._args()) == EXIT_FINDINGS
        out = capsys.readouterr().out
        assert "Assessed 6 vendors" in out
        assert "Risk tiers" in out

    def test_writes_report_and_charts(self, workdir, capsys):
        main(self._args(["--report", str(workdir / "out")]))
        assert (workdir / "out" / "assurance_report.md").exists()
        assert (workdir / "out" / "images" / "risk_tiers.png").exists()

    def test_no_charts_flag_skips_images(self, workdir):
        main(self._args(["--report", str(workdir / "out"), "--no-charts"]))
        assert not (workdir / "out" / "images").exists()

    def test_writes_an_audit_trail(self, workdir):
        from assureops.audit import AuditLog
        main(self._args())
        log = AuditLog(workdir / "var" / "audit" / "assureops_audit.jsonl")
        assert log.verify().ok
        assert any(r["action"] == "vendor_assessed" for r in log.records())

    def test_without_authorisation_posture_is_suppressed(self, workdir):
        """Scope refusal must degrade gracefully, not crash the run."""
        args = [a for a in self._args() if a != "--i-am-authorised"]
        assert main(args) in (EXIT_OK, EXIT_FINDINGS)

    def test_findings_register_is_merged_for_sla(self, workdir, capsys):
        main(self._args(["--findings", str(SAMPLES / "findings.csv")]))
        assert "breached" in capsys.readouterr().out


class TestAccessReview:
    def test_runs_and_flags_findings(self, workdir, capsys):
        code = main(["access-review", "--config", str(CONFIG),
                     "--entitlements", str(SAMPLES / "entitlements.csv"),
                     "--as-of", "2026-08-22"])
        out = capsys.readouterr().out
        assert "Reviewed 42 entitlements" in out
        assert code == EXIT_FINDINGS

    def test_limit_truncates_output(self, workdir, capsys):
        main(["access-review", "--config", str(CONFIG),
              "--entitlements", str(SAMPLES / "entitlements.csv"), "--limit", "2"])
        assert "more" in capsys.readouterr().out


class TestSlaReport:
    def test_reports_breaches(self, workdir, capsys):
        code = main(["sla-report", "--config", str(CONFIG),
                     "--findings", str(SAMPLES / "findings.csv"),
                     "--as-of", "2026-08-22"])
        out = capsys.readouterr().out
        assert "Compliance" in out and "BREACH" in out
        assert code == EXIT_FINDINGS


class TestAuditCommands:
    def test_verify_reports_intact_chain(self, workdir, capsys):
        from assureops.audit import AuditLog
        path = workdir / "audit.jsonl"
        log = AuditLog(path)
        log.append("a", "ok")
        assert main(["audit", "verify", "--path", str(path)]) == EXIT_OK
        assert "verified" in capsys.readouterr().out

    def test_verify_detects_tampering(self, workdir, capsys):
        from assureops.audit import AuditLog
        path = workdir / "audit.jsonl"
        AuditLog(path).append("a", "ok", amount=1)
        path.write_text(path.read_text().replace('"amount":1', '"amount":999'))
        assert main(["audit", "verify", "--path", str(path)]) == EXIT_AUDIT
        assert "BROKEN" in capsys.readouterr().err

    def test_tail_emits_json_lines(self, workdir, capsys):
        from assureops.audit import AuditLog
        path = workdir / "audit.jsonl"
        log = AuditLog(path)
        for i in range(3):
            log.append("a", "ok", index=i)
        main(["audit", "tail", "--path", str(path), "--count", "2"])
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        assert len(lines) == 2
        assert json.loads(lines[0])["index"] == 1


class TestParser:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_missing_subcommand_exits(self):
        with pytest.raises(SystemExit):
            main([])
