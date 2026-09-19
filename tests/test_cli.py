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


class TestTrend:
    def _assess_args(self, answers=None, observations=None, as_of="2026-07-01"):
        return [
            "assess", "--config", str(CONFIG),
            "--vendors", str(SAMPLES / "vendors.csv"),
            "--answers", str(answers or SAMPLES / "answers.csv"),
            "--observations", str(observations or SAMPLES / "observations.json"),
            "--as-of", as_of, "--i-am-authorised",
        ]

    def test_a_single_cycle_has_no_trend_yet(self, workdir, capsys):
        main(self._assess_args())
        assert main(["trend", "--config", str(CONFIG)]) == EXIT_OK
        assert "Not enough history yet" in capsys.readouterr().out

    def test_two_identical_cycles_show_no_regression(self, workdir, capsys):
        main(self._assess_args(as_of="2026-07-01"))
        main(self._assess_args(as_of="2026-08-01"))
        assert main(["trend", "--config", str(CONFIG)]) == EXIT_OK
        out = capsys.readouterr().out
        assert "Regressed      : 0" in out

    def test_a_new_critical_finding_trips_the_regression_gate(self, workdir, tmp_path, capsys):
        import csv

        rows = list(csv.DictReader(open(SAMPLES / "answers.csv")))
        for row in rows:
            if row["vendor_id"] == "vendor-f":
                row["answer"] = "no"
        worse = tmp_path / "answers_worse.csv"
        with worse.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["vendor_id", "question_id", "answer"])
            writer.writeheader()
            writer.writerows(rows)

        main(self._assess_args(as_of="2026-07-01"))
        main(self._assess_args(answers=worse, as_of="2026-08-15"))

        assert main(["trend", "--config", str(CONFIG)]) == EXIT_FINDINGS
        out = capsys.readouterr().out
        assert "REGRESSED vendor-f" in out

    def test_trend_snapshots_land_in_the_same_audit_log_as_assess(self, workdir):
        from assureops.audit import AuditLog

        main(self._assess_args(as_of="2026-07-01"))
        main(self._assess_args(as_of="2026-08-01"))
        log = AuditLog(workdir / "var" / "audit" / "assureops_audit.jsonl")
        assert log.verify().ok
        assert any(r["action"] == "trend_snapshot" for r in log.records())
        assert any(r["action"] == "vendor_assessed" for r in log.records())

    def test_disabling_trend_in_config_records_no_snapshots(self, workdir, tmp_path):
        from assureops.audit import AuditLog

        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(
            "audit:\n  path: var/audit/assureops_audit.jsonl\ntrend:\n  enabled: false\n"
        )
        args = ["assess", "--config", str(cfg),
                "--vendors", str(SAMPLES / "vendors.csv"),
                "--answers", str(SAMPLES / "answers.csv"),
                "--observations", str(SAMPLES / "observations.json"),
                "--as-of", "2026-07-01", "--i-am-authorised"]
        main(args)
        log = AuditLog(workdir / "var" / "audit" / "assureops_audit.jsonl")
        assert not any(r["action"] == "trend_snapshot" for r in log.records())

    def test_trend_writes_a_chart_when_asked(self, workdir):
        main(self._assess_args(as_of="2026-07-01"))
        main(self._assess_args(as_of="2026-08-15"))
        code = main(["trend", "--config", str(CONFIG), "--report", str(workdir / "out")])
        assert code in (EXIT_OK, EXIT_FINDINGS)
        assert (workdir / "out" / "images" / "risk_trend.png").exists()

    def test_missing_history_skips_the_chart_without_crashing(self, workdir, capsys):
        main(self._assess_args())
        main(["trend", "--config", str(CONFIG), "--report", str(workdir / "out")])
        assert "Not enough history" in capsys.readouterr().out
        assert not (workdir / "out").exists()
