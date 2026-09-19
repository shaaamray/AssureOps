"""Command line interface.

Exit codes are stable so the same binary works interactively and in a
pipeline:

    0  success, nothing at or above the failure severity
    1  runtime error
    2  findings at or above --fail-on
    3  configuration, validation or scope error
    4  audit verification failed
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import __version__, ingest, trend
from .access_review import review as run_access_review
from .audit import AuditLog
from .config import load as load_config
from .errors import AssureOpsError, AuditChainError, ConfigError, ScopeError, ValidationError
from .models import Severity
from .pipeline import assess_portfolio
from .posture import Observation, make_static_prober, null_prober
from .scope import ScopeGuard
from .sla import DEFAULT_SLA_DAYS
from .sla import evaluate as evaluate_sla

EXIT_OK, EXIT_RUNTIME, EXIT_FINDINGS, EXIT_CONFIG, EXIT_AUDIT = 0, 1, 2, 3, 4


def _audit_from_config(cfg: dict) -> AuditLog:
    return AuditLog(cfg["audit"]["path"])


def _sla_table(cfg: dict) -> dict[Severity, int]:
    s = cfg["sla"]
    return {
        Severity.CRITICAL: int(s["critical_days"]),
        Severity.HIGH: int(s["high_days"]),
        Severity.MEDIUM: int(s["medium_days"]),
        Severity.LOW: int(s["low_days"]),
        Severity.INFO: DEFAULT_SLA_DAYS[Severity.INFO],
    }


def _load_prober(path: str | None):
    """Build a prober from a recorded observation file, or the null prober."""
    if not path:
        return null_prober
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    table = {
        host: Observation(
            host=host,
            reachable=bool(rec.get("reachable", True)),
            tls_version=rec.get("tls_version"),
            cert_days_to_expiry=rec.get("cert_days_to_expiry"),
            cert_self_signed=bool(rec.get("cert_self_signed", False)),
            hostname_match=bool(rec.get("hostname_match", True)),
            headers=rec.get("headers", {}) or {},
            open_ports=tuple(rec.get("open_ports", []) or ()),
            error=rec.get("error"),
        )
        for host, rec in data.items()
    }
    return make_static_prober(table)


def cmd_validate(args) -> int:
    cfg = load_config(args.config)
    print(f"Configuration valid. Organisation: {cfg['organisation']}")
    print(f"Scope allow list: {len(cfg['scope']['allow'])} entries, "
          f"authorisation required: {cfg['scope']['require_authorisation']}")
    return EXIT_OK


def cmd_assess(args) -> int:
    cfg = load_config(args.config)
    audit = _audit_from_config(cfg)
    guard = ScopeGuard.from_config(cfg).authorise(args.i_am_authorised)

    vendors = ingest.load_vendors(args.vendors)
    answers = ingest.load_answers(args.answers)
    prober = _load_prober(args.observations) if cfg["assessment"]["posture_enabled"] else None
    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()

    portfolio = assess_portfolio(vendors, answers, guard, prober, as_of, audit)

    # Every cycle's result rides on the same audit log as everything else,
    # so the trend history is tamper evident for free. See trend.py.
    if cfg["trend"]["enabled"]:
        trend.record_snapshot(audit, portfolio)

    # An open findings register from prior cycles is merged in for SLA
    # reporting, so remediation clocks run from when a finding was first
    # raised rather than restarting at every assessment.
    tracked = list(portfolio.findings)
    if args.findings:
        tracked.extend(ingest.load_findings(args.findings))
    sla = evaluate_sla(tracked, as_of, _sla_table(cfg))

    print(f"Assessed {len(portfolio.assessments)} vendors as at {as_of.isoformat()}")
    print(f"  Risk tiers      : {portfolio.tier_counts()}")
    print(f"  Findings        : {portfolio.severity_counts()}")
    print(f"  SLA compliance  : {sla.compliance_rate:.1%} ({len(sla.breached)} breached)")

    for item in portfolio.assessments:
        print(f"  {item.vendor.vendor_id:<14} tier={item.risk.tier.value:<8} "
              f"residual={item.risk.residual_score:>6.2f}  findings={len(item.findings)}")

    if args.report:
        from .reporting import write_report
        written = write_report(portfolio, sla, args.report, cfg["organisation"],
                               int(cfg["reporting"]["chart_dpi"]), charts=not args.no_charts)
        print(f"\nReport written to {written['report']}")
        for chart in written.get("charts", []):
            print(f"  chart: {chart}")

    threshold = Severity(cfg["assessment"]["fail_on"])
    if portfolio.worst_severity() >= threshold:
        print(f"\nFindings at or above {threshold.value}.", file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_access_review(args) -> int:
    cfg = load_config(args.config)
    audit = _audit_from_config(cfg)
    entitlements = ingest.load_entitlements(args.entitlements)
    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()

    summary = run_access_review(entitlements, as_of)
    audit.append("access_review", "completed", entitlements=summary.total,
                 privileged=summary.privileged, findings=len(summary.findings))

    print(f"Reviewed {summary.total} entitlements ({summary.privileged} privileged)")
    print(f"  Findings: {summary.by_severity() or 'none'}")
    for finding in summary.findings[: args.limit]:
        print(f"  [{finding.severity.value:<8}] {finding.subject:<34} {finding.title}")
    if len(summary.findings) > args.limit:
        print(f"  ... {len(summary.findings) - args.limit} more")

    threshold = Severity(cfg["assessment"]["fail_on"])
    worst = max((f.severity for f in summary.findings), default=Severity.INFO)
    return EXIT_FINDINGS if worst >= threshold else EXIT_OK


def cmd_sla_report(args) -> int:
    cfg = load_config(args.config)
    findings = ingest.load_findings(args.findings)
    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
    report = evaluate_sla(findings, as_of, _sla_table(cfg))

    print(f"SLA report as at {as_of.isoformat()}")
    print(f"  Tracked        : {len(report.records)}")
    print(f"  Compliance     : {report.compliance_rate:.1%}")
    print(f"  Breached       : {len(report.breached)}")
    print(f"  Approaching    : {len(report.approaching)}")
    print(f"  Mean days open : {report.mean_days_open()}")
    print(f"  Aging          : {report.aging_buckets()}")
    for rec in report.breached[: args.limit]:
        print(f"  BREACH {rec.finding_id:<16} {rec.severity.value:<8} "
              f"{abs(rec.days_remaining)} days overdue")
    return EXIT_FINDINGS if report.breached else EXIT_OK


def cmd_trend(args) -> int:
    cfg = load_config(args.config)
    audit = _audit_from_config(cfg)
    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()

    snapshots = trend.load_snapshots(audit)
    vendor_count = len({s.vendor_id for s in snapshots})
    report = trend.build_trend_report(snapshots, as_of)
    threshold = float(cfg["trend"]["regression_delta"])
    regressed = report.regressed(threshold)
    improved = report.improved()

    print(f"Trend analysis across {vendor_count} vendor(s), {len(snapshots)} snapshot(s) on record")
    if not report.trends:
        print("  Not enough history yet: each vendor needs at least two assess cycles.")
        return EXIT_OK

    print(f"  Regressed      : {len(regressed)}")
    print(f"  Improved       : {len(improved)}")
    print(f"  New findings   : {report.new_findings_by_severity() or 'none'}")
    print(f"  Resolved       : {report.resolved_count()}")

    for item in sorted(regressed, key=lambda t: -t.residual_delta)[: args.limit]:
        movement = (
            f"{item.tier_previous.value} to {item.tier_current.value}"
            if item.tier_worsened
            else "tier unchanged"
        )
        print(
            f"  REGRESSED {item.vendor_id:<14} residual {item.previous.residual_score:>6.2f} "
            f"to {item.current.residual_score:>6.2f} ({item.residual_delta:+.2f}, "
            f"{item.velocity:+.3f}/day)  {movement}"
        )

    if args.report:
        from .reporting import chart_risk_trend
        images_dir = Path(args.report) / "images"
        chart_path = chart_risk_trend(snapshots, images_dir, int(cfg["reporting"]["chart_dpi"]))
        print(f"\n  chart: {chart_path}")

    return EXIT_FINDINGS if regressed else EXIT_OK


def cmd_audit_verify(args) -> int:
    log = AuditLog(args.path)
    result = log.verify()
    if result.ok:
        print(f"Audit chain verified: {result.records} records intact"
              f"{' (keyed)' if log.keyed else ''}")
        return EXIT_OK
    print(f"Audit chain BROKEN at record {result.broken_at}: {result.reason}", file=sys.stderr)
    return EXIT_AUDIT


def cmd_audit_tail(args) -> int:
    for rec in AuditLog(args.path).tail(args.count):
        print(json.dumps(rec, sort_keys=True))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="assureops", description="Cyber assurance toolkit")
    parser.add_argument("--version", action="version", version=f"assureops {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = {"--config": {"default": None, "help": "path to assureops.yaml"}}

    p_val = sub.add_parser("validate", help="parse and validate configuration, then exit")
    p_val.add_argument("--config", **{k: v for k, v in common["--config"].items()})
    p_val.set_defaults(func=cmd_validate)

    p_as = sub.add_parser("assess", help="assess a vendor portfolio")
    p_as.add_argument("--config", default=None)
    p_as.add_argument("--vendors", required=True)
    p_as.add_argument("--answers", required=True)
    p_as.add_argument("--observations", default=None,
                      help="recorded posture observations as JSON")
    p_as.add_argument("--findings", default=None,
                      help="open findings register carried forward from prior cycles")
    p_as.add_argument("--report", default=None, help="directory to write the report into")
    p_as.add_argument("--no-charts", action="store_true")
    p_as.add_argument("--as-of", default=None, help="ISO date to assess as at")
    p_as.add_argument("--i-am-authorised", action="store_true",
                      help="confirm written permission exists to assess these targets")
    p_as.set_defaults(func=cmd_assess)

    p_ar = sub.add_parser("access-review", help="run an access recertification review")
    p_ar.add_argument("--config", default=None)
    p_ar.add_argument("--entitlements", required=True)
    p_ar.add_argument("--as-of", default=None)
    p_ar.add_argument("--limit", type=int, default=15)
    p_ar.set_defaults(func=cmd_access_review)

    p_sla = sub.add_parser("sla-report", help="report remediation SLA status")
    p_sla.add_argument("--config", default=None)
    p_sla.add_argument("--findings", required=True)
    p_sla.add_argument("--as-of", default=None)
    p_sla.add_argument("--limit", type=int, default=10)
    p_sla.set_defaults(func=cmd_sla_report)

    p_tr = sub.add_parser("trend", help="detect change in vendor risk since the last assess cycle")
    p_tr.add_argument("--config", default=None)
    p_tr.add_argument("--as-of", default=None)
    p_tr.add_argument("--limit", type=int, default=10)
    p_tr.add_argument("--report", default=None, help="directory to write the trend chart into")
    p_tr.set_defaults(func=cmd_trend)

    p_av = sub.add_parser("audit", help="inspect the audit trail")
    av_sub = p_av.add_subparsers(dest="audit_command", required=True)
    p_v = av_sub.add_parser("verify")
    p_v.add_argument("--path", required=True)
    p_v.set_defaults(func=cmd_audit_verify)
    p_t = av_sub.add_parser("tail")
    p_t.add_argument("--path", required=True)
    p_t.add_argument("--count", type=int, default=5)
    p_t.set_defaults(func=cmd_audit_tail)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, ValidationError, ScopeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except AuditChainError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_AUDIT
    except AssureOpsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":
    raise SystemExit(main())
