# Architecture

## Shape of a run

```
                 ┌──────────────┐
config.yaml ────▶│    Config    │  strict validation, env interpolation,
                 └──────┬───────┘  credential shaped literals rejected
                        ▼
      vendors.csv ─┐
      answers.csv ─┼──▶ Ingest ──▶ typed models (validated on construction)
 entitlements.csv ─┘                      │
                                          ▼
                              ┌───────────────────────┐
                              │      ScopeGuard       │ allow list, hard deny
                              │  (every probe passes  │ list, protected ranges,
                              │   through this gate)  │ explicit authorisation
                              └───────────┬───────────┘
                                          ▼
   ┌──────────────┬───────────────────────┴─────────┬──────────────────┐
   ▼              ▼                                 ▼                  ▼
Questionnaire  Posture probe                  Access review        SLA clock
 weighted      TLS, cert, headers             dormancy, MFA,       windows by
 scoring       (pluggable prober)             SoD, orphaned        severity
   │              │                                 │                  │
   └──────┬───────┘                                 │                  │
          ▼                                         │                  │
    Risk engine ──▶ findings ────────────────────────┴──────────────────┘
    impact x likelihood            each mapped to ISO 27001 Annex A
          │                                    │
          ▼                                    ▼
   Markdown report + charts          Hash chained audit log
```

## Design decisions worth calling out

**The scope guard is not optional.** `assess_host` takes a guard as a required
argument and calls `check` before the prober is invoked. There is no code path
that reaches the network without passing the gate, and the test suite asserts
it. The hard deny list is a module level constant that no configuration key
can reach.

**The prober is a seam, not a dependency.** `posture.py` accepts any callable
returning an `Observation`. In production that wraps a real handshake and HTTP
request; in tests it is a plain function returning canned data. This is what
makes full posture coverage possible in CI with no network access and no
third party consent required.

**Out of scope is an outcome, not a crash.** When a vendor's domain is not on
the allow list, the assessment continues without posture evidence and records
a `suppressed` entry in the audit trail. Assurance work should degrade
gracefully; a single out of scope domain must not abort a portfolio run.

**Validation happens on construction.** `Vendor`, `Entitlement` and `Finding`
validate in `__post_init__` and are frozen. An invalid object cannot exist
far enough down the pipeline to reach a report.

**Severity ordering is explicit.** `Severity` subclasses `str` so it
serialises cleanly to JSON and CSV, but that means the inherited comparisons
would order it alphabetically, putting `critical` below `low`. All four
comparison operators are overridden against a rank table, because severity
ordering drives SLA windows and the CI failure gate.

**Suppressed decisions are audited.** Knowing that the scope guard refused a
probe is as valuable during a review as knowing that one ran.

**One path from observation to action.** Everything a run learns becomes a
typed `Finding`, and only findings drive risk scoring, SLA tracking and
reporting. There is a single place to audit how an observation became a
number.

**Tier comparisons are explicit too.** `RiskTier` has the exact same problem
`Severity` did before its comparison operators were overridden: it subclasses
`str`, so `"critical" < "high"` alphabetically. `trend.py` never compares
`RiskTier` values directly. It looks them up in an explicit rank table, the
same fix applied for the same reason.

## Continuous monitoring

A single `assess` run answers "how risky is this vendor right now." It has no
opinion on whether that is better or worse than last time, because it never
sees last time. `trend.py` exists to answer the second question without
requiring a second thing to operate and secure.

**Snapshots are audit records, not a parallel file.** Every `assess` cycle
already writes to `AuditLog` when `trend.enabled` is true. Rather than invent
a `SnapshotStore` with its own file format and its own integrity story, a
snapshot is written as an ordinary record with `action="trend_snapshot"`.
`trend.load_snapshots` reads them back by filtering `audit.records()`. This
was the deciding design choice in this module: a parallel store would need
its own hash chain to make the same tamper evidence claim the rest of the
tool already makes, and would need its own answer to "what happens if this
file and the audit log disagree." Reusing the audit log makes that question
not arise. Editing a snapshot to hide a regression breaks the same chain that
editing a finding would.

**Grouping snapshots by vendor is a single sort, not a filter per vendor.**
`compute_trends` sorts the full snapshot list once by `(vendor_id, as_of)`,
an O(n log n) operation, then walks it in one linear pass to group consecutive
entries into per vendor histories. The alternative — for each distinct vendor,
filter the whole snapshot list for that vendor's entries — is O(n × v) for v
vendors, and a monitoring history is exactly the kind of data that keeps
growing in both dimensions: more vendors over time, and more snapshots per
vendor the longer the tool has been running.

**A trend is data; a regression is policy.** `compute_trends` returns plain
`VendorTrend` facts: the delta, the tier movement, which findings are new or
resolved. Nothing in that step decides whether a given delta counts as bad
enough to act on. `TrendReport.regressed(threshold)` applies
`trend.regression_delta` from configuration afterwards, the same separation
`risk.py` keeps between the raw score and the tier band it falls into.

**Velocity, not just delta.** `VendorTrend.velocity` divides the residual
delta by the number of days between snapshots. A vendor whose score rose by
six points in five days and one whose score rose by six points in five months
are not the same problem, and a bare delta cannot tell them apart.

## Exit codes

Stable, so the same binary works interactively and as a pipeline gate.

| Code | Meaning |
| ---: | --- |
| 0 | Success, nothing at or above the failure severity |
| 1 | Runtime error |
| 2 | Findings at or above `assessment.fail_on`, or a vendor regression at or above `trend.regression_delta` |
| 3 | Configuration, validation or scope error |
| 4 | Audit verification failed |
