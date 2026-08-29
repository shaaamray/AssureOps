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

## Exit codes

Stable, so the same binary works interactively and as a pipeline gate.

| Code | Meaning |
| ---: | --- |
| 0 | Success, nothing at or above the failure severity |
| 1 | Runtime error |
| 2 | Findings at or above `assessment.fail_on` |
| 3 | Configuration, validation or scope error |
| 4 | Audit verification failed |
