# Risk methodology

A risk score that cannot be explained to an auditor, a vendor or a risk
committee is not useful. This document states every weight and threshold the
engine uses, and the reasoning behind each one.

## The model

```
impact       = f(data sensitivity, business criticality)          1 to 5
likelihood   = 1 + 4 x (1 - control_effectiveness)                1 to 5
inherent     = impact x 5                                         5 to 25
residual     = impact x likelihood                                1 to 25
tier         = band(residual)
```

Inherent risk assumes worst case likelihood, so it represents the exposure if
the third party had no effective controls at all. Residual risk is what remains
once measured control effectiveness is credited.

## Impact

Impact is driven by the sensitivity of the data the third party can reach,
because that is what determines the consequence of a breach at that vendor.

| Data classification | Base impact |
| --- | ---: |
| Restricted | 5 |
| Confidential | 4 |
| Internal | 2 |
| Public | 1 |

A vendor supporting a business critical process is uplifted by one band,
capped at 5. A vendor holding only public data but running a critical process
still carries real availability risk, which is what the uplift represents.

## Control effectiveness

Two sources of evidence, deliberately weighted differently:

| Source | Weight | Why |
| --- | ---: | --- |
| Questionnaire | 0.65 | Covers far more ground: governance, resilience, people, incident response |
| External posture | 0.35 | Weighted heavily for its narrow scope, because it is observed evidence rather than a claim |

**Attestation alone is capped at 0.85.** When no posture evidence exists, the
questionnaire score is multiplied by 0.85, so a vendor can never reach full
effectiveness on self attestation. This is the single most important
assumption in the model: a supplier telling you their controls are good is
weaker assurance than seeing it, and the arithmetic should say so.

### Finding penalties

Open findings suppress measured effectiveness, because a control that is
documented but demonstrably failing is not effective.

| Severity | Penalty |
| --- | ---: |
| Critical | 0.30 |
| High | 0.18 |
| Medium | 0.08 |
| Low | 0.03 |
| Info | 0.00 |

Penalties accumulate but are **capped at 0.60**. Without the cap, a long tail
of low severity findings would drive effectiveness to zero and make a
moderately weak vendor indistinguishable from one with no controls at all.
That would destroy the signal exactly where prioritisation matters most.

## Likelihood floor

Likelihood bottoms out at 1, never 0. No control set is complete, no
questionnaire covers everything, and residual likelihood of zero would imply
certainty that nothing can go wrong. A model that can output zero risk invites
misplaced confidence.

## Residual risk bands

| Residual score | Tier |
| --- | --- |
| 15.0 and above | Critical |
| 9.0 to 14.9 | High |
| 4.0 to 8.9 | Medium |
| below 4.0 | Low |

## Remediation SLA windows

| Severity | Days to remediate |
| --- | ---: |
| Critical | 7 |
| High | 30 |
| Medium | 90 |
| Low | 180 |

A finding is flagged as approaching breach once 80% of its window has elapsed,
which gives an owner time to act before the clock runs out rather than
reporting the breach after the fact.

## Known limitations

Worth stating plainly, because a methodology document that only lists
strengths is not credible.

- **The ISO to CSF mapping is one to one.** Real controls support several CSF
  functions. The simplification is defensible for reporting coverage by
  function, but it is a simplification.
- **Questionnaire responses are unverified.** Nothing here validates that a
  vendor answering "yes" is telling the truth. That is what evidence requests
  and audit rights are for, and they sit outside this tool.
- **Posture checks cover the public edge only.** A clean TLS configuration and
  a full set of security headers say nothing about what happens inside the
  vendor's estate.
- **Weights are judgement, not measurement.** They are calibrated to be
  defensible and are held in one place so they can be argued with, adjusted
  and version controlled, which is the honest position for any scoring model
  of this kind.
