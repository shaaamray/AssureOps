# Contributing

## Getting set up

```bash
git clone https://github.com/shaaamray/AssureOps.git
cd AssureOps
make dev
make test
```

## Before opening a pull request

```bash
make all      # ruff, bandit and the full suite with coverage
```

Coverage must not fall below 95%.

## Conventions

- Every rule that produces a finding maps to a real ISO/IEC 27001:2022
  Annex A control. If you add a rule, add the mapping and a test that
  resolves it.
- Anything that reaches the network goes through `ScopeGuard.check` first.
  There are no exceptions to this, and the tests assert it.
- New tests must run offline. Use the pluggable prober seam rather than
  making a real request.
- Validate inputs before they reach a side effect, and raise the specific
  exception type from `errors.py` so the CLI maps it to the right exit code.
