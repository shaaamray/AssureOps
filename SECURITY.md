# Security policy

## Authorised use only

AssureOps performs external checks against hosts you nominate. Running those
checks against infrastructure you do not own or have written permission to
assess may be unlawful in your jurisdiction.

Three controls make that difficult to do by accident:

1. **Explicit authorisation.** With `scope.require_authorisation` enabled,
   which is the default, no external check runs unless the operator passes
   `--i-am-authorised` on the command line.
2. **An allow list.** Only hosts listed under `scope.allow` are ever probed.
3. **A built in deny list.** A set of well known domains can never be
   assessed, regardless of configuration. This cannot be switched off.

Private, loopback and link local addresses are also refused unless
`scope.allow_private` is explicitly enabled.

## Handling of secrets

- Credentials are never written to the configuration file. The config names
  the environment variable to read; the value stays in the environment.
- The loader rejects credential shaped literals in the config file, so an
  accidental paste fails at startup rather than reaching a commit.
- Redaction runs on key name as well as value shape, because a strong password
  matches no pattern but still must never reach a log line.
- The audit trail is written through the same redaction filter.

## Audit integrity

The audit log is hash chained: each record carries the digest of the record
before it. Editing, deleting or reordering any line breaks the chain, and
`assureops audit verify` reports the sequence number where it broke.

Set `ASSUREOPS_AUDIT_HMAC_KEY` to make the chain keyed. An attacker who can
write to the log file but does not hold the key cannot forge a record that
verifies.

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue.
