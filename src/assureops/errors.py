"""Exception hierarchy.

Every failure mode gets a distinct type so the CLI can map them to stable
exit codes instead of guessing from a message string.
"""


class AssureOpsError(Exception):
    """Base class for every error raised by this package."""


class ConfigError(AssureOpsError):
    """Configuration is missing, malformed, or contains an unknown key."""


class ValidationError(AssureOpsError):
    """A supplied value failed validation before it reached any side effect."""


class ScopeError(AssureOpsError):
    """A target was rejected by the authorisation scope guard."""


class AuditChainError(AssureOpsError):
    """The audit hash chain failed verification."""


class FrameworkError(AssureOpsError):
    """A control framework reference could not be resolved."""
