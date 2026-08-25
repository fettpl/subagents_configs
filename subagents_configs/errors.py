"""Exception types used internally by the trusted orchestration seams.

Exception messages are implementation data only.  The command-line boundary
maps exception classes to typed diagnostics and never renders their text.
"""


class CliError(ValueError):
    """Raised when command-line arguments cannot form a valid request."""


class ValidationBlockedError(ValueError, RuntimeError):
    """Raised when source or validation-runtime checks block an operation."""


class TransactionError(RuntimeError):
    """Base class for failures while applying or recovering a transaction."""
