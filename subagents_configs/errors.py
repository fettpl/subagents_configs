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


class PiPackageError(RuntimeError):
    """Raised with a stable, non-sensitive code for Pi package failures."""

    _CODES = frozenset(
        {
            "PI_CONSENT_REQUIRED",
            "PI_RUNTIME_INCOMPATIBLE",
            "PI_PACKAGE_CONFLICT",
            "PI_PACKAGE_COMMAND",
            "PI_RECEIPT_INVALID",
        }
    )

    def __init__(self, reason: str) -> None:
        if reason in self._CODES:
            code = reason
        elif "consent" in reason:
            code = "PI_CONSENT_REQUIRED"
        elif "runtime" in reason or "help probe" in reason:
            code = "PI_RUNTIME_INCOMPATIBLE"
        elif "receipt" in reason or "ownership" in reason:
            code = "PI_RECEIPT_INVALID"
        elif (
            "command" in reason
            or "timed out" in reason
            or "pipes" in reason
            or "cleanup" in reason
        ):
            code = "PI_PACKAGE_COMMAND"
        else:
            code = "PI_PACKAGE_CONFLICT"
        self.code = code
        super().__init__(code)
