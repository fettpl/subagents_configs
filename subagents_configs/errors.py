class CliError(ValueError):
    """Raised when command-line arguments cannot form a valid request."""


class ValidationBlockedError(ValueError, RuntimeError):
    """Raised when source or validation-runtime checks block an operation."""


class TransactionError(RuntimeError):
    """Base class for failures while applying or recovering a transaction."""
