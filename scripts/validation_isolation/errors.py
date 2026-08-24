"""Errors raised by validation-isolation preparation."""


class ValidationIsolationError(ValueError, RuntimeError):
    """A source, destination, Git, or environment trust check failed."""


class UnsafePathError(ValidationIsolationError):
    """A path is not safe to inspect or use in the isolated helper."""


class GitSnapshotError(ValidationIsolationError):
    """Git inventory or snapshot creation failed closed."""


class EnvironmentBuildError(ValidationIsolationError):
    """The exact child environment could not be built safely."""
