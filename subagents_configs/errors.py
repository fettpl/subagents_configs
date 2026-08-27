"""Exception types used internally by the trusted orchestration seams.

Exception messages are implementation data only.  The command-line boundary
maps exception classes to typed diagnostics and never renders their text.
"""

from __future__ import annotations

import re
from collections.abc import Mapping


class CliError(ValueError):
    """Raised when command-line arguments cannot form a valid request."""


class ValidationBlockedError(ValueError, RuntimeError):
    """Raised when source or validation-runtime checks block an operation."""


class TransactionError(RuntimeError):
    """Base class for failures while applying or recovering a transaction."""


class PiPackageError(ValueError, RuntimeError):
    """Raised with a stable, non-sensitive code for Pi package failures."""

    _CODES = frozenset(
        {
            "PI_CONSENT_REQUIRED",
            "PI_EXECUTABLE_INVALID",
            "PI_RUNTIME_INCOMPATIBLE",
            "PI_SETTINGS_INVALID",
            "PI_PACKAGE_DRIFT",
            "PI_PACKAGE_CONFLICT",
            "PI_PACKAGE_COMMAND",
            "PI_RECEIPT_INVALID",
            "PI_CATALOG_CONFLICT",
            "PI_PACKAGE_PHASE_FAILED",
            "PI_CATALOG_PHASE_FAILED",
            "PI_UNINSTALL_PRESERVED",
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


_PI_CODES = frozenset(
    {
        "PI_CONSENT_REQUIRED",
        "PI_EXECUTABLE_INVALID",
        "PI_RUNTIME_INCOMPATIBLE",
        "PI_SETTINGS_INVALID",
        "PI_PACKAGE_DRIFT",
        "PI_RECEIPT_INVALID",
        "PI_CATALOG_CONFLICT",
        "PI_PACKAGE_PHASE_FAILED",
        "PI_CATALOG_PHASE_FAILED",
        "PI_UNINSTALL_PRESERVED",
    }
)
_PI_PHASES = frozenset({"preflight", "runtime", "package", "catalog", "recovery"})
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")


def sanitize_pi_context(
    code: str,
    *,
    target: str,
    phase: str,
    safe_identifier: str,
    normalized_home: str,
) -> Mapping[str, str]:
    """Return only fixed, non-sensitive context for a Pi diagnostic.

    The caller supplies already-normalized values, but this boundary still
    rejects unexpected vocabularies and strips anything that could carry a
    private path, exception, or child-process transcript.
    """

    if code not in _PI_CODES:
        raise ValueError("unknown Pi diagnostic code")
    if target != "pi" or phase not in _PI_PHASES:
        raise ValueError("invalid Pi diagnostic context")
    if (
        type(safe_identifier) is not str
        or _SAFE_IDENTIFIER.fullmatch(safe_identifier) is None
    ):
        safe_identifier = "unknown"
    if type(normalized_home) is not str or not normalized_home:
        raise ValueError("normalized Pi home is required")
    # Homes are represented by a fixed ordinal label at the renderer boundary;
    # accepting only that form prevents accidental private path disclosure.
    if not re.fullmatch(r"home-[1-9][0-9]*", normalized_home):
        normalized_home = "home-1"
    return {
        "target": "pi",
        "phase": phase,
        "identifier": safe_identifier,
        "home": normalized_home,
    }
