"""Typed, stable diagnostics for command-line failures.

Diagnostic rendering deliberately has no exception or environment input.  All
values that can reach the renderer are reduced to the small vocabulary below;
in particular, home paths become ordinal labels rather than user-controlled
paths.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TextIO


class DiagnosticCode(enum.StrEnum):
    CLI_INVALID = "CLI_INVALID"
    PREFLIGHT_REJECTED = "PREFLIGHT_REJECTED"
    PREFLIGHT_CONCURRENT_CHANGE = "PREFLIGHT_CONCURRENT_CHANGE"
    VALIDATION_BLOCKED = "VALIDATION_BLOCKED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    RECOVERY_INCOMPLETE = "RECOVERY_INCOMPLETE"
    APPLY_ROLLED_BACK = "APPLY_ROLLED_BACK"
    APPLY_AMBIGUOUS = "APPLY_AMBIGUOUS"
    MANAGED_CONFLICT = "MANAGED_CONFLICT"
    UNRESOLVED_UNINSTALL = "UNRESOLVED_UNINSTALL"
    OUTPUT_FAILED = "OUTPUT_FAILED"


_TARGET_ORDER = {"codex": 0, "opencode": 1, "claude-code": 2}
_OPERATIONS = frozenset(("install", "uninstall"))
_PHASES = frozenset(("cli", "recovery", "validation", "preflight", "apply", "output"))
_STATUSES = frozenset(
    (
        "invalid",
        "blocked",
        "rejected",
        "required",
        "incomplete",
        "rolled-back",
        "ambiguous",
        "conflict",
        "unresolved",
        "failed",
    )
)
_COMPATIBILITY_REASONS = frozenset(
    {
        "target_unsupported",
        "format_unsupported",
        "feature_unsupported",
        "platform_unsupported",
        "scope_unsupported",
        "package_unsupported",
        "client_version_too_old",
    }
)


@dataclass(frozen=True)
class SafeContext:
    """The only context permitted in a rendered diagnostic."""

    targets: tuple[str, ...]
    homes: tuple[str, ...]
    operation: str
    phase: str
    status: str

    def __post_init__(self) -> None:
        if type(self.targets) is not tuple or any(
            type(target) is not str for target in self.targets
        ):
            raise TypeError("diagnostic targets must be a tuple of strings")
        if type(self.homes) is not tuple or any(
            type(home) is not str for home in self.homes
        ):
            raise TypeError("diagnostic homes must be a tuple of strings")
        for value in (self.operation, self.phase, self.status):
            if type(value) is not str:
                raise TypeError("diagnostic context fields must be strings")


@dataclass(frozen=True)
class Diagnostic:
    code: DiagnosticCode
    context: SafeContext

    def __post_init__(self) -> None:
        if not isinstance(self.code, DiagnosticCode):
            raise TypeError("diagnostic code must be a DiagnosticCode")
        if type(self.context) is not SafeContext:
            raise TypeError("diagnostic context must be SafeContext")


def _safe_targets(targets: tuple[str, ...]) -> str:
    known = {target for target in targets if target in _TARGET_ORDER}
    if any(target not in _TARGET_ORDER for target in targets):
        known.add("unknown")
    ordered = sorted(known, key=lambda target: (_TARGET_ORDER.get(target, 99), target))
    return ",".join(ordered) if ordered else "none"


def _safe_homes(homes: tuple[str, ...]) -> str:
    return ",".join(f"home-{index}" for index in range(1, len(homes) + 1)) or "none"


def _safe_field(value: str, allowed: frozenset[str]) -> str:
    return value if value in allowed else "unknown"


def render_diagnostic(diagnostic: Diagnostic) -> str:
    """Render one fixed, newline-terminated diagnostic line."""

    if type(diagnostic) is not Diagnostic:
        raise TypeError("renderer accepts Diagnostic only")
    context = diagnostic.context
    operation = _safe_field(context.operation, _OPERATIONS)
    phase = _safe_field(context.phase, _PHASES)
    status = _safe_field(context.status, _STATUSES)
    return (
        f"error: code={diagnostic.code.value} targets={_safe_targets(context.targets)} "
        f"homes={_safe_homes(context.homes)} operation={operation} phase={phase} "
        f"status={status}\n"
    )


def emit_diagnostic(
    stderr: TextIO,
    code: DiagnosticCode,
    targets: tuple[str, ...],
    homes: tuple[str, ...],
    operation: str,
    phase: str,
    status: str,
    reasons: tuple[str, ...] = (),
) -> bool:
    """Render and write a diagnostic without accepting exception data."""

    try:
        diagnostic = Diagnostic(
            code,
            SafeContext(
                targets=tuple(targets),
                homes=tuple(homes),
                operation=operation,
                phase=phase,
                status=status,
            ),
        )
        if any(reason not in _COMPATIBILITY_REASONS for reason in reasons):
            return False
        rendered = render_diagnostic(diagnostic)
        if reasons:
            rendered = rendered[:-1] + f" reasons={','.join(reasons)}\n"
        stderr.write(rendered)
    except Exception:
        return False
    return True
