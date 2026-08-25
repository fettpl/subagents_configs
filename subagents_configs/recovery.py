"""Journal-group recovery public seam."""

from collections.abc import Mapping
from pathlib import Path

from .locks import locked_target_homes
from .models import Target
from .targets import DESCRIPTOR_ORDER


def recover_transaction(
    homes: Mapping[Target, Path], targets: tuple[Target, ...]
) -> None:
    """Recover exactly the requested participant set under canonical locks."""
    if not isinstance(homes, Mapping) or not isinstance(targets, tuple) or not targets:
        raise ValueError("recovery requires participant homes and targets")
    if tuple(target for target in DESCRIPTOR_ORDER if target in targets) != targets:
        raise ValueError("recovery targets must use canonical registry order")
    if set(homes) != set(targets):
        raise ValueError("recovery homes must exactly match targets")
    if any(
        not isinstance(target, Target) or not isinstance(home, Path)
        for target, home in homes.items()
    ):
        raise ValueError("recovery participant mapping is invalid")
    from .transaction import recover_participants

    with locked_target_homes(homes, targets):
        recover_participants(homes)


__all__ = ["recover_transaction"]
