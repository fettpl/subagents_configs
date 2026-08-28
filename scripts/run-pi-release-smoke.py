#!/usr/bin/env python3
"""Run the mandatory release smoke against the caller-supplied Pi binary."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_REPOSITORY = Path(__file__).resolve().parents[1]
if str(_REPOSITORY) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY))

from tests.pi_smoke_support import select_pi_executable  # noqa: E402


def main() -> int:
    if "PI_EXECUTABLE" not in os.environ:
        print("PI_EXECUTABLE_UNAVAILABLE")
        return 2
    if "PI_SMOKE_ROOT" not in os.environ:
        print("PI_SMOKE_ROOT_UNAVAILABLE")
        return 2
    supplied = os.environ["PI_EXECUTABLE"]
    executable = Path(supplied)
    smoke_root = Path(os.environ["PI_SMOKE_ROOT"])
    try:
        evidence = select_pi_executable(executable, smoke_root, release=True)
    except (OSError, TypeError, ValueError):
        print("PI_RELEASE_SMOKE_FAILED")
        return 2
    if evidence.status != "ok" or evidence.version != "0.84.1":
        print("PI_RELEASE_SMOKE_FAILED")
        return 2
    print("PI_RELEASE_SMOKE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
