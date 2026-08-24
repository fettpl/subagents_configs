#!/usr/bin/env python3
"""Validate all native role catalogs and project policy sources."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from subagents_configs.formats import validate_all_catalogs  # noqa: E402


def main() -> int:
    try:
        validate_all_catalogs(REPO_ROOT)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"catalog validation failed: {exc}", file=sys.stderr)
        return 1
    print("catalog validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
