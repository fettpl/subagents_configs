#!/usr/bin/env python3
"""Validate all native role catalogs and project policy sources."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from subagents_configs.formats import validate_all_catalogs  # noqa: E402

_GENERATOR_PATH = REPO_ROOT / "scripts/generate-catalogs.py"
_GENERATOR_SPEC = importlib.util.spec_from_file_location(
    "generate_catalogs", _GENERATOR_PATH
)
if _GENERATOR_SPEC is None or _GENERATOR_SPEC.loader is None:
    raise RuntimeError("catalog generator is unavailable")
_GENERATOR = importlib.util.module_from_spec(_GENERATOR_SPEC)
_GENERATOR_SPEC.loader.exec_module(_GENERATOR)


def main() -> int:
    try:
        validate_all_catalogs(REPO_ROOT)
        if _GENERATOR.main(["--check"]) != 0:
            raise ValueError("generated catalogs are not reproducible")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"catalog validation failed: {exc}", file=sys.stderr)
        return 1
    print("catalog validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
