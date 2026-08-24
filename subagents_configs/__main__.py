"""Module entry point for the installer command."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .orchestrator import run


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("error: operation is required (install or uninstall)\n")
        return 2
    operation = sys.argv[1]
    return run(
        operation,
        sys.argv[2:],
        repo_root=Path(__file__).resolve().parents[1],
        environ=os.environ,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
