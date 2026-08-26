"""Module entry point for the installer command."""

from __future__ import annotations

import os
import sys


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("error: operation is required (install or uninstall)\n")
        return 2
    operation = sys.argv[1]
    if operation == "policy-diff":
        from .catalog_policy import run_policy_diff

        try:
            sys.stdout.write(run_policy_diff(sys.argv[2:]))
        except Exception:
            sys.stderr.write("error: policy-diff rejected\n")
            return 2
        return 0
    from pathlib import Path

    from .orchestrator import run

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
