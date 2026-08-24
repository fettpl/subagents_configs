"""Python entry point used by the fixed POSIX wrappers."""

# The guarded import order is intentional: this script is also parsed by old
# Python versions, which must fail before the engine package is imported.
# ruff: noqa: E402, UP036

import os
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    sys.stderr.write("error: Python 3.11 or newer is required\n")
    raise SystemExit(2)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from subagents_configs.orchestrator import run


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("error: operation is required (install or uninstall)\n")
        return 2
    return run(
        sys.argv[1],
        sys.argv[2:],
        repo_root=REPOSITORY_ROOT,
        environ=os.environ,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
