"""Python entry point used by the fixed POSIX wrappers."""

# The guarded import order is intentional: this script is also parsed by old
# Python versions, which must fail before the engine package is imported.
# ruff: noqa: UP036

import os
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    sys.stderr.write("error: Python 3.11 or newer is required\n")
    raise SystemExit(2)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("error: operation is required (install or uninstall)\n")
        return 2
    operation = sys.argv[1]
    if operation == "policy-diff":
        from subagents_configs.catalog_policy import run_policy_diff

        try:
            sys.stdout.write(run_policy_diff(sys.argv[2:]))
        except Exception:
            sys.stderr.write("error: policy-diff rejected\n")
            return 2
        return 0
    from subagents_configs.orchestrator import run

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
