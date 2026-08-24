#!/usr/bin/env python3
"""Thin entry point for fail-closed isolated validation."""

import sys

if sys.version_info < (3, 11):  # noqa: UP036 - guard runs before implementation import
    print(
        "validation helper requires Python 3.11 or newer",
        file=sys.stderr,
    )
    raise SystemExit(1)

from validation_isolation.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
