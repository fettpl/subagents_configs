#!/usr/bin/env python3
"""Public entrypoint for the separately authorized Pi provider smoke."""

import sys
from pathlib import Path

_REPOSITORY = Path(__file__).resolve().parents[1]
if str(_REPOSITORY) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY))

from scripts.run_pi_provider_smoke import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
