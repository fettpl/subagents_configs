#!/usr/bin/env python3
"""Run the mandatory release smoke against the caller-supplied Pi binary."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_REPOSITORY = Path(__file__).resolve().parents[1]
if str(_REPOSITORY) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY))

from scripts.run_pi_provider_smoke import _private_output  # noqa: E402
from subagents_configs import filesystem  # noqa: E402
from subagents_configs.compatibility import (  # noqa: E402
    pi_release_transition_allowed,
    release_evidence_record,
    validate_pi_release_evidence,
)
from subagents_configs.errors import TransactionError  # noqa: E402
from tests.pi_smoke_support import (  # noqa: E402
    build_release_evidence,
    select_pi_executable,
)


def main() -> int:
    if "PI_EXECUTABLE" not in os.environ:
        print("PI_EXECUTABLE_UNAVAILABLE")
        return 2
    if "PI_SMOKE_ROOT" not in os.environ:
        print("PI_SMOKE_ROOT_UNAVAILABLE")
        return 2
    if "PI_RELEASE_EVIDENCE_OUTPUT" not in os.environ:
        print("PI_RELEASE_EVIDENCE_UNAVAILABLE")
        return 2
    if "PI_RELEASE_BACKEND" not in os.environ:
        print("PI_RELEASE_BACKEND_UNAVAILABLE")
        return 2
    supplied = os.environ["PI_EXECUTABLE"]
    executable = Path(supplied)
    smoke_root = Path(os.environ["PI_SMOKE_ROOT"])
    backend = os.environ["PI_RELEASE_BACKEND"]
    try:
        safe_output = _private_output(Path(os.environ["PI_RELEASE_EVIDENCE_OUTPUT"]))
        evidence = select_pi_executable(executable, smoke_root, release=True)
        if evidence.status != "ok" or evidence.version != "0.84.1":
            raise ValueError("PI_RELEASE_SMOKE_FAILED")
        raw_record = build_release_evidence(
            executable, smoke_root, evidence, backend=backend
        )
        validated = validate_pi_release_evidence(raw_record)
        if not pi_release_transition_allowed(validated, all_gates_passed=True):
            raise ValueError("PI_RELEASE_EVIDENCE_INVALID")
        record = release_evidence_record(validated)
        payload = (
            json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        with filesystem.expected_atomic_identity(None):
            filesystem.atomic_write(safe_output, payload, mode=0o600)
    except (OSError, TypeError, ValueError, TransactionError):
        print("PI_RELEASE_SMOKE_FAILED")
        return 2
    print(json.dumps(record, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
