#!/usr/bin/env python3
"""Render deterministic, metadata-only normalized target catalogs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from subagents_configs.formats import (  # noqa: E402
    ROLE_POLICY,
    validate_source_inventory,
)
from subagents_configs.models import Target  # noqa: E402
from subagents_configs.targets import (  # noqa: E402
    CAPABILITIES,
    descriptor_for,
    selected_sources,
)


def _hash(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _native_specs(target: Target):
    return tuple(
        spec
        for spec in selected_sources(descriptor_for(target), include_commit_pusher=True)
        if spec.kind in {"agent", "routing-source", "project-template", "command-gate"}
    )


def render_catalog(root: Path, target: Target) -> bytes:
    capability = next(item for item in CAPABILITIES if item.target is target)
    validated = validate_source_inventory(
        root, target, _native_specs(target), require_commit_pusher=True
    )
    sources: list[dict[str, object]] = []
    roles: list[dict[str, object]] = []
    for item in validated:
        spec = item.spec
        record: dict[str, object] = {
            "identifier": spec.identifier,
            "source": spec.source.as_posix(),
            "destination": spec.destination.as_posix() if spec.destination else None,
            "kind": spec.kind,
            "source_format": spec.source_format,
            "optional_role": spec.optional_role,
            "sha256": item.sha256,
        }
        sources.append(record)
        if spec.kind == "agent":
            overlay = ROLE_POLICY[target.value][spec.identifier]["overlay"]
            roles.append(
                {
                    "identifier": spec.identifier,
                    "source": spec.source.as_posix(),
                    "destination": spec.destination.as_posix()
                    if spec.destination
                    else None,
                    "optional": spec.optional_role is not None,
                    "contract": {
                        "optional": ROLE_POLICY[target.value][spec.identifier][
                            "optional"
                        ],
                        "read_only": ROLE_POLICY[target.value][spec.identifier][
                            "read_only"
                        ],
                    },
                    "overlay": overlay,
                    "policy_sha256": _hash(overlay),
                }
            )
    sources.sort(key=lambda item: (str(item["kind"]), str(item["identifier"])))
    roles.sort(key=lambda item: str(item["identifier"]))
    policy_hash = _hash({"roles": roles, "shared": ROLE_POLICY})
    body: dict[str, Any] = {
        "schema_version": 1,
        "target": target.value,
        "order": capability.order,
        "include_in_all": capability.include_in_all,
        "agent_directory": capability.agent_directory.as_posix(),
        "source_format": capability.source_format,
        "parser": capability.parser,
        "semantic_validator": capability.semantic_validator,
        "global_instruction": {
            "block_id": capability.global_instruction.block_id,
            "filename": capability.global_instruction.filename.as_posix(),
            "source": capability.global_instruction.source.as_posix(),
        },
        "optional_blocks": [
            {
                "block_id": item.block_id,
                "relative_path": item.relative_path.as_posix(),
                "source": item.source.as_posix() if item.source else None,
            }
            for item in capability.optional_blocks
        ],
        "lifecycle_capabilities": sorted(capability.lifecycle_capabilities),
        "external_lifecycle": None,
        "roles": roles,
        "sources": sources,
        "policy_sha256": policy_hash,
        "source_sha256": _hash(sources),
    }
    body["catalog_sha256"] = _hash(body)
    return (
        json.dumps(body, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--target", choices=[item.target.value for item in CAPABILITIES]
    )
    args = parser.parse_args(argv)
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    targets = (
        [Target(args.target)] if args.target else [item.target for item in CAPABILITIES]
    )
    catalog_dir = ROOT / "catalogs"
    if args.write:
        catalog_dir.mkdir(mode=0o755, exist_ok=True)
    ok = True
    for target in targets:
        rendered = render_catalog(ROOT, target)
        destination = catalog_dir / f"{target.value}.json"
        if args.write:
            destination.write_bytes(rendered)
        elif not destination.exists() or destination.read_bytes() != rendered:
            print(f"catalog drift: {destination}", file=sys.stderr)
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
