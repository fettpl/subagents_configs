"""Read-only, deterministic install and uninstall planning."""

from __future__ import annotations

import hashlib
import os
import stat
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from . import filesystem
from .blocks import _markers, _scan, insert_or_replace_block, remove_exact_block
from .errors import ValidationBlockedError
from .formats import (
    ValidatedSource,
    validate_rendered_agent,
    validate_source_inventory,
    validate_validation_helper,
)
from .models import (
    ManagedBlock,
    Manifest,
    ManifestEntry,
    Ownership,
    Request,
    Target,
)
from .paths import (
    assert_contained,
    assert_safe_home,
    assert_safe_managed_path,
    lstat_existing,
    normalized_absolute,
)
from .state import encode_manifest, load_journal, load_manifest
from .targets import DESCRIPTOR_ORDER, descriptor_for, selected_sources


@dataclass(frozen=True)
class PlannedOperation:
    target: Target
    identifier: str
    action: Literal[
        "create",
        "replace",
        "remove",
        "restore",
        "write-block",
        "remove-block",
        "write-manifest",
    ]
    relative_path: str
    expected_before_hash: str | None
    expected_after_hash: str | None
    expected_before_mode: int | None
    expected_after_mode: int | None
    content: bytes | None
    ownership: Ownership | None
    backup_required: bool
    managed_block_id: str | None
    expected_before_evidence: object | None = None
    expected_after_evidence: object | None = None


@dataclass(frozen=True)
class TargetPlan:
    target: Target
    home: Path
    operations: tuple[PlannedOperation, ...]
    resulting_manifest: Manifest | None
    conflicts: tuple[str, ...]


@dataclass(frozen=True)
class TransactionPlan:
    operation: Literal["install", "uninstall"]
    targets: tuple[TargetPlan, ...]


_LEGACY_STATE_NAMES = {
    Target.CODEX: ".subagents_configs-state.json",
    Target.OPENCODE: ".subagents_configs-opencode-state.json",
    Target.CLAUDE_CODE: ".subagents_configs-claude-code-state.json",
}


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _path(home: Path, relative: str) -> Path:
    candidate = normalized_absolute(home / Path(relative))
    assert_contained(home, candidate)
    return candidate


def _read_regular(path: Path, label: str) -> tuple[bytes, int]:
    result = lstat_existing(path, label)
    if result is None:
        raise FileNotFoundError(path)
    if not stat.S_ISREG(result.st_mode):
        raise ValueError(f"{label} must be a regular file: {path}")
    descriptor = filesystem._open_regular_read(path, label)
    chunks: list[bytes] = []
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks), stat.S_IMODE(result.st_mode)


def _safe_destination(home: Path, relative: str, label: str) -> Path:
    destination = _path(home, relative)
    assert_safe_managed_path(home, destination, label)
    return destination


def _backup_name(identifier: str, before_hash: str) -> str:
    value = hashlib.sha256(f"{identifier}:{before_hash}".encode()).hexdigest()
    return f"backups/{value}"


def _entry_for_file(
    identifier: str,
    relative_path: str,
    content: bytes,
    mode: int,
    ownership: Ownership,
    *,
    backup_path: str | None = None,
    backup_hash: str | None = None,
    original_mode: int | None = None,
    unresolved_reason: str | None = None,
) -> ManifestEntry:
    return ManifestEntry(
        identifier=identifier,
        relative_path=relative_path,
        installed_hash=_digest(content),
        installed_mode=mode,
        ownership=ownership,
        backup_path=backup_path,
        backup_hash=backup_hash,
        original_mode=original_mode,
        managed_block_id=None,
        installed_block_hash=None,
        unresolved_reason=unresolved_reason,
    )


def _entry_for_block(
    identifier: str,
    relative_path: str,
    content: bytes,
    mode: int,
    ownership: Ownership,
    block_hash: str,
    *,
    backup_path: str | None = None,
    backup_hash: str | None = None,
    original_mode: int | None = None,
    unresolved_reason: str | None = None,
) -> ManifestEntry:
    return ManifestEntry(
        identifier=identifier,
        relative_path=relative_path,
        installed_hash=_digest(content),
        installed_mode=mode,
        ownership=ownership,
        backup_path=backup_path,
        backup_hash=backup_hash,
        original_mode=original_mode,
        managed_block_id=identifier,
        installed_block_hash=block_hash,
        unresolved_reason=unresolved_reason,
    )


def _block_from_file(content: bytes, block_id: str) -> ManagedBlock | None:
    begin, end = _markers(block_id)
    matches = [item for item in _scan(content) if item[0] == block_id]
    if not matches:
        return None
    _marker_id, start, stop = matches[0]
    rendered = content[start:stop]
    prefix = begin + b"\n"
    suffix = end + b"\n"
    if not rendered.startswith(prefix) or not rendered.endswith(suffix):
        raise ValueError("malformed managed block")
    body = rendered[len(prefix) : -len(suffix)]
    return ManagedBlock(block_id, begin, end, body, _digest(rendered))


def _selected_sources(
    repo_root: Path, request: Request
) -> dict[Target, tuple[ValidatedSource, ...]]:
    inventories: dict[Target, tuple[ValidatedSource, ...]] = {}
    for target in DESCRIPTOR_ORDER:
        if target not in request.targets:
            continue
        descriptor = descriptor_for(target)
        specs = selected_sources(descriptor, request.include_commit_pusher)
        try:
            inventories[target] = validate_source_inventory(
                repo_root,
                target,
                specs,
                require_commit_pusher=request.include_commit_pusher,
            )
        except ValidationBlockedError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValidationBlockedError(str(exc)) from exc
    return inventories


def _reject_legacy_state(home: Path, target: Target) -> None:
    legacy = home / _LEGACY_STATE_NAMES[target]
    if lstat_existing(legacy, "legacy installer state") is not None:
        raise ValueError(
            f"legacy {target.value} installer state detected; manual recovery "
            "is required and automatic conversion is disabled"
        )


def _source_bytes(target: Target, source: ValidatedSource, home: Path) -> bytes:
    if source.spec.kind != "agent":
        return source.content
    if source.spec.identifier != "code-validator":
        if (
            b"{{VALIDATION_HELPER}}" in source.content
            or b"{{CLAUDE_HOOK}}" in source.content
        ):
            raise ValueError("agent placeholders are restricted to code-validator")
        return source.content
    if b"{{VALIDATION_HELPER}}" not in source.content:
        raise ValueError("code-validator source is missing validation placeholder")
    if target is Target.CLAUDE_CODE and b"{{CLAUDE_HOOK}}" not in source.content:
        raise ValueError("Claude validator source is missing hook placeholder")
    helper = normalized_absolute(
        home / ".subagents_configs/validation/run-validation-isolated.py"
    )
    helper_text = validate_validation_helper(str(helper))
    rendered = source.content.replace(
        b"{{VALIDATION_HELPER}}", helper_text.encode("utf-8")
    )
    if target is Target.CLAUDE_CODE:
        hook = normalized_absolute(
            home / ".subagents_configs/claude-hooks/code-validator-pretooluse.py"
        )
        rendered = rendered.replace(b"{{CLAUDE_HOOK}}", str(hook).encode("utf-8"))
    if b"{{VALIDATION_HELPER}}" in rendered:
        raise ValueError("validation placeholder remained unresolved")
    if b"{{CLAUDE_HOOK}}" in rendered:
        raise ValueError("Claude hook placeholder remained unresolved")
    validate_rendered_agent(
        target,
        source.spec.identifier,
        Path(source.spec.destination or source.spec.source),
        rendered,
        helper_text,
        hook_path=(
            str(
                normalized_absolute(
                    home
                    / ".subagents_configs/claude-hooks/code-validator-pretooluse.py"
                )
            )
            if target is Target.CLAUDE_CODE
            else "{{CLAUDE_HOOK}}"
        ),
    )
    return rendered


def _existing_manifest_by_path(manifest: Manifest | None) -> dict[str, ManifestEntry]:
    if manifest is None:
        return {}
    return {entry.relative_path: entry for entry in manifest.entries}


def _make_file_operation(
    target: Target,
    identifier: str,
    relative_path: str,
    before: bytes | None,
    before_mode: int | None,
    after: bytes,
    ownership: Ownership,
    *,
    backup_required: bool,
    after_mode: int = 0o600,
) -> PlannedOperation | None:
    after_hash = _digest(after)
    before_hash = _digest(before) if before is not None else None
    if before is not None and before_hash == after_hash and before_mode is not None:
        if before_mode & ~0o600:
            return PlannedOperation(
                target,
                identifier,
                "replace",
                relative_path,
                before_hash,
                after_hash,
                before_mode,
                after_mode,
                after,
                ownership,
                False,
                None,
            )
        return None
    action = "create" if before is None else "replace"
    return PlannedOperation(
        target,
        identifier,
        action,
        relative_path,
        before_hash,
        after_hash,
        before_mode,
        after_mode,
        after,
        ownership,
        backup_required,
        None,
    )


def _plan_regular_source(
    target: Target,
    home: Path,
    source: ValidatedSource,
    prior: ManifestEntry | None,
    conflicts: list[str],
) -> tuple[PlannedOperation | None, ManifestEntry | None]:
    if source.spec.destination is None:
        raise ValueError(f"source has no managed destination: {source.spec.identifier}")
    relative = source.spec.destination.as_posix()
    try:
        destination = _safe_destination(home, relative, source.spec.identifier)
    except ValueError:
        if prior is None:
            raise
        reason = f"unsafe managed destination {relative}"
        conflicts.append(reason)
        return None, ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
    proposed = _source_bytes(target, source, home)
    installed_mode = 0o700 if source.spec.kind == "command-gate" else 0o600
    existing: tuple[bytes, int] | None
    try:
        existing = _read_regular(destination, source.spec.identifier)
    except FileNotFoundError:
        existing = None
    if prior is not None and existing is not None:
        current, current_mode = existing
        if (
            _digest(current) != prior.installed_hash
            or current_mode != prior.installed_mode
        ):
            reason = f"drift in managed destination {relative}"
            conflicts.append(reason)
            return None, ManifestEntry(
                **{**prior.__dict__, "unresolved_reason": reason}
            )
        if _digest(proposed) == _digest(current):
            return None, ManifestEntry(**{**prior.__dict__, "unresolved_reason": None})
        if prior.ownership == "preexisting":
            reason = f"source update conflicts with preexisting destination {relative}"
            conflicts.append(reason)
            return None, ManifestEntry(
                **{**prior.__dict__, "unresolved_reason": reason}
            )
        # A managed file that is still exact may be updated without making a
        # new user backup; a replaced file keeps its existing backup metadata.
        operation = _make_file_operation(
            target,
            source.spec.identifier,
            relative,
            current,
            current_mode,
            proposed,
            prior.ownership,
            backup_required=True,
            after_mode=installed_mode,
        )
        return operation, _entry_for_file(
            source.spec.identifier,
            relative,
            proposed,
            installed_mode,
            prior.ownership,
            backup_path=prior.backup_path,
            backup_hash=prior.backup_hash,
            original_mode=prior.original_mode,
        )
    if prior is not None and existing is None:
        reason = f"managed destination is missing: {relative}"
        conflicts.append(reason)
        return None, ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
    if existing is None:
        operation = _make_file_operation(
            target,
            source.spec.identifier,
            relative,
            None,
            None,
            proposed,
            "created",
            backup_required=False,
            after_mode=installed_mode,
        )
        return operation, _entry_for_file(
            source.spec.identifier, relative, proposed, installed_mode, "created"
        )
    current, current_mode = existing
    current_hash = _digest(current)
    proposed_hash = _digest(proposed)
    if current_hash == proposed_hash:
        if current_mode & ~installed_mode:
            reason = f"identical preexisting destination has broad mode {relative}"
            conflicts.append(reason)
            return None, None
        return None, _entry_for_file(
            source.spec.identifier,
            relative,
            current,
            current_mode,
            "preexisting",
        )
    operation = _make_file_operation(
        target,
        source.spec.identifier,
        relative,
        current,
        current_mode,
        proposed,
        "replaced",
        backup_required=True,
        after_mode=installed_mode,
    )
    backup_path = _backup_name(source.spec.identifier, current_hash)
    return operation, _entry_for_file(
        source.spec.identifier,
        relative,
        proposed,
        installed_mode,
        "replaced",
        backup_path=backup_path,
        backup_hash=current_hash,
        original_mode=current_mode,
    )


def _block_body(
    inventories: Sequence[ValidatedSource],
    identifier: str,
) -> bytes:
    source = next(
        source for source in inventories if source.spec.identifier == "routing"
    )
    return source.content


def _plan_block(
    target: Target,
    home: Path,
    identifier: str,
    relative: str,
    body: bytes,
    prior: ManifestEntry | None,
    conflicts: list[str],
) -> tuple[PlannedOperation | None, ManifestEntry | None]:
    from .blocks import render_managed_block

    block = render_managed_block(identifier, body)
    try:
        destination = _safe_destination(home, relative, identifier)
    except ValueError:
        if prior is None:
            raise
        reason = f"unsafe managed destination {relative}"
        conflicts.append(reason)
        return None, ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
    try:
        existing = _read_regular(destination, identifier)
    except FileNotFoundError:
        existing = None
    if prior is not None and existing is None:
        reason = f"managed block destination is missing: {relative}"
        conflicts.append(reason)
        return None, ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
    if existing is not None:
        current, current_mode = existing
        current_block = _block_from_file(current, identifier)
        prior_exact = prior is not None and (
            _digest(current) == prior.installed_hash
            and current_mode == prior.installed_mode
        )
        if prior is not None and not prior_exact:
            reason = f"drift in managed block {identifier}"
            conflicts.append(reason)
            return None, ManifestEntry(
                **{**prior.__dict__, "unresolved_reason": reason}
            )
        if current_block is not None:
            if current_block.sha256 != block.sha256:
                if (
                    prior_exact
                    and prior is not None
                    and prior.ownership
                    in {
                        "created",
                        "replaced",
                    }
                ):
                    updated = insert_or_replace_block(current, block)
                    operation = PlannedOperation(
                        target,
                        identifier,
                        "write-block",
                        relative,
                        _digest(current),
                        _digest(updated),
                        current_mode,
                        0o600,
                        updated,
                        prior.ownership,
                        True,
                        identifier,
                    )
                    return operation, _entry_for_block(
                        identifier,
                        relative,
                        updated,
                        0o600,
                        prior.ownership,
                        block.sha256,
                        backup_path=prior.backup_path,
                        backup_hash=prior.backup_hash,
                        original_mode=prior.original_mode,
                    )
                reason = f"managed block {identifier} differs from proposed bytes"
                conflicts.append(reason)
                if prior is not None:
                    return None, ManifestEntry(
                        **{**prior.__dict__, "unresolved_reason": reason}
                    )
                return None, None
            if current_mode & ~0o600:
                conflicts.append(f"managed block has broad mode {relative}")
                return None, prior
            if prior is not None:
                return None, ManifestEntry(
                    **{**prior.__dict__, "unresolved_reason": None}
                )
            return None, _entry_for_block(
                identifier,
                relative,
                current,
                current_mode,
                "preexisting",
                block.sha256,
                original_mode=current_mode,
            )
        updated = insert_or_replace_block(current, block)
        operation = PlannedOperation(
            target,
            identifier,
            "write-block",
            relative,
            _digest(current),
            _digest(updated),
            current_mode,
            0o600,
            updated,
            None,
            True,
            identifier,
        )
        backup_path = _backup_name(identifier, _digest(current))
        return operation, _entry_for_block(
            identifier,
            relative,
            updated,
            0o600,
            "replaced",
            block.sha256,
            backup_path=backup_path,
            backup_hash=_digest(current),
            original_mode=current_mode,
        )
    updated = insert_or_replace_block(b"", block)
    operation = PlannedOperation(
        target,
        identifier,
        "write-block",
        relative,
        None,
        _digest(updated),
        None,
        0o600,
        updated,
        None,
        False,
        identifier,
    )
    return operation, _entry_for_block(
        identifier,
        relative,
        updated,
        0o600,
        "created",
        block.sha256,
    )


def _config_is_safe(content: bytes, *, require_feature_absent: bool) -> bool:
    try:
        parsed = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid Codex config.toml: {exc}") from exc
    if not require_feature_absent:
        return True
    features = parsed.get("features")
    if features is None:
        return True
    if not isinstance(features, Mapping):
        raise ValueError("Codex config features has a conflicting non-table type")
    if "multi_agent_v2" in features:
        if not isinstance(features["multi_agent_v2"], Mapping):
            raise ValueError("Codex multi_agent_v2 has a conflicting type")
        return False
    return True


def _plan_manifest_operation(
    target: Target,
    home: Path,
    current: Manifest | None,
    resulting: Manifest | None,
) -> PlannedOperation | None:
    relative = ".subagents_configs/manifest.json"
    destination = _path(home, relative)
    current_bytes: bytes | None = None
    current_mode: int | None = None
    try:
        current_bytes, current_mode = _read_regular(destination, "manifest")
    except FileNotFoundError:
        pass
    after = encode_manifest(resulting) if resulting is not None else None
    if current_bytes == after:
        return None
    return PlannedOperation(
        target,
        "state/manifest",
        "write-manifest",
        relative,
        _digest(current_bytes) if current_bytes is not None else None,
        _digest(after) if after is not None else None,
        current_mode,
        0o600 if after is not None else None,
        after,
        None,
        current_bytes is not None,
        None,
    )


def _stale_install(
    target: Target,
    home: Path,
    prior: ManifestEntry,
    operations: list[PlannedOperation],
    conflicts: list[str],
) -> ManifestEntry | None:
    try:
        destination = _safe_destination(home, prior.relative_path, prior.identifier)
    except ValueError:
        reason = f"unsafe stale managed path: {prior.relative_path}"
        conflicts.append(reason)
        return ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
    try:
        current, current_mode = _read_regular(destination, prior.identifier)
    except FileNotFoundError:
        reason = f"stale managed path missing: {prior.relative_path}"
        conflicts.append(reason)
        return ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
    current_hash = _digest(current)
    if current_hash != prior.installed_hash or current_mode != prior.installed_mode:
        reason = f"drift in stale managed path: {prior.relative_path}"
        conflicts.append(reason)
        return ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
    if prior.managed_block_id and prior.ownership == "preexisting":
        reason = f"preexisting managed block preserved: {prior.relative_path}"
        conflicts.append(reason)
        return ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
    if prior.managed_block_id:
        block = _block_from_file(current, prior.managed_block_id)
        if block is None or block.sha256 != prior.installed_block_hash:
            reason = f"stale managed block is changed: {prior.identifier}"
            conflicts.append(reason)
            return ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
        updated, changed = remove_exact_block(current, block)
        if not changed:
            reason = f"stale managed block is ambiguous: {prior.identifier}"
            conflicts.append(reason)
            return ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
        if prior.ownership == "replaced":
            backup = _path(home, f".subagents_configs/{prior.backup_path}")
            restored, _ = _read_regular(backup, "backup")
            if _digest(restored) != prior.backup_hash:
                raise ValueError("stale managed block backup hash mismatch")
            final_bytes = restored
            after_hash = _digest(restored)
            after_mode = prior.original_mode
        else:
            final_bytes = updated if updated else None
            after_hash = _digest(updated) if updated else None
            after_mode = current_mode if updated else None
        operations.append(
            PlannedOperation(
                target,
                prior.identifier,
                "remove-block",
                prior.relative_path,
                current_hash,
                after_hash,
                current_mode,
                after_mode,
                final_bytes,
                prior.ownership,
                True,
                prior.managed_block_id,
            )
        )
        return None
    if prior.ownership == "created":
        operations.append(
            PlannedOperation(
                target,
                prior.identifier,
                "remove",
                prior.relative_path,
                current_hash,
                None,
                current_mode,
                None,
                None,
                prior.ownership,
                True,
                None,
            )
        )
        return None
    if prior.ownership == "replaced":
        backup = _path(home, f".subagents_configs/{prior.backup_path}")
        backup_bytes, _backup_mode = _read_regular(backup, "backup")
        if _digest(backup_bytes) != prior.backup_hash:
            raise ValueError("verified backup changed during planning")
        operations.append(
            PlannedOperation(
                target,
                prior.identifier,
                "restore",
                prior.relative_path,
                current_hash,
                _digest(backup_bytes),
                current_mode,
                prior.original_mode,
                backup_bytes,
                prior.ownership,
                True,
                None,
            )
        )
        return None
    reason = f"preexisting stale path preserved: {prior.relative_path}"
    conflicts.append(reason)
    return ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})


def _target_install(
    repo_root: Path,
    request: Request,
    target: Target,
    inventory: tuple[ValidatedSource, ...],
) -> TargetPlan:
    descriptor = descriptor_for(target)
    home = normalized_absolute(request.homes[target])
    assert_safe_home(home)
    _reject_legacy_state(home, target)
    if load_journal(home, descriptor) is not None:
        raise ValueError(f"existing transaction journal blocks {target.value}")
    prior_manifest = load_manifest(home, descriptor)
    prior = _existing_manifest_by_path(prior_manifest)
    operations: list[PlannedOperation] = []
    entries: dict[str, ManifestEntry] = {}
    conflicts: list[str] = []
    for source in inventory:
        if source.spec.destination is None or (
            source.spec.kind not in {"agent", "validation-runtime", "command-gate"}
        ):
            continue
        operation, entry = _plan_regular_source(
            target,
            home,
            source,
            prior.get(source.spec.destination.as_posix()),
            conflicts,
        )
        if operation is not None:
            operations.append(operation)
        if entry is not None:
            entries[entry.relative_path] = entry

    instruction = _safe_destination(home, descriptor.global_filename, "instructions")
    try:
        instruction_bytes, _instruction_mode = _read_regular(
            instruction, "instructions"
        )
    except FileNotFoundError:
        pass
    else:
        _scan(instruction_bytes)

    if request.enable_global_routing:
        routing_identifier = f"routing-{target.value}"
        operation, entry = _plan_block(
            target,
            home,
            routing_identifier,
            descriptor.global_filename,
            _block_body(inventory, "routing"),
            prior.get(descriptor.global_filename),
            conflicts,
        )
        if operation is not None:
            operations.append(operation)
        if entry is not None:
            entries[entry.relative_path] = entry
    elif prior_manifest is not None:
        # A previously installed opted-in block is stale when the option is
        # now absent, and is handled conservatively like all other stale data.
        pass

    if target is Target.CODEX:
        config = _safe_destination(
            home, descriptor.config_filename or "config.toml", "config"
        )
        try:
            existing_config, config_mode = _read_regular(config, "config")
        except FileNotFoundError:
            existing_config, config_mode = None, None
        config_identifier = descriptor.config_filename or "config.toml"
        prior_config = prior.get(config_identifier)
        exact_managed_config = False
        if existing_config is not None and prior_config is not None:
            current_block = _block_from_file(existing_config, "codex-multi-agent-v2")
            exact_managed_config = (
                prior_config.identifier == "codex-multi-agent-v2"
                and prior_config.managed_block_id == "codex-multi-agent-v2"
                and _digest(existing_config) == prior_config.installed_hash
                and config_mode == prior_config.installed_mode
                and current_block is not None
                and current_block.sha256 == prior_config.installed_block_hash
            )
        if existing_config is not None:
            _config_is_safe(
                existing_config,
                require_feature_absent=False,
            )
        if request.enable_codex_multi_agent:
            feature_absent = _config_is_safe(
                existing_config or b"", require_feature_absent=True
            )
            if not feature_absent and not exact_managed_config:
                raise ValueError(
                    "Codex multi_agent_v2 has an unrecorded table or type collision"
                )
            config_body = (
                b"[features.multi_agent_v2]\n"
                b"hide_spawn_agent_metadata = false\n"
                b'tool_namespace = "agents"\n'
            )
            operation, entry = _plan_block(
                target,
                home,
                "codex-multi-agent-v2",
                config_identifier,
                config_body,
                prior_config,
                conflicts,
            )
            if operation is not None:
                try:
                    tomllib.loads((operation.content or b"").decode("utf-8"))
                except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                    raise ValueError(
                        f"proposed Codex config is invalid: {exc}"
                    ) from exc
                operations.append(operation)
            if entry is not None:
                entries[entry.relative_path] = entry

    for prior_entry in prior_manifest.entries if prior_manifest else ():
        if prior_entry.relative_path in entries:
            continue
        stale = _stale_install(target, home, prior_entry, operations, conflicts)
        if stale is not None:
            entries[stale.relative_path] = stale

    resulting_entries = tuple(entries[key] for key in sorted(entries))
    resulting = Manifest(2, target, resulting_entries)
    manifest_operation = _plan_manifest_operation(
        target, home, prior_manifest, resulting
    )
    if manifest_operation is not None:
        operations.append(manifest_operation)
    operations.sort(key=lambda item: (item.relative_path, item.identifier, item.action))
    return TargetPlan(
        target, home, tuple(operations), resulting, tuple(sorted(conflicts))
    )


def _target_uninstall(
    repo_root: Path,
    request: Request,
    target: Target,
    inventory: tuple[ValidatedSource, ...],
) -> TargetPlan:
    del repo_root, inventory
    descriptor = descriptor_for(target)
    home = normalized_absolute(request.homes[target])
    assert_safe_home(home)
    _reject_legacy_state(home, target)
    if load_journal(home, descriptor) is not None:
        raise ValueError(f"existing transaction journal blocks {target.value}")
    manifest = load_manifest(home, descriptor)
    if manifest is None:
        return TargetPlan(target, home, (), None, ())
    operations: list[PlannedOperation] = []
    entries: list[ManifestEntry] = []
    conflicts: list[str] = []
    for prior in manifest.entries:
        # Validation runtime files are shared installer machinery. They stay
        # in the private state tree across uninstall and are no longer
        # managed by the reduced manifest.
        if prior.relative_path.startswith(".subagents_configs/validation/"):
            continue
        try:
            destination = _safe_destination(home, prior.relative_path, prior.identifier)
            current_result = _read_regular(destination, prior.identifier)
            if current_result is None:
                raise FileNotFoundError(destination)
            current, current_mode = current_result
        except FileNotFoundError:
            reason = (
                f"uninstall preserved missing managed block {prior.identifier}"
                if prior.managed_block_id
                else f"uninstall preserved missing {prior.relative_path}"
            )
            conflicts.append(reason)
            entries.append(
                ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
            )
            continue
        except ValueError:
            reason = (
                f"uninstall preserved unsafe managed block {prior.identifier}"
                if prior.managed_block_id
                else f"uninstall preserved {prior.relative_path}: missing or unsafe"
            )
            conflicts.append(reason)
            entries.append(
                ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
            )
            continue
        if prior.managed_block_id:
            if prior.ownership == "preexisting":
                reason = f"preexisting managed block preserved: {prior.relative_path}"
                conflicts.append(reason)
                entries.append(
                    ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
                )
                continue
            if current_mode != prior.installed_mode:
                reason = (
                    f"uninstall preserved drifted managed block {prior.identifier} mode"
                )
                conflicts.append(reason)
                entries.append(
                    ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
                )
                continue
            try:
                block = _block_from_file(current, prior.managed_block_id)
            except ValueError:
                block = None
            if block is None or block.sha256 != prior.installed_block_hash:
                reason = (
                    f"uninstall preserved changed or ambiguous block {prior.identifier}"
                )
                conflicts.append(reason)
                entries.append(
                    ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
                )
                continue
            updated, changed = remove_exact_block(current, block)
            if not changed:
                reason = f"uninstall preserved ambiguous block {prior.identifier}"
                conflicts.append(reason)
                entries.append(
                    ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
                )
                continue
            if prior.ownership == "replaced":
                backup = _path(home, f".subagents_configs/{prior.backup_path}")
                backup_result = _read_regular(backup, "backup")
                if backup_result is None:
                    raise FileNotFoundError(backup)
                backup_bytes, backup_mode = backup_result
                if backup_mode & ~0o600:
                    raise ValueError("uninstall managed block backup is not private")
                if _digest(backup_bytes) != prior.backup_hash:
                    raise ValueError("uninstall managed block backup hash mismatch")
                # The permanent backup proves ownership and original mode; it
                # must not replace current user edits surrounding this block.
                if not updated and _digest(current) == prior.installed_hash:
                    final_bytes = backup_bytes
                    after_hash = _digest(final_bytes)
                    after_mode = prior.original_mode
                else:
                    # An edited file can legitimately have empty surrounding
                    # bytes. Keep that regular file present; only an exact
                    # installed full-file match may restore the backup bytes.
                    final_bytes = updated
                    after_hash = _digest(final_bytes)
                    after_mode = prior.original_mode
            else:
                final_bytes = updated if updated else None
                after_hash = _digest(updated) if updated else None
                after_mode = current_mode if updated else None
            operations.append(
                PlannedOperation(
                    target,
                    prior.identifier,
                    "remove-block",
                    prior.relative_path,
                    _digest(current),
                    after_hash,
                    current_mode,
                    after_mode,
                    final_bytes,
                    prior.ownership,
                    True,
                    prior.managed_block_id,
                )
            )
            continue
        if (
            _digest(current) != prior.installed_hash
            or current_mode != prior.installed_mode
        ):
            reason = f"uninstall preserved drifted {prior.relative_path}"
            conflicts.append(reason)
            entries.append(
                ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason})
            )
            continue
        if prior.ownership == "created":
            operations.append(
                PlannedOperation(
                    target,
                    prior.identifier,
                    "remove",
                    prior.relative_path,
                    _digest(current),
                    None,
                    current_mode,
                    None,
                    None,
                    prior.ownership,
                    True,
                    None,
                )
            )
            continue
        if prior.ownership == "replaced":
            backup = _path(home, f".subagents_configs/{prior.backup_path}")
            backup_bytes, _ = _read_regular(backup, "backup")
            if _digest(backup_bytes) != prior.backup_hash:
                raise ValueError("uninstall backup hash mismatch")
            operations.append(
                PlannedOperation(
                    target,
                    prior.identifier,
                    "restore",
                    prior.relative_path,
                    _digest(current),
                    _digest(backup_bytes),
                    current_mode,
                    prior.original_mode,
                    backup_bytes,
                    prior.ownership,
                    True,
                    None,
                )
            )
            continue
        reason = f"uninstall preserved preexisting {prior.relative_path}"
        conflicts.append(reason)
        entries.append(ManifestEntry(**{**prior.__dict__, "unresolved_reason": reason}))
    resulting = Manifest(
        2, target, tuple(sorted(entries, key=lambda item: item.relative_path))
    )
    manifest_operation = _plan_manifest_operation(
        target, home, manifest, resulting if entries else None
    )
    if manifest_operation is not None:
        operations.append(manifest_operation)
    operations.sort(key=lambda item: (item.relative_path, item.identifier, item.action))
    return TargetPlan(
        target,
        home,
        tuple(operations),
        resulting if entries else None,
        tuple(sorted(conflicts)),
    )


def _validate_request(request: Request, operation: str) -> None:
    if not isinstance(request, Request):
        raise ValueError("request must be a Request")
    if request.operation != operation:
        raise ValueError(f"request operation must be {operation}")
    for option in (
        "enable_global_routing",
        "enable_codex_multi_agent",
        "include_commit_pusher",
        "dry_run",
    ):
        if type(getattr(request, option)) is not bool:
            raise ValueError(f"{option} must be a bool")
    if not request.targets:
        raise ValueError("at least one target is required")
    if any(type(target) is not Target for target in request.targets):
        raise ValueError("targets must use supported Target values")
    if len(set(request.targets)) != len(request.targets):
        raise ValueError("duplicate targets are not supported")
    unknown = set(request.targets) - set(DESCRIPTOR_ORDER)
    if unknown:
        raise ValueError("unsupported target selection")
    if not isinstance(request.homes, Mapping):
        raise ValueError("homes must map every selected target")
    if set(request.homes) != set(request.targets) or any(
        type(target) is not Target for target in request.homes
    ):
        raise ValueError("homes keys must exactly match selected targets")
    normalized_homes = [
        normalized_absolute(request.homes[target]) for target in request.targets
    ]
    if len(set(normalized_homes)) != len(normalized_homes):
        raise ValueError("selected target homes must be distinct after normalization")
    if any("{{VALIDATION_HELPER}}" in str(home) for home in normalized_homes):
        raise ValueError("target home must not contain the validation placeholder")
    for home in normalized_homes:
        helper = home / ".subagents_configs/validation/run-validation-isolated.py"
        validate_validation_helper(str(helper))
    if operation == "uninstall" and (
        request.enable_global_routing
        or request.enable_codex_multi_agent
        or request.include_commit_pusher
    ):
        raise ValueError("uninstall does not accept install-only options")
    if request.enable_codex_multi_agent and Target.CODEX not in request.targets:
        raise ValueError("Codex multi-agent configuration requires Codex")


def preflight_install(repo_root: Path, request: Request) -> TransactionPlan:
    _validate_request(request, "install")
    root = normalized_absolute(repo_root)
    inventories = _selected_sources(root, request)
    target_plans = tuple(
        _target_install(root, request, target, inventories[target])
        for target in DESCRIPTOR_ORDER
        if target in request.targets
    )
    return TransactionPlan("install", target_plans)


def preflight_uninstall(repo_root: Path, request: Request) -> TransactionPlan:
    _validate_request(request, "uninstall")
    root = normalized_absolute(repo_root)
    inventories = _selected_sources(root, request)
    target_plans = tuple(
        _target_uninstall(root, request, target, inventories[target])
        for target in DESCRIPTOR_ORDER
        if target in request.targets
    )
    return TransactionPlan("uninstall", target_plans)


def render_plan(plan: TransactionPlan) -> str:
    lines = [f"operation: {plan.operation}"]
    for target in plan.targets:
        lines.append(
            f"target: {target.target.value} home={normalized_absolute(target.home)}"
        )
        for operation in target.operations:
            lines.append(
                "  "
                + " ".join(
                    (
                        operation.action,
                        operation.identifier,
                        operation.relative_path,
                        f"before={operation.expected_before_hash or 'absent'}",
                        f"after={operation.expected_after_hash or 'absent'}",
                    )
                )
            )
        for conflict in target.conflicts:
            lines.append(f"  conflict: {conflict}")
    return "\n".join(lines) + "\n"
