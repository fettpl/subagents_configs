import enum
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal


class Target(enum.StrEnum):
    CODEX = "codex"
    OPENCODE = "opencode"
    CLAUDE_CODE = "claude-code"


@dataclass(frozen=True)
class Request:
    operation: Literal["install", "uninstall"]
    targets: tuple[Target, ...]
    homes: Mapping[Target, Path]
    enable_global_routing: bool
    enable_codex_multi_agent: bool
    include_commit_pusher: bool
    dry_run: bool


@dataclass(frozen=True)
class SourceSpec:
    identifier: str
    source: PurePosixPath
    destination: PurePosixPath | None
    kind: Literal[
        "agent",
        "routing-source",
        "project-template",
        "validation-runtime",
        "command-gate",
    ]
    source_format: Literal["toml", "yaml-frontmatter", "markdown", "python", "json"]
    optional_role: Literal["commit-pusher"] | None = None


@dataclass(frozen=True)
class ManagedSettingSpec:
    """A target-owned JSON setting represented as a deterministic path/value."""

    identifier: str
    relative_path: PurePosixPath
    key_path: tuple[str, ...]
    value: object


@dataclass(frozen=True)
class TargetDescriptor:
    target: Target
    environment_variable: str
    default_home: str
    global_filename: str
    config_filename: str | None
    sources: tuple[SourceSpec, ...]
    managed_settings: tuple[ManagedSettingSpec, ...] = ()


Ownership = Literal["created", "replaced", "preexisting"]


@dataclass(frozen=True)
class ManifestEntry:
    identifier: str
    relative_path: str
    installed_hash: str
    installed_mode: int
    ownership: Ownership
    backup_path: str | None
    backup_hash: str | None
    original_mode: int | None
    managed_block_id: str | None
    installed_block_hash: str | None
    unresolved_reason: str | None
    managed_setting_id: str | None = None


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    target: Target
    entries: tuple[ManifestEntry, ...]


@dataclass(frozen=True)
class JournalOperation:
    operation_id: str
    identifier: str
    action: str
    expected_before_hash: str | None
    expected_after_hash: str | None
    expected_before_mode: int | None
    expected_after_mode: int | None
    backup_path: str | None
    backup_hash: str | None
    status: Literal[
        "planned",
        "applying",
        "applied",
        "rollback-planned",
        "rolled-back",
        "ambiguous",
    ]
    expected_before_evidence: object | None = None
    expected_after_evidence: object | None = None


@dataclass(frozen=True)
class Journal:
    schema_version: int
    transaction_id: str
    target: Target
    participants: tuple[Target, ...]
    operation: Literal["install", "uninstall"]
    operations: tuple[JournalOperation, ...]
    rollback_status: Literal["not-started", "in-progress", "complete", "incomplete"]


@dataclass(frozen=True)
class ManagedBlock:
    block_id: str
    begin_marker: bytes
    end_marker: bytes
    content: bytes
    sha256: str
