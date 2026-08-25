import base64
import enum
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import ClassVar, Literal

ParserName = Literal["toml", "yaml-frontmatter"]
ValidatorName = Literal["agent"]
LifecycleCapability = Literal["file", "block", "manifest", "runtime"]


@dataclass(frozen=True)
class IdentityEvidence:
    """Stable identity evidence required at every mutation boundary."""

    device: int
    inode: int
    size: int
    nlink: int
    mode: int
    sha256: str


@dataclass(frozen=True)
class DesiredFile:
    content: bytes
    mode: int = 0o600

    def __post_init__(self) -> None:
        if type(self.content) is not bytes:
            raise TypeError("desired file content must be bytes")
        if type(self.mode) is not int or not 0 <= self.mode <= 0o700:
            raise ValueError("desired file mode is invalid")


@dataclass(frozen=True)
class BackupSpec:
    relative_path: PurePosixPath
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.relative_path, PurePosixPath)
            or self.relative_path.is_absolute()
            or not self.relative_path.parts
            or any(part in {"", ".", ".."} for part in self.relative_path.parts)
            or len(self.relative_path.parts) != 2
            or self.relative_path.parts[0] != "backups"
        ):
            raise ValueError("backup path must be relative")
        if (
            type(self.sha256) is not str
            or len(self.sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.sha256)
        ):
            raise ValueError("backup hash must be lowercase SHA-256")


def _relative_path(value: PurePosixPath) -> PurePosixPath:
    if (
        not isinstance(value, PurePosixPath)
        or value.is_absolute()
        or not value.parts
        or any(part in {"", ".", ".."} for part in value.parts)
    ):
        raise ValueError("lifecycle path must be a safe relative POSIX path")
    return value


def _identifier(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("lifecycle identifier must be a non-empty string")
    return value


def _evidence(
    value: IdentityEvidence | None, *, required: bool
) -> IdentityEvidence | None:
    if value is None:
        if required:
            raise ValueError("lifecycle action requires identity evidence")
        return None
    if not isinstance(value, IdentityEvidence):
        raise TypeError("lifecycle evidence has the wrong type")
    if any(
        type(getattr(value, field)) is not int or getattr(value, field) < 0
        for field in ("device", "inode", "size", "nlink", "mode")
    ):
        raise ValueError("lifecycle evidence has invalid numeric fields")
    if value.nlink < 1 or value.mode > 0o777:
        raise ValueError("lifecycle evidence has invalid link count or mode")
    if (
        type(value.sha256) is not str
        or len(value.sha256) != 64
        or any(char not in "0123456789abcdef" for char in value.sha256)
    ):
        raise ValueError("lifecycle evidence has an invalid hash")
    return value


class LifecycleAction:
    """Base type for validated, tagged lifecycle operations."""

    action: ClassVar[str]


@dataclass(frozen=True, init=False)
class FileAction(LifecycleAction):
    action: Literal["create", "replace", "remove", "restore"]
    identifier: str
    relative_path: PurePosixPath
    expected: IdentityEvidence | None
    desired: DesiredFile | None
    backup: BackupSpec | None
    ownership: Literal["created", "replaced"]

    @classmethod
    def _make(
        cls,
        action: str,
        identifier: str,
        relative_path: PurePosixPath,
        expected: IdentityEvidence | None,
        desired: DesiredFile | None,
        backup: BackupSpec | None,
        ownership: Literal["created", "replaced"],
    ):
        _identifier(identifier)
        _relative_path(relative_path)
        if action == "create":
            _evidence(expected, required=False)
            if expected is not None or desired is None or backup is not None:
                raise ValueError("create action has invalid evidence or backup")
        elif action == "replace":
            _evidence(expected, required=True)
            if desired is None or backup is None or backup.sha256 != expected.sha256:
                raise ValueError("replace action requires matching backup evidence")
        elif action == "remove":
            _evidence(expected, required=True)
            if desired is not None or backup is not None:
                raise ValueError("remove action cannot carry desired or backup data")
        elif action == "restore":
            _evidence(expected, required=True)
            if desired is not None or backup is None:
                raise ValueError("restore action requires a backup")
        else:
            raise ValueError("unsupported file lifecycle action")
        item = object.__new__(cls)
        object.__setattr__(item, "action", action)
        object.__setattr__(item, "identifier", identifier)
        object.__setattr__(item, "relative_path", relative_path)
        object.__setattr__(item, "expected", expected)
        object.__setattr__(item, "desired", desired)
        object.__setattr__(item, "backup", backup)
        object.__setattr__(item, "ownership", ownership)
        return item

    @classmethod
    def create(
        cls, identifier: str, relative_path: PurePosixPath, desired: DesiredFile
    ) -> "FileAction":
        if not isinstance(desired, DesiredFile):
            raise TypeError("desired file has the wrong type")
        return cls._make(
            "create", identifier, relative_path, None, desired, None, "created"
        )

    @classmethod
    def replace(
        cls,
        identifier: str,
        relative_path: PurePosixPath,
        expected: IdentityEvidence,
        desired: DesiredFile,
        backup: BackupSpec,
    ) -> "FileAction":
        return cls._make(
            "replace", identifier, relative_path, expected, desired, backup, "replaced"
        )

    @classmethod
    def remove(
        cls, identifier: str, relative_path: PurePosixPath, expected: IdentityEvidence
    ) -> "FileAction":
        return cls._make(
            "remove", identifier, relative_path, expected, None, None, "created"
        )

    @classmethod
    def restore(
        cls,
        identifier: str,
        relative_path: PurePosixPath,
        expected: IdentityEvidence,
        backup: BackupSpec,
    ) -> "FileAction":
        return cls._make(
            "restore", identifier, relative_path, expected, None, backup, "replaced"
        )


@dataclass(frozen=True, init=False)
class BlockAction(LifecycleAction):
    action: Literal["write-block", "remove-block"]
    identifier: str
    relative_path: PurePosixPath
    expected: IdentityEvidence | None
    block: "ManagedBlock"

    @classmethod
    def write(
        cls,
        identifier: str,
        relative_path: PurePosixPath,
        expected: IdentityEvidence | None,
        block: "ManagedBlock",
    ) -> "BlockAction":
        _identifier(identifier)
        _relative_path(relative_path)
        if not isinstance(block, ManagedBlock):
            raise TypeError("managed block has the wrong type")
        _evidence(expected, required=False)
        item = object.__new__(cls)
        for name, value in (
            ("action", "write-block"),
            ("identifier", identifier),
            ("relative_path", relative_path),
            ("expected", expected),
            ("block", block),
        ):
            object.__setattr__(item, name, value)
        return item

    @classmethod
    def remove(
        cls,
        identifier: str,
        relative_path: PurePosixPath,
        expected: IdentityEvidence,
        block: "ManagedBlock",
    ) -> "BlockAction":
        _identifier(identifier)
        _relative_path(relative_path)
        _evidence(expected, required=True)
        if not isinstance(block, ManagedBlock):
            raise TypeError("managed block has the wrong type")
        item = object.__new__(cls)
        for name, value in (
            ("action", "remove-block"),
            ("identifier", identifier),
            ("relative_path", relative_path),
            ("expected", expected),
            ("block", block),
        ):
            object.__setattr__(item, name, value)
        return item


def _raw_string(value: object, field: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _raw_evidence(value: object, field: str) -> IdentityEvidence:
    if type(value) is not dict or set(value) != {
        "device",
        "inode",
        "size",
        "nlink",
        "mode",
        "sha256",
    }:
        raise ValueError(f"{field} has unknown or missing fields")
    try:
        evidence = IdentityEvidence(
            *(
                value[key]
                for key in ("device", "inode", "size", "nlink", "mode", "sha256")
            )
        )
    except (KeyError, TypeError) as exc:
        raise ValueError(f"{field} is invalid") from exc
    if any(
        type(getattr(evidence, key)) is not int or getattr(evidence, key) < 0
        for key in ("device", "inode", "size", "nlink", "mode")
    ):
        raise ValueError(f"{field} has invalid numeric evidence")
    return _evidence(evidence, required=True)  # type: ignore[return-value]


def decode_lifecycle_action(raw: Mapping[str, object]) -> LifecycleAction:
    """Decode hostile persisted lifecycle data with exact action schemas."""
    if not isinstance(raw, Mapping) or type(raw.get("action")) is not str:
        raise ValueError("lifecycle action must be an object with an action")
    action = raw["action"]
    identifier = _raw_string(raw.get("identifier"), "identifier")
    relative_path = _relative_path(
        PurePosixPath(_raw_string(raw.get("relative_path"), "relative_path"))
    )

    def desired(value: object) -> DesiredFile:
        if type(value) is not dict or set(value) != {"content", "mode"}:
            raise ValueError("invalid desired file fields")
        try:
            content = base64.b64decode(value["content"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("desired content is not canonical base64") from exc
        return DesiredFile(content, value["mode"])

    def backup(value: object) -> BackupSpec:
        if type(value) is not dict or set(value) != {"relative_path", "sha256"}:
            raise ValueError("invalid backup fields")
        return BackupSpec(
            PurePosixPath(_raw_string(value["relative_path"], "backup.relative_path")),
            _raw_string(value["sha256"], "backup.sha256"),
        )

    def expected(value: object) -> IdentityEvidence:
        return _raw_evidence(value, "expected")

    if action == "create":
        if set(raw) != {"action", "identifier", "relative_path", "desired"}:
            raise ValueError("invalid create lifecycle fields")
        return FileAction.create(identifier, relative_path, desired(raw["desired"]))
    if action == "replace":
        if set(raw) != {
            "action",
            "identifier",
            "relative_path",
            "expected",
            "desired",
            "backup",
        }:
            raise ValueError("invalid replace lifecycle fields")
        return FileAction.replace(
            identifier,
            relative_path,
            expected(raw["expected"]),
            desired(raw["desired"]),
            backup(raw["backup"]),
        )
    if action == "remove":
        if set(raw) != {"action", "identifier", "relative_path", "expected"}:
            raise ValueError("invalid remove lifecycle fields")
        return FileAction.remove(identifier, relative_path, expected(raw["expected"]))
    if action == "restore":
        if set(raw) != {"action", "identifier", "relative_path", "expected", "backup"}:
            raise ValueError("invalid restore lifecycle fields")
        return FileAction.restore(
            identifier, relative_path, expected(raw["expected"]), backup(raw["backup"])
        )
    raise ValueError("unsupported lifecycle action")


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
        "target-extension",
    ]
    source_format: Literal[
        "toml",
        "yaml-frontmatter",
        "markdown",
        "python",
        "json",
        "typescript",
    ]
    optional_role: Literal["commit-pusher"] | None = None


@dataclass(frozen=True)
class TargetDescriptor:
    target: Target
    environment_variable: str
    default_home: str
    global_filename: str
    config_filename: str | None
    sources: tuple[SourceSpec, ...]


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


@dataclass(frozen=True)
class GlobalInstructionSpec:
    """Canonical description of a target's optional global instruction block."""

    block_id: str
    filename: PurePosixPath
    source: PurePosixPath


@dataclass(frozen=True)
class ManagedBlockSpec:
    block_id: str
    relative_path: PurePosixPath
    source: PurePosixPath | None = None


@dataclass(frozen=True)
class ExternalLifecycleSpec:
    name: str
    capabilities: frozenset[str] = frozenset()


@dataclass(frozen=True)
class TargetCapability:
    target: Target
    order: int
    include_in_all: bool
    agent_directory: PurePosixPath
    source_format: ParserName
    parser: ParserName
    semantic_validator: ValidatorName
    global_instruction: GlobalInstructionSpec
    optional_blocks: tuple[ManagedBlockSpec, ...]
    runtime_sources: tuple[SourceSpec, ...]
    lifecycle_capabilities: frozenset[LifecycleCapability]
    external_lifecycle: ExternalLifecycleSpec | None
