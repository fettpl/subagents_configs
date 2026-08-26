import base64
import enum
import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import ClassVar, Literal

from .paths import validate_profile_home_path

ParserName = Literal["toml", "yaml-frontmatter", "markdown"]
ValidatorName = Literal["agent"]
LifecycleCapability = Literal["file", "block", "manifest", "runtime"]
COMMITMENT_ANCHOR_COUNT = 3
COMMITMENT_ANCHOR_SIZE = 4096


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
            if (
                ownership != "created"
                or expected is not None
                or type(desired) is not DesiredFile
                or backup is not None
            ):
                raise ValueError("create action has invalid evidence or backup")
        elif action == "replace":
            _evidence(expected, required=True)
            if (
                ownership != "replaced"
                or type(desired) is not DesiredFile
                or type(backup) is not BackupSpec
            ):
                raise TypeError(
                    "replace action requires typed desired and backup values"
                )
            if backup.sha256 != expected.sha256:
                raise ValueError("replace action requires matching backup evidence")
        elif action == "remove":
            _evidence(expected, required=True)
            if ownership != "created" or desired is not None or backup is not None:
                raise ValueError("remove action cannot carry desired or backup data")
        elif action == "restore":
            _evidence(expected, required=True)
            if (
                ownership != "replaced"
                or desired is not None
                or type(backup) is not BackupSpec
            ):
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
        if type(desired) is not DesiredFile:
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


def _validated_managed_block(identifier: str, block: "ManagedBlock") -> "ManagedBlock":
    _identifier(identifier)
    if type(block) is not ManagedBlock:
        raise TypeError("managed block has the wrong type")
    begin = f"# BEGIN SUBAGENTS_CONFIGS {identifier}".encode("ascii")
    end = f"# END SUBAGENTS_CONFIGS {identifier}".encode("ascii")
    if block.block_id != identifier:
        raise ValueError("managed block id does not match lifecycle identifier")
    if block.begin_marker != begin or block.end_marker != end:
        raise ValueError("managed block markers do not match lifecycle identifier")
    if type(block.content) is not bytes:
        raise TypeError("managed block body must be bytes")
    if b"\r" in block.content or not block.content.endswith(b"\n"):
        raise ValueError("managed block content must use canonical LF boundaries")
    if (
        b"# BEGIN SUBAGENTS_CONFIGS" in block.content
        or b"# END SUBAGENTS_CONFIGS" in block.content
    ):
        raise ValueError("managed block body contains an ambiguous marker")
    rendered = begin + b"\n" + block.content + end + b"\n"
    if block.sha256 != hashlib.sha256(rendered).hexdigest():
        raise ValueError("managed block hash does not match canonical bytes")
    return block


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
        block = _validated_managed_block(identifier, block)
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
        block = _validated_managed_block(identifier, block)
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

    def managed_block(value: object) -> ManagedBlock:
        if type(value) is not dict or set(value) != {
            "block_id",
            "begin_marker",
            "end_marker",
            "content",
            "sha256",
        }:
            raise ValueError("invalid managed block fields")
        block_id = _raw_string(value["block_id"], "block.block_id")
        try:
            begin = base64.b64decode(value["begin_marker"], validate=True)
            end = base64.b64decode(value["end_marker"], validate=True)
            content = base64.b64decode(value["content"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("managed block content is not canonical base64") from exc
        expected_begin = f"# BEGIN SUBAGENTS_CONFIGS {block_id}".encode("ascii")
        expected_end = f"# END SUBAGENTS_CONFIGS {block_id}".encode("ascii")
        if (
            begin != expected_begin
            or end != expected_end
            or not content.endswith(b"\n")
        ):
            raise ValueError("managed block markers or content are invalid")
        rendered = begin + b"\n" + content + end + b"\n"
        digest = _raw_string(value["sha256"], "block.sha256")
        if digest != hashlib.sha256(rendered).hexdigest():
            raise ValueError("managed block hash does not match rendered bytes")
        return ManagedBlock(block_id, begin, end, content, digest)

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
    if action == "write-block":
        if set(raw) != {"action", "identifier", "relative_path", "expected", "block"}:
            raise ValueError("invalid write-block lifecycle fields")
        before = None if raw["expected"] is None else expected(raw["expected"])
        return BlockAction.write(
            identifier, relative_path, before, managed_block(raw["block"])
        )
    if action == "remove-block":
        if set(raw) != {"action", "identifier", "relative_path", "expected", "block"}:
            raise ValueError("invalid remove-block lifecycle fields")
        return BlockAction.remove(
            identifier,
            relative_path,
            expected(raw["expected"]),
            managed_block(raw["block"]),
        )
    raise ValueError("unsupported lifecycle action")


DryRunFormat = Literal["text", "json"]


class Target(enum.StrEnum):
    CODEX = "codex"
    OPENCODE = "opencode"
    CLAUDE_CODE = "claude-code"
    PI = "pi"


@dataclass(frozen=True)
class TargetProfileDefaults:
    """Safe, immutable defaults that a profile may provide for Pi."""

    home: Path

    def __post_init__(self) -> None:
        validate_profile_home_path(self.home)


@dataclass(frozen=True)
class ProfileOptions:
    """Immutable, strictly typed options loaded from a declarative profile."""

    enable_global_routing: bool
    enable_codex_multi_agent: bool
    include_commit_pusher: bool
    dry_run: bool
    dry_run_format: DryRunFormat

    def __post_init__(self) -> None:
        for name in (
            "enable_global_routing",
            "enable_codex_multi_agent",
            "include_commit_pusher",
            "dry_run",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"profile option {name} must be a bool")
        if self.dry_run_format not in ("text", "json"):
            raise ValueError("profile dry_run_format must be text or json")
        if self.dry_run_format == "json" and not self.dry_run:
            raise ValueError("profile json format requires dry_run")


@dataclass(frozen=True)
class ProfileRequest:
    """Immutable, typed representation of a strict install profile."""

    schema_version: Literal[1]
    operation: Literal["install", "uninstall"]
    targets: tuple[Target, ...]
    homes: Mapping[Target, Path]
    options: ProfileOptions
    target_defaults: Mapping[Target, TargetProfileDefaults] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("profile schema_version must be 1")
        if self.operation not in ("install", "uninstall"):
            raise ValueError("profile operation is unsupported")
        if type(self.targets) is not tuple or not self.targets:
            raise ValueError("profile targets must be a non-empty tuple")
        if any(type(target) is not Target for target in self.targets):
            raise TypeError("profile targets must use Target values")
        if Target.PI in self.targets:
            raise ValueError("Pi cannot be selected by a profile")
        if len(set(self.targets)) != len(self.targets):
            raise ValueError("profile targets must be unique")
        canonical_targets = tuple(
            target
            for target in (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE)
            if target in self.targets
        )
        if self.targets != canonical_targets:
            raise ValueError("profile targets must be in canonical descriptor order")
        if not isinstance(self.homes, Mapping):
            raise TypeError("profile homes must be a mapping")
        if set(self.homes) != set(self.targets):
            raise ValueError("profile homes must exactly match targets")
        if any(type(target) is not Target for target in self.homes):
            raise TypeError("profile home keys must use Target values")
        if any(not isinstance(home, Path) for home in self.homes.values()):
            raise TypeError("profile homes must use Path values")
        normalized_homes: list[Path] = []
        for home in self.homes.values():
            if not home.is_absolute():
                raise ValueError("profile homes must be absolute")
            raw_home = os.fspath(home)
            if "\\" in raw_home or any(
                ord(character) < 32 or ord(character) == 127 for character in raw_home
            ):
                raise ValueError("profile home contains unsafe characters")
            if raw_home != "/" and (
                raw_home.startswith("//") or raw_home.endswith("/") or "//" in raw_home
            ):
                raise ValueError("profile home is not canonical")
            if any(component in {".", ".."} for component in raw_home.split("/")):
                raise ValueError("profile home contains unsafe lexical components")
            normalized_homes.append(Path(os.path.normpath(os.path.abspath(raw_home))))
        if len(set(normalized_homes)) != len(normalized_homes):
            raise ValueError("profile homes must be distinct after normalization")
        if type(self.options) is not ProfileOptions:
            raise TypeError("profile options must use ProfileOptions")
        if not isinstance(self.target_defaults, Mapping):
            raise TypeError("profile target_defaults must be a mapping")
        if any(target is not Target.PI for target in self.target_defaults):
            raise ValueError("only Pi target defaults are supported")
        if any(
            type(value) is not TargetProfileDefaults
            for value in self.target_defaults.values()
        ):
            raise TypeError("profile target defaults have the wrong type")
        for defaults in self.target_defaults.values():
            validate_profile_home_path(defaults.home)
        object.__setattr__(self, "homes", MappingProxyType(dict(self.homes)))
        object.__setattr__(
            self, "target_defaults", MappingProxyType(dict(self.target_defaults))
        )


@dataclass(frozen=True)
class Request:
    operation: Literal["install", "uninstall"]
    targets: tuple[Target, ...]
    homes: Mapping[Target, Path]
    enable_global_routing: bool
    enable_codex_multi_agent: bool
    include_commit_pusher: bool
    dry_run: bool
    dry_run_format: DryRunFormat = "text"
    client_versions: Mapping[str, str] = field(default_factory=dict)
    pi_executable: Path | None = None
    consent_third_party_code: bool = False
    consent_network: bool = False
    remove_pi_package: bool = False


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
    cleanup_backup_evidence: IdentityEvidence | None = None
    backup_identity_evidence: IdentityEvidence | None = None


@dataclass(frozen=True)
class Journal:
    schema_version: int
    transaction_id: str
    target: Target
    participants: tuple[Target, ...]
    operation: Literal["install", "uninstall"]
    operations: tuple[JournalOperation, ...]
    rollback_status: Literal[
        "not-started", "in-progress", "complete", "incomplete", "cleanup"
    ]
    cleanup_participant_digests: tuple[str, ...] = ()
    cleanup_commitment_evidence: tuple[IdentityEvidence, ...] = ()


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
    environment_variable: str
    default_home: str
    config_filename: str | None
    project_template: PurePosixPath
    agent_suffix: str
    compatibility_features: frozenset[str] = frozenset()
    supported_platforms: tuple[Literal["linux", "macos"], ...] = (
        "linux",
        "macos",
    )
    scope: Literal["user"] = "user"
    package_source: str | None = None
