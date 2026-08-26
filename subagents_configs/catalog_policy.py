"""Strict, read-only normalized catalog policy comparison.

Catalogs are untrusted generated input.  This module deliberately has no
filesystem mutation or target-client integration; it only validates snapshots,
maps native capability declarations, compares them, and renders safe reports.
"""

from __future__ import annotations

import enum
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from .models import Target


class AuthorityCapability(enum.StrEnum):
    FILESYSTEM_READ = "filesystem-read"
    FILESYSTEM_WRITE = "filesystem-write"
    SHELL_EXECUTION = "shell-execution"
    NETWORK = "network"
    CREDENTIALS = "credentials"
    EXTERNAL_DIRECTORY = "external-directory"
    MCP = "mcp"
    EXTENSION = "extension"
    PACKAGE = "package"
    SKILL = "skill"
    PUBLICATION = "publication"
    REPOSITORY_HISTORY = "repository-history"


_AUTHORITY_VALUES = frozenset(item.value for item in AuthorityCapability)
_KINDS = frozenset(
    {"role", "model", "tool", "permission", "destination", "source_hash", "authority"}
)
_TARGETS = frozenset(Target)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]*$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_UNSAFE_TEXT = re.compile(r"[\x00-\x1f\x7f]")


def _safe_identifier(value: object, field: str) -> str:
    if type(value) is not str or not value or len(value) > 200:
        raise ValueError(f"{field} must be a bounded string")
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} is unsafe")
    return value


def _safe_model(value: object, field: str = "model") -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value or len(value) > 200:
        raise ValueError(f"{field} must be a bounded string or null")
    if not _MODEL.fullmatch(value) or value.startswith(("/", "~")) or ".." in value:
        raise ValueError(f"{field} is unsafe")
    return value


def _safe_path(value: object, field: str) -> str:
    if type(value) is not str or not value or len(value) > 400:
        raise ValueError(f"{field} must be a bounded relative path")
    if _UNSAFE_TEXT.search(value) or value.startswith(("/", "~")):
        raise ValueError(f"{field} is unsafe")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{field} is not canonical")
    return value


def _safe_source_identifier(value: object, field: str) -> str:
    if type(value) is not str or not value or len(value) > 400:
        raise ValueError(f"{field} must be a bounded identifier")
    if _UNSAFE_TEXT.search(value) or value.startswith(("/", "~")):
        raise ValueError(f"{field} is unsafe")
    parts = value.split("/")
    if any(
        part in {"", ".", ".."} or not _IDENTIFIER.fullmatch(part) for part in parts
    ):
        raise ValueError(f"{field} is unsafe")
    return value


def _safe_scalar(value: object, field: str) -> str:
    # Native values are identifiers, not paths or arbitrary source content.
    if type(value) is not str or not value or len(value) > 200:
        raise ValueError(f"{field} must be a bounded string")
    if _UNSAFE_TEXT.search(value) or value.startswith(("/", "~")) or ".." in value:
        raise ValueError(f"{field} is unsafe")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@+ -]*", value):
        raise ValueError(f"{field} is unsafe")
    return value


def _target(value: object) -> Target:
    if type(value) is not str:
        raise ValueError("target must be a string")
    try:
        return Target(value)
    except ValueError as exc:
        raise ValueError("unsupported target") from exc


def _string_set(value: object, field: str) -> frozenset[str]:
    if type(value) is not list:
        raise ValueError(f"{field} must be a list")
    result: list[str] = []
    for item in value:
        result.append(_safe_identifier(item, field))
    if len(set(result)) != len(result):
        raise ValueError(f"{field} contains duplicate members")
    if result != sorted(result):
        raise ValueError(f"{field} must use canonical order")
    return frozenset(result)


def _authority_set(value: object) -> frozenset[AuthorityCapability]:
    if type(value) is not list:
        raise ValueError("authorities must be a list")
    result: list[AuthorityCapability] = []
    for item in value:
        if type(item) is not str or item not in _AUTHORITY_VALUES:
            raise ValueError("unknown authority capability")
        result.append(AuthorityCapability(item))
    if len(set(result)) != len(result):
        raise ValueError("authorities contains duplicate members")
    if [item.value for item in result] != sorted(item.value for item in result):
        raise ValueError("authorities must use canonical order")
    return frozenset(result)


@dataclass(frozen=True)
class RolePolicy:
    target: Target
    role: str
    model: str | None = None
    effort: str | None = None
    tools: frozenset[str] = frozenset()
    permissions: frozenset[str] = frozenset()
    authorities: frozenset[AuthorityCapability] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.target, Target):
            raise TypeError("role target must be a Target")
        object.__setattr__(self, "role", _safe_identifier(self.role, "role"))
        object.__setattr__(self, "model", _safe_model(self.model))
        if self.effort is not None:
            object.__setattr__(self, "effort", _safe_identifier(self.effort, "effort"))
        for name in ("tools", "permissions"):
            raw = getattr(self, name)
            if not isinstance(raw, (set, frozenset, tuple, list)):
                raise TypeError(f"{name} must be a set-like collection")
            values = [_safe_identifier(item, name) for item in raw]
            if len(set(values)) != len(values):
                raise ValueError(f"{name} contains duplicate members")
            object.__setattr__(self, name, frozenset(values))
        raw_authorities = self.authorities
        if not isinstance(raw_authorities, (set, frozenset, tuple, list)):
            raise TypeError("authorities must be a set-like collection")
        authorities: list[AuthorityCapability] = []
        for item in raw_authorities:
            if not isinstance(item, AuthorityCapability):
                raise TypeError("authorities must contain AuthorityCapability values")
            authorities.append(item)
        if len(set(authorities)) != len(authorities):
            raise ValueError("authorities contains duplicate members")
        object.__setattr__(self, "authorities", frozenset(authorities))


@dataclass(frozen=True)
class DestinationPolicy:
    target: Target
    role: str
    destination: str

    def __post_init__(self) -> None:
        if not isinstance(self.target, Target):
            raise TypeError("destination target must be a Target")
        object.__setattr__(self, "role", _safe_identifier(self.role, "role"))
        object.__setattr__(
            self, "destination", _safe_path(self.destination, "destination")
        )


@dataclass(frozen=True)
class NormalizedCatalog:
    target: Target
    revision: str
    roles: tuple[RolePolicy, ...]
    destinations: tuple[DestinationPolicy, ...]
    source_hashes: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.target, Target):
            raise TypeError("catalog target must be a Target")
        object.__setattr__(
            self, "revision", _safe_identifier(self.revision, "revision")
        )
        if type(self.roles) is not tuple or any(
            not isinstance(item, RolePolicy) for item in self.roles
        ):
            raise TypeError("catalog roles must be a tuple of RolePolicy")
        if type(self.destinations) is not tuple or any(
            not isinstance(item, DestinationPolicy) for item in self.destinations
        ):
            raise TypeError("catalog destinations must be a tuple of DestinationPolicy")
        if any(
            item.target is not self.target for item in (*self.roles, *self.destinations)
        ):
            raise ValueError("catalog member target does not match envelope")
        role_keys = [(item.target.value, item.role) for item in self.roles]
        destination_keys = [
            (item.target.value, item.role, item.destination)
            for item in self.destinations
        ]
        if len(set(role_keys)) != len(role_keys) or role_keys != sorted(role_keys):
            raise ValueError("roles must be unique and canonical")
        if len(set(destination_keys)) != len(
            destination_keys
        ) or destination_keys != sorted(destination_keys):
            raise ValueError("destinations must be unique and canonical")
        if not isinstance(self.source_hashes, Mapping):
            raise TypeError("source_hashes must be a mapping")
        hashes: dict[str, str] = {}
        for key, value in self.source_hashes.items():
            identifier = _safe_source_identifier(key, "source hash identifier")
            if type(value) is not str or not _HASH.fullmatch(value):
                raise ValueError("source hashes must be lowercase SHA-256 values")
            hashes[identifier] = value
        object.__setattr__(
            self, "source_hashes", MappingProxyType(dict(sorted(hashes.items())))
        )


@dataclass(frozen=True)
class PolicyChange:
    kind: Literal[
        "role", "model", "tool", "permission", "destination", "source_hash", "authority"
    ]
    target: Target
    role: str | None
    before: str | None
    after: str | None
    authority_broadening: bool

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError("unknown policy change kind")
        if not isinstance(self.target, Target):
            raise TypeError("policy change target must be a Target")
        if self.role is not None:
            if self.kind == "source_hash":
                object.__setattr__(
                    self,
                    "role",
                    _safe_source_identifier(self.role, "source hash identifier"),
                )
            else:
                object.__setattr__(self, "role", _safe_identifier(self.role, "role"))
        if self.before is not None:
            object.__setattr__(self, "before", _safe_scalar(self.before, "before"))
        if self.after is not None:
            object.__setattr__(self, "after", _safe_scalar(self.after, "after"))
        if type(self.authority_broadening) is not bool:
            raise TypeError("authority_broadening must be bool")
        if self.kind == "authority":
            for value in (self.before, self.after):
                if value is not None and value not in _AUTHORITY_VALUES:
                    raise ValueError("unknown authority in policy change")


@dataclass(frozen=True)
class PolicyChangeReport:
    from_revision: str
    to_revision: str
    changes: tuple[PolicyChange, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "from_revision", _safe_identifier(self.from_revision, "from_revision")
        )
        object.__setattr__(
            self, "to_revision", _safe_identifier(self.to_revision, "to_revision")
        )
        if type(self.changes) is not tuple or any(
            not isinstance(item, PolicyChange) for item in self.changes
        ):
            raise TypeError("changes must be a tuple of PolicyChange")
        keys = [_change_key(item) for item in self.changes]
        if keys != sorted(keys):
            raise ValueError("changes must be in canonical order")


def _change_key(change: PolicyChange) -> tuple[object, ...]:
    order = {
        kind: index
        for index, kind in enumerate(
            (
                "role",
                "model",
                "tool",
                "permission",
                "destination",
                "source_hash",
                "authority",
            )
        )
    }
    return (
        change.target.value,
        order[change.kind],
        change.role or "",
        change.before or "",
        change.after or "",
    )


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError("unable to read catalog") from exc
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("catalog is not strict UTF-8 JSON") from exc
    if type(parsed) is not dict:
        raise ValueError("catalog envelope must be an object")
    return parsed


def _regular_path(path: Path, *, directory: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("catalog path does not exist") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ValueError("symlink catalog paths are not accepted")
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("revision must be a directory")
    elif not stat.S_ISREG(info.st_mode):
        raise ValueError("catalog must be a regular file")


def _parse_catalog(raw: dict[str, object]) -> NormalizedCatalog:
    expected = {
        "schema_version",
        "revision",
        "target",
        "roles",
        "destinations",
        "source_hashes",
    }
    if (
        set(raw) != expected
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
    ):
        raise ValueError("catalog envelope has an invalid schema")
    target = _target(raw["target"])
    revision = _safe_identifier(raw["revision"], "revision")
    if (
        type(raw["roles"]) is not list
        or type(raw["destinations"]) is not list
        or type(raw["source_hashes"]) is not dict
    ):
        raise ValueError("catalog members have invalid types")
    roles: list[RolePolicy] = []
    for item in raw["roles"]:
        if type(item) is not dict or set(item) != {
            "target",
            "role",
            "model",
            "effort",
            "tools",
            "permissions",
            "authorities",
        }:
            raise ValueError("role has an invalid schema")
        if _target(item["target"]) is not target:
            raise ValueError("role target does not match catalog")
        roles.append(
            RolePolicy(
                target,
                _safe_identifier(item["role"], "role"),
                _safe_model(item["model"]),
                None
                if item["effort"] is None
                else _safe_identifier(item["effort"], "effort"),
                _string_set(item["tools"], "tools"),
                _string_set(item["permissions"], "permissions"),
                _authority_set(item["authorities"]),
            )
        )
    role_keys = [(item.target.value, item.role) for item in roles]
    if role_keys != sorted(role_keys):
        raise ValueError("roles must use canonical order")
    destinations: list[DestinationPolicy] = []
    for item in raw["destinations"]:
        if type(item) is not dict or set(item) != {"target", "role", "destination"}:
            raise ValueError("destination has an invalid schema")
        if _target(item["target"]) is not target:
            raise ValueError("destination target does not match catalog")
        destinations.append(
            DestinationPolicy(
                target,
                _safe_identifier(item["role"], "role"),
                _safe_path(item["destination"], "destination"),
            )
        )
    destination_keys = [
        (item.target.value, item.role, item.destination) for item in destinations
    ]
    if destination_keys != sorted(destination_keys):
        raise ValueError("destinations must use canonical order")
    hashes: dict[str, str] = {}
    for key, value in raw["source_hashes"].items():
        identifier = _safe_source_identifier(key, "source hash identifier")
        if type(value) is not str or not _HASH.fullmatch(value):
            raise ValueError("source hashes must be lowercase SHA-256 values")
        hashes[identifier] = value
    if list(hashes) != sorted(hashes):
        raise ValueError("source hashes must use canonical order")
    return NormalizedCatalog(
        target, revision, tuple(roles), tuple(destinations), hashes
    )


def load_catalog(path: str | os.PathLike[str]) -> NormalizedCatalog:
    """Load exactly one strict normalized catalog without following symlinks."""
    catalog_path = Path(path)
    _regular_path(catalog_path)
    return _parse_catalog(_read_json(catalog_path))


def load_revision(path: str | os.PathLike[str]) -> tuple[NormalizedCatalog, ...]:
    """Load a file or an unambiguous single/all-target revision directory."""
    revision_path = Path(path)
    try:
        info = revision_path.lstat()
    except OSError as exc:
        raise ValueError("revision path does not exist") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ValueError("symlink revision paths are not accepted")
    if stat.S_ISREG(info.st_mode):
        return (load_catalog(revision_path),)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("revision must be a regular file or directory")
    entries = list(revision_path.iterdir())
    if any(entry.is_symlink() for entry in entries):
        raise ValueError("revision contains a symlink")
    files = [entry for entry in entries if entry.is_file()]
    if len(files) != len(entries):
        raise ValueError("revision contains a directory or special file")
    names = {entry.name for entry in files}
    if names == {"catalog.json"}:
        return (load_catalog(revision_path / "catalog.json"),)
    expected = {f"{target.value}.json" for target in Target}
    if names != expected:
        raise ValueError("revision directory is ambiguous")
    catalogs = tuple(
        load_catalog(revision_path / f"{target.value}.json") for target in Target
    )
    revisions = {catalog.revision for catalog in catalogs}
    if len(revisions) != 1:
        raise ValueError("revision catalogs disagree on revision")
    return catalogs


def _native_authority(
    target: Target, field: str, value: object
) -> frozenset[AuthorityCapability]:
    if target is Target.CODEX:
        fields: dict[str, dict[object, frozenset[AuthorityCapability]]] = {
            "sandbox_mode": {
                "read-only": frozenset({AuthorityCapability.FILESYSTEM_READ}),
                "workspace-write": frozenset(
                    {
                        AuthorityCapability.FILESYSTEM_READ,
                        AuthorityCapability.FILESYSTEM_WRITE,
                    }
                ),
                "danger-full-access": frozenset(AuthorityCapability),
            },
            "network_access": {
                False: frozenset(),
                True: frozenset({AuthorityCapability.NETWORK}),
            },
        }
    elif target is Target.OPENCODE:
        fields = {"permission": {}}
    elif target is Target.CLAUDE_CODE:
        fields = {
            "permissionMode": {
                "default": frozenset(),
                "plan": frozenset(),
                "acceptEdits": frozenset({AuthorityCapability.FILESYSTEM_WRITE}),
                "bypassPermissions": frozenset(AuthorityCapability),
            },
        }
    else:  # pragma: no cover - Target is closed
        raise ValueError("unsupported target")
    if field not in fields:
        raise ValueError("unknown native authority field")
    if field == "network_access" and type(value) is not bool:
        raise ValueError("network_access must be a boolean")
    if field != "network_access" and type(value) is not str:
        raise ValueError("native authority value must be a string")
    try:
        return fields[field][value]
    except (KeyError, TypeError) as exc:
        raise ValueError("unknown native authority value") from exc


def authorities_from_native(
    target: Target, native: Mapping[str, object]
) -> frozenset[AuthorityCapability]:
    """Map an explicit native declaration to closed authority capabilities."""
    if not isinstance(target, Target) or not isinstance(native, Mapping):
        raise TypeError("native authority input has invalid type")
    result: set[AuthorityCapability] = set()
    for field, value in native.items():
        if type(field) is not str:
            raise ValueError("native authority fields must be strings")
        if target is Target.OPENCODE and field == "permission":
            if type(value) is not dict:
                raise ValueError("permission must be an object")
            permission_map = {
                "edit": AuthorityCapability.FILESYSTEM_WRITE,
                "bash": AuthorityCapability.SHELL_EXECUTION,
                "external_directory": AuthorityCapability.EXTERNAL_DIRECTORY,
                "webfetch": AuthorityCapability.NETWORK,
                "websearch": AuthorityCapability.NETWORK,
                "mcp": AuthorityCapability.MCP,
                "skill": AuthorityCapability.SKILL,
                "task": AuthorityCapability.EXTENSION,
            }
            for permission, declaration in value.items():
                if type(permission) is not str or permission not in permission_map:
                    raise ValueError("unknown native permission")
                capability = permission_map[permission]
                if type(declaration) is str:
                    if declaration not in {"allow", "deny"}:
                        raise ValueError("unknown native permission value")
                    if declaration == "allow":
                        result.add(capability)
                elif type(declaration) is dict:
                    if set(declaration) - {
                        "*",
                        "{{VALIDATION_HELPER}}",
                        "python3 {{VALIDATION_HELPER}} -- *",
                    }:
                        raise ValueError("unknown nested native permission")
                    for nested in declaration.values():
                        if type(nested) is not str or nested not in {"allow", "deny"}:
                            raise ValueError("unknown nested native permission value")
                        if nested == "allow":
                            result.add(capability)
                else:
                    raise ValueError("native permission value has invalid type")
            continue
        if target is Target.CLAUDE_CODE and field == "tools":
            if type(value) is not str:
                raise ValueError("Claude tools must be a string")
            tool_map = {
                "Read": AuthorityCapability.FILESYSTEM_READ,
                "Grep": AuthorityCapability.FILESYSTEM_READ,
                "Glob": AuthorityCapability.FILESYSTEM_READ,
                "Edit": AuthorityCapability.FILESYSTEM_WRITE,
                "Write": AuthorityCapability.FILESYSTEM_WRITE,
                "NotebookEdit": AuthorityCapability.FILESYSTEM_WRITE,
                "Bash": AuthorityCapability.SHELL_EXECUTION,
                "WebFetch": AuthorityCapability.NETWORK,
                "WebSearch": AuthorityCapability.NETWORK,
                "MCP": AuthorityCapability.MCP,
                "Skill": AuthorityCapability.SKILL,
            }
            tools = [part.strip() for part in value.split(",")]
            if any(not part or part not in tool_map for part in tools) or len(
                set(tools)
            ) != len(tools):
                raise ValueError("unknown Claude native tool")
            result.update(tool_map[part] for part in tools)
            continue
        result.update(_native_authority(target, field, value))
    return frozenset(result)


def compare_catalogs(
    before: NormalizedCatalog, after: NormalizedCatalog
) -> PolicyChangeReport:
    if not isinstance(before, NormalizedCatalog) or not isinstance(
        after, NormalizedCatalog
    ):
        raise TypeError("compare_catalogs requires normalized catalogs")
    if before.target is not after.target:
        raise ValueError("catalog targets must match")
    before_roles = {(item.target, item.role): item for item in before.roles}
    after_roles = {(item.target, item.role): item for item in after.roles}
    changes: list[PolicyChange] = []
    for key in sorted(
        set(before_roles) | set(after_roles), key=lambda item: (item[0].value, item[1])
    ):
        old, new = before_roles.get(key), after_roles.get(key)
        target, role = key
        if old is None:
            changes.append(PolicyChange("role", target, role, None, role, False))
            continue
        if new is None:
            changes.append(PolicyChange("role", target, role, role, None, False))
            continue
        if old.model != new.model:
            changes.append(
                PolicyChange("model", target, role, old.model, new.model, False)
            )
        for kind, old_values, new_values in (
            ("tool", old.tools, new.tools),
            ("permission", old.permissions, new.permissions),
            ("authority", old.authorities, new.authorities),
        ):
            for value in sorted(
                old_values - new_values,
                key=lambda item: (
                    item.value if isinstance(item, AuthorityCapability) else item
                ),
            ):
                rendered = (
                    value.value if isinstance(value, AuthorityCapability) else value
                )
                changes.append(PolicyChange(kind, target, role, rendered, None, False))
            for value in sorted(
                new_values - old_values,
                key=lambda item: (
                    item.value if isinstance(item, AuthorityCapability) else item
                ),
            ):
                rendered = (
                    value.value if isinstance(value, AuthorityCapability) else value
                )
                changes.append(
                    PolicyChange(
                        kind, target, role, None, rendered, kind == "authority"
                    )
                )
    before_dest = {
        (item.target, item.role): item.destination for item in before.destinations
    }
    after_dest = {
        (item.target, item.role): item.destination for item in after.destinations
    }
    for key in sorted(
        set(before_dest) | set(after_dest), key=lambda item: (item[0].value, item[1])
    ):
        if before_dest.get(key) != after_dest.get(key):
            changes.append(
                PolicyChange(
                    "destination",
                    key[0],
                    key[1],
                    before_dest.get(key),
                    after_dest.get(key),
                    False,
                )
            )
    for key in sorted(set(before.source_hashes) | set(after.source_hashes)):
        if before.source_hashes.get(key) != after.source_hashes.get(key):
            changes.append(
                PolicyChange(
                    "source_hash",
                    before.target,
                    key,
                    before.source_hashes.get(key),
                    after.source_hashes.get(key),
                    False,
                )
            )
    ordered = tuple(sorted(changes, key=_change_key))
    return PolicyChangeReport(before.revision, after.revision, ordered)


def _validate_report(report: PolicyChangeReport) -> None:
    if not isinstance(report, PolicyChangeReport):
        raise TypeError("render_policy_report requires a PolicyChangeReport")
    # Re-run constructor validation and ordering checks against hostile objects
    # that may have been assembled by bypassing normal dataclass construction.
    checked = tuple(
        PolicyChange(
            item.kind,
            item.target,
            item.role,
            item.before,
            item.after,
            item.authority_broadening,
        )
        for item in report.changes
    )
    PolicyChangeReport(report.from_revision, report.to_revision, checked)


def render_policy_report(
    report: PolicyChangeReport, format: Literal["text", "json"] = "text"
) -> str:
    _validate_report(report)
    if format not in {"text", "json"}:
        raise ValueError("format must be text or json")
    changes = [
        {
            "kind": change.kind,
            "target": change.target.value,
            "role": change.role,
            "before": change.before,
            "after": change.after,
            "authority_broadening": change.authority_broadening,
        }
        for change in report.changes
    ]
    if format == "json":
        return json.dumps(
            {
                "from_revision": report.from_revision,
                "to_revision": report.to_revision,
                "changes": changes,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
    lines = [f"policy changes: {report.from_revision} -> {report.to_revision}"]
    for change in changes:
        role = f" role={change['role']}" if change["role"] is not None else ""
        lines.append(
            f"{change['kind']} target={change['target']}{role} "
            f"before={change['before']!r} after={change['after']!r} "
            f"authority_broadening={change['authority_broadening']}"
        )
    return "\n".join(lines) + "\n"
