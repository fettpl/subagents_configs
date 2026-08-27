"""Read-only validation of Pi's effective, repository-owned agent catalog.

The Pi package can discover configuration outside the files written by the
installer.  This module therefore treats discovery as an input contract: all
interesting state is inspected locally, values are reduced to safe labels,
and a caller must explicitly handle every conflict before applying a plan.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from .paths import normalized_absolute
from .pi_catalog import (
    PI_BUNDLED_ROLES,
    PI_DEFAULT_ROLES,
    PI_OPTIONAL_ROLES,
    PiAgentContract,
    render_pi_source,
    validate_pi_agent,
    validate_pi_contract,
)
from .pi_package import PACKAGE_POLICY_PATH, PiPackageEvidence

ConflictKind = Literal[
    "path-collision",
    "package-drift",
    "override",
    "alias",
    "ambient-extension",
    "discovery",
]


@dataclass(frozen=True)
class PiConflict:
    kind: ConflictKind
    role: str | None
    source_id: str
    field: str
    safe_value: str
    observed_value: str


@dataclass(frozen=True)
class PiEffectiveCatalog:
    managed_roles: tuple[str, ...]
    bundled_roles: tuple[str, ...]
    optional_managed_roles: tuple[str, ...]
    conflicts: tuple[PiConflict, ...]
    source_hashes: Mapping[str, str]


_MANAGED = frozenset(PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES)
_SAFE_HASH = frozenset("0123456789abcdef")
_PACKAGE_SOURCE = "npm:pi-subagents@0.56.0"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _directory(path: Path, label: str) -> Path:
    """Require an existing, canonical directory without following links."""
    if not isinstance(path, Path) or not path.is_absolute() or path == Path("/"):
        raise ValueError(f"{label} must be an absolute directory")
    if normalized_absolute(path) != path or any(
        part in {".", ".."} for part in path.parts
    ):
        raise ValueError(f"{label} must be canonical")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except OSError as exc:
            raise ValueError(f"{label} must be an existing directory") from exc
        if stat.S_ISLNK(item.st_mode):
            # macOS's /var -> /private/var is a fixed system alias used by
            # tempfile.TemporaryDirectory; no user-controlled link is allowed.
            if current == Path("/var") and os.path.realpath(current) == "/private/var":
                continue
            raise ValueError(f"{label} contains a symlink")
        if current == path and not stat.S_ISDIR(item.st_mode):
            raise ValueError(f"{label} must be a directory")
        if current != path and not stat.S_ISDIR(item.st_mode):
            raise ValueError(f"{label} contains a non-directory component")
    return path


def _conflict(
    kind: ConflictKind,
    role: str | None,
    source_id: str,
    field: str,
    safe: str = "absent",
    observed: str = "present",
) -> PiConflict:
    # Inputs are deliberately converted to fixed labels.  In particular, do
    # not put settings values, package specs, paths, or exception text here.
    safe_id = (
        source_id
        if source_id in _MANAGED or source_id.startswith("pi-")
        else "pi-source"
    )
    safe_field = field if field.isidentifier() else "contract"
    return PiConflict(
        kind, role if role in _MANAGED else None, safe_id, safe_field, safe, observed
    )


def _json(path: Path, label: str) -> object:
    try:
        item = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise ValueError(f"{label} is not a regular file")
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _safe_contract_hash(contract: PiAgentContract) -> str:
    def plain(value: object) -> object:
        if isinstance(value, Mapping):
            return {str(k): plain(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [plain(item) for item in value]
        return value

    payload = {
        "role": contract.role,
        "frontmatter": plain(contract.frontmatter),
        "body": contract.body,
    }
    return hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _walk(root: Path, skip: Path):
    """Yield regular files beneath root; reject links and special files."""
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise ValueError("project resource discovery failed") from exc
        for entry in entries:
            path = directory / entry.name
            if path == skip or _under(path, skip):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ValueError("project resource discovery failed") from exc
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("project resource discovery encountered a symlink")
            if stat.S_ISDIR(info.st_mode):
                stack.append(path)
            elif stat.S_ISREG(info.st_mode):
                yield path
            else:
                raise ValueError("project resource discovery encountered unsafe data")


def _named_files(root: Path, name: str) -> list[Path]:
    """Inspect one conventional discovery directory, without broad walking."""
    directory = root / name
    try:
        item = os.lstat(directory)
    except FileNotFoundError:
        return []
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
        raise ValueError("Pi discovery directory is unsafe")
    result: list[Path] = []
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ValueError("Pi discovery file is unsafe")
            result.append(directory / entry.name)
    except OSError as exc:
        raise ValueError("Pi discovery directory cannot be inspected") from exc
    return result


def _settings_conflicts(settings: object, conflicts: list[PiConflict]) -> None:
    if settings is None:
        return
    if not isinstance(settings, Mapping):
        conflicts.append(
            _conflict("discovery", None, "pi-settings", "settings", observed="invalid")
        )
        return
    packages = settings.get("packages", [])
    if type(packages) is not list or any(type(item) is not str for item in packages):
        conflicts.append(
            _conflict(
                "package-drift", None, "pi-settings", "packages", observed="invalid"
            )
        )
    elif len(packages) != len(set(packages)):
        conflicts.append(
            _conflict(
                "package-drift", None, "pi-settings", "packages", observed="duplicate"
            )
        )
    else:
        identities = [item for item in packages if "pi-subagents" in item.casefold()]
        if identities != [] and identities != [_PACKAGE_SOURCE]:
            conflicts.append(
                _conflict(
                    "package-drift", None, "pi-package", "packages", observed="drift"
                )
            )
        if identities.count(_PACKAGE_SOURCE) > 1:
            conflicts.append(
                _conflict(
                    "package-drift",
                    None,
                    "pi-package",
                    "packages",
                    observed="duplicate",
                )
            )
    if "npmCommand" in settings:
        conflicts.append(
            _conflict(
                "package-drift", None, "pi-settings", "npmCommand", observed="custom"
            )
        )
    subagents = settings.get("subagents", {})
    if subagents is not None and not isinstance(subagents, Mapping):
        conflicts.append(
            _conflict("override", None, "pi-settings", "subagents", observed="invalid")
        )
        subagents = {}
    if isinstance(subagents, Mapping):
        for field in ("defaultModel", "defaultThinking", "defaultExtensions"):
            if field in subagents and subagents[field] not in (None, [], ""):
                conflicts.append(
                    _conflict(
                        "override", None, "pi-settings", field, observed="configured"
                    )
                )
        overrides = subagents.get("agentOverrides", {})
        if overrides is not None and not isinstance(overrides, Mapping):
            conflicts.append(
                _conflict(
                    "override",
                    None,
                    "pi-settings",
                    "agentOverrides",
                    observed="invalid",
                )
            )
        elif isinstance(overrides, Mapping):
            for role, override in overrides.items():
                if role not in _MANAGED or not isinstance(override, Mapping):
                    conflicts.append(
                        _conflict(
                            "override",
                            role if role in _MANAGED else None,
                            "pi-settings",
                            "agentOverrides",
                            observed="configured",
                        )
                    )
                    continue
                protected = {
                    "extensions",
                    "subagentOnlyExtensions",
                    "skills",
                    "model",
                    "fallbackModels",
                    "thinking",
                    "inheritSkills",
                    "inheritProjectContext",
                    "tools",
                }
                for field in sorted(set(override) & protected):
                    conflicts.append(
                        _conflict(
                            "override",
                            role,
                            "pi-settings",
                            field,
                            observed="configured",
                        )
                    )
    for field, kind in (
        ("extensions", "ambient-extension"),
        ("skills", "ambient-extension"),
        ("aliases", "alias"),
    ):
        value = settings.get(field)
        if value in (None, [], {}):
            continue
        if field == "aliases":
            aliases = (
                value
                if isinstance(value, (list, tuple))
                else list(value) + list(value.values())
                if isinstance(value, Mapping)
                else []
            )
            managed_aliases = [
                alias for alias in aliases if type(alias) is str and alias in _MANAGED
            ]
            if managed_aliases:
                conflicts.append(
                    _conflict(
                        "alias",
                        str(managed_aliases[0]),
                        "pi-settings",
                        "aliases",
                        observed="managed",
                    )
                )
        else:
            conflicts.append(
                _conflict(kind, None, "pi-settings", field, observed="configured")
            )


def inspect_effective_catalog(
    agent_dir: Path,
    rendered: Mapping[str, PiAgentContract],
    package: PiPackageEvidence,
    *,
    project_root: Path,
) -> PiEffectiveCatalog:
    """Inspect all effective Pi inputs without executing Pi or package code."""
    agent = _directory(agent_dir, "Pi agent directory")
    project = _directory(project_root, "Pi project root")
    if not isinstance(rendered, Mapping) or not isinstance(package, PiPackageEvidence):
        raise TypeError("Pi effective catalog inputs have invalid types")
    conflicts: list[PiConflict] = []
    managed: list[str] = []
    hashes: dict[str, str] = {}
    for key, contract in sorted(rendered.items(), key=lambda item: str(item[0])):
        if (
            key not in _MANAGED
            or not isinstance(contract, PiAgentContract)
            or contract.role != key
        ):
            conflicts.append(
                _conflict(
                    "discovery",
                    key if key in _MANAGED else None,
                    "pi-rendered",
                    "role",
                    observed="invalid",
                )
            )
            continue
        try:
            validate_pi_contract(
                key, contract.frontmatter, contract.body, allow_rendered_extension=True
            )
        except (TypeError, ValueError):
            conflicts.append(
                _conflict(
                    "discovery", key, "pi-rendered", "contract", observed="invalid"
                )
            )
            continue
        managed.append(key)
        hashes[key] = _safe_contract_hash(contract)
    if not managed:
        conflicts.append(
            _conflict("discovery", None, "pi-rendered", "roles", observed="empty")
        )
    elif not set(PI_DEFAULT_ROLES).issubset(managed):
        conflicts.append(
            _conflict("discovery", None, "pi-rendered", "roles", observed="incomplete")
        )
    if set(managed) != set(PI_DEFAULT_ROLES) and not set(managed).issubset(
        set(PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES)
    ):
        conflicts.append(
            _conflict("discovery", None, "pi-rendered", "roles", observed="unreviewed")
        )

    try:
        settings = _json(agent / "settings.json", "Pi settings")
    except ValueError:
        settings = object()
        conflicts.append(
            _conflict("discovery", None, "pi-settings", "settings", observed="invalid")
        )
    _settings_conflicts(settings, conflicts)
    try:
        package_config = _json(
            agent / "extensions/subagent/config.json", "Pi extension config"
        )
        if isinstance(package_config, Mapping):
            allowed = {
                "toolDescriptionMode",
                "inlineToolDisplay",
                "mainWindowRenderer",
                "foregroundDetachShortcut",
                "orcaProgressTabs",
                "asyncByDefault",
                "fleetView",
                "fleetViewPlacement",
                "fleetKeybindings",
                "asyncWidget",
                "waitTool",
                "resultScanLogging",
                "forceTopLevelAsync",
                "intercomBridge",
            }
            if set(package_config) - allowed:
                conflicts.append(
                    _conflict(
                        "override",
                        None,
                        "pi-extension-config",
                        "config",
                        observed="configured",
                    )
                )
        elif package_config is not None:
            conflicts.append(
                _conflict(
                    "discovery",
                    None,
                    "pi-extension-config",
                    "config",
                    observed="invalid",
                )
            )
    except ValueError:
        conflicts.append(
            _conflict(
                "discovery",
                None,
                "pi-extension-config",
                "config",
                observed="invalid",
            )
        )

    # Evidence must agree with the strict settings view.  The package object
    # itself is intentionally not trusted as a source of arbitrary strings.
    if package.status == "conflict" or (
        not package.package_identity_valid and package.status == "exact"
    ):
        conflicts.append(
            _conflict(
                "package-drift", None, "pi-package", "inventory", observed="drift"
            )
        )
    entries = tuple(item for item in package.package_entries if isinstance(item, str))
    if package.status == "exact" and entries != (_PACKAGE_SOURCE,):
        conflicts.append(
            _conflict("package-drift", None, "pi-package", "packages", observed="drift")
        )
    if package.status == "absent" and entries:
        conflicts.append(
            _conflict(
                "package-drift", None, "pi-package", "packages", observed="present"
            )
        )
    if package.status not in {"absent", "exact"}:
        conflicts.append(
            _conflict("package-drift", None, "pi-package", "status", observed="drift")
        )
    if isinstance(settings, Mapping):
        configured = settings.get("packages", [])
        if type(configured) is list:
            identities = tuple(
                item
                for item in configured
                if isinstance(item, str) and "pi-subagents" in item.casefold()
            )
            if package.status == "absent" and identities:
                conflicts.append(
                    _conflict(
                        "package-drift",
                        None,
                        "pi-package",
                        "packages",
                        observed="present",
                    )
                )
            if package.status == "exact" and identities != (_PACKAGE_SOURCE,):
                conflicts.append(
                    _conflict(
                        "package-drift",
                        None,
                        "pi-package",
                        "packages",
                        observed="drift",
                    )
                )
    elif package.status == "exact":
        conflicts.append(
            _conflict(
                "package-drift", None, "pi-package", "settings", observed="missing"
            )
        )

    # Existing managed destination files would be overwritten by local apply.
    managed_paths = {f"agents/{role}.md": role for role in _MANAGED}
    try:
        for path in _named_files(agent, "agents"):
            role = managed_paths.get(path.relative_to(agent).as_posix())
            if role is not None:
                conflicts.append(
                    _conflict(
                        "path-collision",
                        role,
                        "pi-agent",
                        "destination",
                        observed="present",
                    )
                )
    except ValueError:
        conflicts.append(
            _conflict("discovery", None, "pi-agent", "inventory", observed="invalid")
        )

    # Project resources are only considered within the explicit root and the
    # selected Pi home is excluded, preventing accidental ambient-home reads.
    try:
        project_settings = project / "settings.json"
        if project_settings.exists() and not _under(project_settings, agent):
            conflicts.append(
                _conflict(
                    "ambient-extension",
                    None,
                    "pi-project",
                    "projectSettings",
                    observed="configured",
                )
            )
        if _named_files(project, "agents"):
            conflicts.append(
                _conflict(
                    "ambient-extension",
                    None,
                    "pi-project",
                    "projectAgents",
                    observed="configured",
                )
            )
        if _named_files(project, "extensions"):
            conflicts.append(
                _conflict(
                    "ambient-extension",
                    None,
                    "pi-project",
                    "projectExtensions",
                    observed="configured",
                )
            )
    except ValueError:
        conflicts.append(
            _conflict("discovery", None, "pi-project", "inventory", observed="invalid")
        )

    # Compare against repository-owned source identity.  The validator's
    # rendered extension is normalized through the same safe renderer, so a
    # modified contract cannot masquerade as the checked-in source.
    for role in tuple(managed):
        source = _REPOSITORY_ROOT / "pi/agents" / f"{role}.md"
        try:
            source_bytes = source.read_bytes()
            expected = validate_pi_agent(role, source_bytes)
            if role == "code-validator":
                expected = validate_pi_agent(
                    role,
                    render_pi_source(source_bytes, agent_dir=agent),
                    allow_rendered_extension=True,
                )
            if _safe_contract_hash(expected) != _safe_contract_hash(rendered[role]):
                conflicts.append(
                    _conflict(
                        "discovery", role, "pi-source", "source_hash", observed="drift"
                    )
                )
            hashes[role] = hashlib.sha256(source_bytes).hexdigest()
        except (OSError, ValueError):
            conflicts.append(
                _conflict(
                    "discovery", role, "pi-source", "source_hash", observed="invalid"
                )
            )

    # Manifest inventory is a direct, bounded read, never a recursive package
    # search.  The policy itself is repository-owned and supplies the reviewed
    # bundled identity set.
    bundled = tuple(PI_BUNDLED_ROLES)
    policy: object = None
    try:
        policy = _json(PACKAGE_POLICY_PATH, "Pi package policy")
        if (
            not isinstance(policy, Mapping)
            or tuple(policy.get("bundledAgents", ())) != bundled
        ):
            conflicts.append(
                _conflict(
                    "package-drift",
                    None,
                    "pi-package",
                    "bundledAgents",
                    observed="drift",
                )
            )
    except ValueError:
        conflicts.append(
            _conflict("package-drift", None, "pi-package", "policy", observed="invalid")
        )
    if package.package_manifest_path is not None:
        try:
            if not _under(package.package_manifest_path, agent):
                raise ValueError("manifest escapes Pi home")
            manifest = _json(package.package_manifest_path, "Pi package manifest")
            if isinstance(manifest, Mapping):
                names = manifest.get("agents", manifest.get("bundledAgents", []))
                file_names = manifest.get("files", [])
                if isinstance(file_names, list):
                    names = list(names) if isinstance(names, list) else []
                    names.extend(
                        item.removeprefix("agents/").removesuffix(".md")
                        for item in file_names
                        if isinstance(item, str) and item.startswith("agents/")
                    )
                if isinstance(names, list) and any(name in _MANAGED for name in names):
                    conflicts.append(
                        _conflict(
                            "path-collision",
                            None,
                            "pi-package",
                            "agents",
                            observed="managed",
                        )
                    )
                if package.manifest_hash != (
                    policy.get("packageJsonSha256")
                    if isinstance(policy, Mapping)
                    else None
                ):
                    conflicts.append(
                        _conflict(
                            "package-drift",
                            None,
                            "pi-package",
                            "manifest",
                            observed="drift",
                        )
                    )
            elif manifest is None:
                conflicts.append(
                    _conflict(
                        "package-drift",
                        None,
                        "pi-package",
                        "manifest",
                        observed="missing",
                    )
                )
                if isinstance(names, list) and any(
                    name not in bundled for name in names
                ):
                    conflicts.append(
                        _conflict(
                            "discovery",
                            None,
                            "pi-package",
                            "agents",
                            observed="unreviewed",
                        )
                    )
        except ValueError:
            conflicts.append(
                _conflict(
                    "package-drift", None, "pi-package", "manifest", observed="invalid"
                )
            )

    conflicts = sorted(
        set(conflicts),
        key=lambda item: (
            item.kind,
            item.role or "",
            item.source_id,
            item.field,
            item.observed_value,
        ),
    )
    return PiEffectiveCatalog(
        tuple(role for role in PI_DEFAULT_ROLES if role in managed),
        bundled,
        tuple(role for role in PI_OPTIONAL_ROLES if role in managed),
        tuple(conflicts),
        MappingProxyType(dict(sorted(hashes.items()))),
    )
