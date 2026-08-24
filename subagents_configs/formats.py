"""Native catalog parsing and fail-closed semantic validation."""

from __future__ import annotations

import hashlib
import os
import stat
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import filesystem
from .models import SourceSpec, Target
from .paths import normalized_absolute, strict_relative_path
from .targets import DESCRIPTORS, selected_sources


@dataclass(frozen=True)
class ValidatedSource:
    spec: SourceSpec
    content: bytes
    sha256: str
    parsed: Mapping[str, object] | None


def validate_toml_agent(path: Path, content: bytes) -> Mapping[str, object]:
    """Parse a complete Codex TOML agent and require a top-level mapping."""
    try:
        parsed = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid TOML agent {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"invalid TOML agent {path}: expected a mapping")
    return parsed


def validate_yaml_agent(path: Path, content: bytes) -> Mapping[str, object]:
    """Parse YAML frontmatter lazily so Codex-only use needs no PyYAML."""
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to validate YAML agent sources") from exc

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid YAML agent {path}: not UTF-8") from exc
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError(f"invalid YAML agent {path}: missing opening frontmatter")
    try:
        closing = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError(
            f"invalid YAML agent {path}: missing closing frontmatter"
        ) from exc
    try:
        parsed = yaml.safe_load("\n".join(lines[1:closing]))
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML agent {path}: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise ValueError(f"invalid YAML agent {path}: frontmatter must be a mapping")
    return dict(parsed)


def _text_value(parsed: Mapping[str, object], key: str) -> str:
    value = parsed.get(key)
    return value if isinstance(value, str) else ""


def _require_body_concepts(path_role: str, body: str, concepts: Sequence[str]) -> None:
    lowered = body.lower()
    missing = [concept for concept in concepts if concept.lower() not in lowered]
    if missing:
        raise ValueError(
            f"unsafe or incomplete agent {path_role}: missing {', '.join(missing)}"
        )


def _reject_opencode_permission_escalation(
    parsed: Mapping[str, object], role: str
) -> None:
    permission = parsed.get("permission")
    if permission is None:
        return
    if not isinstance(permission, Mapping):
        raise ValueError(f"unsafe permission declaration in {role}")
    protected = {"edit", "bash", "external_directory", "webfetch", "task"}
    for key, value in permission.items():
        if key in protected and value != "deny":
            raise ValueError(f"unsafe permission declaration in {role}: {key}")


def _claude_tool_names(value: object) -> set[str]:
    if isinstance(value, str):
        return {part.strip() for part in value.split(",") if part.strip()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return {item for item in value if isinstance(item, str)}
    return set()


def _reject_claude_tool_escalation(parsed: Mapping[str, object], role: str) -> None:
    unsafe_names = {
        "Agent",
        "MCP",
        "Skill",
        "WebFetch",
        "WebSearch",
        "Write",
        "acceptEdits",
        "bypassPermissions",
    }
    tools = _claude_tool_names(parsed.get("tools"))
    if tools & unsafe_names or any(
        any(
            fragment in tool.lower()
            for fragment in ("mcp", "network", "webfetch", "websearch")
        )
        for tool in tools
    ):
        raise ValueError(f"unsafe tool declaration in {role}")
    permission_mode = parsed.get("permissionMode")
    if permission_mode in {"acceptEdits", "bypassPermissions"}:
        raise ValueError(f"unsafe permission declaration in {role}")


def validate_agent_semantics(
    target: Target,
    role: str,
    parsed: Mapping[str, object],
    body: str,
) -> None:
    """Reject unknown roles and authority increases in native definitions."""
    expected_roles = {
        "code-explorer",
        "code-reviewer",
        "code-validator",
        "quick-implementer",
        "implementer",
        "commit-pusher",
    }
    if role not in expected_roles:
        raise ValueError(f"unknown role: {role}")
    if _text_value(parsed, "name") != role:
        raise ValueError(f"agent name does not match source role: {role}")

    if target is Target.CODEX:
        if (
            role in {"code-explorer", "code-reviewer"}
            and parsed.get("sandbox_mode") != "read-only"
        ):
            raise ValueError(f"Codex {role} must use sandbox_mode=read-only")
        if role == "code-validator" and parsed.get("model") != "gpt-5.6-luna":
            raise ValueError("Codex code-validator must use gpt-5.6-luna")
        for key in ("sandbox_mode", "network_access"):
            if parsed.get(key) in {
                "workspace-write",
                "acceptEdits",
                "bypassPermissions",
                True,
            }:
                raise ValueError(f"unsafe Codex permission in {role}: {key}")
    elif target is Target.OPENCODE:
        _reject_opencode_permission_escalation(parsed, role)
        if role in {"code-explorer", "code-reviewer"}:
            if parsed.get("mode") != "subagent":
                raise ValueError(f"OpenCode {role} must use mode=subagent")
            expected = {
                "edit": "deny",
                "bash": "deny",
                "external_directory": "deny",
                "webfetch": "deny",
                "task": "deny",
            }
            if parsed.get("permission") != expected:
                raise ValueError(f"OpenCode {role} has unsafe read permissions")
        if role == "code-validator" and parsed.get("model") != "openai/gpt-5.6-luna":
            raise ValueError("OpenCode code-validator must use openai/gpt-5.6-luna")
    elif target is Target.CLAUDE_CODE:
        _reject_claude_tool_escalation(parsed, role)
        if role in {"code-explorer", "code-reviewer"}:
            if (
                parsed.get("tools") != "Read, Grep, Glob"
                or parsed.get("permissionMode") != "plan"
            ):
                raise ValueError(f"Claude {role} must be plan-mode read-only")
        if role == "code-validator" and parsed.get("model") != "inherit":
            raise ValueError("Claude code-validator must use model=inherit")

    unsafe_values = {"workspace-write", "acceptEdits", "bypassPermissions"}
    if any(
        isinstance(value, str) and value in unsafe_values for value in parsed.values()
    ):
        raise ValueError(f"unsafe permission declaration in {role}")

    if role == "code-validator":
        _require_body_concepts(
            role,
            body,
            (
                "{{VALIDATION_HELPER}}",
                "only through",
                "refuses direct validation",
                "fails closed",
                "verified backend",
            ),
        )
    if role == "code-reviewer":
        _require_body_concepts(
            role,
            body,
            (
                "P0",
                "P1",
                "P2",
                "P3",
                "security",
                "reliability",
                "path:line",
                "APPROVE",
                "REQUEST_CHANGES",
                "COMMENT",
            ),
        )
    if role == "commit-pusher":
        _require_body_concepts(
            role,
            body,
            ("both a commit and a push", "separate explicit", "never force-push"),
        )


def _validate_source_spec(spec: SourceSpec) -> None:
    source = spec.source
    if source.is_absolute() or ".." in source.parts:
        raise ValueError(f"unsafe source path: {spec.source}")


def _read_source(repo_root: Path, spec: SourceSpec) -> bytes:
    """Read a source through pinned descriptor-relative no-follow handles."""
    _validate_source_spec(spec)
    # The temporary-test root may be exposed through macOS's /private alias;
    # canonicalize only that trusted repository root before no-follow traversal
    # of every source component.
    root = Path(os.path.realpath(normalized_absolute(repo_root)))
    parts = spec.source.parts
    with filesystem._pinned_directory(root, "source repository") as root_fd:
        parent_fd = root_fd
        opened: list[int] = []
        try:
            for component in parts[:-1]:
                child = filesystem._open_directory_component(
                    component, parent_fd, "source directory"
                )
                opened.append(child)
                parent_fd = child
            expected = filesystem._stat_at_no_follow(parent_fd, parts[-1])
            if expected is None:
                raise ValueError(f"missing source: {spec.source}")
            if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
                raise ValueError(f"source is not a regular file: {spec.source}")
            expected_identity = (expected.st_dev, expected.st_ino)
            filesystem._after_parent_pin("source-read", root / spec.source.parent)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(parts[-1], flags, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise ValueError(f"missing source: {spec.source}") from exc
            except OSError as exc:
                raise ValueError(
                    f"source must not be a symlink: {spec.source}"
                ) from exc
            try:
                result = os.fstat(descriptor)
                if stat.S_ISLNK(result.st_mode) or not stat.S_ISREG(result.st_mode):
                    raise ValueError(f"source is not a regular file: {spec.source}")
                if (result.st_dev, result.st_ino) != expected_identity:
                    raise ValueError(f"source changed during read: {spec.source}")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                os.close(descriptor)
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)


def validate_source_inventory(
    repo_root: Path,
    target: Target,
    specs: Sequence[SourceSpec],
) -> tuple[ValidatedSource, ...]:
    """Validate every explicit source before returning any inventory item."""
    seen: set[str] = set()
    destinations: set[str] = set()
    parsed_roles: set[str] = set()
    result: list[ValidatedSource] = []
    for spec in specs:
        if spec.identifier in seen:
            raise ValueError(f"duplicate source identifier: {spec.identifier}")
        seen.add(spec.identifier)
        if spec.destination is not None:
            try:
                destination = strict_relative_path(str(spec.destination)).as_posix()
            except ValueError as exc:
                raise ValueError(
                    f"unsafe source destination: {spec.destination}"
                ) from exc
            if destination in destinations:
                raise ValueError(f"duplicate source destination: {destination}")
            destinations.add(destination)
        content = _read_source(repo_root, spec)
        if not content.strip():
            raise ValueError(f"empty source: {spec.source}")
        placeholder = b"{{VALIDATION_HELPER}}"
        if placeholder in content and spec.identifier != "code-validator":
            raise ValueError(
                f"validation placeholder is restricted to code-validator: {spec.source}"
            )
        if spec.kind == "agent" and spec.identifier == "code-validator":
            if placeholder not in content:
                raise ValueError(
                    "code-validator source is missing validation placeholder"
                )
        parsed: Mapping[str, object] | None = None
        try:
            body = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"malformed UTF-8 source: {spec.source}") from exc
        if spec.kind == "agent":
            if spec.source_format == "toml":
                parsed = validate_toml_agent(Path(spec.source), content)
            elif spec.source_format == "yaml-frontmatter":
                parsed = validate_yaml_agent(Path(spec.source), content)
            else:
                raise ValueError(f"unsupported agent format: {spec.source_format}")
            parsed_role = parsed.get("name")
            if isinstance(parsed_role, str) and parsed_role in parsed_roles:
                raise ValueError(f"duplicate parsed role: {parsed_role}")
            if isinstance(parsed_role, str):
                parsed_roles.add(parsed_role)
            validate_agent_semantics(target, spec.identifier, parsed, body)
        elif spec.kind in {"routing-source", "project-template"}:
            if spec.source_format != "markdown":
                raise ValueError(f"invalid policy format: {spec.source}")
            if "@/absolute/path" in body:
                raise ValueError(f"unsafe absolute import in policy: {spec.source}")
        elif spec.kind == "validation-runtime":
            if spec.source_format != "python":
                raise ValueError(f"invalid validation runtime format: {spec.source}")
            try:
                compile(body, str(spec.source), "exec")
            except SyntaxError as exc:
                raise ValueError(f"malformed Python source: {spec.source}") from exc
        else:
            raise ValueError(f"unsupported source kind: {spec.kind}")
        result.append(
            ValidatedSource(
                spec=spec,
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                parsed=parsed,
            )
        )
    return tuple(result)


def validate_all_catalogs(repo_root: Path) -> None:
    """Validate native agents and policy sources for every active target."""
    for target, descriptor in DESCRIPTORS.items():
        specs = tuple(
            spec
            for spec in selected_sources(descriptor, include_commit_pusher=True)
            if spec.kind in {"agent", "routing-source", "project-template"}
        )
        try:
            validate_source_inventory(repo_root, target, specs)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError(f"{target.value}: {exc}") from exc
