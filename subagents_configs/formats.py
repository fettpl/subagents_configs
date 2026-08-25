"""Native catalog parsing and fail-closed semantic validation."""

from __future__ import annotations

import ast
import hashlib
import os
import stat
import tomllib
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import filesystem
from .models import SourceSpec, Target
from .paths import normalized_absolute, strict_relative_path
from .targets import (
    CAPABILITIES,
    descriptor_for,
    parser_for,
    selected_sources,
    semantic_validator_for,
)

_COMMAND_GATE_SHA256 = (
    "834025bb3af05ef4f6fc3977be9ff81c2c136ea6c9fc213f37aefe83de7ba270"
)

# One normalized role contract is the sole semantic source for native overlays.
# Values are policy metadata, never prompt bodies or private source contents.
_ROLES = (
    "code-explorer",
    "code-reviewer",
    "code-validator",
    "quick-implementer",
    "implementer",
    "commit-pusher",
)
ROLE_POLICY = {
    "codex": {
        role: {
            "optional": role == "commit-pusher",
            "read_only": role in {"code-explorer", "code-reviewer", "code-validator"},
            "overlay": {
                "model": "gpt-5.6-sol" if role == "code-reviewer" else "gpt-5.6-luna",
                "model_reasoning_effort": "medium" if role == "implementer" else "low",
                **(
                    {"sandbox_mode": "read-only"}
                    if role in {"code-explorer", "code-reviewer"}
                    else {}
                ),
            },
        }
        for role in _ROLES
    },
    "opencode": {
        role: {
            "optional": role == "commit-pusher",
            "read_only": role in {"code-explorer", "code-reviewer", "code-validator"},
            "overlay": {
                "model": "openai/gpt-5.6-luna",
                "mode": "subagent",
                **(
                    {
                        "permission": {
                            "edit": "deny",
                            "bash": "deny",
                            "external_directory": "deny",
                            "webfetch": "deny",
                            "websearch": "deny",
                            "task": "deny",
                            "skill": "deny",
                        }
                    }
                    if role in {"code-explorer", "code-reviewer"}
                    else {}
                ),
                **(
                    {
                        "permission": {
                            "edit": "deny",
                            "webfetch": "deny",
                            "websearch": "deny",
                            "task": "deny",
                            "skill": "deny",
                            "external_directory": {
                                "*": "deny",
                                "{{VALIDATION_HELPER}}": "allow",
                            },
                            "bash": {
                                "*": "deny",
                                "python3 {{VALIDATION_HELPER}} -- *": "allow",
                            },
                        }
                    }
                    if role == "code-validator"
                    else {}
                ),
            },
        }
        for role in _ROLES
    },
    "claude-code": {
        role: {
            "optional": role == "commit-pusher",
            "read_only": role in {"code-explorer", "code-reviewer", "code-validator"},
            "overlay": {
                "model": "inherit",
                "tools": {
                    "code-explorer": "Read, Grep, Glob",
                    "code-reviewer": "Read, Grep, Glob",
                    "code-validator": "Read, Grep, Glob, Bash",
                    "quick-implementer": "Read, Grep, Glob, Edit, Bash",
                    "implementer": "Read, Grep, Glob, Edit, Bash",
                    "commit-pusher": "Read, Grep, Glob, Bash",
                }[role],
                **(
                    {"permissionMode": "plan"}
                    if role in {"code-explorer", "code-reviewer"}
                    else {}
                ),
            },
        }
        for role in _ROLES
    },
}


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

    class _StrictLoader(yaml.SafeLoader):
        pass

    def _mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None, None, "duplicate YAML frontmatter key", key_node.start_mark
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    _StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping
    )
    try:
        parsed = yaml.load(
            "\n".join(lines[1:closing]),
            Loader=_StrictLoader,  # noqa: S506
        )
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML agent {path}: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise ValueError(f"invalid YAML agent {path}: frontmatter must be a mapping")
    parsed = dict(parsed)
    allowed = {
        "name",
        "description",
        "mode",
        "model",
        "permission",
        "tools",
        "permissionMode",
        "hooks",
    }
    unknown = set(parsed) - allowed
    if unknown:
        raise ValueError(f"invalid YAML agent {path}: unknown frontmatter fields")
    return parsed


def validate_validation_helper(value: str) -> str:
    """Validate a helper path before embedding it in agent source contexts."""
    if type(value) is not str or not value or not Path(value).is_absolute():
        raise ValueError("validation helper path must be absolute")
    if "{{VALIDATION_HELPER}}" in value:
        raise ValueError("validation helper path must not contain the placeholder")
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        or character in {"\u2028", "\u2029", '"', "\\", "`", "{", "}"}
        for character in value
    ):
        raise ValueError("validation helper path contains unsafe rendering characters")
    path = Path(value)
    if path.name != "run-validation-isolated.py" or ".." in path.parts:
        raise ValueError("validation helper path is not the pinned helper")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("validation helper path is not valid UTF-8") from exc
    return value


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
    protected = {
        "edit",
        "bash",
        "external_directory",
        "webfetch",
        "websearch",
        "task",
        "skill",
    }
    for key, value in permission.items():
        if role == "code-validator" and key in {"bash", "external_directory"}:
            continue
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


def _validate_command_gate_source(content: bytes, source: Path) -> None:
    """Require the command gate's fail-closed AST contract, not syntax only."""
    try:
        tree = ast.parse(content.decode("utf-8"), str(source), "exec")
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise ValueError(f"malformed command gate source: {source}") from exc
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imports.update(
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    if imports & {
        "subprocess",
        "os",
        "socket",
        "urllib",
        "requests",
        "http",
        "shutil",
    }:
        raise ValueError("command gate source imports an unsafe module")
    forbidden_calls = {
        "eval",
        "exec",
        "system",
        "popen",
        "run",
        "Popen",
        "check_call",
        "check_output",
        "create_subprocess_exec",
        "create_subprocess_shell",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if name in forbidden_calls:
                raise ValueError("command gate source can execute commands")
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    required_functions = {
        "parse_pretooluse_event",
        "validate_validator_command",
        "hook_main",
        "_safe_relative_argument",
        "_safe_helper",
    }
    if not required_functions <= set(functions):
        raise ValueError("command gate source is missing required functions")
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    required_literals = {
        "PreToolUse",
        "Bash",
        "python3",
        "--",
        "validation command denied\n",
        "bash",
        "env",
        "python",
        "*",
        "?",
        "~",
        ";",
        "&",
        "|",
        "<",
        ">",
        "$",
    }
    if not required_literals <= literals:
        raise ValueError("command gate source is missing fixed policy constants")
    hook = functions["hook_main"]
    hook_calls = {
        node.func.id
        for node in ast.walk(hook)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    returns = {
        node.value.value
        for node in ast.walk(hook)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Constant)
        and type(node.value.value) is int
    }
    if not {"parse_pretooluse_event", "validate_validator_command"} <= hook_calls:
        raise ValueError("command gate hook does not validate events")
    if not {0, 2} <= returns:
        raise ValueError("command gate hook lacks fixed allow/deny statuses")
    if hashlib.sha256(content).hexdigest() != _COMMAND_GATE_SHA256:
        raise ValueError("command gate source digest is not pinned")


def validate_agent_semantics(
    target: Target,
    role: str,
    parsed: Mapping[str, object],
    body: str,
    *,
    validation_helper: str = "{{VALIDATION_HELPER}}",
    hook_path: str = "{{CLAUDE_HOOK}}",
) -> None:
    """Reject unknown roles and authority increases in native definitions."""
    expected_roles = set(ROLE_POLICY.get(target.value, {}))
    if role not in expected_roles:
        raise ValueError(f"unknown role: {role}")
    if _text_value(parsed, "name") != role:
        raise ValueError(f"agent name does not match source role: {role}")
    if target is Target.OPENCODE:
        allowed_fields = {"name", "description", "mode", "model", "permission"}
    elif target is Target.CLAUDE_CODE:
        allowed_fields = {
            "name",
            "description",
            "tools",
            "model",
            "permissionMode",
            "hooks",
        }
    else:
        allowed_fields = set(parsed)
    if set(parsed) - allowed_fields:
        raise ValueError(f"unknown {target.value} agent frontmatter field")
    policy = ROLE_POLICY[target.value][role]["overlay"]

    if target is Target.CODEX:
        if "sandbox_mode" in parsed and "sandbox_mode" not in policy:
            raise ValueError(f"Codex {role} has an unexpected sandbox mode")
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
        if "permission" in parsed and "permission" not in policy:
            raise ValueError(f"OpenCode {role} has unexpected permissions")
    elif target is Target.CLAUDE_CODE:
        _reject_claude_tool_escalation(parsed, role)
        if "permissionMode" in parsed and "permissionMode" not in policy:
            raise ValueError(f"Claude {role} has an unexpected permission mode")
        if role != "code-validator" and "hooks" in parsed:
            raise ValueError(f"Claude {role} has an unexpected hook")

    if validation_helper != "{{VALIDATION_HELPER}}":
        validation_helper = validate_validation_helper(validation_helper)

    def render_policy(value: object) -> object:
        if isinstance(value, str):
            return value.replace("{{VALIDATION_HELPER}}", validation_helper)
        if isinstance(value, Mapping):
            return {
                render_policy(key) if isinstance(key, str) else key: render_policy(item)
                for key, item in value.items()
            }
        return value

    if target is Target.OPENCODE and "permission" in policy:
        expected_permission = render_policy(policy["permission"])
        if parsed.get("permission") != expected_permission:
            if role == "code-validator":
                raise ValueError("unsafe validator permissions")
            raise ValueError(f"OpenCode {role} has unsafe read permissions")

    for key, expected in policy.items():
        if key not in parsed or parsed[key] != render_policy(expected):
            raise ValueError(
                f"{target.value} {role} disagrees with canonical role policy"
            )
    if target is Target.OPENCODE and "permission" in policy:
        expected_permission = render_policy(policy["permission"])
        permission = parsed["permission"]
        if tuple(permission) != tuple(expected_permission):
            raise ValueError(f"OpenCode {role} has unsafe permission order")
        for key, expected_rules in expected_permission.items():
            if isinstance(expected_rules, Mapping):
                rules = permission.get(key)
                if not isinstance(rules, Mapping) or tuple(rules) != tuple(
                    expected_rules
                ):
                    raise ValueError("unsafe validator permissions")

    unsafe_values = {"workspace-write", "acceptEdits", "bypassPermissions"}
    if any(
        isinstance(value, str) and value in unsafe_values for value in parsed.values()
    ):
        raise ValueError(f"unsafe permission declaration in {role}")

    if role == "code-validator":
        if validation_helper != "{{VALIDATION_HELPER}}":
            validation_helper = validate_validation_helper(validation_helper)
        _require_body_concepts(
            role,
            body,
            (
                validation_helper,
                "only through",
                "refuses direct validation",
                "fails closed",
                "verified backend",
            ),
        )
        if target is Target.CLAUDE_CODE:
            _require_body_concepts(
                role,
                body,
                ("PreToolUse", "technical command gate", "never executes"),
            )
            expected_hooks = {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": hook_path, "args": []},
                        ],
                    }
                ]
            }
            if parsed.get("hooks") != expected_hooks:
                raise ValueError("Claude validator hook contract is not exact")
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


def _validate_agent_with_registry(
    target: Target,
    role: str,
    parsed: Mapping[str, object],
    body: str,
    *,
    validation_helper: str = "{{VALIDATION_HELPER}}",
    hook_path: str = "{{CLAUDE_HOOK}}",
) -> None:
    validator = semantic_validator_for(target)
    if validator != "agent":
        raise ValueError(f"unsupported semantic validator: {validator}")
    validate_agent_semantics(
        target,
        role,
        parsed,
        body,
        validation_helper=validation_helper,
        hook_path=hook_path,
    )


def validate_rendered_agent(
    target: Target,
    role: str,
    path: Path,
    content: bytes,
    validation_helper: str,
    hook_path: str = "{{CLAUDE_HOOK}}",
) -> Mapping[str, object]:
    """Parse and semantically validate an agent after helper substitution."""
    helper = validate_validation_helper(validation_helper)
    try:
        body = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"malformed UTF-8 rendered agent: {path}") from exc
    parser = parser_for(target)
    if parser == "toml":
        parsed = validate_toml_agent(path, content)
    elif parser == "yaml-frontmatter":
        parsed = validate_yaml_agent(path, content)
    else:
        raise ValueError(f"unsupported rendered agent parser: {parser}")
    _validate_agent_with_registry(
        target,
        role,
        parsed,
        body,
        validation_helper=helper,
        hook_path=hook_path,
    )
    return parsed


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
    *,
    require_commit_pusher: bool = False,
    cache: filesystem.CommandCache | None = None,
) -> tuple[ValidatedSource, ...]:
    """Validate every explicit source before returning any inventory item."""
    seen: set[str] = set()
    destinations: set[str] = set()
    parsed_roles: set[str] = set()
    parsed_by_role: dict[str, Mapping[str, object]] = {}
    pending_agents: list[tuple[SourceSpec, Mapping[str, object], str]] = []
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
        hook_placeholder = b"{{CLAUDE_HOOK}}"
        if (
            placeholder in content or hook_placeholder in content
        ) and spec.identifier != "code-validator":
            raise ValueError(
                f"agent placeholder is restricted to code-validator: {spec.source}"
            )
        if spec.kind == "agent" and spec.identifier == "code-validator":
            if placeholder not in content:
                raise ValueError(
                    "code-validator source is missing validation placeholder"
                )
            if target is Target.CLAUDE_CODE and hook_placeholder not in content:
                raise ValueError("Claude validator source is missing hook placeholder")
        parsed: Mapping[str, object] | None = None
        try:
            body = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"malformed UTF-8 source: {spec.source}") from exc
        if spec.kind == "agent":
            parser = parser_for(target)
            if spec.source_format != parser:
                raise ValueError(
                    f"agent source format disagrees with registry: {spec.source}"
                )
            if parser == "toml":
                parsed = validate_toml_agent(Path(spec.source), content)
            elif parser == "yaml-frontmatter":
                parsed = validate_yaml_agent(Path(spec.source), content)
            else:
                raise ValueError(f"unsupported agent parser: {parser}")
            parsed_role = parsed.get("name")
            if isinstance(parsed_role, str) and parsed_role in parsed_roles:
                raise ValueError(f"duplicate parsed role: {parsed_role}")
            if isinstance(parsed_role, str):
                parsed_roles.add(parsed_role)
                parsed_by_role[parsed_role] = parsed
            pending_agents.append((spec, parsed, body))
        elif spec.kind in {"routing-source", "project-template"}:
            if spec.source_format != "markdown":
                raise ValueError(f"invalid policy format: {spec.source}")
            if "@/absolute/path" in body:
                raise ValueError(f"unsafe absolute import in policy: {spec.source}")
        elif spec.kind in {"validation-runtime", "command-gate"}:
            if spec.source_format != "python":
                raise ValueError(f"invalid Python source format: {spec.source}")
            if spec.kind == "command-gate":
                _validate_command_gate_source(content, Path(spec.source))
            else:
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
    for spec, parsed, body in pending_agents:
        _validate_agent_with_registry(target, spec.identifier, parsed, body)
    if parsed_roles and sum(spec.kind == "agent" for spec in specs) >= 5:
        required_roles = {
            "code-explorer",
            "code-reviewer",
            "code-validator",
            "quick-implementer",
            "implementer",
        }
        supplied_roles = parsed_roles
        if not required_roles <= supplied_roles or not supplied_roles <= (
            required_roles | {"commit-pusher"}
        ):
            raise ValueError("incomplete agent role inventory")
        selected_optional = {
            spec.optional_role for spec in specs if spec.optional_role is not None
        }
        if (
            "commit-pusher" in supplied_roles
            and "commit-pusher" not in selected_optional
        ):
            raise ValueError("optional role inventory is inconsistent")
        if (
            "commit-pusher" not in supplied_roles
            and "commit-pusher" in selected_optional
        ):
            raise ValueError("optional role inventory is inconsistent")
        if require_commit_pusher and "commit-pusher" not in supplied_roles:
            raise ValueError("required optional role is missing")
        if required_roles <= supplied_roles:
            for role, parsed in parsed_by_role.items():
                required_overlay = set(ROLE_POLICY[target.value][role]["overlay"])
                if not required_overlay <= set(parsed):
                    raise ValueError("incomplete role semantics")
    return tuple(result)


def validate_all_catalogs(repo_root: Path) -> None:
    """Validate native agents and policy sources for every active target."""
    for capability in CAPABILITIES:
        target = capability.target
        descriptor = descriptor_for(target)
        specs = tuple(
            spec
            for spec in selected_sources(descriptor, include_commit_pusher=True)
            if spec.kind
            in {
                "agent",
                "routing-source",
                "project-template",
                "command-gate",
            }
        )
        try:
            validate_source_inventory(
                repo_root, target, specs, require_commit_pusher=True
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError(f"{target.value}: {exc}") from exc
