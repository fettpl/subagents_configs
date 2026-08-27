"""Strict, repository-owned catalog for Pi-native subagents.

Pi's Markdown frontmatter is deliberately parsed here rather than through the
other clients' semantic policy.  The Pi package inherits the parent model and
has a different extension model, so accepting a familiar field from another
client would be an authority increase.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .paths import normalized_absolute

PI_DEFAULT_ROLES = (
    "code-explorer",
    "code-reviewer",
    "code-validator",
    "quick-implementer",
    "implementer",
)
PI_OPTIONAL_ROLES = ("commit-pusher",)
PI_BUNDLED_ROLES = (
    "delegate",
    "oracle",
    "researcher",
    "reviewer",
    "scout",
    "worker",
)

READ_TOOLS = ("read", "grep", "find", "ls")
WRITE_TOOLS = ("read", "grep", "find", "ls", "write", "edit", "bash")
VALIDATOR_TOOLS = ("read", "grep", "find", "ls", "run_validation")
PUSHER_TOOLS = ("read", "grep", "find", "ls", "bash")
PI_VALIDATION_EXTENSION = "{{PI_VALIDATION_EXTENSION}}"
PI_VALIDATION_EXTENSION_PATH = "extensions/subagents-configs-run-validation.ts"

_ALL_ROLES = PI_DEFAULT_ROLES + PI_OPTIONAL_ROLES
_FRONTMATTER_FIELDS = frozenset(
    {
        "name",
        "description",
        "systemPromptMode",
        "inheritProjectContext",
        "inheritSkills",
        "tools",
        "skills",
        "extensions",
        "subagentOnlyExtensions",
    }
)
_PLACEHOLDER_RE = re.compile(r"\{\{[^{}\r\n]+\}\}")


@dataclass(frozen=True)
class PiAgentContract:
    """The bounded, normalized contract accepted for one managed Pi role."""

    role: str
    name: str
    description: str
    system_prompt_mode: str
    inherit_project_context: bool
    inherit_skills: bool
    tools: tuple[str, ...]
    skills: tuple[str, ...]
    extensions: tuple[str, ...]
    subagent_only_extensions: tuple[str, ...]
    body: str
    frontmatter: Mapping[str, object]


def normalize_model_policy(frontmatter: Mapping[str, object]) -> str:
    """Return Pi's only safe model policy: inherit from the parent session."""

    if not isinstance(frontmatter, Mapping):
        raise ValueError("Pi frontmatter must be a mapping")
    if any(field in frontmatter for field in ("model", "thinking", "fallbackModels")):
        raise ValueError("Pi managed roles must inherit model and thinking policy")
    return "inherit"


def _strict_yaml_frontmatter(content: bytes) -> tuple[dict[str, object], str]:
    if type(content) is not bytes:
        raise TypeError("Pi agent source must be bytes")
    try:
        text = content.decode("utf-8")
    except (AttributeError, UnicodeDecodeError) as exc:
        raise ValueError("Pi agent source must be UTF-8 bytes") from exc
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("Pi agent source is missing opening frontmatter")
    try:
        closing = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError("Pi agent source is missing closing frontmatter") from exc

    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to validate Pi agent sources") from exc

    class _StrictLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        result: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "duplicate Pi frontmatter key",
                    key_node.start_mark,
                )
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "Pi frontmatter keys must be strings",
                    key_node.start_mark,
                )
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    _StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping
    )
    # SafeLoader rejects unknown tags; reject aliases explicitly as well.  An
    # alias can otherwise make two policy fields share mutable YAML data.
    try:
        for event in yaml.parse("\n".join(lines[1:closing]), Loader=yaml.SafeLoader):
            if isinstance(event, yaml.events.AliasEvent):
                raise ValueError("Pi frontmatter aliases are not allowed")
        parsed = yaml.load(
            "\n".join(lines[1:closing]),
            Loader=_StrictLoader,  # noqa: S506
        )
    except ValueError:
        raise
    except (TypeError, yaml.YAMLError) as exc:
        raise ValueError(f"invalid Pi YAML frontmatter: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Pi frontmatter must be a mapping")
    body = "\n".join(lines[closing + 1 :])
    if not body.strip():
        raise ValueError("Pi agent body must be non-empty")
    return parsed, body


def _sequence(value: object, field: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise ValueError(f"Pi {field} must be an explicit list")
    if any(
        type(item) is not str
        or not item
        or any(unicodedata.category(char) in {"Cc", "Cf"} for char in item)
        for item in value
    ):
        raise ValueError(f"Pi {field} must contain non-empty strings")
    if len(set(value)) != len(value):
        raise ValueError(f"Pi {field} contains duplicates")
    return tuple(value)


def _plain_string(value: object, field: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value.strip()):
        raise ValueError(f"Pi {field} must be a non-empty string")
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
        raise ValueError(f"Pi {field} contains control characters")
    return value


def _expected_tools(role: str) -> tuple[str, ...]:
    if role in {"code-explorer", "code-reviewer"}:
        return READ_TOOLS
    if role == "code-validator":
        return VALIDATOR_TOOLS
    if role in {"quick-implementer", "implementer"}:
        return WRITE_TOOLS
    return PUSHER_TOOLS


def _validate_contract_fields(
    role: str,
    parsed: Mapping[str, object],
    body: str,
    *,
    allow_rendered_extension: bool = False,
) -> PiAgentContract:
    if role not in _ALL_ROLES:
        raise ValueError(f"unknown Pi role: {role}")
    unknown = set(parsed) - _FRONTMATTER_FIELDS
    if unknown:
        raise ValueError("unknown Pi agent frontmatter field")
    name = _plain_string(parsed.get("name"), "name")
    if name != role:
        raise ValueError("Pi agent name does not match source role")
    description = _plain_string(parsed.get("description"), "description")
    if parsed.get("systemPromptMode") != "replace":
        raise ValueError("Pi systemPromptMode must be replace")
    if parsed.get("inheritProjectContext") is not False:
        raise ValueError("Pi roles must not inherit project context")
    if parsed.get("inheritSkills") is not False:
        raise ValueError("Pi roles must not inherit skills")
    tools = _sequence(parsed.get("tools"), "tools")
    if tools != _expected_tools(role):
        raise ValueError(f"Pi {role} has an unsafe tool policy")
    skills = _sequence(parsed.get("skills"), "skills")
    extensions = _sequence(parsed.get("extensions"), "extensions")
    if skills or extensions:
        raise ValueError("managed Pi roles must declare empty skills and extensions")
    provider = parsed.get("subagentOnlyExtensions")
    if role == "code-validator":
        if provider == PI_VALIDATION_EXTENSION:
            providers = (PI_VALIDATION_EXTENSION,)
        elif allow_rendered_extension and type(provider) is str:
            rendered_extension = Path(provider)
            if (
                not rendered_extension.is_absolute()
                or rendered_extension.name != "subagents-configs-run-validation.ts"
                or rendered_extension.parts[-2:]
                != (
                    "extensions",
                    rendered_extension.name,
                )
                or any(
                    unicodedata.category(char) in {"Cc", "Cf"}
                    or char in {'"', "'", "`", "\\", "{", "}"}
                    for char in provider
                )
                or str(normalized_absolute(rendered_extension)) != provider
            ):
                raise ValueError("Pi validator has an unsafe rendered extension path")
            providers = (provider,)
        else:
            raise ValueError("Pi validator must use only the validation extension")
        lowered = body.lower()
        for concept in ("run_validation", "fails closed", "only through"):
            if concept not in lowered:
                raise ValueError(f"Pi validator body is missing {concept}")
    else:
        if "subagentOnlyExtensions" in parsed:
            raise ValueError("only code-validator may declare a Pi extension provider")
        providers = ()

    if _PLACEHOLDER_RE.search(body) or any(marker in body for marker in ("{{", "}}")):
        raise ValueError("Pi agent body contains an unresolved placeholder")
    if any(
        (unicodedata.category(char) in {"Cc", "Cf"} and char not in {"\n", "\t"})
        or char in {"\u2028", "\u2029"}
        for char in body
    ):
        raise ValueError("Pi agent body contains control characters")
    lowered = body.lower()
    required_concepts = {
        "code-explorer": ("read-only", "never implement"),
        "code-reviewer": ("read-only", "never implement"),
        "quick-implementer": ("parent", "credential", "network"),
        "implementer": ("parent", "credential", "network"),
        "commit-pusher": (
            "both a commit and a push",
            "separate explicit",
            "never force-push",
        ),
    }
    missing = [
        concept for concept in required_concepts.get(role, ()) if concept not in lowered
    ]
    if missing:
        raise ValueError(f"Pi {role} body is missing required policy language")
    frontmatter = dict(parsed)
    return PiAgentContract(
        role=role,
        name=name,
        description=description,
        system_prompt_mode="replace",
        inherit_project_context=False,
        inherit_skills=False,
        tools=tools,
        skills=skills,
        extensions=extensions,
        subagent_only_extensions=providers,
        body=body,
        frontmatter=MappingProxyType(frontmatter),
    )


def validate_pi_agent(
    role: str, content: bytes, *, allow_rendered_extension: bool = False
) -> PiAgentContract:
    """Parse and validate one authoritative Pi Markdown agent source."""

    if (
        type(role) is not str
        or not role
        or any(unicodedata.category(char) in {"Cc", "Cf"} for char in role)
    ):
        raise ValueError("Pi role must be a non-empty string")
    parsed, body = _strict_yaml_frontmatter(content)
    normalize_model_policy(parsed)
    return _validate_contract_fields(
        role,
        parsed,
        body,
        allow_rendered_extension=allow_rendered_extension,
    )


def validate_pi_contract(
    role: str,
    frontmatter: Mapping[str, object],
    body: str,
    *,
    allow_rendered_extension: bool = False,
) -> PiAgentContract:
    """Validate an already parsed Pi contract for registry dispatch."""

    if type(role) is not str or not role:
        raise ValueError("Pi role must be a non-empty string")
    if not isinstance(frontmatter, Mapping) or type(body) is not str:
        raise ValueError("Pi contract has invalid parsed values")
    if not body.strip():
        raise ValueError("Pi agent body must be non-empty")
    normalize_model_policy(frontmatter)
    return _validate_contract_fields(
        role,
        frontmatter,
        body,
        allow_rendered_extension=allow_rendered_extension,
    )


def _safe_agent_dir(agent_dir: Path) -> Path:
    if type(agent_dir) is not type(Path()):
        raise TypeError("Pi agent directory must be a Path")
    raw = os.fspath(agent_dir)
    if not raw or not agent_dir.is_absolute() or raw == "/":
        raise ValueError("Pi agent directory must be a non-root absolute path")
    if any(
        char in raw for char in ("\x00", "\r", "\n", '"', "'", "`", "\\", "{", "}")
    ) or any(unicodedata.category(char) in {"Cc", "Cf"} for char in raw):
        raise ValueError("Pi agent directory contains unsafe characters")
    if any(part in {".", ".."} for part in agent_dir.parts):
        raise ValueError("Pi agent directory contains unsafe lexical components")
    normalized = normalized_absolute(agent_dir)
    if normalized != agent_dir:
        raise ValueError("Pi agent directory is not canonical")
    current = Path(agent_dir.anchor)
    for component in agent_dir.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(item.st_mode):
            # macOS exposes /tmp and /var as canonical aliases below /private.
            # Permit only those exact system aliases; user-controlled links
            # must remain rejected before a rendered path is handed to Pi.
            private_alias = Path("/private") / current.relative_to("/")
            if Path(os.path.realpath(current)) != private_alias:
                raise ValueError("Pi agent directory contains a symlink")
            continue
        if not stat.S_ISDIR(item.st_mode):
            raise ValueError("Pi agent directory has a non-directory component")
    extension_parent = agent_dir / "extensions"
    try:
        item = os.lstat(extension_parent)
    except FileNotFoundError:
        item = None
    except OSError as exc:
        raise ValueError("Pi extensions directory cannot be inspected") from exc
    if item is not None and (
        stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode)
    ):
        raise ValueError("Pi extensions directory must be a regular directory")
    return agent_dir


def render_pi_source(source: bytes, *, agent_dir: Path) -> bytes:
    """Validate a source and render only the validator's safe extension path."""
    role = _role_from_source(source)
    contract = validate_pi_agent(role, source)
    safe_dir = _safe_agent_dir(agent_dir)
    placeholder = PI_VALIDATION_EXTENSION.encode("utf-8")
    count = source.count(placeholder)
    if contract.role == "code-validator":
        if count != 1:
            raise ValueError(
                "Pi validator must contain exactly one extension placeholder"
            )
        rendered_path = safe_dir / PI_VALIDATION_EXTENSION_PATH
        rendered = source.replace(placeholder, os.fsencode(rendered_path))
    else:
        if count:
            raise ValueError("Pi extension placeholder is restricted to code-validator")
        rendered = source
    if b"{{" in rendered or b"}}" in rendered:
        raise ValueError("Pi source contains an unresolved placeholder")
    return rendered


def _role_from_source(source: bytes) -> str:
    parsed, _body = _strict_yaml_frontmatter(source)
    role = parsed.get("name")
    if type(role) is not str:
        raise ValueError("Pi source has no role name")
    return role
