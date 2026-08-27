from pathlib import PurePosixPath

from .models import (
    GlobalInstructionSpec,
    ManagedBlockSpec,
    SourceSpec,
    Target,
    TargetCapability,
    TargetDescriptor,
)

_ROLES = (
    "code-explorer",
    "code-reviewer",
    "code-validator",
    "quick-implementer",
    "implementer",
    "commit-pusher",
)
_VALIDATION_FILES = (
    "scripts/run-validation-isolated.py",
    "scripts/validation_isolation/__init__.py",
    "scripts/validation_isolation/errors.py",
    "scripts/validation_isolation/models.py",
    "scripts/validation_isolation/git_snapshot.py",
    "scripts/validation_isolation/environment.py",
    "scripts/validation_isolation/backend.py",
    "scripts/validation_isolation/runner.py",
    "scripts/validation_isolation/cli.py",
)
_CLAUDE_HOOK_SOURCE = "claude-code/hooks/code-validator-pretooluse.py"
_CLAUDE_HOOK_DESTINATION = (
    ".subagents_configs/claude-hooks/code-validator-pretooluse.py"
)
_PI_EXTENSION_SOURCE = "pi/extensions/run-validation.ts"
_PI_EXTENSION_DESTINATION = "extensions/subagents-configs-run-validation.ts"
_COMPATIBILITY_BASE_FEATURES = frozenset(
    {"agents", "managed-blocks", "validation-runtime"}
)
COMPATIBILITY_FEATURES: dict[Target, frozenset[str]] = {
    Target.CODEX: _COMPATIBILITY_BASE_FEATURES | {"codex-multi-agent-v2"},
    Target.OPENCODE: _COMPATIBILITY_BASE_FEATURES,
    Target.CLAUDE_CODE: _COMPATIBILITY_BASE_FEATURES | {"command-gate"},
    Target.PI: _COMPATIBILITY_BASE_FEATURES,
}


def _agent_sources(directory: str, suffix: str, source_format: str) -> list[SourceSpec]:
    return [
        SourceSpec(
            identifier=role,
            source=PurePosixPath(directory) / f"{role}{suffix}",
            destination=PurePosixPath("agents") / f"{role}{suffix}",
            kind="agent",
            source_format=source_format,
            optional_role="commit-pusher" if role == "commit-pusher" else None,
        )
        for role in _ROLES
    ]


def _runtime_sources() -> list[SourceSpec]:
    return [
        SourceSpec(
            identifier=path,
            source=PurePosixPath(path),
            destination=PurePosixPath(".subagents_configs/validation")
            / PurePosixPath(path).relative_to("scripts"),
            kind="validation-runtime",
            source_format="python",
        )
        for path in _VALIDATION_FILES
    ]


def _capability_sources(capability: TargetCapability) -> tuple[SourceSpec, ...]:
    if capability.target is Target.PI:
        return tuple(
            [
                *_agent_sources("pi/agents", ".md", "markdown"),
                SourceSpec(
                    identifier="pi/run-validation",
                    source=PurePosixPath(_PI_EXTENSION_SOURCE),
                    destination=PurePosixPath(_PI_EXTENSION_DESTINATION),
                    kind="target-extension",
                    source_format="typescript",
                ),
                SourceSpec(
                    identifier="routing",
                    source=capability.global_instruction.source,
                    destination=None,
                    kind="routing-source",
                    source_format="markdown",
                ),
            ]
        )
    sources = [
        *_agent_sources(
            capability.agent_directory.as_posix(),
            capability.agent_suffix,
            capability.source_format,
        ),
        SourceSpec(
            identifier="routing",
            source=capability.global_instruction.source,
            destination=None,
            kind="routing-source",
            source_format="markdown",
        ),
        SourceSpec(
            identifier="project-template",
            source=capability.project_template,
            destination=None,
            kind="project-template",
            source_format="markdown",
        ),
        *capability.runtime_sources,
    ]
    return tuple(sources)


CAPABILITIES: tuple[TargetCapability, ...] = (
    TargetCapability(
        target=Target.CODEX,
        order=0,
        include_in_all=True,
        agent_directory=PurePosixPath("agents"),
        source_format="toml",
        parser="toml",
        semantic_validator="agent",
        global_instruction=GlobalInstructionSpec(
            "routing-codex",
            PurePosixPath("AGENTS.md"),
            PurePosixPath("rules/SUBAGENT_ROUTING.md"),
        ),
        optional_blocks=(
            ManagedBlockSpec(
                "routing-codex",
                PurePosixPath("AGENTS.md"),
                PurePosixPath("rules/SUBAGENT_ROUTING.md"),
            ),
            ManagedBlockSpec("codex-multi-agent-v2", PurePosixPath("config.toml")),
        ),
        runtime_sources=tuple(_runtime_sources()),
        lifecycle_capabilities=frozenset({"file", "block", "manifest", "runtime"}),
        external_lifecycle=None,
        environment_variable="CODEX_HOME",
        default_home="~/.codex",
        config_filename="config.toml",
        project_template=PurePosixPath("templates/AGENTS.md.template"),
        agent_suffix=".toml",
        compatibility_features=COMPATIBILITY_FEATURES[Target.CODEX],
    ),
    TargetCapability(
        target=Target.OPENCODE,
        order=1,
        include_in_all=True,
        agent_directory=PurePosixPath("opencode/agents"),
        source_format="yaml-frontmatter",
        parser="yaml-frontmatter",
        semantic_validator="agent",
        global_instruction=GlobalInstructionSpec(
            "routing-opencode",
            PurePosixPath("AGENTS.md"),
            PurePosixPath("rules/OPENCODE_SUBAGENT_ROUTING.md"),
        ),
        optional_blocks=(
            ManagedBlockSpec(
                "routing-opencode",
                PurePosixPath("AGENTS.md"),
                PurePosixPath("rules/OPENCODE_SUBAGENT_ROUTING.md"),
            ),
        ),
        runtime_sources=tuple(_runtime_sources()),
        lifecycle_capabilities=frozenset({"file", "block", "manifest", "runtime"}),
        external_lifecycle=None,
        environment_variable="OPENCODE_HOME",
        default_home="~/.config/opencode",
        config_filename=None,
        project_template=PurePosixPath("templates/opencode/AGENTS.md.template"),
        agent_suffix=".md",
        compatibility_features=COMPATIBILITY_FEATURES[Target.OPENCODE],
    ),
    TargetCapability(
        target=Target.CLAUDE_CODE,
        order=2,
        include_in_all=True,
        agent_directory=PurePosixPath("claude-code/agents"),
        source_format="yaml-frontmatter",
        parser="yaml-frontmatter",
        semantic_validator="agent",
        global_instruction=GlobalInstructionSpec(
            "routing-claude-code",
            PurePosixPath("CLAUDE.md"),
            PurePosixPath("rules/CLAUDE_SUBAGENT_ROUTING.md"),
        ),
        optional_blocks=(
            ManagedBlockSpec(
                "routing-claude-code",
                PurePosixPath("CLAUDE.md"),
                PurePosixPath("rules/CLAUDE_SUBAGENT_ROUTING.md"),
            ),
        ),
        runtime_sources=tuple(
            [
                *_runtime_sources(),
                SourceSpec(
                    identifier="claude/code-validator-command-gate",
                    source=PurePosixPath(_CLAUDE_HOOK_SOURCE),
                    destination=PurePosixPath(_CLAUDE_HOOK_DESTINATION),
                    kind="command-gate",
                    source_format="python",
                ),
            ]
        ),
        lifecycle_capabilities=frozenset({"file", "block", "manifest", "runtime"}),
        external_lifecycle=None,
        environment_variable="CLAUDE_CONFIG_DIR",
        default_home="~/.claude",
        config_filename=None,
        project_template=PurePosixPath("templates/claude-code/CLAUDE.md.template"),
        agent_suffix=".md",
        compatibility_features=COMPATIBILITY_FEATURES[Target.CLAUDE_CODE],
    ),
    TargetCapability(
        target=Target.PI,
        order=3,
        include_in_all=False,
        agent_directory=PurePosixPath("pi/agents"),
        source_format="markdown",
        parser="markdown",
        semantic_validator="agent",
        global_instruction=GlobalInstructionSpec(
            "routing-pi",
            PurePosixPath("APPEND_SYSTEM.md"),
            PurePosixPath("rules/PI_SUBAGENT_ROUTING.md"),
        ),
        optional_blocks=(),
        runtime_sources=(),
        lifecycle_capabilities=frozenset(),
        external_lifecycle=None,
        environment_variable="PI_CODING_AGENT_DIR",
        default_home="~/.pi/agent",
        config_filename=None,
        project_template=PurePosixPath("templates/pi/AGENTS.md.template"),
        agent_suffix=".md",
        compatibility_features=COMPATIBILITY_FEATURES[Target.PI],
    ),
)


def _descriptor_from_capability(capability: TargetCapability) -> TargetDescriptor:
    return TargetDescriptor(
        target=capability.target,
        environment_variable=capability.environment_variable,
        default_home=capability.default_home,
        global_filename=capability.global_instruction.filename.name,
        config_filename=capability.config_filename,
        sources=_capability_sources(capability),
    )


DESCRIPTORS: dict[Target, TargetDescriptor] = {
    capability.target: _descriptor_from_capability(capability)
    for capability in CAPABILITIES
}


def registry_target_order() -> tuple[Target, ...]:
    """Return targets in the order declared by the canonical registry."""
    ordered = tuple(sorted(CAPABILITIES, key=lambda capability: capability.order))
    if len({capability.order for capability in ordered}) != len(ordered):
        raise ValueError("capability registry contains duplicate target orders")
    if len({capability.target for capability in ordered}) != len(ordered):
        raise ValueError("capability registry contains duplicate targets")
    return tuple(capability.target for capability in ordered)


DESCRIPTOR_ORDER = registry_target_order()


def capability_for(target: Target) -> TargetCapability:
    """Return the sole canonical capability record for ``target``."""
    for capability in CAPABILITIES:
        if capability.target is target:
            return capability
    raise ValueError(f"unsupported target: {target}")


def parser_for(target: Target) -> str:
    return capability_for(target).parser


def semantic_validator_for(target: Target) -> str:
    return capability_for(target).semantic_validator


def runtime_sources_for(target: Target) -> tuple[SourceSpec, ...]:
    return capability_for(target).runtime_sources


def targets_for_request(
    explicit: tuple[Target, ...], include_all: bool
) -> tuple[Target, ...]:
    """Normalize a target request using registry order and all-selection policy."""
    if type(include_all) is not bool or not isinstance(explicit, tuple):
        raise ValueError("target request has invalid shape")
    if any(not isinstance(target, Target) for target in explicit):
        raise ValueError("target request contains an unsupported target")
    if len(set(explicit)) != len(explicit):
        raise ValueError("duplicate targets are not supported")
    if include_all and explicit:
        raise ValueError("--all cannot be combined with explicit targets")
    if include_all:
        selected = {
            capability.target
            for capability in CAPABILITIES
            if capability.include_in_all
        }
        return tuple(target for target in registry_target_order() if target in selected)
    requested = set(explicit)
    if requested - set(registry_target_order()):
        raise ValueError("target request contains an unsupported target")
    return tuple(target for target in registry_target_order() if target in requested)


def descriptor_for(target: Target) -> TargetDescriptor:
    try:
        return DESCRIPTORS[target]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"unsupported target: {target}") from exc


def selected_sources(
    descriptor: TargetDescriptor,
    include_commit_pusher: bool,
) -> tuple[SourceSpec, ...]:
    if include_commit_pusher:
        return descriptor.sources
    return tuple(
        source
        for source in descriptor.sources
        if source.optional_role != "commit-pusher"
    )
