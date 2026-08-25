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


def _agent_sources(target: Target, directory: str, suffix: str) -> list[SourceSpec]:
    return [
        SourceSpec(
            identifier=role,
            source=PurePosixPath(directory) / f"{role}{suffix}",
            destination=PurePosixPath("agents") / f"{role}{suffix}",
            kind="agent",
            source_format="toml" if target is Target.CODEX else "yaml-frontmatter",
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


def _descriptor(
    target: Target,
    *,
    environment_variable: str,
    default_home: str,
    global_filename: str,
    config_filename: str | None,
    agent_directory: str,
    agent_suffix: str,
    routing_source: str,
    template_source: str,
) -> TargetDescriptor:
    sources = [
        *_agent_sources(target, agent_directory, agent_suffix),
        SourceSpec(
            identifier="routing",
            source=PurePosixPath(routing_source),
            destination=None,
            kind="routing-source",
            source_format="markdown",
        ),
        SourceSpec(
            identifier="project-template",
            source=PurePosixPath(template_source),
            destination=None,
            kind="project-template",
            source_format="markdown",
        ),
        *_runtime_sources(),
    ]
    if target is Target.CLAUDE_CODE:
        sources.append(
            SourceSpec(
                identifier="claude/code-validator-command-gate",
                source=PurePosixPath(_CLAUDE_HOOK_SOURCE),
                destination=PurePosixPath(_CLAUDE_HOOK_DESTINATION),
                kind="command-gate",
                source_format="python",
            )
        )
    return TargetDescriptor(
        target=target,
        environment_variable=environment_variable,
        default_home=default_home,
        global_filename=global_filename,
        config_filename=config_filename,
        sources=tuple(sources),
    )


_DESCRIPTORS: dict[Target, TargetDescriptor] = {
    Target.CODEX: _descriptor(
        Target.CODEX,
        environment_variable="CODEX_HOME",
        default_home="~/.codex",
        global_filename="AGENTS.md",
        config_filename="config.toml",
        agent_directory="agents",
        agent_suffix=".toml",
        routing_source="rules/SUBAGENT_ROUTING.md",
        template_source="templates/AGENTS.md.template",
    ),
    Target.OPENCODE: _descriptor(
        Target.OPENCODE,
        environment_variable="OPENCODE_HOME",
        default_home="~/.config/opencode",
        global_filename="AGENTS.md",
        config_filename=None,
        agent_directory="opencode/agents",
        agent_suffix=".md",
        routing_source="rules/OPENCODE_SUBAGENT_ROUTING.md",
        template_source="templates/opencode/AGENTS.md.template",
    ),
    Target.CLAUDE_CODE: _descriptor(
        Target.CLAUDE_CODE,
        environment_variable="CLAUDE_CONFIG_DIR",
        default_home="~/.claude",
        global_filename="CLAUDE.md",
        config_filename=None,
        agent_directory="claude-code/agents",
        agent_suffix=".md",
        routing_source="rules/CLAUDE_SUBAGENT_ROUTING.md",
        template_source="templates/claude-code/CLAUDE.md.template",
    ),
}


def _capability(descriptor: TargetDescriptor, order: int) -> TargetCapability:
    agent = next(source for source in descriptor.sources if source.kind == "agent")
    routing = next(
        source for source in descriptor.sources if source.kind == "routing-source"
    )
    optional_blocks = [
        ManagedBlockSpec(
            block_id=f"routing-{descriptor.target.value}",
            relative_path=PurePosixPath(descriptor.global_filename),
            source=routing.source,
        )
    ]
    if descriptor.target is Target.CODEX:
        optional_blocks.append(
            ManagedBlockSpec(
                block_id="codex-multi-agent-v2",
                relative_path=PurePosixPath(
                    descriptor.config_filename or "config.toml"
                ),
            )
        )
    runtime = tuple(
        source
        for source in descriptor.sources
        if source.kind in {"validation-runtime", "command-gate", "target-extension"}
    )
    return TargetCapability(
        target=descriptor.target,
        order=order,
        include_in_all=True,
        agent_directory=agent.source.parent,
        source_format=agent.source_format,
        parser=agent.source_format,
        semantic_validator="agent",
        global_instruction=GlobalInstructionSpec(
            optional_blocks[0].block_id,
            PurePosixPath(descriptor.global_filename),
            routing.source,
        ),
        optional_blocks=tuple(optional_blocks),
        runtime_sources=runtime,
        lifecycle_capabilities=frozenset({"file", "block", "manifest", "runtime"}),
        external_lifecycle=None,
    )


CAPABILITIES: tuple[TargetCapability, ...] = tuple(
    _capability(descriptor, order)
    for order, descriptor in enumerate(_DESCRIPTORS.values())
)
_CAPABILITY_BY_TARGET = {capability.target: capability for capability in CAPABILITIES}
DESCRIPTORS: dict[Target, TargetDescriptor] = {
    capability.target: _DESCRIPTORS[capability.target] for capability in CAPABILITIES
}
DESCRIPTOR_ORDER = tuple(capability.target for capability in CAPABILITIES)


def capability_for(target: Target) -> TargetCapability:
    """Return the sole canonical capability record for ``target``."""
    try:
        return _CAPABILITY_BY_TARGET[target]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"unsupported target: {target}") from exc


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
        return tuple(
            capability.target
            for capability in CAPABILITIES
            if capability.include_in_all
        )
    requested = set(explicit)
    if requested - set(_CAPABILITY_BY_TARGET):
        raise ValueError("target request contains an unsupported target")
    return tuple(
        capability.target
        for capability in CAPABILITIES
        if capability.target in requested
    )


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
