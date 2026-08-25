from pathlib import PurePosixPath

from .models import ManagedSettingSpec, SourceSpec, Target, TargetDescriptor

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
    managed_settings: tuple[ManagedSettingSpec, ...] = (),
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
        managed_settings=managed_settings,
    )


DESCRIPTORS: dict[Target, TargetDescriptor] = {
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
        managed_settings=(
            ManagedSettingSpec(
                identifier="claude/code-validator-command-gate/settings",
                relative_path=PurePosixPath("settings.json"),
                key_path=("hooks", "PreToolUse"),
                value={
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "{{CLAUDE_HOOK}}",
                        }
                    ],
                },
            ),
        ),
    ),
}

DESCRIPTOR_ORDER = (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE)


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
