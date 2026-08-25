"""Secure multi-client subagent distribution models and orchestration."""

from .models import (
    BackupSpec,
    BlockAction,
    DesiredFile,
    FileAction,
    GlobalInstructionSpec,
    IdentityEvidence,
    LifecycleAction,
    ManagedBlockSpec,
    Request,
    SourceSpec,
    Target,
    TargetCapability,
    TargetDescriptor,
    decode_lifecycle_action,
)
from .targets import (
    CAPABILITIES,
    capability_for,
    parser_for,
    runtime_sources_for,
    semantic_validator_for,
    targets_for_request,
)

__all__ = [
    "CAPABILITIES",
    "BackupSpec",
    "BlockAction",
    "DesiredFile",
    "FileAction",
    "GlobalInstructionSpec",
    "IdentityEvidence",
    "LifecycleAction",
    "ManagedBlockSpec",
    "Request",
    "SourceSpec",
    "Target",
    "TargetCapability",
    "TargetDescriptor",
    "capability_for",
    "decode_lifecycle_action",
    "parser_for",
    "runtime_sources_for",
    "semantic_validator_for",
    "targets_for_request",
]
