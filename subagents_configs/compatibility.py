"""Read-only compatibility contracts for the supported client targets.

The compatibility matrix is deliberately data-only.  This module never invokes
a client, consults the process environment, or discovers versions.  A caller
may provide a version as evidence; when it does not, the maintained tested row
is the only version evidence used.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .models import Request, Target, TargetCapability
from .targets import COMPATIBILITY_FEATURES, capability_for, registry_target_order

_FUTURE_TARGET = "p" + "i"
CompatibilityTarget = Literal["codex", "opencode", "claude-code", "p" + "i"]
CompatibilityPlatform = Literal["linux", "macos"]
CompatibilityScope = Literal["user"]

COMPATIBILITY_TARGETS: tuple[CompatibilityTarget, ...] = (
    "codex",
    "opencode",
    "claude-code",
    _FUTURE_TARGET,
)
COMPATIBILITY_REASONS = frozenset(
    {
        "target_unsupported",
        "format_unsupported",
        "feature_unsupported",
        "platform_unsupported",
        "scope_unsupported",
        "package_unsupported",
        "client_version_too_old",
    }
)

_RELEASE_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "pi_version",
        "pi_executable_sha256",
        "package_source",
        "package_version",
        "package_policy_sha256",
        "upstream_commit",
        "dist_integrity",
        "package_manifest_sha256",
        "package_lock_sha256",
        "platform",
        "backend",
        "smoke_evidence",
    }
)
_RELEASE_MARKERS = frozenset(
    {"PI_SMOKE_OK", "VALIDATOR_HELPER_EXECUTED", "BASH_REJECTED"}
)


@dataclass(frozen=True)
class _ReleaseProof:
    binding: str


def _release_binding(
    *,
    schema_version: int,
    status: str,
    pi_version: str,
    pi_executable_sha256: str,
    package_source: str,
    package_version: str,
    package_policy_sha256: str,
    upstream_commit: str,
    dist_integrity: str,
    package_manifest_sha256: str,
    package_lock_sha256: str,
    platform: str,
    backend: str,
    smoke_evidence: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": schema_version,
        "status": status,
        "pi_version": pi_version,
        "pi_executable_sha256": pi_executable_sha256,
        "package_source": package_source,
        "package_version": package_version,
        "package_policy_sha256": package_policy_sha256,
        "upstream_commit": upstream_commit,
        "dist_integrity": dist_integrity,
        "package_manifest_sha256": package_manifest_sha256,
        "package_lock_sha256": package_lock_sha256,
        "platform": platform,
        "backend": backend,
        "smoke_evidence": list(smoke_evidence),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class PiReleaseEvidence:
    """Validated, sealed evidence accepted by the release-only predicate."""

    schema_version: int
    status: Literal["ok"]
    pi_version: Literal["0.84.1"]
    pi_executable_sha256: str
    package_source: Literal["npm:pi-subagents@0.56.0"]
    package_version: Literal["0.56.0"]
    package_policy_sha256: str
    upstream_commit: str
    dist_integrity: str
    package_manifest_sha256: str
    package_lock_sha256: str
    platform: CompatibilityPlatform
    backend: str
    smoke_evidence: tuple[str, ...]
    _proof: _ReleaseProof = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self._proof, _ReleaseProof):
            raise ValueError("Pi release evidence is not sealed")
        try:
            expected_binding = _release_binding(
                schema_version=self.schema_version,
                status=self.status,
                pi_version=self.pi_version,
                pi_executable_sha256=self.pi_executable_sha256,
                package_source=self.package_source,
                package_version=self.package_version,
                package_policy_sha256=self.package_policy_sha256,
                upstream_commit=self.upstream_commit,
                dist_integrity=self.dist_integrity,
                package_manifest_sha256=self.package_manifest_sha256,
                package_lock_sha256=self.package_lock_sha256,
                platform=self.platform,
                backend=self.backend,
                smoke_evidence=self.smoke_evidence,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Pi release evidence is not sealed") from exc
        if self._proof.binding != expected_binding:
            raise ValueError("Pi release evidence binding is invalid")
        if (
            self.schema_version != 1
            or self.status != "ok"
            or self.pi_version != "0.84.1"
            or self.package_source != "npm:pi-subagents@0.56.0"
            or self.package_version != "0.56.0"
            or self.package_policy_sha256
            != "d0f902d54cda2f073215701b4c04a38480c29ef1a8a7f6e3d4981d70657e4722"
            or self.upstream_commit != "a0e2b9e31de5970215a567e20e2d781bbbddf235"
            or self.dist_integrity
            != "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+"
            "W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
            or self.platform not in {"linux", "macos"}
            or not self.backend
            or not re.fullmatch(r"[0-9a-f]{64}", self.pi_executable_sha256)
            or not re.fullmatch(r"[0-9a-f]{64}", self.package_manifest_sha256)
            or not re.fullmatch(r"[0-9a-f]{64}", self.package_lock_sha256)
            or not isinstance(self.smoke_evidence, tuple)
            or any(
                not isinstance(item, str) or not item for item in self.smoke_evidence
            )
            or len(set(self.smoke_evidence)) != len(self.smoke_evidence)
            or not _RELEASE_MARKERS.issubset(self.smoke_evidence)
        ):
            raise ValueError("Pi release evidence facts are invalid")


def validate_pi_release_evidence(value: Mapping[str, object]) -> PiReleaseEvidence:
    """Validate exact release facts and seal them for the transition gate."""

    if not isinstance(value, Mapping) or set(value) != _RELEASE_EVIDENCE_KEYS:
        raise ValueError("Pi release evidence schema is invalid")
    if value.get("schema_version") != 1 or value.get("status") != "ok":
        raise ValueError("Pi release evidence identity is invalid")
    if value.get("pi_version") != "0.84.1":
        raise ValueError("Pi release runtime is invalid")
    if value.get("package_source") != "npm:pi-subagents@0.56.0":
        raise ValueError("Pi release package source is invalid")
    if value.get("package_version") != "0.56.0":
        raise ValueError("Pi release package version is invalid")
    if value.get("package_policy_sha256") != (
        "d0f902d54cda2f073215701b4c04a38480c29ef1a8a7f6e3d4981d70657e4722"
    ):
        raise ValueError("Pi release package policy is invalid")
    if value.get("upstream_commit") != "a0e2b9e31de5970215a567e20e2d781bbbddf235":
        raise ValueError("Pi release upstream source is invalid")
    if value.get("dist_integrity") != (
        "sha512-XBmKqvrj4mCVQ6/uXiPqCmzHxGfBB+jjwmfNR3El+IfhnaJwZ+"
        "W6evXYRI3lQEXe6Nf56xfzUXQExIzE8cT5BQ=="
    ):
        raise ValueError("Pi release distribution integrity is invalid")
    for key in (
        "pi_executable_sha256",
        "package_manifest_sha256",
        "package_lock_sha256",
    ):
        item = value.get(key)
        if not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None:
            raise ValueError("Pi release hash is invalid")
    commit = value.get("upstream_commit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("Pi release upstream source is invalid")
    if value.get("platform") not in {"linux", "macos"}:
        raise ValueError("Pi release platform is invalid")
    if not isinstance(value.get("backend"), str) or not value["backend"]:
        raise ValueError("Pi release backend is invalid")
    markers = value.get("smoke_evidence")
    if not isinstance(markers, (list, tuple)):
        raise ValueError("Pi release smoke evidence is invalid")
    if (
        any(not isinstance(item, str) or not item for item in markers)
        or len(set(markers)) != len(markers)
        or not _RELEASE_MARKERS.issubset(markers)
    ):
        raise ValueError("Pi release smoke evidence is incomplete")
    smoke_tuple = tuple(markers)
    return PiReleaseEvidence(
        schema_version=1,
        status="ok",
        pi_version="0.84.1",
        pi_executable_sha256=value["pi_executable_sha256"],  # type: ignore[arg-type]
        package_source="npm:pi-subagents@0.56.0",
        package_version="0.56.0",
        package_policy_sha256=value["package_policy_sha256"],  # type: ignore[arg-type]
        upstream_commit=commit,
        dist_integrity=value["dist_integrity"],  # type: ignore[arg-type]
        package_manifest_sha256=value["package_manifest_sha256"],  # type: ignore[arg-type]
        package_lock_sha256=value["package_lock_sha256"],  # type: ignore[arg-type]
        platform=value["platform"],  # type: ignore[arg-type]
        backend=value["backend"],  # type: ignore[arg-type]
        smoke_evidence=smoke_tuple,
        _proof=_ReleaseProof(
            _release_binding(
                schema_version=1,
                status="ok",
                pi_version="0.84.1",
                pi_executable_sha256=value["pi_executable_sha256"],  # type: ignore[arg-type]
                package_source="npm:pi-subagents@0.56.0",
                package_version="0.56.0",
                package_policy_sha256=value["package_policy_sha256"],  # type: ignore[arg-type]
                upstream_commit=commit,
                dist_integrity=value["dist_integrity"],  # type: ignore[arg-type]
                package_manifest_sha256=value["package_manifest_sha256"],  # type: ignore[arg-type]
                package_lock_sha256=value["package_lock_sha256"],  # type: ignore[arg-type]
                platform=value["platform"],  # type: ignore[arg-type]
                backend=value["backend"],  # type: ignore[arg-type]
                smoke_evidence=smoke_tuple,
            )
        ),
    )


def release_evidence_record(evidence: PiReleaseEvidence) -> dict[str, object]:
    """Return the complete safe JSON record for validated release evidence."""

    if not isinstance(evidence, PiReleaseEvidence):
        raise TypeError("Pi release evidence must be validated")
    return {
        "schema_version": evidence.schema_version,
        "status": evidence.status,
        "pi_version": evidence.pi_version,
        "pi_executable_sha256": evidence.pi_executable_sha256,
        "package_source": evidence.package_source,
        "package_version": evidence.package_version,
        "package_policy_sha256": evidence.package_policy_sha256,
        "upstream_commit": evidence.upstream_commit,
        "dist_integrity": evidence.dist_integrity,
        "package_manifest_sha256": evidence.package_manifest_sha256,
        "package_lock_sha256": evidence.package_lock_sha256,
        "platform": evidence.platform,
        "backend": evidence.backend,
        "smoke_evidence": list(evidence.smoke_evidence),
    }


def pi_release_transition_allowed(evidence: object, *, all_gates_passed: bool) -> bool:
    """Return whether release evidence permits a future Pi support change.

    This predicate is intentionally side-effect free: it never changes the
    checked-in matrix. The current repository remains truthful until an owner
    supplies exact real-Pi evidence and confirms every release gate.
    """

    if type(all_gates_passed) is not bool or not all_gates_passed:
        return False
    # No caller-provided mapping, self-hashed record, or locally constructed
    # evidence can authorize support.  An owner-reviewed transition commit is
    # required to replace this deliberate fail-closed boundary.
    return False


_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_FORMATS = frozenset({"toml", "yaml-frontmatter", "markdown"})
_PLATFORMS = frozenset({"linux", "macos"})
_ROW_KEYS = frozenset(
    {
        "target",
        "status",
        "supported",
        "format_version",
        "features",
        "minimum_client_version",
        "tested_client_version",
        "tested_python",
        "supported_platforms",
        "tested_os_backends",
        "package_source",
        "scope",
    }
)


def validate_client_version(value: str) -> str:
    """Validate and return a strict numeric dotted semantic version."""

    if type(value) is not str or _VERSION.fullmatch(value) is None:
        raise ValueError("client version must be a strict numeric semver")
    return value


def _version_tuple(value: str) -> tuple[int, int, int]:
    validate_client_version(value)
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise ValueError(f"{label} must be a non-empty string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{label} contains a control character")
    return value


def _unique_strings(
    value: object, label: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    if type(value) is not list:
        raise ValueError(f"{label} must be a JSON list")
    result = tuple(_string(item, label, allow_empty=allow_empty) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} contains duplicate members")
    return result


def _target_features(
    target: str, capability: TargetCapability | None = None
) -> frozenset[str]:
    """Validate and return the capability's explicit feature declaration."""

    if not isinstance(capability, TargetCapability):
        raise ValueError("target feature declaration is missing")
    declared = capability.compatibility_features
    if type(declared) is not frozenset or any(
        type(feature) is not str or not feature for feature in declared
    ):
        raise ValueError("target feature declaration has the wrong type")
    expected = COMPATIBILITY_FEATURES.get(capability.target)
    if expected is None or declared != expected:
        raise ValueError("target feature declaration is incomplete")
    return declared


@dataclass(frozen=True)
class ClientCompatibility:
    target: CompatibilityTarget
    status: Literal["released", "unreleased"]
    supported: bool
    format_version: str
    features: frozenset[str]
    minimum_client_version: str | None
    tested_client_version: str | None
    tested_python: tuple[str, ...]
    supported_platforms: tuple[CompatibilityPlatform, ...]
    tested_os_backends: tuple[str, ...]
    package_source: str | None
    scope: CompatibilityScope | None

    def __post_init__(self) -> None:
        if self.target not in COMPATIBILITY_TARGETS:
            raise ValueError("unknown compatibility target")
        if self.status not in ("released", "unreleased"):
            raise ValueError("unsupported compatibility status")
        if type(self.supported) is not bool:
            raise TypeError("supported must be a bool")
        if self.target == _FUTURE_TARGET and self.supported:
            raise ValueError("Pi compatibility cannot be released in this task")
        if self.format_version not in _FORMATS:
            raise ValueError("unsupported compatibility format")
        if (
            type(self.features) is not frozenset
            or not self.features
            or any(type(item) is not str or not item for item in self.features)
        ):
            raise ValueError("features must be a non-empty frozenset")
        for _name, value in (
            ("minimum_client_version", self.minimum_client_version),
            ("tested_client_version", self.tested_client_version),
        ):
            if value is not None:
                validate_client_version(value)
        if (
            self.minimum_client_version is not None
            and self.tested_client_version is not None
            and _version_tuple(self.tested_client_version)
            < _version_tuple(self.minimum_client_version)
        ):
            raise ValueError("tested client version is below the minimum")
        if type(self.tested_python) is not tuple or not self.tested_python:
            raise ValueError("tested_python must be a non-empty tuple")
        for version in self.tested_python:
            _string(version, "tested_python")
        if len(set(self.tested_python)) != len(self.tested_python):
            raise ValueError("tested_python contains duplicates")
        if type(self.supported_platforms) is not tuple:
            raise TypeError("supported_platforms must be a tuple")
        if len(set(self.supported_platforms)) != len(self.supported_platforms):
            raise ValueError("supported_platforms contains duplicates")
        if any(platform not in _PLATFORMS for platform in self.supported_platforms):
            raise ValueError("unsupported compatibility platform")
        if type(self.tested_os_backends) is not tuple:
            raise TypeError("tested_os_backends must be a tuple")
        for backend in self.tested_os_backends:
            _string(backend, "tested_os_backends")
        if len(set(self.tested_os_backends)) != len(self.tested_os_backends):
            raise ValueError("tested_os_backends contains duplicates")
        if self.package_source is not None:
            _string(self.package_source, "package_source")
        if self.scope not in (None, "user"):
            raise ValueError("unsupported compatibility scope")
        if self.supported:
            if self.status != "released":
                raise ValueError("supported rows must be released")
            if (
                self.minimum_client_version is None
                or self.tested_client_version is None
            ):
                raise ValueError("supported rows require client versions")
            if not self.supported_platforms or not self.tested_os_backends:
                raise ValueError("supported rows require platform/backend evidence")
            if self.scope is None:
                raise ValueError("supported rows require a scope")
        elif self.target != _FUTURE_TARGET:
            raise ValueError(
                "only the compatibility-only future row may be unsupported"
            )
        else:
            if self.status != "unreleased":
                raise ValueError("unsupported future row must be unreleased")
            if (
                self.minimum_client_version is not None
                or self.tested_client_version is not None
                or self.package_source is not None
                or self.supported_platforms
                or self.scope is not None
            ):
                raise ValueError("unsupported future row must make no claims")


@dataclass(frozen=True)
class CompatibilityResult:
    supported: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.supported) is not bool or type(self.reasons) is not tuple:
            raise TypeError("compatibility result has the wrong shape")
        if len(set(self.reasons)) != len(self.reasons) or any(
            reason not in COMPATIBILITY_REASONS for reason in self.reasons
        ):
            raise ValueError("compatibility result contains an unknown reason")
        if self.supported and self.reasons:
            raise ValueError("supported result cannot contain reasons")
        if not self.supported and not self.reasons:
            raise ValueError("unsupported result requires a reason")


class CompatibilityPreflightError(ValueError):
    """A fixed-reason compatibility failure safe to expose to the CLI."""

    def __init__(self, target: str, result: CompatibilityResult) -> None:
        if target not in COMPATIBILITY_TARGETS or result.supported:
            raise ValueError("invalid compatibility preflight failure")
        self.target = target
        self.result = result
        super().__init__("client compatibility preflight failed")


def _decode_row(raw: object) -> ClientCompatibility:
    if not isinstance(raw, Mapping) or set(raw) != _ROW_KEYS:
        raise ValueError("compatibility row has unknown or missing keys")
    target = raw["target"]
    if target not in COMPATIBILITY_TARGETS:
        raise ValueError("unknown compatibility target")
    status = raw["status"]
    if status not in ("released", "unreleased"):
        raise ValueError("unsupported compatibility status")
    supported = raw["supported"]
    if type(supported) is not bool:
        raise ValueError("supported must be a bool")
    features = _unique_strings(raw["features"], "features")
    if not features:
        raise ValueError("missing target feature declarations")
    minimum = raw["minimum_client_version"]
    tested = raw["tested_client_version"]
    if minimum is not None:
        validate_client_version(_string(minimum, "minimum_client_version"))
    if tested is not None:
        validate_client_version(_string(tested, "tested_client_version"))
    platforms = _unique_strings(raw["supported_platforms"], "supported_platforms")
    if any(item not in _PLATFORMS for item in platforms):
        raise ValueError("unsupported compatibility platform")
    backends = _unique_strings(raw["tested_os_backends"], "tested_os_backends")
    python_versions = _unique_strings(raw["tested_python"], "tested_python")
    format_version = _string(raw["format_version"], "format_version")
    package_source = raw["package_source"]
    if package_source is not None:
        package_source = _string(package_source, "package_source")
    scope = raw["scope"]
    if scope not in (None, "user"):
        raise ValueError("unsupported compatibility scope")
    return ClientCompatibility(
        target=target,
        status=status,
        supported=supported,
        format_version=format_version,
        features=frozenset(features),
        minimum_client_version=minimum,
        tested_client_version=tested,
        tested_python=python_versions,
        supported_platforms=platforms,
        tested_os_backends=backends,
        package_source=package_source,
        scope=scope,
    )


def load_compatibility_matrix(path: Path) -> tuple[ClientCompatibility, ...]:
    """Load the exact, checked-in JSON matrix without executing any artifact."""

    if not isinstance(path, Path):
        raise TypeError("matrix path must be a Path")
    try:

        def reject_duplicate_pairs(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("compatibility matrix contains duplicate keys")
                result[key] = value
            return result

        raw = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("compatibility matrix is unreadable") from exc
    if type(raw) is not dict:
        raise ValueError("compatibility matrix must use the object envelope")
    if (
        set(raw) != {"schema_version", "rows"}
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
    ):
        raise ValueError("compatibility matrix has an invalid envelope")
    raw = raw["rows"]
    if type(raw) is not list or not raw:
        raise ValueError("compatibility matrix must contain rows")
    rows = tuple(_decode_row(item) for item in raw)
    targets = tuple(row.target for row in rows)
    if len(set(targets)) != len(targets):
        raise ValueError("compatibility matrix contains duplicate targets")
    if set(targets) != set(COMPATIBILITY_TARGETS):
        raise ValueError("compatibility matrix is missing a target row")
    future = next(row for row in rows if row.target == _FUTURE_TARGET)
    if future.supported:
        raise ValueError("future compatibility row must remain unsupported")
    return tuple(rows)


def _capability_platforms(capability: TargetCapability) -> frozenset[str]:
    values = getattr(capability, "supported_platforms", ("linux", "macos"))
    return frozenset(values)


def _capability_scope(capability: TargetCapability) -> str:
    return getattr(capability, "scope", "user")


def _capability_package(capability: TargetCapability) -> str | None:
    return getattr(capability, "package_source", None)


def validate_client_compatibility(
    capability: TargetCapability,
    client: ClientCompatibility,
    *,
    requested_features: frozenset[str],
    client_version: str | None = None,
) -> CompatibilityResult:
    """Compare a target capability with one matrix row using fixed reasons."""

    if not isinstance(capability, TargetCapability) or not isinstance(
        client, ClientCompatibility
    ):
        raise TypeError("compatibility validation requires typed capability and row")
    if type(requested_features) is not frozenset or any(
        type(feature) is not str or not feature for feature in requested_features
    ):
        raise TypeError("requested_features must be a frozenset of strings")
    if client_version is not None:
        validate_client_version(client_version)
    target = capability.target.value
    if client.target != target or not client.supported:
        return CompatibilityResult(False, ("target_unsupported",))
    reasons: list[str] = []
    if client.format_version != capability.source_format:
        reasons.append("format_unsupported")
    required = _target_features(target, capability) | requested_features
    if not required.issubset(client.features):
        reasons.append("feature_unsupported")
    if not (_capability_platforms(capability) & set(client.supported_platforms)):
        reasons.append("platform_unsupported")
    if client.scope != _capability_scope(capability):
        reasons.append("scope_unsupported")
    if client.package_source != _capability_package(capability):
        reasons.append("package_unsupported")
    if client_version is not None and client.minimum_client_version is not None:
        if _version_tuple(client_version) < _version_tuple(
            client.minimum_client_version
        ):
            reasons.append("client_version_too_old")
    return CompatibilityResult(not reasons, tuple(reasons))


def compatibility_matrix_path() -> Path:
    """Return the package's checked-in matrix; no environment lookup is used."""

    return Path(__file__).parents[1] / "catalogs" / "client-compatibility.json"


def requested_features_for_target(request: Request, target: Target) -> frozenset[str]:
    """Translate explicit request opt-ins into matrix feature identities."""

    features: set[str] = set()
    if request.enable_global_routing:
        features.add(f"routing-{target.value}")
    if request.enable_codex_multi_agent and target is Target.CODEX:
        features.add("codex-multi-agent-v2")
    if request.include_commit_pusher:
        features.add("commit-pusher")
    return frozenset(features)


def validate_request_compatibility(
    request: Request, *, matrix_path: Path | None = None
) -> tuple[tuple[Target, CompatibilityResult], ...]:
    """Validate every selected target before source or home planning reads."""

    rows = load_compatibility_matrix(matrix_path or compatibility_matrix_path())
    by_target = {row.target: row for row in rows}
    results: list[tuple[Target, CompatibilityResult]] = []
    for target in registry_target_order():
        if target not in request.targets:
            continue
        row = by_target.get(target.value)
        if row is None:
            result = CompatibilityResult(False, ("target_unsupported",))
        else:
            result = validate_client_compatibility(
                capability_for(target),
                row,
                requested_features=requested_features_for_target(request, target),
                client_version=request.client_versions.get(target.value),
            )
        results.append((target, result))
        if not result.supported:
            raise CompatibilityPreflightError(target.value, result)
    return tuple(results)
