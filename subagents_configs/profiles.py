"""Strict, local declarative install profiles and CLI precedence."""

from __future__ import annotations

import json
import stat
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from .errors import CliError
from .models import ProfileOptions, ProfileRequest, Request, Target
from .targets import descriptor_for, targets_for_request

_PROFILE_KEYS = frozenset(
    {"schema_version", "operation", "targets", "homes", "options"}
)
_OPTION_KEYS = frozenset(
    {
        "enable_global_routing",
        "enable_codex_multi_agent",
        "include_commit_pusher",
        "dry_run",
        "dry_run_format",
    }
)
_SENSITIVE_FRAGMENTS = (
    "credential",
    "secret",
    "token",
    "password",
    "privatekey",
)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("profile contains duplicate keys")
        result[key] = value
    return result


def _reject_hostile_strings(value: object) -> None:
    if isinstance(value, str):
        normalized = "".join(
            character for character in value.lower() if character.isalnum()
        )
        if any(fragment in normalized for fragment in _SENSITIVE_FRAGMENTS):
            raise ValueError("profile contains credential-like data")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("profile contains control data")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("profile object keys must be strings")
            _reject_hostile_strings(key)
            _reject_hostile_strings(child)
        return
    if isinstance(value, list):
        for child in value:
            _reject_hostile_strings(child)


def _load_raw(path: Path) -> object:
    if not isinstance(path, Path):
        raise TypeError("profile path must be a Path")
    if path.suffix not in {".json", ".toml"}:
        raise ValueError("profile format must be .json or .toml")
    try:
        item = path.lstat()
    except OSError as exc:
        raise ValueError("profile cannot be inspected") from exc
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        raise ValueError("profile must be a regular file")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError("profile cannot be read") from exc
    try:
        if path.suffix == ".json":
            return json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
        return tomllib.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("profile is malformed") from exc


def _absolute_profile_home(raw: object) -> Path:
    if type(raw) is not str or not raw:
        raise ValueError("profile home must be an absolute string path")
    if not Path(raw).is_absolute():
        raise ValueError("profile home must be absolute")
    if "\\" in raw or (len(raw) >= 2 and raw[1] == ":"):
        raise ValueError("profile home must be a POSIX path")
    lexical = PurePosixPath(raw)
    if raw != "/" and (raw.startswith("//") or raw.endswith("/") or "//" in raw):
        raise ValueError("profile home is not canonical")
    if any(component in {".", ".."} for component in raw.split("/")):
        raise ValueError("profile home contains an unsafe lexical component")
    if lexical.as_posix() != raw:
        raise ValueError("profile home is not canonical")
    return Path(raw)


def _decode_profile(raw: object) -> ProfileRequest:
    _reject_hostile_strings(raw)
    if type(raw) is not dict or set(raw) != _PROFILE_KEYS:
        raise ValueError("profile has unknown or missing top-level keys")
    schema_version = raw["schema_version"]
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError("profile schema_version must be exactly 1")
    operation = raw["operation"]
    if type(operation) is not str or operation not in {"install", "uninstall"}:
        raise ValueError("profile operation is unsupported")
    raw_targets = raw["targets"]
    if type(raw_targets) is not list or not raw_targets:
        raise ValueError("profile targets must be a non-empty list")
    targets: list[Target] = []
    for raw_target in raw_targets:
        if type(raw_target) is not str:
            raise ValueError("profile targets must be strings")
        try:
            target = Target(raw_target)
        except ValueError as exc:
            raise ValueError("profile target is unsupported") from exc
        if target in targets:
            raise ValueError("profile targets must be unique")
        targets.append(target)
    canonical_targets = targets_for_request(tuple(targets), False)
    if tuple(targets) != canonical_targets:
        raise ValueError("profile targets are not in canonical order")

    raw_homes = raw["homes"]
    if type(raw_homes) is not dict or set(raw_homes) != {
        target.value for target in targets
    }:
        raise ValueError("profile homes must exactly match targets")
    homes = {
        target: _absolute_profile_home(raw_homes[target.value]) for target in targets
    }

    raw_options = raw["options"]
    if type(raw_options) is not dict or set(raw_options) != _OPTION_KEYS:
        raise ValueError("profile options have unknown or missing keys")
    bools: dict[str, bool] = {}
    for name in _OPTION_KEYS - {"dry_run_format"}:
        value = raw_options[name]
        if type(value) is not bool:
            raise ValueError(f"profile option {name} must be a bool")
        bools[name] = value
    dry_run_format = raw_options["dry_run_format"]
    if type(dry_run_format) is not str or dry_run_format not in {"text", "json"}:
        raise ValueError("profile dry_run_format must be text or json")
    options = ProfileOptions(
        bools["enable_global_routing"],
        bools["enable_codex_multi_agent"],
        bools["include_commit_pusher"],
        bools["dry_run"],
        dry_run_format,
    )
    return ProfileRequest(
        1, operation, tuple(targets), MappingProxyType(homes), options
    )


def load_profile(path: Path) -> ProfileRequest:
    """Load one strict JSON/TOML profile without executing or expanding it."""

    return _decode_profile(_load_raw(path))


def _profile_cli_parser():
    from .cli import profile_parser

    return profile_parser()


def _parse_profile_cli(argv: Sequence[str]):
    from .cli import reject_duplicate_flags

    reject_duplicate_flags(argv)
    parser = _profile_cli_parser()
    args, unknown = parser.parse_known_args(list(argv))
    if unknown:
        raise CliError(f"unknown option: {unknown[0]}")
    return args


def _resolve_bool(cli_value: bool | None, profile_value: bool | None) -> bool:
    if cli_value is not None:
        return cli_value
    return bool(profile_value)


def merge_profile_with_cli(
    profile: ProfileRequest, argv: Sequence[str], environ: Mapping[str, str]
) -> Request:
    """Merge explicit CLI values over a profile and return a validated request."""

    if type(profile) is not ProfileRequest:
        raise TypeError("profile must be a ProfileRequest")
    args = _parse_profile_cli(argv)
    if args.profile is not None and not args.profile:
        raise CliError("--profile requires a path")

    raw_targets = args.target or []
    if args.all and raw_targets:
        raise CliError("--all cannot be combined with --target")
    if args.all:
        targets = list(targets_for_request((), True))
    elif raw_targets:
        targets = []
        for raw_target in raw_targets:
            try:
                target = Target(raw_target)
            except ValueError as exc:
                raise CliError(f"unknown target: {raw_target}") from exc
            if target in targets:
                raise CliError(f"duplicate target: {raw_target}")
            targets.append(target)
        targets = list(targets_for_request(tuple(targets), False))
    else:
        targets = list(profile.targets)

    from .cli import default_home, expand_user

    homes: dict[Target, Path] = {
        target: profile.homes[target] for target in targets if target in profile.homes
    }
    explicit_home_targets: set[Target] = set()
    for raw_home in args.home or []:
        target_name, separator, raw_path = raw_home.partition("=")
        if not separator or not target_name or not raw_path:
            raise CliError("--home requires TARGET=PATH")
        try:
            target = Target(target_name)
        except ValueError as exc:
            raise CliError(f"unknown target in --home: {target_name}") from exc
        if target not in targets:
            raise CliError(f"home supplied for unselected target: {target_name}")
        if target in explicit_home_targets:
            raise CliError(f"duplicate home: {target_name}")
        explicit_home_targets.add(target)
        homes[target] = expand_user(raw_path, environ)
    for target in targets:
        if target not in homes:
            homes[target] = default_home(descriptor_for(target), environ)

    dry_run = _resolve_bool(args.dry_run, profile.options.dry_run)
    dry_run_format = (
        args.format if args.format is not None else profile.options.dry_run_format
    )
    if not dry_run and args.format is None:
        dry_run_format = "text"
    if dry_run_format == "json" and not dry_run:
        raise CliError("--format json requires --dry-run")

    client_versions: dict[str, str] = {}
    from .compatibility import validate_client_version

    for raw_version in args.client_version or []:
        target_name, separator, version = raw_version.partition("=")
        if not separator or not target_name or not version:
            raise CliError("--client-version requires TARGET=VERSION")
        try:
            target = Target(target_name)
        except ValueError as exc:
            raise CliError(
                f"unknown target in --client-version: {target_name}"
            ) from exc
        if target not in targets:
            raise CliError(
                f"client version supplied for unselected target: {target_name}"
            )
        if target.value in client_versions:
            raise CliError(f"duplicate client version: {target_name}")
        try:
            client_versions[target.value] = validate_client_version(version)
        except ValueError as exc:
            raise CliError(f"invalid client version for {target_name}") from exc

    request = Request(
        operation=profile.operation,
        targets=tuple(targets),
        homes=homes,
        enable_global_routing=_resolve_bool(
            args.enable_global_routing, profile.options.enable_global_routing
        ),
        enable_codex_multi_agent=_resolve_bool(
            args.enable_codex_multi_agent, profile.options.enable_codex_multi_agent
        ),
        include_commit_pusher=_resolve_bool(
            args.include_commit_pusher, profile.options.include_commit_pusher
        ),
        dry_run=dry_run,
        dry_run_format=dry_run_format,
        client_versions=client_versions,
    )
    from .planning import validate_request_shape

    validate_request_shape(request, profile.operation)
    return request
