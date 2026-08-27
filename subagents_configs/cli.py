import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from .compatibility import validate_client_version
from .errors import CliError
from .models import DryRunFormat, Request, Target
from .targets import descriptor_for, targets_for_request


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliError(message)


def profile_parser() -> argparse.ArgumentParser:
    """Return the shared parser used by profile/CLI request merging."""

    return _parser()


def reject_duplicate_flags(argv: Sequence[str]) -> None:
    """Apply the CLI duplicate-option rule to profile merges."""

    _reject_duplicate_flags(argv)


def expand_user(raw: str, environ: Mapping[str, str]) -> Path:
    """Expand one CLI home spelling using only the supplied environment."""

    return _expand_user(raw, environ)


def default_home(descriptor, environ: Mapping[str, str]) -> Path:
    """Resolve one target's existing environment/default home policy."""

    return _default_home(descriptor, environ)


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--target", action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--home", action="append")
    routing = parser.add_mutually_exclusive_group()
    routing.add_argument(
        "--enable-global-routing",
        dest="enable_global_routing",
        action="store_true",
        default=None,
    )
    routing.add_argument(
        "--no-global-routing", dest="enable_global_routing", action="store_false"
    )
    multi_agent = parser.add_mutually_exclusive_group()
    multi_agent.add_argument(
        "--enable-codex-multi-agent",
        dest="enable_codex_multi_agent",
        action="store_true",
        default=None,
    )
    multi_agent.add_argument(
        "--no-codex-multi-agent", dest="enable_codex_multi_agent", action="store_false"
    )
    commit_pusher = parser.add_mutually_exclusive_group()
    commit_pusher.add_argument(
        "--include-commit-pusher",
        dest="include_commit_pusher",
        action="store_true",
        default=None,
    )
    commit_pusher.add_argument(
        "--no-commit-pusher", dest="include_commit_pusher", action="store_false"
    )
    dry_run = parser.add_mutually_exclusive_group()
    dry_run.add_argument("--dry-run", dest="dry_run", action="store_true", default=None)
    dry_run.add_argument("--no-dry-run", dest="dry_run", action="store_false")
    parser.add_argument("--format", choices=("text", "json"), default=None)
    parser.add_argument("--client-version", action="append")
    parser.add_argument("--pi-executable")
    parser.add_argument("--consent-third-party-code", action="store_true")
    parser.add_argument("--consent-network", action="store_true")
    parser.add_argument("--remove-pi-package", action="store_true")
    parser.add_argument("--profile")
    return parser


def _reject_duplicate_flags(argv: Sequence[str]) -> None:
    repeatable = {"--target", "--home", "--client-version"}
    seen: set[str] = set()
    for argument in argv:
        option = argument.split("=", 1)[0]
        if option in repeatable:
            continue
        if option.startswith("--"):
            if option in seen:
                raise CliError(f"duplicate option: {option}")
            seen.add(option)


def _expand_user(raw: str, environ: Mapping[str, str]) -> Path:
    if raw.startswith("~"):
        if raw != "~" and not raw.startswith("~/"):
            raise CliError("home path must use ~ or ~/PATH")
        home = environ.get("HOME")
        if not home:
            raise CliError("HOME is required to expand a home path")
        raw = home + raw[1:]
    return Path(raw).expanduser()


def _default_home(descriptor, environ: Mapping[str, str]) -> Path:
    home = environ.get(descriptor.environment_variable)
    if home is None or home == "":
        base = environ.get("HOME")
        if not base:
            raise CliError("HOME is required when no target home is supplied")
        suffix = descriptor.default_home.removeprefix("~/")
        home = str(Path(base) / suffix)
    return _expand_user(home, environ)


def parse_request(
    operation: Literal["install", "uninstall"],
    argv: Sequence[str],
    environ: Mapping[str, str],
    *,
    platform_name: str | None = None,
) -> Request:
    if operation not in ("install", "uninstall"):
        raise CliError(f"unsupported operation: {operation}")
    _reject_duplicate_flags(argv)
    parser = _parser()
    args, unknown = parser.parse_known_args(list(argv))
    if unknown:
        raise CliError(f"unknown option: {unknown[0]}")
    if args.profile is not None:
        from .profiles import load_profile, merge_profile_with_cli

        try:
            profile = load_profile(Path(args.profile))
        except (OSError, TypeError, ValueError) as exc:
            raise CliError("invalid profile") from exc
        if profile.operation != operation:
            raise CliError("profile operation conflicts with CLI operation")
        return merge_profile_with_cli(
            profile, argv, environ, platform_name=platform_name
        )

    dry_run_format: DryRunFormat = args.format or "text"
    dry_run = bool(args.dry_run)
    if dry_run_format == "json" and not args.dry_run:
        raise CliError("--format json requires --dry-run")

    raw_targets = args.target or []
    if args.all and raw_targets:
        raise CliError("--all cannot be combined with --target")
    if not args.all and not raw_targets:
        raise CliError("one or more --target options or --all is required")

    if args.all:
        targets = list(targets_for_request((), True))
    else:
        parsed_targets: list[Target] = []
        for raw_target in raw_targets:
            try:
                target = Target(raw_target)
            except ValueError as exc:
                raise CliError(f"unknown target: {raw_target}") from exc
            if target in parsed_targets:
                raise CliError(f"duplicate target: {raw_target}")
            parsed_targets.append(target)
        targets = list(targets_for_request(tuple(parsed_targets), False))

    if operation == "uninstall" and (
        args.enable_global_routing
        or args.enable_codex_multi_agent
        or args.include_commit_pusher
    ):
        raise CliError("install-only options are not valid for uninstall")
    if args.enable_codex_multi_agent and Target.CODEX not in targets:
        raise CliError("--enable-codex-multi-agent requires the codex target")

    pi_options_used = (
        args.pi_executable is not None
        or args.consent_third_party_code
        or args.consent_network
        or args.remove_pi_package
    )
    if pi_options_used and Target.PI not in targets:
        raise CliError("Pi options require the pi target")
    if Target.PI in targets:
        selected_platform = platform_name if platform_name is not None else sys.platform
        if selected_platform not in ("linux", "darwin", "macos"):
            raise CliError("Pi is unsupported on this platform")
    if operation == "install" and args.remove_pi_package:
        raise CliError("--remove-pi-package is uninstall-only")
    if operation == "uninstall" and (
        args.pi_executable is not None and not args.remove_pi_package
    ):
        raise CliError("Pi executable requires --remove-pi-package on uninstall")
    if operation == "uninstall" and (
        args.consent_third_party_code or args.consent_network
    ):
        raise CliError("Pi consent options are install-only")
    pi_executable = None
    if args.pi_executable is not None:
        if not Path(args.pi_executable).is_absolute():
            raise CliError("--pi-executable must be a lexical absolute path")
        pi_executable = _expand_user(args.pi_executable, environ)
        if not pi_executable.is_absolute():
            raise CliError("--pi-executable must be an absolute path")
    if operation == "install" and Target.PI in targets and pi_executable is None:
        raise CliError("Pi install requires --pi-executable")
    if (
        operation == "uninstall"
        and Target.PI in targets
        and args.remove_pi_package
        and pi_executable is None
    ):
        raise CliError("Pi package removal requires --pi-executable")
    client_versions: dict[str, str] = {}
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

    homes: dict[Target, Path] = {}
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
        if target in homes:
            raise CliError(f"duplicate home: {target_name}")
        homes[target] = _expand_user(raw_path, environ)

    for target in targets:
        if target not in homes:
            homes[target] = _default_home(descriptor_for(target), environ)

    return Request(
        operation=operation,
        targets=tuple(targets),
        homes=homes,
        enable_global_routing=bool(args.enable_global_routing),
        enable_codex_multi_agent=bool(args.enable_codex_multi_agent),
        include_commit_pusher=bool(args.include_commit_pusher),
        dry_run=dry_run,
        dry_run_format=dry_run_format,
        client_versions=client_versions,
        pi_executable=pi_executable,
        consent_third_party_code=bool(args.consent_third_party_code and not dry_run),
        consent_network=bool(args.consent_network and not dry_run),
        remove_pi_package=bool(args.remove_pi_package),
    )
