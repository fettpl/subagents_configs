import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from .errors import CliError
from .models import Request, Target
from .targets import descriptor_for, targets_for_request


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--target", action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--home", action="append")
    parser.add_argument("--enable-global-routing", action="store_true")
    parser.add_argument("--enable-codex-multi-agent", action="store_true")
    parser.add_argument("--include-commit-pusher", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def _reject_duplicate_flags(argv: Sequence[str]) -> None:
    repeatable = {"--target", "--home"}
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
) -> Request:
    if operation not in ("install", "uninstall"):
        raise CliError(f"unsupported operation: {operation}")
    _reject_duplicate_flags(argv)
    parser = _parser()
    args, unknown = parser.parse_known_args(list(argv))
    if unknown:
        raise CliError(f"unknown option: {unknown[0]}")

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
        enable_global_routing=args.enable_global_routing,
        enable_codex_multi_agent=args.enable_codex_multi_agent,
        include_commit_pusher=args.include_commit_pusher,
        dry_run=args.dry_run,
    )
