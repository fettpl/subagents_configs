import shutil
import stat
import tempfile
from pathlib import Path

from subagents_configs.models import Request, Target

_RUNTIME_FIXTURES = (
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


def environment(tmp_home: Path) -> dict[str, str]:
    """Return a deterministic environment for parser tests."""
    return {"HOME": str(tmp_home)}


def real_repository() -> Path:
    """Return the checked-out repository used by integration tests."""

    return Path(__file__).parents[1].resolve()


def private_tempdir(*, prefix: str = "subagents-configs-"):
    """Return a 0700 temporary directory below the canonical temp root."""

    root = Path(tempfile.gettempdir()).resolve()
    if not root.is_dir():
        raise RuntimeError("the canonical temporary root is unavailable")
    temporary = tempfile.TemporaryDirectory(prefix=prefix, dir=root)
    directory = Path(temporary.name)
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        temporary.cleanup()
        raise RuntimeError("private temporary directory is not mode 0700")
    return temporary


def tree_snapshot(root: Path) -> dict[str, tuple[str, int, bytes | str | None]]:
    """Capture bytes, modes, and symlink targets without following links."""

    root = root.resolve()
    snapshot: dict[str, tuple[str, int, bytes | str | None]] = {}
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        relative = path.relative_to(root).as_posix()
        item = path.lstat()
        mode = stat.S_IMODE(item.st_mode)
        if path.is_symlink():
            snapshot[relative] = ("symlink", mode, path.readlink().as_posix())
        elif path.is_dir():
            snapshot[relative] = ("directory", mode, None)
        elif path.is_file():
            snapshot[relative] = ("file", mode, path.read_bytes())
        else:
            snapshot[relative] = ("other", mode, None)
    return snapshot


def planning_repository(repo_root: Path) -> Path:
    """Make a complete source inventory suitable for planner tests."""
    fixture = repo_root / "fixture-repository"
    fixture.mkdir()
    for relative in (
        "agents",
        "opencode/agents",
        "claude-code/agents",
        "rules",
        "templates",
    ):
        source = Path(__file__).parents[1] / relative
        destination = fixture / relative
        shutil.copytree(source, destination)
    for relative in _RUNTIME_FIXTURES:
        destination = fixture / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("# fixture runtime\n", encoding="utf-8")
    return fixture


def planning_request(
    operation: str,
    homes: dict[Target, Path],
    *,
    targets: tuple[Target, ...] | None = None,
    **options: bool,
) -> Request:
    selected = targets or tuple(
        target
        for target in (Target.CODEX, Target.OPENCODE, Target.CLAUDE_CODE)
        if target in homes
    )
    return Request(
        operation=operation,
        targets=selected,
        homes=homes,
        enable_global_routing=options.get("enable_global_routing", False),
        enable_codex_multi_agent=options.get("enable_codex_multi_agent", False),
        include_commit_pusher=options.get("include_commit_pusher", False),
        dry_run=options.get("dry_run", False),
    )
