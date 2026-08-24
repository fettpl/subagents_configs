"""Secure Git inventory, checkout fingerprinting, and private snapshots."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath

from .errors import GitSnapshotError, UnsafePathError
from .models import CheckoutState, GitSnapshot, SnapshotFile

GIT_EXECUTABLE = Path("/usr/bin/git")
_CHUNK_SIZE = 1024 * 1024
GitRunner = Callable[[Sequence[str], Path], subprocess.CompletedProcess[bytes]]

_COMMON_SECRET_BASENAMES = frozenset(
    {
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ecdsa_sk",
        "id_ed25519",
        "id_ed25519_sk",
        "id_rsa",
        "private.key",
        "private.pem",
        "private_key",
        "private_key.pem",
    }
)
_COMMON_SECRET_PATH_SUFFIXES = frozenset(
    {
        ".aws/credentials",
        ".config/gh/hosts.yml",
        ".config/gcloud/application_default_credentials.json",
        ".docker/config.json",
    }
)


def _trusted_git() -> Path:
    path = GIT_EXECUTABLE
    if path != Path("/usr/bin/git") or not path.is_absolute():
        raise UnsafePathError("trusted Git path is not /usr/bin/git")
    current = Path(path.anchor)
    try:
        for component in path.parts[1:]:
            current /= component
            item = os.lstat(current)
            if stat.S_ISLNK(item.st_mode):
                raise UnsafePathError("trusted Git path contains a symlink")
        item = os.lstat(path)
    except OSError as exc:
        raise UnsafePathError("trusted Git executable is unavailable") from exc
    if not stat.S_ISREG(item.st_mode) or item.st_uid != 0:
        raise UnsafePathError("trusted Git executable is not root-owned regular file")
    if not item.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise UnsafePathError("trusted Git executable is not executable")
    if stat.S_IMODE(item.st_mode) & 0o022:
        raise UnsafePathError("trusted Git executable is group/other writable")
    return path


def run_git(arguments: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    """Run fixed Git with bytes, no shell, explicit cwd, and sterile config."""

    executable = _trusted_git()
    if not cwd.is_absolute():
        raise UnsafePathError("Git cwd must be absolute")
    _safe_directory(cwd, "Git cwd")
    command = [
        str(executable),
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.pager=cat",
        "-c",
        "pager.status=cat",
        "-c",
        "credential.helper=",
        "-c",
        "core.askPass=",
        *arguments,
    ]
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_EDITOR": ":",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ASKPASS": "/usr/bin/false",
        "SSH_ASKPASS": "/usr/bin/false",
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(  # noqa: S603
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        shell=False,
        check=False,
    )


def _safe_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise UnsafePathError(f"{label} must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            item = os.lstat(current)
        except FileNotFoundError as exc:
            raise UnsafePathError(f"{label} does not exist: {path}") from exc
        if stat.S_ISLNK(item.st_mode) and not (
            current == Path("/var")
            and Path(os.path.realpath(current)) == Path("/private/var")
        ):
            raise UnsafePathError(f"{label} contains a symlink: {path}")
    item = os.lstat(path)
    if not stat.S_ISDIR(item.st_mode):
        raise UnsafePathError(f"{label} is not a directory")
    return path


def _checked_git(
    arguments: Sequence[str], cwd: Path, git_runner: GitRunner
) -> subprocess.CompletedProcess[bytes]:
    result = git_runner(tuple(arguments), cwd)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace")[:160]
        raise GitSnapshotError(f"Git command failed: {detail}")
    if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
        raise GitSnapshotError("Git runner did not return captured bytes")
    return result


def locate_worktree(start: Path, git_runner: GitRunner = run_git) -> Path:
    start = _safe_directory(start, "Git start directory")
    canonical_start = start.resolve(strict=True)
    result = _checked_git(("rev-parse", "--show-toplevel"), start, git_runner)
    output = result.stdout
    if b"\x00" in output:
        raise GitSnapshotError("Git worktree path contains NUL")
    if not output.endswith(b"\n") or output.count(b"\n") != 1:
        raise GitSnapshotError("Git returned a malformed worktree path")
    try:
        raw = output[:-1].decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise GitSnapshotError("Git worktree path is not UTF-8") from exc
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise GitSnapshotError("Git returned a relative worktree path")
    try:
        canonical_candidate = candidate.resolve(strict=True)
    except OSError as exc:
        raise GitSnapshotError("Git returned an unusable worktree path") from exc
    if candidate != canonical_candidate:
        raise GitSnapshotError("Git returned a non-canonical worktree path")
    _safe_directory(canonical_candidate, "Git worktree")
    try:
        canonical_start.relative_to(canonical_candidate)
    except ValueError as exc:
        raise GitSnapshotError(
            "Git worktree does not contain the start directory"
        ) from exc
    return canonical_candidate


def _relative_path(raw: bytes) -> PurePosixPath | None:
    if not raw or b"\x00" in raw:
        raise GitSnapshotError("Git inventory contains an empty or NUL path")
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise GitSnapshotError("Git inventory contains a non-UTF-8 path") from exc
    if "\\" in value or value.startswith("/") or (len(value) >= 2 and value[1] == ":"):
        raise GitSnapshotError("Git inventory contains an unsafe path")
    raw_components = value.split("/")
    if any(component in ("", ".", "..") for component in raw_components):
        raise GitSnapshotError("Git inventory contains a malformed path")
    path = PurePosixPath(value)
    if path == PurePosixPath(".") or path.is_absolute() or ".." in path.parts:
        raise GitSnapshotError("Git inventory contains a traversal path")
    if any(component in ("", ".") for component in path.parts):
        raise GitSnapshotError("Git inventory contains a malformed path")
    if ".git" in path.parts:
        raise GitSnapshotError("Git inventory exposed .git")
    if path.name.casefold() in _COMMON_SECRET_BASENAMES or any(
        path.as_posix().casefold().endswith(suffix)
        for suffix in _COMMON_SECRET_PATH_SUFFIXES
    ):
        return None
    if any(
        component
        in {
            "cache",
            ".cache",
            "__pycache__",
            ".pytest_cache",
            ".ruff_cache",
            "node_modules",
        }
        for component in path.parts
    ):
        return None
    basename = path.name
    if basename in {".env", ".envrc"} or basename.startswith(".env."):
        return None
    return path


def _parse_nul_inventory(output: bytes) -> tuple[PurePosixPath, ...]:
    if output == b"":
        return ()
    if not output.endswith(b"\x00"):
        raise GitSnapshotError("Git inventory is not NUL terminated")
    raw_records = output.split(b"\x00")[:-1]
    parsed = [_relative_path(raw) for raw in raw_records]
    if len(set(raw_records)) != len(raw_records):
        raise GitSnapshotError("Git inventory contains duplicate paths")
    filtered = [path for path in parsed if path is not None]
    paths = set(filtered)
    if len(paths) != len(filtered):
        raise GitSnapshotError("Git inventory contains duplicate paths")
    return tuple(sorted(paths, key=lambda item: item.as_posix()))


def list_source_paths(
    worktree: Path, git_runner: GitRunner = run_git
) -> tuple[PurePosixPath, ...]:
    worktree = _safe_directory(worktree, "Git worktree")
    tracked_result = _checked_git(
        ("ls-files", "--cached", "-z"),
        worktree,
        git_runner,
    )
    untracked_result = _checked_git(
        ("ls-files", "--others", "--exclude-standard", "-z"),
        worktree,
        git_runner,
    )
    ignored_result = git_runner(
        ("ls-files", "--others", "--ignored", "--exclude-standard", "-z"),
        worktree,
    )
    if not isinstance(ignored_result.stdout, bytes) or not isinstance(
        ignored_result.stderr, bytes
    ):
        raise GitSnapshotError("Git runner did not return captured bytes")
    if ignored_result.returncode != 0:
        detail = ignored_result.stderr.decode("utf-8", "replace")[:160]
        raise GitSnapshotError(f"Git ignored-file inventory failed: {detail}")
    tracked = _parse_nul_inventory(tracked_result.stdout)
    untracked = _parse_nul_inventory(untracked_result.stdout)
    _parse_nul_inventory(ignored_result.stdout)
    if set(tracked).intersection(untracked):
        raise GitSnapshotError("Git inventories contain overlapping paths")
    return tuple(
        sorted(set(tracked).union(untracked), key=lambda item: item.as_posix())
    )


def _open_directory(path: Path, label: str) -> int:
    # macOS's /var is a fixed system alias; descriptor traversal must use its
    # canonical spelling because O_NOFOLLOW quite correctly rejects the alias.
    if path.parts[1:2] == ("var",) and Path("/var").is_symlink():
        if Path(os.path.realpath("/var")) != Path("/private/var"):
            raise UnsafePathError(f"{label} contains an unexpected system alias")
        path = Path("/private/var", *path.parts[2:])
    descriptor = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for component in path.parts[1:]:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise UnsafePathError(
            f"{label} contains an unsafe directory component"
        ) from exc


def _pin_directory(path: Path, label: str) -> tuple[int, tuple[int, int]]:
    """Open a directory and prove its pathname did not swap during opening."""

    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise UnsafePathError(f"{label} is not a stable directory")
    descriptor = _open_directory(path, label)
    try:
        opened = os.fstat(descriptor)
        after = os.lstat(path)
        identity = (before.st_dev, before.st_ino)
        if (opened.st_dev, opened.st_ino) != identity or (
            after.st_dev,
            after.st_ino,
        ) != identity:
            raise UnsafePathError(f"{label} changed while opening")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _check_pinned_directory(
    descriptor: int, path: Path, identity: tuple[int, int], label: str
) -> None:
    current = os.fstat(descriptor)
    try:
        pathname = os.lstat(path)
    except OSError as exc:
        raise UnsafePathError(f"{label} disappeared or changed") from exc
    if (current.st_dev, current.st_ino) != identity or (
        pathname.st_dev,
        pathname.st_ino,
    ) != identity:
        raise UnsafePathError(f"{label} changed during operation")


def _verify_destination_root(
    descriptor: int,
    path: Path,
    identity: tuple[int, int],
    label: str,
) -> None:
    item = os.fstat(descriptor)
    owner = os.getuid() if hasattr(os, "getuid") else item.st_uid
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid not in (0, owner)
        or item.st_nlink < 2
        or stat.S_IMODE(item.st_mode) != 0o700
    ):
        raise UnsafePathError(f"{label} is not a private stable directory")
    _check_pinned_directory(descriptor, path, identity, label)


def _open_relative_directory(
    root_descriptor: int,
    components: Sequence[str],
    label: str,
    expected_identities: dict[tuple[str, ...], tuple[int, int] | None] | None = None,
) -> int | None:
    descriptor = os.dup(root_descriptor)
    prefix: tuple[str, ...] = ()
    try:
        for component in components:
            prefix += (component,)
            has_expected = (
                expected_identities is not None and prefix in expected_identities
            )
            expected = expected_identities.get(prefix) if has_expected else None
            try:
                current = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if has_expected and expected is not None:
                    raise UnsafePathError(f"{label} ancestor disappeared") from None
                os.close(descriptor)
                return None
            if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
                raise UnsafePathError(f"{label} contains an unsafe component")
            if has_expected and expected != (
                current.st_dev,
                current.st_ino,
            ):
                raise UnsafePathError(f"{label} ancestor changed before open")
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if has_expected and expected is not None:
                    raise UnsafePathError(f"{label} ancestor disappeared") from None
                os.close(descriptor)
                return None
            opened = os.fstat(next_descriptor)
            if has_expected and expected != (
                opened.st_dev,
                opened.st_ino,
            ):
                os.close(next_descriptor)
                raise UnsafePathError(f"{label} ancestor changed during open")
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise UnsafePathError(f"{label} contains an unsafe component") from exc


def _check_relative_directory(
    root_descriptor: int,
    components: Sequence[str],
    expected_descriptor: int,
    label: str,
    expected_identities: dict[tuple[str, ...], tuple[int, int] | None] | None = None,
) -> None:
    probe = _open_relative_directory(
        root_descriptor, components, label, expected_identities
    )
    if probe is None:
        raise UnsafePathError(f"{label} disappeared during operation")
    try:
        expected = os.fstat(expected_descriptor)
        actual = os.fstat(probe)
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            raise UnsafePathError(f"{label} changed during operation")
    finally:
        os.close(probe)


def _capture_ancestor_identities(
    root_descriptor: int,
    paths: Sequence[PurePosixPath],
) -> dict[tuple[str, ...], tuple[int, int] | None]:
    """Capture every listed path's directory chain before opening files."""

    identities: dict[tuple[str, ...], tuple[int, int] | None] = {}
    for path in paths:
        descriptor = os.dup(root_descriptor)
        prefix: tuple[str, ...] = ()
        try:
            for component in path.parts[:-1]:
                prefix += (component,)
                try:
                    current = os.stat(
                        component, dir_fd=descriptor, follow_symlinks=False
                    )
                except FileNotFoundError:
                    prior = identities.setdefault(prefix, None)
                    if prior is not None:
                        raise UnsafePathError(
                            "source ancestor identity changed"
                        ) from None
                    break
                if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
                    raise UnsafePathError("source ancestor is not a directory")
                identity = (current.st_dev, current.st_ino)
                prior = identities.setdefault(prefix, identity)
                if prior != identity:
                    raise UnsafePathError("source ancestor identity changed")
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
                opened = os.fstat(next_descriptor)
                if (opened.st_dev, opened.st_ino) != identity:
                    os.close(next_descriptor)
                    raise UnsafePathError("source ancestor changed during preflight")
                os.close(descriptor)
                descriptor = next_descriptor
        finally:
            os.close(descriptor)
    return identities


def _snapshot_file(
    worktree: Path,
    relative: PurePosixPath,
    root_descriptor: int | None = None,
    ancestor_identities: dict[tuple[str, ...], tuple[int, int] | None] | None = None,
) -> SnapshotFile:
    owns_root = root_descriptor is None
    root_identity: tuple[int, int] | None = None
    if owns_root:
        root_descriptor, root_identity = _pin_directory(worktree, "source root")
    if root_descriptor is None:
        raise UnsafePathError("source root descriptor is unavailable")
    parent_descriptor = _open_relative_directory(
        root_descriptor,
        relative.parts[:-1],
        "source",
        ancestor_identities,
    )
    if parent_descriptor is None:
        if owns_root:
            _check_pinned_directory(
                root_descriptor, worktree, root_identity, "source root"
            )
            os.close(root_descriptor)
        return SnapshotFile(relative, False, None, None)
    descriptor: int | None = None
    try:
        name = relative.parts[-1]
        try:
            before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return SnapshotFile(relative, False, None, None)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise UnsafePathError(f"source path is not a regular file: {relative}")
        if before.st_nlink != 1:
            raise UnsafePathError(f"source path is hard-linked: {relative}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise UnsafePathError(f"source path changed before read: {relative}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, _CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        identity = (before.st_dev, before.st_ino)
        if (after_fd.st_dev, after_fd.st_ino) != identity or (
            after_path.st_dev,
            after_path.st_ino,
        ) != identity:
            raise UnsafePathError(f"source path changed while reading: {relative}")
        if (
            after_fd.st_size != before.st_size
            or after_fd.st_mtime_ns != before.st_mtime_ns
            or stat.S_IMODE(after_fd.st_mode) != stat.S_IMODE(before.st_mode)
            or after_fd.st_nlink != 1
        ):
            raise UnsafePathError(
                f"source path metadata changed while reading: {relative}"
            )
        if root_descriptor is not None:
            _check_relative_directory(
                root_descriptor,
                relative.parts[:-1],
                parent_descriptor,
                "source parent",
                ancestor_identities,
            )
        return SnapshotFile(
            relative, True, digest.hexdigest(), stat.S_IMODE(before.st_mode)
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)
        if owns_root:
            _check_pinned_directory(
                root_descriptor, worktree, root_identity, "source root"
            )
            os.close(root_descriptor)


def _capture_checkout_state(
    worktree: Path,
    git_runner: GitRunner,
    root_descriptor: int,
    root_identity: tuple[int, int],
    ancestor_identities_out: dict[tuple[str, ...], tuple[int, int] | None]
    | None = None,
) -> CheckoutState:
    _check_pinned_directory(root_descriptor, worktree, root_identity, "source root")
    status = _checked_git(
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        worktree,
        git_runner,
    ).stdout
    paths = list_source_paths(worktree, git_runner)
    ancestor_identities = _capture_ancestor_identities(root_descriptor, paths)
    if ancestor_identities_out is not None:
        ancestor_identities_out.update(ancestor_identities)
    files = tuple(
        _snapshot_file(worktree, path, root_descriptor, ancestor_identities)
        for path in paths
    )
    _check_pinned_directory(root_descriptor, worktree, root_identity, "source root")
    return CheckoutState(status, files)


def capture_checkout_state(
    worktree: Path, git_runner: GitRunner = run_git
) -> CheckoutState:
    worktree = _safe_directory(worktree, "Git worktree")
    root_descriptor, root_identity = _pin_directory(worktree, "source root")
    try:
        return _capture_checkout_state(
            worktree, git_runner, root_descriptor, root_identity
        )
    finally:
        os.close(root_descriptor)


def _mkdir_private(parent_descriptor: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
    except FileExistsError:
        pass
    item = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
        raise UnsafePathError("snapshot destination component is unsafe")
    os.chmod(name, 0o700, dir_fd=parent_descriptor, follow_symlinks=False)
    return os.open(
        name,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_descriptor,
    )


def _destination_directory(
    root: Path, relative: PurePosixPath, root_descriptor: int | None = None
) -> int:
    descriptor = (
        os.dup(root_descriptor)
        if root_descriptor is not None
        else _open_directory(root, "snapshot destination")
    )
    try:
        for component in relative.parts:
            next_descriptor = _mkdir_private(descriptor, component)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_destination_file(
    descriptor: int,
    parent_descriptor: int,
    name: str,
    expected: SnapshotFile,
    mode: int,
    size: int,
) -> None:
    held = os.fstat(descriptor)
    pathname = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        (held.st_dev, held.st_ino) != (pathname.st_dev, pathname.st_ino)
        or not stat.S_ISREG(held.st_mode)
        or held.st_nlink != 1
        or stat.S_IMODE(held.st_mode) != mode
        or held.st_size != size
    ):
        raise UnsafePathError("destination final file changed")
    verifier = os.open(
        name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_descriptor
    )
    try:
        opened = os.fstat(verifier)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(verifier, _CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(verifier)
        final = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            (opened.st_dev, opened.st_ino) != (held.st_dev, held.st_ino)
            or (after.st_dev, after.st_ino) != (held.st_dev, held.st_ino)
            or (final.st_dev, final.st_ino) != (held.st_dev, held.st_ino)
            or after.st_nlink != 1
            or stat.S_IMODE(after.st_mode) != mode
            or after.st_size != size
            or digest.hexdigest() != expected.sha256
        ):
            raise UnsafePathError("destination final content changed")
    finally:
        os.close(verifier)


def _copy_one(
    worktree: Path,
    destination: Path,
    relative: PurePosixPath,
    expected: SnapshotFile,
    source_root_descriptor: int | None = None,
    destination_root_descriptor: int | None = None,
    ancestor_identities: dict[tuple[str, ...], tuple[int, int] | None] | None = None,
) -> None:
    source_parent = (
        _open_relative_directory(
            source_root_descriptor,
            relative.parts[:-1],
            "source",
            ancestor_identities,
        )
        if source_root_descriptor is not None
        else _open_directory(worktree / Path(*relative.parts[:-1]), "source")
    )
    if source_parent is None:
        raise UnsafePathError(f"source parent disappeared: {relative}")
    destination_parent = _destination_directory(
        destination,
        PurePosixPath(*relative.parts[:-1]),
        destination_root_descriptor,
    )
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    try:
        name = relative.parts[-1]
        source_stat = os.stat(name, dir_fd=source_parent, follow_symlinks=False)
        if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISREG(source_stat.st_mode):
            raise UnsafePathError(f"source path is not a regular file: {relative}")
        if source_stat.st_nlink != 1:
            raise UnsafePathError(f"source path is hard-linked: {relative}")
        source_mode = stat.S_IMODE(source_stat.st_mode)
        if source_mode != expected.mode:
            raise UnsafePathError(f"source mode changed before copying: {relative}")
        source_descriptor = os.open(
            name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_parent
        )
        opened = os.fstat(source_descriptor)
        if (opened.st_dev, opened.st_ino) != (source_stat.st_dev, source_stat.st_ino):
            raise UnsafePathError(f"source path changed before copy: {relative}")
        destination_descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600 | (source_mode & 0o111),
            dir_fd=destination_parent,
        )
        digest = hashlib.sha256()
        copied_size = 0
        while True:
            chunk = os.read(source_descriptor, _CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            copied_size += len(chunk)
            offset = 0
            while offset < len(chunk):
                offset += os.write(destination_descriptor, chunk[offset:])
        os.fchmod(destination_descriptor, 0o600 | (source_mode & 0o111))
        os.fsync(destination_descriptor)
        destination_mode = 0o600 | (source_mode & 0o111)
        destination_stat = os.fstat(destination_descriptor)
        if (
            not stat.S_ISREG(destination_stat.st_mode)
            or destination_stat.st_nlink != 1
            or stat.S_IMODE(destination_stat.st_mode) != destination_mode
            or destination_stat.st_size != copied_size
        ):
            raise UnsafePathError(f"destination file metadata changed: {relative}")
        final_stat = os.stat(name, dir_fd=destination_parent, follow_symlinks=False)
        if (
            (final_stat.st_dev, final_stat.st_ino)
            != (destination_stat.st_dev, destination_stat.st_ino)
            or not stat.S_ISREG(final_stat.st_mode)
            or final_stat.st_nlink != 1
            or stat.S_IMODE(final_stat.st_mode) != destination_mode
            or final_stat.st_size != copied_size
        ):
            raise UnsafePathError(f"destination file was replaced: {relative}")
        verify_descriptor = os.open(
            name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=destination_parent
        )
        try:
            verify_stat = os.fstat(verify_descriptor)
            verify_digest = hashlib.sha256()
            while True:
                chunk = os.read(verify_descriptor, _CHUNK_SIZE)
                if not chunk:
                    break
                verify_digest.update(chunk)
            verify_after = os.fstat(verify_descriptor)
            final_after = os.stat(
                name, dir_fd=destination_parent, follow_symlinks=False
            )
            if (
                (verify_stat.st_dev, verify_stat.st_ino)
                != (destination_stat.st_dev, destination_stat.st_ino)
                or (verify_after.st_dev, verify_after.st_ino)
                != (destination_stat.st_dev, destination_stat.st_ino)
                or final_after.st_ino != destination_stat.st_ino
                or final_after.st_dev != destination_stat.st_dev
                or verify_after.st_nlink != 1
                or stat.S_IMODE(verify_after.st_mode) != destination_mode
                or verify_after.st_size != copied_size
                or verify_digest.hexdigest() != expected.sha256
            ):
                raise UnsafePathError(f"destination content changed: {relative}")
        finally:
            os.close(verify_descriptor)
        after_source = os.fstat(source_descriptor)
        after_path = os.stat(name, dir_fd=source_parent, follow_symlinks=False)
        if (after_source.st_dev, after_source.st_ino) != (
            source_stat.st_dev,
            source_stat.st_ino,
        ) or (
            after_path.st_dev,
            after_path.st_ino,
        ) != (source_stat.st_dev, source_stat.st_ino):
            raise UnsafePathError(f"source path changed while copying: {relative}")
        if (
            after_source.st_size != source_stat.st_size
            or stat.S_IMODE(after_source.st_mode) != expected.mode
            or after_source.st_nlink != 1
            or digest.hexdigest() != expected.sha256
        ):
            raise UnsafePathError(f"source path size changed while copying: {relative}")
        if source_root_descriptor is not None:
            _check_relative_directory(
                source_root_descriptor,
                relative.parts[:-1],
                source_parent,
                "source parent",
                ancestor_identities,
            )
        if destination_root_descriptor is not None:
            _check_relative_directory(
                destination_root_descriptor,
                relative.parts[:-1],
                destination_parent,
                "snapshot parent",
            )
        _verify_destination_file(
            destination_descriptor,
            destination_parent,
            name,
            expected,
            destination_mode,
            copied_size,
        )
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
        os.close(destination_parent)
        os.close(source_parent)


def _prepare_destination(
    destination: Path, worktree: Path
) -> tuple[int, tuple[int, int]]:
    if not destination.is_absolute():
        raise UnsafePathError("snapshot destination must be absolute")
    parent = destination.parent
    _safe_directory(parent, "snapshot destination parent")
    resolved_worktree = worktree.resolve(strict=True)
    resolved_destination = destination.resolve(strict=False)
    if (
        resolved_destination == resolved_worktree
        or resolved_worktree in resolved_destination.parents
        or resolved_destination in resolved_worktree.parents
    ):
        raise UnsafePathError("snapshot destination overlaps worktree")
    try:
        item = os.lstat(destination)
    except FileNotFoundError:
        item = None
    if item is not None:
        raise UnsafePathError("snapshot destination already exists")
    parent_descriptor = _open_directory(parent, "snapshot destination parent")
    descriptor: int | None = None
    try:
        os.mkdir(destination.name, 0o700, dir_fd=parent_descriptor)
        descriptor = os.open(
            destination.name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        item = os.fstat(descriptor)
        identity = (item.st_dev, item.st_ino)
        _verify_destination_root(
            descriptor, destination, identity, "snapshot destination"
        )
        return descriptor, identity
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent_descriptor)


def create_snapshot(
    worktree: Path, destination: Path, git_runner: GitRunner = run_git
) -> GitSnapshot:
    worktree = _safe_directory(worktree, "Git worktree")
    destination_root_descriptor, destination_root_identity = _prepare_destination(
        destination, worktree
    )
    source_root_descriptor: int | None = None
    try:
        source_root_descriptor, source_root_identity = _pin_directory(
            worktree, "source root"
        )
        _verify_destination_root(
            destination_root_descriptor,
            destination,
            destination_root_identity,
            "snapshot destination",
        )
        ancestor_identities: dict[tuple[str, ...], tuple[int, int] | None] = {}
        before = _capture_checkout_state(
            worktree,
            git_runner,
            source_root_descriptor,
            source_root_identity,
            ancestor_identities,
        )
        for source in before.files:
            if source.exists:
                _copy_one(
                    worktree,
                    destination,
                    source.relative_path,
                    source,
                    source_root_descriptor,
                    destination_root_descriptor,
                    ancestor_identities,
                )
        _check_pinned_directory(
            source_root_descriptor, worktree, source_root_identity, "source root"
        )
        _verify_destination_root(
            destination_root_descriptor,
            destination,
            destination_root_identity,
            "snapshot destination",
        )
    except BaseException:
        # The destination was newly created by this call.  It is deliberately
        # not returned as a valid snapshot after a partial or raced copy.
        raise
    finally:
        os.close(destination_root_descriptor)
        if source_root_descriptor is not None:
            os.close(source_root_descriptor)
    return GitSnapshot(worktree, destination, before)


def assert_checkout_unchanged(
    snapshot: GitSnapshot, git_runner: GitRunner = run_git
) -> None:
    root_descriptor, root_identity = _pin_directory(snapshot.worktree, "source root")
    try:
        current = _capture_checkout_state(
            snapshot.worktree, git_runner, root_descriptor, root_identity
        )
        _check_pinned_directory(
            root_descriptor, snapshot.worktree, root_identity, "source root"
        )
    finally:
        os.close(root_descriptor)
    if current != snapshot.before:
        raise GitSnapshotError("source checkout changed during validation")
