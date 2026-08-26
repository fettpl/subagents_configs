"""Small filesystem operations with explicit non-following and atomicity rules."""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from .errors import TransactionError
from .locks import IdentityEvidence
from .models import DesiredFile
from .paths import normalized_absolute

_UNSUPPORTED_DIRECTORY_SYNC = {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}
_CHUNK_SIZE = 1024 * 1024
_DIRECTORY_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_ATOMIC_EXPECTATION_UNSET = object()
_ATOMIC_EXPECTATION: ContextVar[object] = ContextVar(
    "subagents_configs_atomic_expectation", default=_ATOMIC_EXPECTATION_UNSET
)


@contextmanager
def expected_atomic_identity(before: IdentityEvidence | None):
    """Bind an expected identity for callers that retain the atomic-write seam."""

    token = _ATOMIC_EXPECTATION.set(before)
    try:
        yield
    finally:
        _ATOMIC_EXPECTATION.reset(token)


def _after_parent_pin(operation: str, parent: Path) -> None:
    """Narrow operation seam used to exercise parent-swap races in tests."""


def _open_directory_component(component: str, parent_fd: int, label: str) -> int:
    try:
        return os.open(component, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError(f"{label} contains a symlink or non-directory") from exc
        raise


@contextmanager
def _pinned_directory(path: Path, label: str):
    """Yield a directory fd after no-following traversal from a pinned root."""

    absolute = normalized_absolute(path)
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in absolute.parts[1:]:
            next_descriptor = _open_directory_component(component, descriptor, label)
            os.close(descriptor)
            descriptor = next_descriptor
        yield descriptor
    finally:
        os.close(descriptor)


def _stat_at_no_follow(parent_fd: int, name: str):
    try:
        result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None
        raise
    return result


def _stat_at(parent_fd: int, name: str, label: str):
    result = _stat_at_no_follow(parent_fd, name)
    if result is None:
        return None
    if stat.S_ISLNK(result.st_mode):
        raise ValueError(f"{label} must not be a symlink")
    return result


def _open_regular_read(path: Path, label: str, operation: str = "read") -> int:
    absolute = normalized_absolute(path)
    with _pinned_directory(absolute.parent, label) as parent_fd:
        _after_parent_pin(operation, absolute.parent)
        result = _stat_at(parent_fd, absolute.name, label)
        if result is None:
            raise FileNotFoundError(absolute)
        if not stat.S_ISREG(result.st_mode):
            raise ValueError(f"{label} must be a regular file: {absolute}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError(f"{label} must be a regular file: {absolute}")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    descriptor = _open_regular_read(path, "file")
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, _CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _read_descriptor_bytes(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, _CHUNK_SIZE)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def read_bytes_with_evidence(path: Path, label: str) -> tuple[IdentityEvidence, bytes]:
    """Read one regular file and derive its complete evidence from its fd."""

    descriptor = _open_regular_read(path, label)
    try:
        return read_descriptor_with_evidence(descriptor, label)
    finally:
        os.close(descriptor)


def read_descriptor_with_evidence(
    descriptor: int, label: str
) -> tuple[IdentityEvidence, bytes]:
    """Read one already pinned descriptor and derive complete evidence."""

    content = _read_descriptor_bytes(descriptor)
    evidence = _evidence_from_descriptor(descriptor, label, known_content=content)
    return evidence, content


@dataclass(frozen=True)
class StateInventory:
    """Validated state objects captured together for one planning command."""

    manifest: object | None
    journal: object | None


@dataclass(frozen=True)
class ReadSnapshot:
    """Immutable bytes tied to complete evidence for one normalized path."""

    path: Path
    evidence: IdentityEvidence
    content: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("read snapshot path must be a Path")
        if not isinstance(self.evidence, IdentityEvidence):
            raise TypeError("read snapshot evidence is required")
        if type(self.content) is not bytes:
            raise TypeError("read snapshot content must be bytes")
        if self.evidence.size != len(self.content):
            raise ValueError("read snapshot size does not match identity evidence")


class CommandCache:
    """Ephemeral read/hash/state cache owned by one preflight command."""

    def __init__(self) -> None:
        self._bytes: dict[Path, ReadSnapshot] = {}
        self._hashes: dict[bytes, str] = {}
        self._states: dict[tuple[Path, object], StateInventory] = {}

    def __enter__(self) -> CommandCache:
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()

    def close(self) -> None:
        self._bytes.clear()
        self._hashes.clear()
        self._states.clear()

    def remember_bytes(
        self, path: Path, evidence: IdentityEvidence, content: bytes
    ) -> bytes:
        if not isinstance(path, Path) or not isinstance(evidence, IdentityEvidence):
            raise TypeError("cached bytes require a Path and identity evidence")
        if type(content) is not bytes:
            raise TypeError("cached bytes must be bytes")
        digest = self._hashes.get(content)
        if digest is None:
            digest = sha256_bytes(content)
            self._hashes[content] = digest
        if evidence.size != len(content) or evidence.sha256 != digest:
            raise ValueError("cached bytes disagree with identity evidence")
        self._hashes[content] = evidence.sha256
        key = normalized_absolute(path)
        self._bytes[key] = ReadSnapshot(key, evidence, content)
        return content

    def read_bytes(self, path: Path, evidence: IdentityEvidence) -> bytes:
        """Return bytes for evidence, reading and proving them on a cache miss."""

        if not isinstance(path, Path) or not isinstance(evidence, IdentityEvidence):
            raise TypeError("cached read requires a Path and identity evidence")
        key = normalized_absolute(path)
        cached = self._bytes.get(key)
        if cached is not None and cached.evidence == evidence:
            return cached.content
        actual, content = read_bytes_with_evidence(key, "cached file")
        if actual != evidence:
            raise TransactionError("cached file identity evidence does not match")
        self._bytes[key] = ReadSnapshot(key, actual, content)
        return content

    def read_regular(self, path: Path, label: str) -> ReadSnapshot:
        """Read and revalidate a regular file against complete cached evidence."""

        key = normalized_absolute(path)
        cached = self._bytes.get(key)
        if cached is None:
            try:
                evidence, content = read_bytes_with_evidence(key, label)
            except FileNotFoundError:
                raise
            self._hashes[content] = evidence.sha256
            snapshot = ReadSnapshot(key, evidence, content)
            self._bytes[key] = snapshot
            return snapshot
        evidence, content = read_bytes_with_evidence(key, label)
        if evidence != cached.evidence:
            raise TransactionError("cached regular file identity changed")
        return cached

    def read_source(
        self, path: Path, reader: Callable[[], tuple[IdentityEvidence, bytes]]
    ) -> bytes:
        """Read a pinned source once, then reuse its validated immutable buffer."""

        key = normalized_absolute(path)
        cached = self._bytes.get(key)
        if cached is None:
            evidence, content = reader()
            self._hashes[content] = evidence.sha256
            self.remember_bytes(key, evidence, content)
            return content
        return cached.content

    def hash_bytes(self, content: bytes) -> str:
        if type(content) is not bytes:
            raise TypeError("hash input must be bytes")
        digest = self._hashes.get(content)
        if digest is None:
            digest = sha256_bytes(content)
            self._hashes[content] = digest
        return digest

    def inventory_state(self, home: Path, descriptor) -> StateInventory:
        key = (normalized_absolute(home), descriptor.target)
        cached = self._states.get(key)
        if cached is not None:
            return cached
        from .state import load_state

        manifest, journal = load_state(key[0], descriptor)
        result = StateInventory(manifest, journal)
        self._states[key] = result
        return result


def _evidence_from_descriptor(
    descriptor: int, label: str, *, known_content: bytes | None = None
) -> IdentityEvidence:
    result = os.fstat(descriptor)
    if not stat.S_ISREG(result.st_mode):
        raise ValueError(f"{label} must be a regular file")
    if known_content is None:
        digest = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, _CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        sha256 = digest.hexdigest()
    else:
        sha256 = sha256_bytes(known_content)
    after = os.fstat(descriptor)
    if (
        result.st_dev,
        result.st_ino,
        result.st_size,
        result.st_nlink,
        stat.S_IMODE(result.st_mode),
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_nlink,
        stat.S_IMODE(after.st_mode),
    ):
        raise TransactionError(f"{label} changed while collecting identity evidence")
    return IdentityEvidence(
        device=result.st_dev,
        inode=result.st_ino,
        size=result.st_size,
        nlink=result.st_nlink,
        mode=stat.S_IMODE(result.st_mode),
        sha256=sha256,
    )


def capture_evidence(path: Path, label: str) -> IdentityEvidence | None:
    """Capture six identity fields from one pinned, no-following descriptor."""

    target = normalized_absolute(path)
    with _pinned_directory(target.parent, f"{label} parent") as parent_fd:
        _after_parent_pin("evidence", target.parent)
        result = _stat_at(parent_fd, target.name, label)
        if result is None:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(target.name, flags, dir_fd=parent_fd)
        except FileNotFoundError as exc:
            raise TransactionError(
                f"{label} disappeared while collecting evidence"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (result.st_dev, result.st_ino):
                raise TransactionError(
                    f"{label} was replaced while collecting evidence"
                )
            return _evidence_from_descriptor(descriptor, label)
        finally:
            os.close(descriptor)


def _same_evidence(
    left: IdentityEvidence | None, right: IdentityEvidence | None
) -> bool:
    return left == right


def compare_and_swap(
    path: Path,
    before: IdentityEvidence | None,
    after_content: bytes | None,
    after_mode: int | None,
    action: str,
) -> IdentityEvidence | None:
    """Mutate a regular target only when complete descriptor evidence matches.

    Creates use a same-directory hard link so a late-created target can never
    be overwritten. Replacements and removals detach the proven target into a
    private quarantine name before installing/removing anything; if the
    detached identity is not the expected one, it is restored without
    overwriting a concurrent replacement.
    """

    if action not in {"create", "replace", "unlink", "chmod"}:
        raise ValueError("unsupported compare-and-swap action")
    if after_mode is not None and (
        type(after_mode) is not int or after_mode < 0 or after_mode > 0o777
    ):
        raise ValueError("invalid after mode")
    if action == "unlink" and (after_content is not None or after_mode is not None):
        raise ValueError("unlink cannot carry after state")
    if action == "chmod" and after_content is not None:
        raise ValueError("chmod cannot carry replacement content")
    if action in {"create", "replace"} and (
        not isinstance(after_content, bytes) or after_mode is None
    ):
        raise ValueError("file replacement requires bytes and mode")
    target = normalized_absolute(path)
    with _pinned_directory(target.parent, f"{action} parent") as parent_fd:
        _after_parent_pin(f"cas-{action}", target.parent)
        current = None
        existing = _stat_at(parent_fd, target.name, f"{action} target")
        if existing is not None:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(target.name, flags, dir_fd=parent_fd)
            except OSError as exc:
                raise TransactionError(
                    "target disappeared during compare-and-swap"
                ) from exc
            try:
                current = _evidence_from_descriptor(descriptor, f"{action} target")
                if (current.device, current.inode) != (
                    existing.st_dev,
                    existing.st_ino,
                ):
                    raise TransactionError(
                        "target identity changed during compare-and-swap"
                    )
            finally:
                os.close(descriptor)
        if not _same_evidence(current, before):
            raise TransactionError("target identity evidence does not match")
        if action == "unlink":
            if current is None:
                raise TransactionError("unlink requires an existing target")
            _before_unlink_mutation(target.parent)
            descriptor = os.open(
                target.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            try:
                revalidated = _evidence_from_descriptor(descriptor, "unlink target")
            finally:
                os.close(descriptor)
            if revalidated != before:
                raise TransactionError("target identity changed before unlink")
            quarantine = _quarantine_path(target.parent, target).name
            try:
                os.rename(
                    target.name,
                    quarantine,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
            except OSError as exc:
                raise TransactionError("target disappeared during unlink") from exc
            detached = None
            try:
                descriptor = os.open(
                    quarantine,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                try:
                    detached = _evidence_from_descriptor(
                        descriptor, "unlink quarantine"
                    )
                finally:
                    os.close(descriptor)
                if detached != before:
                    _restore_quarantine(parent_fd, quarantine, target.name, detached)
                    raise TransactionError("target identity changed during unlink")
                os.unlink(quarantine, dir_fd=parent_fd)
            except BaseException:
                if detached != before:
                    _restore_quarantine(parent_fd, quarantine, target.name, before)
                raise
            _sync_parent_directory_fd(parent_fd)
            if capture_evidence(target, "unlinked target") is not None:
                raise TransactionError("unlink postcondition could not be proved")
            return None
        if action == "chmod":
            if current is None or after_mode is None:
                raise TransactionError("chmod requires an existing target")
            _before_chmod_mutation(target.parent)
            descriptor = os.open(
                target.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            try:
                revalidated = _evidence_from_descriptor(descriptor, "chmod target")
                if revalidated != before:
                    raise TransactionError("target identity changed before chmod")
                os.fchmod(descriptor, after_mode)
                os.fsync(descriptor)
                result = _evidence_from_descriptor(descriptor, "chmod target")
            finally:
                os.close(descriptor)
            _sync_parent_directory_fd(parent_fd)
            if capture_evidence(target, "chmod target") != result:
                raise TransactionError("chmod target was replaced during mutation")
            return result
        if after_content is None or after_mode is None:
            raise TransactionError("replacement content is missing")
        if action == "create" and current is not None:
            raise TransactionError("create target already exists")
        temporary = _temporary_path(target.parent, target)
        descriptor = None
        created = False
        installed = False
        try:
            descriptor = os.open(
                temporary.name,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                after_mode,
                dir_fd=parent_fd,
            )
            created = True
            _write_all(descriptor, after_content)
            os.fchmod(descriptor, after_mode)
            os.fsync(descriptor)
            temporary_evidence = _evidence_from_descriptor(
                descriptor, "CAS temporary", known_content=after_content
            )
            if action == "create":
                _before_create_mutation(target.parent)
                current = _stat_at(parent_fd, target.name, "create target")
                if current is not None:
                    raise TransactionError("create target appeared during mutation")
                mutation = "create"
            else:
                _before_replace_mutation(target.parent)
                mutation = "replace"
                # The first check is intentionally after the temporary has
                # been flushed. A second descriptor-relative proof happens
                # immediately before detaching the target below.
                descriptor_target = os.open(
                    target.name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                try:
                    if (
                        _evidence_from_descriptor(descriptor_target, "replace target")
                        != before
                    ):
                        raise TransactionError(
                            "target identity changed before replacement"
                        )
                finally:
                    os.close(descriptor_target)

            temporary_stat = _stat_at_no_follow(parent_fd, temporary.name)
            if temporary_stat is None or (
                temporary_stat.st_dev,
                temporary_stat.st_ino,
            ) != (temporary_evidence.device, temporary_evidence.inode):
                raise TransactionError("CAS temporary identity changed")

            if mutation == "create":
                try:
                    _link_no_replace(parent_fd, temporary.name, target.name)
                except FileExistsError as exc:
                    raise TransactionError(
                        "create target appeared during mutation"
                    ) from exc
                installed = True
            else:
                quarantine = _quarantine_path(target.parent, target).name
                detached: IdentityEvidence | None = None
                try:
                    os.rename(
                        target.name,
                        quarantine,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    descriptor_target = os.open(
                        quarantine,
                        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent_fd,
                    )
                    try:
                        detached = _evidence_from_descriptor(
                            descriptor_target, "replace quarantine"
                        )
                    finally:
                        os.close(descriptor_target)
                    if detached != before:
                        _restore_quarantine(
                            parent_fd, quarantine, target.name, detached
                        )
                        raise TransactionError(
                            "target identity changed during replacement"
                        )
                    try:
                        _link_no_replace(parent_fd, temporary.name, target.name)
                    except FileExistsError as exc:
                        _remove_owned_quarantine(parent_fd, quarantine, before)
                        raise TransactionError(
                            "replacement target appeared during mutation"
                        ) from exc
                    installed = True
                    _remove_owned_quarantine(parent_fd, quarantine, before)
                except BaseException:
                    if not installed and detached == before:
                        _restore_quarantine(parent_fd, quarantine, target.name, before)
                    raise

            _remove_owned_temp(parent_fd, temporary.name, temporary_evidence)
            _sync_parent_directory_fd(parent_fd)
        except OSError as exc:
            raise TransactionError("compare-and-swap replacement failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if created and not installed:
                try:
                    temporary_stat = _stat_at_no_follow(parent_fd, temporary.name)
                    if temporary_stat is not None:
                        descriptor_temp = os.open(
                            temporary.name,
                            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=parent_fd,
                        )
                        try:
                            owned_temp = _evidence_from_descriptor(
                                descriptor_temp, "CAS temporary cleanup"
                            )
                        finally:
                            os.close(descriptor_temp)
                        if owned_temp.sha256 == sha256_bytes(after_content):
                            os.unlink(temporary.name, dir_fd=parent_fd)
                except OSError:
                    pass
        if action == "create" and not installed:
            raise TransactionError("create target was not installed")
        descriptor = os.open(
            target.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            result = _evidence_from_descriptor(descriptor, f"{action} target")
        finally:
            os.close(descriptor)
        if result.sha256 != sha256_bytes(after_content) or result.mode != after_mode:
            raise TransactionError("replacement postcondition could not be proved")
        return result


def safe_mutate(
    path: Path,
    expected: IdentityEvidence | None,
    desired: DesiredFile | None,
) -> IdentityEvidence | None:
    """Public typed mutation seam preserving descriptor-relative CAS checks."""
    if not isinstance(path, Path):
        raise TypeError("mutation path must be a Path")
    if expected is not None and not isinstance(expected, IdentityEvidence):
        raise TypeError("expected mutation evidence has the wrong type")
    if desired is not None and not isinstance(desired, DesiredFile):
        raise TypeError("desired mutation file has the wrong type")
    if desired is None:
        if expected is None:
            raise ValueError("safe mutation cannot remove an absent target")
        return compare_and_swap(path, expected, None, None, "unlink")
    action = "create" if expected is None else "replace"
    return compare_and_swap(path, expected, desired.content, desired.mode, action)


def ensure_directory(
    path: Path, *, private: bool = False
) -> list[tuple[Path, tuple[int, int, int, int]]]:
    """Create a directory chain without following existing links."""

    absolute = normalized_absolute(path)
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    current = Path(absolute.anchor)
    created_identities: list[tuple[Path, tuple[int, int, int, int]]] = []
    try:
        components = absolute.parts[1:]
        for index, component in enumerate(components):
            current /= component
            try:
                next_descriptor = _open_directory_component(
                    component, descriptor, "private directory"
                )
                created = False
            except FileNotFoundError:
                _after_parent_pin("mkdir", current.parent)
                os.mkdir(component, 0o700, dir_fd=descriptor)
                next_descriptor = _open_directory_component(
                    component, descriptor, "private directory"
                )
                created = True
            os.close(descriptor)
            descriptor = next_descriptor
            if index == len(components) - 1 and not created and private:
                if stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o077:
                    raise ValueError(f"existing directory is not private: {current}")
            if created:
                result = os.fstat(descriptor)
                created_identities.append(
                    (
                        current,
                        (
                            result.st_dev,
                            result.st_ino,
                            result.st_nlink,
                            stat.S_IMODE(result.st_mode),
                        ),
                    )
                )
    finally:
        os.close(descriptor)
    return created_identities


def ensure_private_directory(path: Path) -> None:
    """Create a private directory chain without following existing links."""

    ensure_directory(path, private=True)


def remove_owned_directory(
    path: Path, expected_identity: tuple[int, int, int, int]
) -> None:
    """Detach and remove a directory only after proving its opened identity."""

    target = normalized_absolute(path)
    with _pinned_directory(target.parent, "owned-directory cleanup") as parent_fd:
        _after_parent_pin("owned-directory-cleanup", target.parent)
        descriptor = _open_directory_component(
            target.name, parent_fd, "owned-directory cleanup"
        )
        try:
            result = os.fstat(descriptor)
            identity = (
                result.st_dev,
                result.st_ino,
                result.st_nlink,
                stat.S_IMODE(result.st_mode),
            )
            if identity != expected_identity:
                return
            quarantine_name = f".{target.name}.cleanup-{secrets.token_hex(16)}"
            os.rename(
                target.name,
                quarantine_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            moved = _stat_at_no_follow(parent_fd, quarantine_name)
            if moved is None or (moved.st_dev, moved.st_ino) != (
                result.st_dev,
                result.st_ino,
            ):
                try:
                    if _stat_at_no_follow(parent_fd, target.name) is None:
                        os.rename(
                            quarantine_name,
                            target.name,
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                        )
                except OSError:
                    pass
                return
            try:
                os.rmdir(quarantine_name, dir_fd=parent_fd)
            except BaseException:
                try:
                    if _stat_at_no_follow(parent_fd, target.name) is None:
                        os.rename(
                            quarantine_name,
                            target.name,
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                        )
                except OSError:
                    pass
                raise
            _sync_parent_directory_fd(parent_fd)
        finally:
            os.close(descriptor)


def _sync_parent_directory_fd(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as exc:
        if exc.errno not in _UNSUPPORTED_DIRECTORY_SYNC:
            raise


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("write returned no progress")
        offset += written


def _temporary_path(parent: Path, target: Path) -> Path:
    return parent / f".{target.name}.tmp-{secrets.token_hex(16)}"


def _quarantine_path(parent: Path, target: Path) -> Path:
    return parent / f".{target.name}.cas-{secrets.token_hex(16)}"


def _before_create_mutation(_parent: Path) -> None:
    """Stable seam immediately before a no-overwrite create."""


def _before_replace_mutation(_parent: Path) -> None:
    """Stable seam immediately before a replacement revalidation."""


def _before_unlink_mutation(_parent: Path) -> None:
    """Stable seam immediately before an unlink revalidation."""


def _before_chmod_mutation(_parent: Path) -> None:
    """Stable seam immediately before a chmod revalidation."""


def _link_no_replace(parent_fd: int, source: str, target: str) -> None:
    os.link(
        source,
        target,
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
        follow_symlinks=False,
    )


def _restore_quarantine(
    parent_fd: int, quarantine: str, target: str, expected: IdentityEvidence
) -> None:
    """Restore a detached expected file without overwriting a replacement."""

    try:
        quarantine_stat = _stat_at_no_follow(parent_fd, quarantine)
        if quarantine_stat is None:
            return
        descriptor = os.open(
            quarantine,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            if _evidence_from_descriptor(descriptor, "CAS quarantine") != expected:
                return
        finally:
            os.close(descriptor)
        try:
            _link_no_replace(parent_fd, quarantine, target)
        except FileExistsError:
            return
        os.unlink(quarantine, dir_fd=parent_fd)
    except (FileNotFoundError, OSError):
        return


def _remove_owned_quarantine(
    parent_fd: int, quarantine: str, expected: IdentityEvidence
) -> None:
    descriptor = os.open(
        quarantine,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    try:
        actual = _evidence_from_descriptor(descriptor, "CAS quarantine")
    finally:
        os.close(descriptor)
    if actual != expected:
        raise TransactionError("CAS quarantine identity changed")
    os.unlink(quarantine, dir_fd=parent_fd)


def _remove_owned_temp(
    parent_fd: int, temporary: str, expected: IdentityEvidence
) -> None:
    descriptor = os.open(
        temporary,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    try:
        actual = _evidence_from_descriptor(descriptor, "CAS temporary cleanup")
    finally:
        os.close(descriptor)
    if (
        actual.device,
        actual.inode,
        actual.size,
        actual.mode,
        actual.sha256,
    ) != (
        expected.device,
        expected.inode,
        expected.size,
        expected.mode,
        expected.sha256,
    ):
        raise TransactionError("CAS temporary identity changed")
    os.unlink(temporary, dir_fd=parent_fd)


def atomic_write(path: Path, content: bytes, mode: int = 0o600) -> IdentityEvidence:
    """Replace a regular target with complete, durably flushed bytes."""

    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if mode < 0 or mode > 0o777 or mode & 0o077:
        raise ValueError("managed file mode must not grant group or other access")
    expected = _ATOMIC_EXPECTATION.get()
    if expected is not _ATOMIC_EXPECTATION_UNSET:
        if expected is not None and not isinstance(expected, IdentityEvidence):
            raise TypeError("atomic expected identity has the wrong type")
        return compare_and_swap(
            path,
            expected,
            content,
            mode,
            "create" if expected is None else "replace",
        )
    target = normalized_absolute(path)
    parent = target.parent
    with _pinned_directory(parent, "atomic-write parent") as parent_fd:
        _after_parent_pin("atomic-write", parent)
        existing = _stat_at(parent_fd, target.name, "atomic-write target")
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ValueError(f"atomic-write target is not a regular file: {target}")

        temporary = _temporary_path(parent, target)
        descriptor: int | None = None
        created = False
        replaced = False
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            descriptor = os.open(temporary.name, flags, mode, dir_fd=parent_fd)
            created = True
            _write_all(descriptor, content)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            evidence = _evidence_from_descriptor(
                descriptor, "atomic-write target", known_content=content
            )
            expected_identity = os.fstat(descriptor)
            os.replace(
                temporary.name,
                target.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            replaced = True
            installed = _stat_at_no_follow(parent_fd, target.name)
            if installed is None or (
                installed.st_dev,
                installed.st_ino,
            ) != (
                expected_identity.st_dev,
                expected_identity.st_ino,
            ):
                raise ValueError("temporary replacement identity mismatch")
            os.close(descriptor)
            descriptor = None
            _sync_parent_directory_fd(parent_fd)
            return evidence
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if created and not replaced:
                try:
                    os.unlink(temporary.name, dir_fd=parent_fd)
                except OSError:
                    pass


def set_regular_mode(path: Path, mode: int) -> None:
    """Set and durably flush a regular file mode without following links."""

    if type(mode) is not int or mode < 0 or mode > 0o777:
        raise ValueError("file mode must be between 000 and 777")
    target = normalized_absolute(path)
    with _pinned_directory(target.parent, "mode parent") as parent_fd:
        descriptor = os.open(
            target.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            result = os.fstat(descriptor)
            if not stat.S_ISREG(result.st_mode):
                raise ValueError("mode target is not a regular file")
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _sync_parent_directory_fd(parent_fd)


def exclusive_backup(source: Path, destination: Path) -> str:
    """Copy a regular source to a new 0600 destination, exclusively."""

    source = normalized_absolute(source)
    destination = normalized_absolute(destination)
    source_descriptor = _open_regular_read(
        source, "backup source", operation="backup-source"
    )
    try:
        with _pinned_directory(
            destination.parent, "backup destination parent"
        ) as parent_fd:
            _after_parent_pin("backup-destination", destination.parent)
            try:
                existing = os.stat(
                    destination.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                existing = None
            if existing is not None:
                raise FileExistsError(destination)

            descriptor: int | None = None
            created = False
            completed = False
            digest = hashlib.sha256()
            try:
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                descriptor = os.open(
                    destination.name,
                    flags,
                    0o600,
                    dir_fd=parent_fd,
                )
                created = True
                while True:
                    chunk = os.read(source_descriptor, _CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
                    _write_all(descriptor, chunk)
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = None
                _sync_parent_directory_fd(parent_fd)
                completed = True
                return digest.hexdigest()
            finally:
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                if created and not completed:
                    try:
                        os.unlink(destination.name, dir_fd=parent_fd)
                    except OSError:
                        pass
    finally:
        os.close(source_descriptor)


def exclusive_write(path: Path, content: bytes, mode: int = 0o600) -> IdentityEvidence:
    """Create private bytes exactly once and durably flush file and parent."""

    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if type(mode) is not int or mode < 0 or mode > 0o777 or mode & 0o077:
        raise ValueError("exclusive file mode must be private")
    target = normalized_absolute(path)
    with _pinned_directory(target.parent, "exclusive-write parent") as parent_fd:
        _after_parent_pin("exclusive-write", target.parent)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                target.name,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=parent_fd,
            )
            _write_all(descriptor, content)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            evidence = _evidence_from_descriptor(
                descriptor, "exclusive-write target", known_content=content
            )
            os.close(descriptor)
            descriptor = None
            _sync_parent_directory_fd(parent_fd)
            return evidence
        except BaseException:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise


def unlink_regular(path: Path) -> None:
    """Remove a regular file, treating an already missing path as a no-op."""

    target = normalized_absolute(path)
    with _pinned_directory(target.parent, "unlink parent") as parent_fd:
        _after_parent_pin("unlink", target.parent)
        result = _stat_at(parent_fd, target.name, "unlink target")
        if result is None:
            return
        if not stat.S_ISREG(result.st_mode):
            raise ValueError(f"unlink target is not a regular file: {target}")
        os.unlink(target.name, dir_fd=parent_fd)


def sync_directory(path: Path) -> None:
    """Flush a directory after descriptor-relative metadata changes."""

    target = normalized_absolute(path)
    with _pinned_directory(target, "directory sync") as descriptor:
        _sync_parent_directory_fd(descriptor)
