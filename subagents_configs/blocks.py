"""Strict rendering and inspection of installer-owned managed blocks."""

from __future__ import annotations

import hashlib

from .models import ManagedBlock

_SUPPORTED = {
    "routing-codex",
    "routing-opencode",
    "routing-claude-code",
    "routing-pi",
    "codex-multi-agent-v2",
}
_PREFIXES = (b"# BEGIN SUBAGENTS_CONFIGS ", b"# END SUBAGENTS_CONFIGS ")
_TOKENS = (b"# BEGIN SUBAGENTS_CONFIGS", b"# END SUBAGENTS_CONFIGS")


def _markers(block_id: str) -> tuple[bytes, bytes]:
    if type(block_id) is not str or block_id not in _SUPPORTED:
        raise ValueError("unsupported managed block id")
    return (
        f"# BEGIN SUBAGENTS_CONFIGS {block_id}".encode("ascii"),
        f"# END SUBAGENTS_CONFIGS {block_id}".encode("ascii"),
    )


def _block_bytes(block: ManagedBlock) -> bytes:
    begin, end = _markers(block.block_id)
    if block.begin_marker != begin or block.end_marker != end:
        raise ValueError("managed block markers do not match block id")
    _validate_content(block.content)
    if not block.content.endswith(b"\n"):
        raise ValueError("managed block content must end with a newline")
    rendered = begin + b"\n" + block.content + end + b"\n"
    digest = hashlib.sha256(rendered).hexdigest()
    if block.sha256 != digest:
        raise ValueError("managed block hash does not match rendered bytes")
    return rendered


def render_managed_block(block_id: str, body: bytes) -> ManagedBlock:
    begin, end = _markers(block_id)
    _validate_content(body)
    content = body if body.endswith(b"\n") else body + b"\n"
    rendered = begin + b"\n" + content + end + b"\n"
    return ManagedBlock(
        block_id=block_id,
        begin_marker=begin,
        end_marker=end,
        content=content,
        sha256=hashlib.sha256(rendered).hexdigest(),
    )


def inspect_managed_block(content: bytes, block_id: str) -> ManagedBlock | None:
    """Inspect one managed block without exposing the parser's private tuple format."""
    begin, end = _markers(block_id)
    matches = [item for item in _scan(content) if item[0] == block_id]
    if not matches:
        return None
    _marker_id, start, stop = matches[0]
    rendered = content[start:stop]
    prefix = begin + b"\n"
    suffix = end + b"\n"
    if not rendered.startswith(prefix) or not rendered.endswith(suffix):
        raise ValueError("managed block boundaries are invalid")
    body = rendered[len(prefix) : -len(suffix)]
    return ManagedBlock(
        block_id=block_id,
        begin_marker=begin,
        end_marker=end,
        content=body,
        sha256=hashlib.sha256(rendered).hexdigest(),
    )


def validate_managed_content(content: bytes) -> None:
    """Validate marker structure without exposing private parser details."""
    _scan(content)


def _validate_content(content: bytes) -> None:
    if type(content) is not bytes:
        raise TypeError("managed block body must be bytes")
    if b"\r" in content:
        raise ValueError("managed block content must use LF boundaries")
    if any(token in content for token in _TOKENS):
        raise ValueError("managed block body contains an ambiguous marker")


def _scan(original: bytes) -> list[tuple[str, int, int]]:
    if type(original) is not bytes:
        raise TypeError("original content must be bytes")
    if b"\r" in original:
        raise ValueError("managed files must use LF boundaries")
    # First reject malformed marker-like text, including a marker without an
    # id or one embedded in an unrelated line.  Otherwise it could become a
    # valid managed marker after a later edit.
    for token in _TOKENS:
        offset = 0
        while True:
            position = original.find(token, offset)
            if position < 0:
                break
            offset = position + len(token)
            if position and original[position - 1 : position] != b"\n":
                raise ValueError("managed marker is not on a line boundary")
            line_end = original.find(b"\n", position)
            if line_end < 0:
                line_end = len(original)
            line = original[position:line_end].rstrip(b"\r")
            if not any(
                line.startswith(prefix) and len(line) > len(prefix)
                for prefix in _PREFIXES
            ):
                raise ValueError("malformed managed marker")

    events: list[tuple[str, str, int, int]] = []
    for prefix in _PREFIXES:
        offset = 0
        while True:
            position = original.find(prefix, offset)
            if position < 0:
                break
            offset = position + len(prefix)
            if position and original[position - 1 : position] != b"\n":
                raise ValueError("managed marker is not on a line boundary")
            line_end = original.find(b"\n", position)
            if line_end < 0:
                raise ValueError("managed marker must end with a newline")
            else:
                line_stop = line_end + 1
            line = original[position:line_end]
            if line.endswith(b"\r"):
                line = line[:-1]
            try:
                marker_id = line[len(prefix) :].decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("managed marker is not valid ASCII") from exc
            if marker_id not in _SUPPORTED or not marker_id:
                raise ValueError("unknown managed marker")
            events.append(
                (
                    "begin" if prefix.startswith(b"# BEGIN") else "end",
                    marker_id,
                    position,
                    line_stop,
                )
            )
    events.sort(key=lambda event: event[2])
    blocks: list[tuple[str, int, int]] = []
    open_block: tuple[str, int] | None = None
    for kind, marker_id, position, line_stop in events:
        if kind == "begin":
            if open_block is not None:
                raise ValueError("nested managed blocks are not allowed")
            open_block = marker_id, position
            continue
        if open_block is None:
            raise ValueError("unbalanced managed end marker")
        open_id, start = open_block
        if open_id != marker_id:
            raise ValueError("managed block markers do not match")
        blocks.append((marker_id, start, line_stop))
        open_block = None
    if open_block is not None:
        raise ValueError("unbalanced managed begin marker")
    counts: dict[str, int] = {}
    for marker_id, _start, _stop in blocks:
        counts[marker_id] = counts.get(marker_id, 0) + 1
    if any(count > 1 for count in counts.values()):
        raise ValueError("duplicate managed block")
    return blocks


def insert_or_replace_block(original: bytes, block: ManagedBlock) -> bytes:
    rendered = _block_bytes(block)
    blocks = _scan(original)
    matches = [item for item in blocks if item[0] == block.block_id]
    if len(matches) > 1:
        raise ValueError("duplicate managed block")
    if matches:
        _marker_id, start, stop = matches[0]
        return original[:start] + rendered + original[stop:]
    if not original:
        return rendered
    separator = b"" if original.endswith(b"\n") else b"\n"
    return original + separator + rendered


def remove_exact_block(original: bytes, block: ManagedBlock) -> tuple[bytes, bool]:
    rendered = _block_bytes(block)
    blocks = _scan(original)
    matches = [item for item in blocks if item[0] == block.block_id]
    if not matches:
        return original, False
    if len(matches) != 1:
        raise ValueError("duplicate managed block")
    _marker_id, start, stop = matches[0]
    if original[start:stop] != rendered:
        return original, False
    return original[:start] + original[stop:], True
