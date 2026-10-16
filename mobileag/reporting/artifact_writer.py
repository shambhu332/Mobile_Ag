"""Bounded private-mode atomic writes for researcher-facing artifacts."""
from __future__ import annotations

import os
import secrets
from contextlib import contextmanager
from enum import Enum
from pathlib import Path


MAX_REPORT_ARTIFACT_BYTES = 32 * 1024 * 1024


def preflight_bounded_structure(value, *, max_bytes: int, max_nodes: int,
                                max_depth: int, label: str = "Input") -> None:
    """Bound caller-owned data before copying, redacting, or rendering it."""
    remaining = max_bytes
    nodes = 0
    active: set[int] = set()
    stack = [(value, 0, False)]
    while stack:
        item, depth, exiting = stack.pop()
        if exiting:
            active.discard(id(item))
            continue
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise ValueError(f"{label} complexity exceeds limits")
        if isinstance(item, str):
            remaining -= len(item) * 4
        elif isinstance(item, bytes):
            remaining -= len(item)
        elif item is None or isinstance(item, (bool, int, float)):
            continue
        elif isinstance(item, Enum):
            stack.append((item.value, depth + 1, False))
        elif isinstance(item, dict):
            identity = id(item)
            if identity in active:
                raise ValueError(f"{label} contains a cycle")
            active.add(identity)
            stack.append((item, depth, True))
            for key, child in item.items():
                stack.append((key, depth + 1, False))
                stack.append((child, depth + 1, False))
        elif isinstance(item, (list, tuple, set, frozenset)):
            identity = id(item)
            if identity in active:
                raise ValueError(f"{label} contains a cycle")
            active.add(identity)
            stack.append((item, depth, True))
            stack.extend((child, depth + 1, False) for child in item)
        elif hasattr(item, "__dict__"):
            stack.append((vars(item), depth + 1, False))
        if remaining < 0:
            raise ValueError(f"{label} exceeds the input size limit")


@contextmanager
def private_artifact_stream(path: str | Path):
    """Yield a temporary binary stream and atomically publish on clean exit.

    Directory-relative operations pin the selected parent so later renames do
    not redirect the temporary file or replacement. Parent components are
    opened one at a time without following symlinks.
    """
    output = Path(path)
    if not output.name or output.name in {".", ".."}:
        raise ValueError("Report artifact path must name a file")
    if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")) or \
            os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd or \
            os.rename not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        raise OSError("Secure directory-relative artifact writes are unsupported")

    parent = Path(os.path.abspath(output.parent))
    directory_fd = os.open(parent.anchor or "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parent.parts[1:]:
            try:
                child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=directory_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd

        temporary_name = f".{output.name}.{secrets.token_hex(12)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
    except BaseException:
        os.close(directory_fd)
        raise
    try:
        with os.fdopen(fd, "wb") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, output.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(directory_fd)


def write_private_artifact(path: str | Path, content: str | bytes,
                           max_bytes: int = MAX_REPORT_ARTIFACT_BYTES) -> Path:
    """Atomically replace a bounded private artifact through a pinned directory."""
    payload = content.encode("utf-8") if isinstance(content, str) else content
    if not isinstance(payload, bytes) or len(payload) > max_bytes:
        raise ValueError("Report artifact exceeds the output size limit")
    output = Path(path)
    with private_artifact_stream(path) as stream:
        stream.write(payload)
    return output


def create_private_artifact_exclusive(path: str | Path, content: str | bytes,
                                      max_bytes: int = MAX_REPORT_ARTIFACT_BYTES) -> Path:
    """Create a new private artifact only; fail without following or replacing links."""
    payload = content.encode("utf-8") if isinstance(content, str) else content
    if not isinstance(payload, bytes) or len(payload) > max_bytes:
        raise ValueError("Report artifact exceeds the output size limit")
    output = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            current = os.stat(output, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                os.unlink(output)
        except OSError:
            pass
        raise
    return output
