"""Bounded private-mode atomic writes for researcher-facing artifacts."""
from __future__ import annotations

import os
import tempfile
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


def write_private_artifact(path: str | Path, content: str | bytes,
                           max_bytes: int = MAX_REPORT_ARTIFACT_BYTES) -> Path:
    """Atomically replace a report file without following a destination symlink."""
    payload = content.encode("utf-8") if isinstance(content, str) else content
    if not isinstance(payload, bytes) or len(payload) > max_bytes:
        raise ValueError("Report artifact exceeds the output size limit")
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_path = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, output)
    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise
    return output
