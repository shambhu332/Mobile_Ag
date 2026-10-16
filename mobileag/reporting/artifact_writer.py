"""Bounded private-mode atomic writes for researcher-facing artifacts."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


MAX_REPORT_ARTIFACT_BYTES = 32 * 1024 * 1024


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
