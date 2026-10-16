"""Read-only, bounded access to decompiler text for the local review UI.

Paths are relative to a scan's private output directory. The descriptor walk
uses O_NOFOLLOW on each segment so an artifact symlink cannot escape the scan
root between validation and read.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import PurePosixPath
from typing import Any


MAX_SOURCE_BYTES = 1024 * 1024
MAX_SOURCE_PATH_CHARS = 2048
TEXT_SUFFIXES = {
    ".java", ".kt", ".smali", ".xml", ".json", ".properties", ".txt",
    ".js", ".mjs", ".dart", ".html", ".htm", ".yaml", ".yml",
    ".gradle", ".cfg", ".conf", ".graphql", ".gql",
}
ALLOWED_ROOTS = ("jadx_out/sources", "jadx_out/resources", "apktool_out")


class SourceReadError(ValueError):
    """A bounded source request was invalid, unavailable, or over budget."""


def _candidate_paths(value: str) -> list[tuple[str, ...]]:
    if not isinstance(value, str) or not value or len(value) > MAX_SOURCE_PATH_CHARS:
        raise SourceReadError("invalid source path")
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise SourceReadError("invalid source path")
    raw = value.split("/")
    if any(part in {"", ".", ".."} for part in raw):
        raise SourceReadError("invalid source path")
    if len(raw) > 64 or any(len(part) > 255 for part in raw):
        raise SourceReadError("invalid source path")

    candidates: list[tuple[str, ...]] = []
    if raw[0] == "jadx_out" and len(raw) >= 3 and raw[1] in {"sources", "resources"}:
        candidates.append(tuple(raw))
    elif raw[0] == "apktool_out" and len(raw) >= 2:
        candidates.append(tuple(raw))
    elif raw[0] in {"sources", "resources"} and len(raw) >= 2:
        root = "sources" if raw[0] == "sources" else "resources"
        candidates.append(("jadx_out", root, *raw[1:]))
    elif raw[0] == "res" and len(raw) >= 2:
        candidates.extend([
            ("jadx_out", "resources", *raw),
            ("apktool_out", *raw),
        ])
    elif raw == ["AndroidManifest.xml"]:
        candidates.extend([
            ("jadx_out", "resources", "AndroidManifest.xml"),
            ("apktool_out", "AndroidManifest.xml"),
        ])
    else:
        # Finding locations emitted by source analyzers are relative to JADX's
        # sources root. Do not interpret them as arbitrary filesystem paths.
        candidates.append(("jadx_out", "sources", *raw))
    return candidates


def _read_candidate(scan_fd: int, parts: tuple[str, ...], max_bytes: int) -> tuple[str, int]:
    if len(parts) < 2 or "/".join(parts[:2]) not in ALLOWED_ROOTS:
        raise SourceReadError("source path is outside the decompiler text roots")
    suffix = PurePosixPath(parts[-1]).suffix.lower()
    if suffix not in TEXT_SUFFIXES:
        raise SourceReadError("only recognized text source files can be opened")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    flags = os.O_RDONLY | nofollow | directory
    fd = None
    try:
        fd = os.dup(scan_fd)
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            next_flags = os.O_RDONLY | nofollow
            if not final:
                next_flags |= directory
            next_fd = os.open(part, next_flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SourceReadError("source path is not a regular file")
        if info.st_size > max_bytes:
            raise SourceReadError("source file exceeds the 1 MiB review limit")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise SourceReadError("source file exceeds the 1 MiB review limit")
        return data.decode("utf-8", errors="replace"), len(data)
    except SourceReadError:
        raise
    except (OSError, TypeError, ValueError):
        raise SourceReadError("source file is unavailable") from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def read_scan_source(output_root: str | os.PathLike[str], scan_id: str, path: str,
                     *, max_bytes: int = MAX_SOURCE_BYTES) -> dict[str, Any]:
    """Read a single approved text file without following artifact symlinks."""
    if not isinstance(scan_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", scan_id):
        raise SourceReadError("invalid scan identifier")
    candidates = _candidate_paths(path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    root_fd = scan_fd = None
    try:
        root_fd = os.open(os.fspath(output_root), os.O_RDONLY | nofollow | directory)
        scan_fd = os.open(scan_id, os.O_RDONLY | nofollow | directory, dir_fd=root_fd)
        for parts in candidates:
            try:
                content, size = _read_candidate(scan_fd, parts, max_bytes)
                return {
                    "path": "/".join(parts),
                    "content": content,
                    "size_bytes": size,
                    "line_count": len(content.splitlines()),
                    "max_bytes": max_bytes,
                    "coverage": "bounded_file_read",
                }
            except SourceReadError as exc:
                last = exc
                # A path that exists but is invalid should not fall through to
                # another root and accidentally select a different file.
                if str(exc) != "source file is unavailable":
                    raise
        raise last if candidates else SourceReadError("source file is unavailable")
    except SourceReadError:
        raise
    except (OSError, TypeError, ValueError):
        raise SourceReadError("source file is unavailable") from None
    finally:
        for fd in (scan_fd, root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
