"""Read-only, bounded access to decompiler text for the local review UI.

Paths are relative to a scan's private output directory. The descriptor walk
uses O_NOFOLLOW on each segment so an artifact symlink cannot escape the scan
root between validation and read.
"""
from __future__ import annotations

import os
import re
import stat
import time
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
SEARCH_FILE_LIMIT = 500
SEARCH_BYTE_LIMIT = 16 * 1024 * 1024
SEARCH_RESULT_LIMIT = 100


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


def _open_dir(scan_fd: int, parts: tuple[str, ...]) -> int:
    """Open a relative directory using no-follow descriptor traversal."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    fd = os.dup(scan_fd)
    try:
        for part in parts:
            nxt = os.open(part, os.O_RDONLY | nofollow | directory, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _enumerate_text_files(scan_fd: int, *, max_entries: int, max_files: int) -> dict[str, Any]:
    files: list[str] = []
    entries = 0
    truncated = False
    root_parts = [tuple(root.split("/")) for root in ALLOWED_ROOTS]

    def walk(fd: int, prefix: tuple[str, ...], depth: int) -> None:
        nonlocal entries, truncated
        if depth > 40:
            truncated = True
            return
        try:
            names = sorted(os.listdir(fd))
        except OSError:
            truncated = True
            return
        for name in names:
            entries += 1
            if entries > max_entries or len(files) >= max_files:
                truncated = True
                return
            if (name in {".", ".."} or not name or len(name) > 255 or "\\" in name
                    or any(ord(ch) < 32 for ch in name)):
                continue
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                truncated = True
                continue
            if stat.S_ISDIR(info.st_mode):
                try:
                    child = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                    | getattr(os, "O_DIRECTORY", 0), dir_fd=fd)
                except OSError:
                    truncated = True
                    continue
                try:
                    walk(child, (*prefix, name), depth + 1)
                finally:
                    os.close(child)
                if truncated and (entries > max_entries or len(files) >= max_files):
                    return
            elif stat.S_ISREG(info.st_mode) and PurePosixPath(name).suffix.lower() in TEXT_SUFFIXES:
                files.append("/".join((*prefix, name)))

    for root in root_parts:
        try:
            fd = _open_dir(scan_fd, root)
        except OSError:
            continue
        try:
            walk(fd, root, 0)
        finally:
            os.close(fd)
        if entries > max_entries or len(files) >= max_files:
            truncated = True
            break
    return {"files": files, "entries_examined": min(entries, max_entries), "truncated": truncated}


def list_scan_source_files(output_root: str | os.PathLike[str], scan_id: str, *,
                           query: str = "", max_entries: int = 10_000,
                           max_files: int = 1_200) -> dict[str, Any]:
    """Return a bounded text-file inventory; query filters paths, not contents."""
    if not isinstance(scan_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", scan_id):
        raise SourceReadError("invalid scan identifier")
    if not isinstance(query, str) or len(query) > 120:
        raise SourceReadError("invalid file filter")
    files = _with_scan_fd(output_root, scan_id, lambda fd: _enumerate_text_files(
        fd, max_entries=max_entries, max_files=max_files))
    if query:
        wanted = query.casefold()
        files["files"] = [p for p in files["files"] if wanted in p.casefold()]
    return {**files, "file_count": len(files["files"]), "coverage": "partial" if files["truncated"] else "complete"}


def _with_scan_fd(output_root: str | os.PathLike[str], scan_id: str, callback):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    root_fd = scan_fd = None
    try:
        root_fd = os.open(os.fspath(output_root), os.O_RDONLY | nofollow | directory)
        scan_fd = os.open(scan_id, os.O_RDONLY | nofollow | directory, dir_fd=root_fd)
        return callback(scan_fd)
    except (OSError, TypeError, ValueError):
        raise SourceReadError("source inventory is unavailable") from None
    finally:
        for fd in (scan_fd, root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def search_scan_sources(output_root: str | os.PathLike[str], scan_id: str, query: str, *,
                        max_files: int = SEARCH_FILE_LIMIT,
                        max_bytes: int = SEARCH_BYTE_LIMIT,
                        max_results: int = SEARCH_RESULT_LIMIT,
                        time_limit_seconds: float = 2.0) -> dict[str, Any]:
    """Literal, case-insensitive search across a bounded set of decompiler text."""
    if not isinstance(query, str) or not query.strip() or len(query) > 120:
        raise SourceReadError("search text must contain 1 to 120 characters")
    inventory = list_scan_source_files(output_root, scan_id, max_files=max_files)
    results = []
    reasons: set[str] = set()
    examined = total_bytes = 0
    deadline = time.monotonic() + time_limit_seconds
    needle = query.casefold()
    partial = inventory["truncated"]
    if partial:
        reasons.add("source_file_inventory_limit")
    for path in inventory["files"]:
        if examined >= max_files:
            partial = True
            reasons.add("source_file_limit")
            break
        if time.monotonic() >= deadline:
            partial = True
            reasons.add("time_limit")
            break
        remaining = max_bytes - total_bytes
        if remaining <= 0:
            partial = True
            reasons.add("byte_limit")
            break
        examined += 1
        try:
            source = read_scan_source(output_root, scan_id, path, max_bytes=min(256 * 1024, remaining))
        except SourceReadError as exc:
            partial = True
            reasons.add("oversize_or_unreadable_file" if "unavailable" in str(exc) or "1 MiB" in str(exc) else "source_file_rejected")
            continue
        total_bytes += source["size_bytes"]
        for line_no, line in enumerate(source["content"].splitlines(), 1):
            if needle in line.casefold():
                results.append({"path": path, "line": line_no})
                if len(results) >= max_results:
                    partial = True
                    reasons.add("match_limit")
                    break
        if len(results) >= max_results:
            break
    return {
        "matches": results,
        "match_count": len(results),
        "files_examined": examined,
        "bytes_examined": total_bytes,
        "coverage": "partial" if partial else "complete",
        "truncated": partial,
        "reasons": sorted(reasons),
    }
