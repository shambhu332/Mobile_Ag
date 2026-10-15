"""Bounded offline artifact reading; no symlink traversal or implicit cwd scan."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable


class SourceInventory:
    def __init__(self, max_entries=5000, max_file_bytes=2*1024*1024,
                 max_total_bytes=32*1024*1024):
        self.max_entries = max_entries
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.coverage = {
            'static_status': 'not_analyzed', 'source_files_analyzed': 0,
            'source_bytes_analyzed': 0, 'source_files_skipped': 0,
            'source_file_skip_reasons': {}, 'limit_reasons': {},
            'entries_examined': 0, 'limits_reached': False,
            'runtime_status': 'not_tested', 'proof_status': 'not_proven',
            'exhaustive': False, 'automatic_exploit_proof': False,
            'limits': {'entries': max_entries, 'file_bytes': max_file_bytes,
                       'total_bytes': max_total_bytes},
        }

    def record_skip(self, reason: str) -> None:
        """Count a skipped bounded input by a fixed, non-path-bearing reason."""
        self.coverage['source_files_skipped'] += 1
        reasons = self.coverage['source_file_skip_reasons']
        reasons[reason] = reasons.get(reason, 0) + 1

    def record_limit(self, reason: str) -> None:
        """Record a bounded stopping condition without retaining file names."""
        self.coverage['limits_reached'] = True
        reasons = self.coverage['limit_reasons']
        reasons[reason] = reasons.get(reason, 0) + 1

    def paths(self, directory, extensions=()):
        """Yield bounded regular-file paths without reading file contents."""
        allowed = {ext.lower() for ext in extensions}
        if not directory:
            return
        root = Path(directory)
        info = self.coverage
        if root.is_symlink() or not root.is_dir():
            return
        pending = [root]
        try:
            while pending:
                current = pending.pop()
                try:
                    with os.scandir(current) as entries:
                        ordered_entries = sorted(entries, key=lambda item: item.name.casefold())
                        for entry in ordered_entries:
                            if info['entries_examined'] >= self.max_entries:
                                self.record_limit('entry_budget')
                                return
                            info['entries_examined'] += 1
                            path = Path(entry.path)
                            if entry.is_symlink():
                                self.record_skip('symlink_entry')
                            elif entry.is_dir(follow_symlinks=False):
                                pending.append(path)
                            elif (not allowed or path.suffix.lower() in allowed) and entry.is_file(follow_symlinks=False):
                                info['source_files_analyzed'] += 1
                                yield path
                except OSError:
                    self.record_skip('directory_read_error')
        finally:
            info['static_status'] = ('partial' if info['limits_reached'] or info['source_files_skipped']
                                    else 'analyzed_heuristically' if info['source_files_analyzed']
                                    else 'not_analyzed')

    def read(
        self, directory, extensions=(), *, names=(), suffixes=(),
        path_filter: Callable[[Path], bool] | None = None,
    ):
        """Yield bounded regular files selected by extension, exact name or suffix.

        Selection is case-insensitive. ``path_filter`` can further restrict
        selected paths before opening them. Limits and skipped/partial status
        are retained in ``coverage`` even when traversal stops early.
        """
        allowed_extensions = {ext.lower() for ext in extensions}
        allowed_names = {name.lower() for name in names}
        allowed_suffixes = tuple(suffix.lower() for suffix in suffixes)
        if not directory:
            return
        root = Path(directory)
        if root.is_symlink() or not root.is_dir():
            return
        pending = [root]
        info = self.coverage
        try:
            while pending:
                current = pending.pop()
                try:
                    with os.scandir(current) as entries:
                        ordered_entries = sorted(entries, key=lambda item: item.name.casefold())
                        for entry in ordered_entries:
                            if info['entries_examined'] >= self.max_entries:
                                self.record_limit('entry_budget')
                                return
                            info['entries_examined'] += 1
                            path = Path(entry.path)
                            if entry.is_symlink():
                                self.record_skip('symlink_entry')
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                pending.append(path)
                                continue
                            if (path.suffix.lower() not in allowed_extensions
                                    and path.name.lower() not in allowed_names
                                    and not any(path.name.lower().endswith(suffix) for suffix in allowed_suffixes)):
                                continue
                            if path_filter is not None:
                                try:
                                    if not path_filter(path):
                                        continue
                                except Exception:
                                    self.record_skip('path_filter_error')
                                    continue
                            try:
                                # O_NOFOLLOW also closes the final-component symlink race.
                                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                                with os.fdopen(fd, 'rb') as stream:
                                    details = os.fstat(stream.fileno())
                                    if not stat.S_ISREG(details.st_mode) or details.st_size > self.max_file_bytes:
                                        self.record_skip('non_regular_or_file_size_limit' if not stat.S_ISREG(details.st_mode)
                                                         else 'file_size_limit')
                                        continue
                                    if info['source_bytes_analyzed'] + details.st_size > self.max_total_bytes:
                                        self.record_limit('total_byte_budget')
                                        return
                                    data = stream.read(self.max_file_bytes + 1)
                                if len(data) > self.max_file_bytes:
                                    self.record_skip('file_size_limit')
                                    continue
                                if info['source_bytes_analyzed'] + len(data) > self.max_total_bytes:
                                    self.record_limit('total_byte_budget')
                                    return
                                info['source_files_analyzed'] += 1
                                info['source_bytes_analyzed'] += len(data)
                                yield path, data
                            except OSError:
                                self.record_skip('unreadable_or_raced_file')
                except OSError:
                    self.record_skip('directory_read_error')
        finally:
            info['static_status'] = ('partial' if info['limits_reached'] or info['source_files_skipped']
                                    else 'analyzed_heuristically' if info['source_files_analyzed']
                                    else 'not_analyzed')
