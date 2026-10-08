"""Bounded offline artifact reading; no symlink traversal or implicit cwd scan."""
from __future__ import annotations

import os
import stat
from pathlib import Path


class SourceInventory:
    def __init__(self, max_entries=5000, max_file_bytes=2*1024*1024,
                 max_total_bytes=32*1024*1024):
        self.max_entries = max_entries
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.coverage = {
            'static_status': 'not_analyzed', 'source_files_analyzed': 0,
            'source_bytes_analyzed': 0, 'source_files_skipped': 0,
            'entries_examined': 0, 'limits_reached': False,
            'runtime_status': 'not_tested', 'proof_status': 'not_proven',
            'exhaustive': False, 'automatic_exploit_proof': False,
            'limits': {'entries': max_entries, 'file_bytes': max_file_bytes,
                       'total_bytes': max_total_bytes},
        }

    def read(self, directory, extensions):
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
                        for entry in entries:
                            if info['entries_examined'] >= self.max_entries:
                                info['limits_reached'] = True
                                return
                            info['entries_examined'] += 1
                            path = Path(entry.path)
                            if entry.is_symlink():
                                info['source_files_skipped'] += 1
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                pending.append(path)
                                continue
                            if path.suffix.lower() not in extensions:
                                continue
                            try:
                                # O_NOFOLLOW also closes the final-component symlink race.
                                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                                with os.fdopen(fd, 'rb') as stream:
                                    details = os.fstat(stream.fileno())
                                    if not stat.S_ISREG(details.st_mode) or details.st_size > self.max_file_bytes:
                                        info['source_files_skipped'] += 1
                                        continue
                                    if info['source_bytes_analyzed'] + details.st_size > self.max_total_bytes:
                                        info['limits_reached'] = True
                                        return
                                    data = stream.read(self.max_file_bytes + 1)
                                if len(data) > self.max_file_bytes:
                                    info['source_files_skipped'] += 1
                                    continue
                                if info['source_bytes_analyzed'] + len(data) > self.max_total_bytes:
                                    info['limits_reached'] = True
                                    return
                                info['source_files_analyzed'] += 1
                                info['source_bytes_analyzed'] += len(data)
                                yield path, data
                            except OSError:
                                info['source_files_skipped'] += 1
                except OSError:
                    info['source_files_skipped'] += 1
        finally:
            info['static_status'] = ('partial' if info['limits_reached'] or info['source_files_skipped']
                                    else 'analyzed_heuristically' if info['source_files_analyzed']
                                    else 'not_analyzed')
