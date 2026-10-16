"""Global symbol resolver and inter-procedural class/method indexer.

Provides symbol indexing across decompiled Java and Kotlin sources to support
cross-file taint tracking and method receiver resolution.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root
from typing import Dict, List, Optional, Set


@dataclass
class MethodSymbol:
    name: str
    class_fqcn: str
    param_types: List[str]
    return_type: str
    line_number: int
    is_static: bool = False
    is_public: bool = True


@dataclass
class ClassSymbol:
    fqcn: str
    simple_name: str
    package: str
    file_path: str
    super_class: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    methods: Dict[str, List[MethodSymbol]] = field(default_factory=dict)
    fields: Dict[str, str] = field(default_factory=dict)
    imports: List[str] = field(default_factory=list)


class SymbolResolver:
    """Indexes classes, interfaces, and methods across project sources."""

    def __init__(self, max_file_count: int = 10_000):
        self.max_file_count = max_file_count
        self.classes: Dict[str, ClassSymbol] = {}
        self.simple_name_index: Dict[str, List[str]] = {}
        self.coverage = SourceInventory().coverage

    def index_directory(self, source_dir: str | Path) -> int:
        """Scan and index all Java and Kotlin files in source_dir."""
        source_path = explicit_scan_root(source_dir)
        if source_path is None or source_path.is_symlink():
            return 0
        if not source_path.is_dir():
            return 0

        inventory = SourceInventory(max_entries=5000, max_file_bytes=2 * 1024 * 1024,
                                    max_total_bytes=64 * 1024 * 1024)
        indexed_count = 0
        for full_path, data in inventory.read(source_path, {".java", ".kt"}):
            if self._index_file(str(full_path), data.decode("utf-8", errors="replace")):
                indexed_count += 1
                if indexed_count >= self.max_file_count:
                    inventory.record_limit("symbol_file_count")
                    break
        self.coverage = dict(inventory.coverage)
        return indexed_count

    def _index_file(self, file_path: str, content: str | None = None) -> bool:
        """Index one already-bounded inventory item (or bounded direct file read)."""
        if content is None:
            try:
                fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        return False
                    raw = stream.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    return False
                content = raw.decode("utf-8", errors="replace")
            except OSError:
                return False

        pkg_match = re.search(r"^\s*package\s+([a-zA-Z0-9_.]+);?", content, re.MULTILINE)
        package_name = pkg_match.group(1) if pkg_match else ""

        imports = re.findall(r"^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.*]+);?", content, re.MULTILINE)

        # Match class/interface/enum declarations
        class_pattern = re.compile(
            r"(?:public|protected|private)?\s*(?:abstract|final|open)?\s*"
            r"(?:class|interface|enum|object)\s+([a-zA-Z0-9_]+)"
            r"(?:\s+extends\s+([a-zA-Z0-9_.]+))?"
            r"(?:\s+implements\s+([a-zA-Z0-9_.,\s]+))?",
            re.MULTILINE,
        )

        for match in class_pattern.finditer(content):
            simple_name = match.group(1)
            fqcn = f"{package_name}.{simple_name}" if package_name else simple_name
            super_class = match.group(2)
            interfaces = [i.strip() for i in match.group(3).split(",")] if match.group(3) else []

            cls_symbol = ClassSymbol(
                fqcn=fqcn,
                simple_name=simple_name,
                package=package_name,
                file_path=file_path,
                super_class=super_class,
                interfaces=interfaces,
                imports=imports,
            )

            self.classes[fqcn] = cls_symbol
            self.simple_name_index.setdefault(simple_name, []).append(fqcn)

            # Index methods inside this file
            self._index_methods(content, cls_symbol)

        return True

    def _index_methods(self, content: str, cls_symbol: ClassSymbol) -> None:
        lines = content.splitlines()
        method_pattern = re.compile(
            r"(?:public|protected|private|static|\s)*"
            r"(?:(?:fun|void|int|String|boolean|[A-Z][a-zA-Z0-9_<>]*)\s+)"
            r"([a-zA-Z0-9_]+)\s*\(([^)]*)\)"
        )

        for idx, line in enumerate(lines, 1):
            match = method_pattern.search(line)
            if match:
                method_name = match.group(1)
                if method_name in ("if", "for", "while", "switch", "catch"):
                    continue
                raw_params = match.group(2).strip()
                params = [p.strip().split()[-1] for p in raw_params.split(",") if p.strip()] if raw_params else []

                sym = MethodSymbol(
                    name=method_name,
                    class_fqcn=cls_symbol.fqcn,
                    param_types=params,
                    return_type="unknown",
                    line_number=idx,
                )
                cls_symbol.methods.setdefault(method_name, []).append(sym)

    def resolve_class(self, type_name: str, context_fqcn: Optional[str] = None) -> Optional[ClassSymbol]:
        """Resolve a type name to a ClassSymbol using imports and context."""
        if type_name in self.classes:
            return self.classes[type_name]

        # Check by simple name
        candidates = self.simple_name_index.get(type_name, [])
        if len(candidates) == 1:
            return self.classes.get(candidates[0])

        if context_fqcn and context_fqcn in self.classes:
            context = self.classes[context_fqcn]
            for imp in context.imports:
                if imp.endswith(f".{type_name}"):
                    return self.classes.get(imp)
                if imp.endswith(".*"):
                    candidate_fqcn = f"{imp[:-2]}.{type_name}"
                    if candidate_fqcn in self.classes:
                        return self.classes.get(candidate_fqcn)

        return None

    def resolve_method(self, class_name: str, method_name: str, context_fqcn: Optional[str] = None) -> List[MethodSymbol]:
        """Resolve method candidates given a class and method name."""
        cls = self.resolve_class(class_name, context_fqcn)
        if cls and method_name in cls.methods:
            return cls.methods[method_name]
        return []
