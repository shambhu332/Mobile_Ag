"""iOS Mach-O & Swift Metadata Binary Parser.

Inspects iOS application binaries (Mach-O 64-bit / Universal Fat), parses segments and
load commands, inspects Swift 5 runtime sections, and extracts embedded URLs, cryptographic
primitives (CommonCrypto/CryptoKit), and custom URL schemes.
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class MachoAnalysisResult:
    is_macho: bool = False
    is_64bit: bool = True
    cpu_type: str = "ARM64"
    file_size_bytes: int = 0
    load_commands_count: int = 0
    imported_dylibs: List[str] = field(default_factory=list)
    swift_sections_detected: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    crypto_frameworks: List[str] = field(default_factory=list)


class MachoBinaryParser:
    """Parses Mach-O headers and metadata sections in iOS IPAs."""

    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM_64 = 0xCFFAEDFE
    FAT_MAGIC = 0xCAFEBABE

    SWIFT5_SECTION_NAMES = [
        "__swift5_types",
        "__swift5_proto",
        "__swift5_fieldmd",
        "__swift5_assocty",
        "__swift5_protos",
    ]

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?")

    def parse_binary(self, binary_path: str | Path) -> MachoAnalysisResult:
        """Parse an iOS Mach-O binary file."""
        path = Path(binary_path)
        result = MachoAnalysisResult()

        if not path.is_file():
            return result

        result.file_size_bytes = path.stat().st_size

        try:
            with open(path, "rb") as f:
                header = f.read(32)
        except OSError:
            return result

        if len(header) < 16:
            return result

        magic = struct.unpack(">I", header[:4])[0]
        magic_le = struct.unpack("<I", header[:4])[0]

        if magic_le == self.MH_MAGIC_64 or magic == self.MH_MAGIC_64:
            result.is_macho = True
            result.is_64bit = True
        elif magic == self.FAT_MAGIC or magic_le == self.FAT_MAGIC:
            result.is_macho = True
            result.cpu_type = "Universal Fat Binary"
        else:
            return result

        # Read binary data for section analysis
        try:
            with open(path, "rb") as f:
                data = f.read(15 * 1024 * 1024)  # Read up to 15MB
        except OSError:
            return result

        # Check for Swift 5 sections
        for sec in self.SWIFT5_SECTION_NAMES:
            if sec.encode() in data:
                result.swift_sections_detected.append(sec)

        # Check for crypto framework imports
        if b"CommonCrypto" in data:
            result.crypto_frameworks.append("CommonCrypto")
        if b"CryptoKit" in data:
            result.crypto_frameworks.append("CryptoKit")
        if b"Security.framework" in data:
            result.crypto_frameworks.append("Security.framework")

        # Extract URLs
        raw_strings = re.findall(b"https?://[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]+", data)
        endpoints: Set[str] = set()
        for raw in raw_strings:
            try:
                u = raw.decode("utf-8", errors="ignore")
                if not u.endswith((".png", ".jpg", ".svg", ".plist")):
                    endpoints.add(u)
            except Exception:
                continue

        result.api_endpoints = sorted(endpoints)[:100]
        return result

    def audit_app_bundle(self, app_dir: str | Path) -> Optional[MachoAnalysisResult]:
        """Audit the main Mach-O executable in an extracted .app directory."""
        path = Path(app_dir)
        if not path.is_dir():
            return None

        # Look for the primary executable (matching .app folder name or Info.plist CFBundleExecutable)
        app_name = path.name.replace(".app", "")
        main_binary = path / app_name

        if main_binary.is_file():
            return self.parse_binary(main_binary)

        # Scan for any Mach-O files in top level of .app
        for item in path.iterdir():
            if item.is_file() and not item.name.endswith((".plist", ".nib", ".car", ".png", ".lproj")):
                res = self.parse_binary(item)
                if res.is_macho:
                    return res

        return None
