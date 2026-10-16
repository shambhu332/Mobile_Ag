from __future__ import annotations

import pytest

from mobileag.web.source_browser import SourceReadError, read_scan_source


def test_reads_only_bounded_text_beneath_jadx_source_root(tmp_path):
    source = tmp_path / "scan_demo" / "jadx_out" / "sources" / "com" / "demo" / "Main.java"
    source.parent.mkdir(parents=True)
    source.write_text("package com.demo;\nclass Main {}\n", encoding="utf-8")

    result = read_scan_source(tmp_path, "scan_demo", "com/demo/Main.java")

    assert result["path"] == "jadx_out/sources/com/demo/Main.java"
    assert result["content"].startswith("package com.demo;")
    assert result["line_count"] == 2
    assert result["coverage"] == "bounded_file_read"


@pytest.mark.parametrize("path", [
    "../../etc/hosts", "/etc/hosts", "jadx_out/sources/../secret.java",
    "jadx_out\\sources\\Main.java", "jadx_out/sources/",
    "jadx_out/sources/Main.bin",
])
def test_rejects_traversal_absolute_malformed_and_binary_paths(tmp_path, path):
    with pytest.raises(SourceReadError):
        read_scan_source(tmp_path, "scan_demo", path)


def test_rejects_symlinked_source_file_and_directory(tmp_path):
    scan = tmp_path / "scan_demo"
    sources = scan / "jadx_out" / "sources"
    sources.mkdir(parents=True)
    outside = tmp_path / "outside.java"
    outside.write_text("synthetic outside", encoding="utf-8")
    (sources / "Leak.java").symlink_to(outside)
    with pytest.raises(SourceReadError):
        read_scan_source(tmp_path, "scan_demo", "sources/Leak.java")

    (scan / "jadx_out" / "sources").rename(scan / "jadx_out" / "sources-real")
    (scan / "jadx_out" / "sources").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(SourceReadError):
        read_scan_source(tmp_path, "scan_demo", "sources/outside.java")


def test_rejects_over_limit_text_before_returning_partial_content(tmp_path):
    source = tmp_path / "scan_demo" / "jadx_out" / "resources" / "res" / "raw" / "large.txt"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"x" * 32)
    with pytest.raises(SourceReadError, match="1 MiB"):
        read_scan_source(tmp_path, "scan_demo", "resources/res/raw/large.txt", max_bytes=16)
