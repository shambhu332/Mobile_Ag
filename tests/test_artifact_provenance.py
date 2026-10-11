import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace

from mobileag.core.state import create_initial_state
from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.ingestion.apk_extractor import APKExtractor
from mobileag.reporting.report_engine import ReportEngine


def test_apk_sha256_is_streamed_and_matches_standard_digest(tmp_path):
    artifact = tmp_path / "sample.apk"
    artifact.write_bytes(b"synthetic apk bytes" * 1000)
    before = artifact.read_bytes()

    assert APKExtractor._sha256(artifact) == hashlib.sha256(before).hexdigest()
    assert artifact.read_bytes() == before


def test_tool_version_failure_is_explicit_and_nonfatal():
    result = asyncio.run(APKExtractor._tool_version(
        str(Path("/definitely/missing/mobileag-tool")), ("--version",)))

    assert result["version"] is None
    assert result["version_error"] == "FileNotFoundError"


def test_extract_records_provenance_and_tool_versions_without_modifying_apk(tmp_path, monkeypatch):
    import mobileag.security.archives as archives

    artifact = tmp_path / "owned.apk"
    original = b"synthetic owned artifact"
    artifact.write_bytes(original)
    monkeypatch.setattr(archives, "validate_archive", lambda _path: "android")

    class FakeProcess:
        def __init__(self, argv):
            self.argv = argv
            self.returncode = 0

        async def wait(self):
            return 0

        async def communicate(self):
            return (b"tool-version 1.2.3", None)

        def kill(self):
            self.returncode = -9

    async def fake_create_subprocess_exec(*argv, **_kwargs):
        output_flag = "-o" if "-o" in argv else "-d" if "-d" in argv else None
        if output_flag:
            out_dir = Path(argv[argv.index(output_flag) + 1])
            if Path(argv[0]).name == "apktool":
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text('<manifest package="org.example.fixture"/>')
            else:
                out_dir.mkdir(parents=True, exist_ok=True)
        return FakeProcess(argv)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    extractor = APKExtractor(SimpleNamespace(JADX_PATH="jadx", APKTOOL_PATH="apktool"))

    result = asyncio.run(extractor.extract(str(artifact), str(tmp_path / "out")))

    assert result["artifact_provenance"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["artifact_provenance"]["tools"]["jadx"]["version"] == "tool-version 1.2.3"
    assert result["package_name"] == "org.example.fixture"
    assert artifact.read_bytes() == original


def test_initial_state_has_empty_artifact_provenance():
    state = create_initial_state("scan-1", "owned.apk", "out")

    assert state["artifact_provenance"] == {}


def test_report_preserves_artifact_and_tool_provenance():
    state = create_initial_state("scan-1", "owned.apk", "out")
    state["artifact_provenance"] = {
        "sha256": "a" * 64,
        "size_bytes": 123,
        "filename": "owned.apk",
        "mobileag_version": "test",
        "python_version": "3.test",
        "tools": {"jadx": {"executable": "jadx", "version": "1.test"}},
    }

    report = ReportEngine()._prepare_data(state)

    assert report["artifact_provenance"] == state["artifact_provenance"]


def test_source_inventory_order_is_stable_and_casefold_sorted(tmp_path):
    (tmp_path / "z.java").write_text("class Z {}", encoding="utf-8")
    (tmp_path / "A.java").write_text("class A {}", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "b.java").write_text("class B {}", encoding="utf-8")

    inventory = SourceInventory()
    actual = [str(path.relative_to(tmp_path)) for path, _ in inventory.read(tmp_path, {".java"})]

    assert actual == ["A.java", "z.java", "nested/b.java"]
