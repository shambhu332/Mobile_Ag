#!/usr/bin/env python3
"""Build two isolated wheels from identical source snapshots and compare bytes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DATE_EPOCH = "1760313600"  # 2025-10-13T00:00:00Z; stable archive timestamps.
SARIF_SCHEMA_SHA256 = "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"


def _copy_build_inputs(destination: Path) -> None:
    destination.mkdir(parents=True)
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(ROOT / name, destination / name)
    for name in ("mobileag", "config"):
        shutil.copytree(ROOT / name, destination / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def _build_once(root: Path, outdir: Path, env: dict[str, str]) -> Path:
    result = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--wheel", "--outdir", str(outdir)],
        cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=240, check=False,
    )
    if result.returncode:
        # Do not echo arbitrary build logs into shared CI logs.
        raise RuntimeError(f"wheel build failed with exit code {result.returncode}")
    wheels = sorted(outdir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one wheel, got {len(wheels)}")
    with zipfile.ZipFile(wheels[0]) as archive:
        schema_name = "mobileag/data/sarif-schema-2.1.0.json"
        if schema_name not in archive.namelist():
            raise RuntimeError("wheel does not contain the vendored SARIF schema")
        if hashlib.sha256(archive.read(schema_name)).hexdigest() != SARIF_SCHEMA_SHA256:
            raise RuntimeError("wheel contains an unexpected SARIF schema digest")
        metadata = next((name for name in archive.namelist() if name.endswith(".dist-info/METADATA")), None)
        if metadata is None or "Requires-Dist: jsonschema<5,>=4" not in archive.read(metadata).decode("utf-8", errors="replace"):
            raise RuntimeError("wheel metadata does not declare the JSON Schema runtime dependency")
    return wheels[0]


def main() -> int:
    env = dict(os.environ)
    env.update(SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH, PYTHONHASHSEED="0", TZ="UTC")
    with tempfile.TemporaryDirectory(prefix="mobileag-wheel-repro-") as temporary:
        base = Path(temporary)
        artifacts = []
        for index in (1, 2):
            build_root, outdir = base / f"source-{index}", base / f"dist-{index}"
            _copy_build_inputs(build_root)
            outdir.mkdir()
            artifacts.append(_build_once(build_root, outdir, env))
        digests = [hashlib.sha256(artifact.read_bytes()).hexdigest() for artifact in artifacts]
        print(json.dumps({
            "status": "reproducible" if digests[0] == digests[1] else "mismatch",
            "source_date_epoch": int(SOURCE_DATE_EPOCH),
            "wheel": artifacts[0].name,
            "vendored_sarif_schema": "OASIS 2.1.0 SHA-256 verified in both wheels",
            "sha256": digests,
            "scope": "two clean isolated wheel builds from identical mobileag/config/pyproject/README source snapshots",
            "exclusions": ["supply-chain reproducibility", "hosted-runner image reproducibility", "runtime scan IDs and timestamps"],
        }, sort_keys=True, indent=2))
        return 0 if digests[0] == digests[1] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__,
                          "message": str(exc)[:1000]}), file=sys.stderr)
        raise SystemExit(2)
