"""Local CLI contract tests; orchestration is mocked, no APK/tool/device is used."""
from unittest.mock import AsyncMock, patch
from pathlib import Path

from click.testing import CliRunner

from config.settings import Settings
from mobileag.cli import main


def _run(monkeypatch, apk, scan_state):
    import mobileag.cli as cli
    monkeypatch.setattr(cli, "get_settings", lambda: Settings(_env_file=None, offline=True))
    with patch.object(cli, "Orchestrator") as factory:
        factory.return_value.scan = AsyncMock(return_value=scan_state)
        result = CliRunner().invoke(main, ["scan", "--apk", str(apk), "--offline", "--format", "json"])
        assert factory.call_args.args[0].offline is True
        return result


def test_offline_cli_success_exit_is_zero_even_with_candidates(monkeypatch, tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"synthetic non-analyzed input")
    result = _run(monkeypatch, apk, {
        "errors": [], "json_report_path": "synthetic-report.json",
        "filtered_findings": [{"status": "UNVERIFIED"}],
    })
    assert result.exit_code == 0, result.output
    assert "synthetic-report.json" in result.output


def test_offline_cli_incomplete_scan_is_nonzero(monkeypatch, tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"synthetic non-analyzed input")
    result = _run(monkeypatch, apk, {"errors": ["synthetic parser failure"]})
    assert result.exit_code != 0
    assert "failed or incomplete" in result.output


def test_osv_lookup_requires_explicit_flag_and_is_forwarded_per_scan(monkeypatch, tmp_path):
    import mobileag.cli as cli
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"synthetic non-analyzed input")
    monkeypatch.setattr(cli, "get_settings", lambda: Settings(_env_file=None, offline=True))
    with patch.object(cli, "Orchestrator") as factory:
        factory.return_value.scan = AsyncMock(return_value={"errors": [], "json_report_path": "out.json"})
        result = CliRunner().invoke(main, ["scan", "--apk", str(apk), "--lookup-advisories", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert factory.return_value.scan.await_args.kwargs["allow_advisory_lookup"] is True


def test_offline_and_osv_lookup_options_conflict(monkeypatch, tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"synthetic non-analyzed input")
    result = CliRunner().invoke(main, ["scan", "--apk", str(apk), "--offline", "--lookup-advisories"])
    assert result.exit_code != 0
    assert "prohibits all network access" in result.output


def test_ci_pins_python_and_test_build_toolchain_constraints():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/project-validation.yml").read_text()
    pyproject = (root / "pyproject.toml").read_text()
    assert "python-version: '3.14.7'" in workflow
    assert "-c requirements/validated-python314.txt" in workflow
    assert '".[test]"' in workflow and '".[test,java-ast]"' not in workflow
    assert '".[test]" build setuptools wheel' in workflow
    assert 'requires = ["setuptools==84.0.0", "wheel==0.48.0"]' in pyproject
    pins = {}
    for line in (root / "requirements/validated-python314.txt").read_text().splitlines():
        if "==" in line and not line.lstrip().startswith("#"):
            name, version = line.split("==", 1)
            pins[name.lower().replace("_", "-")] = version
    for name in ("build", "setuptools", "wheel", "pytest", "pytest-asyncio", "jsonschema",
                 "jsonschema-specifications", "openapi-spec-validator", "openapi-schema-validator",
                 "jsonschema-path", "pathable", "lazy-object-proxy", "rfc3339-validator",
                 "referencing", "rpds-py", "tree-sitter", "tree-sitter-java"):
        assert name in pins, f"CI lock/constraints missing exact pin for {name}"
