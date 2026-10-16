"""Resource-boundary regressions for renderer inputs."""
import pytest


def test_professional_report_preflights_oversized_inputs_before_redaction(monkeypatch):
    from mobileag.reporting import professional_report

    monkeypatch.setattr(professional_report, "_MAX_PROFESSIONAL_INPUT_BYTES", 512)
    monkeypatch.setattr(
        professional_report, "redact",
        lambda value: pytest.fail("redaction must not run before preflight"),
    )
    with pytest.raises(ValueError, match="Professional report input exceeds"):
        professional_report.ProfessionalReportExporter().generate_report(
            [{"title": "Synthetic", "description": "x" * 200}],
        )


def test_professional_report_rejects_cycles_before_rendering():
    from mobileag.reporting.professional_report import ProfessionalReportExporter

    metadata = {}
    metadata["self"] = metadata
    with pytest.raises(ValueError, match="Professional report input contains a cycle"):
        ProfessionalReportExporter().generate_report([], scan_metadata=metadata)


def test_professional_report_bounds_finding_count(monkeypatch):
    from mobileag.reporting import professional_report

    monkeypatch.setattr(professional_report, "_MAX_PROFESSIONAL_FINDINGS", 1)
    with pytest.raises(ValueError, match="finding inventory exceeds limits"):
        professional_report.ProfessionalReportExporter().generate_report([{}, {}])


def test_report_engine_preflights_state_before_formatting(monkeypatch):
    from mobileag.core.state import create_initial_state
    from mobileag.reporting.report_engine import ReportEngine

    monkeypatch.setattr(ReportEngine, "MAX_REPORT_INPUT_BYTES", 512)
    state = create_initial_state("synthetic", "unused", "/tmp/mobileag-test-output")
    state["errors"] = ["x" * 200]
    with pytest.raises(ValueError, match="Report input exceeds"):
        ReportEngine()._prepare_data(state)


def test_report_engine_bounds_findings_and_artifact_output(tmp_path, monkeypatch):
    from mobileag.core.state import create_initial_state
    from mobileag.reporting.report_engine import ReportEngine

    monkeypatch.setattr(ReportEngine, "MAX_REPORT_FINDINGS", 1)
    state = create_initial_state("synthetic", "unused", str(tmp_path))
    state["filtered_findings"] = [{"title": "one"}, {"title": "two"}]
    with pytest.raises(ValueError, match="finding inventory exceeds limits"):
        ReportEngine()._prepare_data(state)

    destination = tmp_path / "existing-report.json"
    destination.write_bytes(b"previous")
    with pytest.raises(ValueError, match="output size limit"):
        ReportEngine._atomic_private_write(destination, b"oversized", max_bytes=4)
    assert destination.read_bytes() == b"previous"
