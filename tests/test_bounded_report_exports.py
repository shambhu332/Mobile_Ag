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
