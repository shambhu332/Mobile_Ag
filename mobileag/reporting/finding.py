"""Finding data model — represents a single security finding."""

import uuid
from enum import Enum
from typing import Optional, Any

from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    """Vulnerability severity levels aligned with bug bounty P-ratings."""
    CRITICAL = "CRITICAL"  # P1
    HIGH = "HIGH"          # P2
    MEDIUM = "MEDIUM"      # P3
    LOW = "LOW"            # P4
    INFO = "INFO"          # P5 / Informational


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""
    UNVERIFIED = "UNVERIFIED"        # Just discovered, not yet validated
    CONFIRMED = "CONFIRMED"          # Passed consensus + filter checks
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Marked as FP by filters or user feedback
    DUPLICATE = "DUPLICATE"          # Duplicate of another finding
    OPEN = "UNVERIFIED"              # Alias for backward compatibility


class Finding(BaseModel):
    """A single security finding with full metadata.

    Each finding tracks its source, severity, confidence, LLM consensus,
    and optionally includes generated Frida hooks and PoC guides.
    """

    # ── Identity ──
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str

    # ── Classification ──
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="0.0 to 1.0 confidence score")
    cwe_id: str = Field(default="CWE-Unknown", description="e.g. CWE-926")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = Field(default="")
    owasp_masvs: str = Field(default="", description="e.g. MASVS-PLATFORM-1")

    # ── Location ──
    affected_component: str = Field(default="ApplicationScope", description="Fully qualified class or component name")
    file_path: str = Field(default="")
    line_number: Optional[int] = None
    code_snippet: str = Field(default="")

    # ── Detection Metadata ──
    detection_method: str = Field(default="StaticAnalysis", description="Which agent/method found this")
    consensus_votes: dict[str, bool] = Field(
        default_factory=dict,
        description="LLM provider name → agree/disagree",
    )

    # ── Generated Outputs ──
    frida_script: Optional[str] = Field(
        default=None,
        description="Generated Frida hook script (JS) for manual execution",
    )
    poc_guide: Optional[str] = Field(
        default=None,
        description="Step-by-step PoC reproduction guide (Markdown)",
    )

    # ── Remediation ──
    remediation: str = Field(default="")

    # ── Status & Filtering ──
    status: FindingStatus = FindingStatus.UNVERIFIED
    false_positive_reasons: list[str] = Field(default_factory=list)
    filter_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Scores from each filter layer",
    )

    # ── Chaining ──
    related_findings: list[str] = Field(
        default_factory=list,
        description="IDs of related findings for chain analysis",
    )

    # ── Extra ──
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def remap_legacy_and_defaults(cls, data: Any) -> Any:
        """Remap legacy field names and assign safe fallback defaults."""
        if isinstance(data, dict):
            # Remap legacy 'cwe' to 'cwe_id'
            if "cwe" in data and "cwe_id" not in data:
                data["cwe_id"] = data.pop("cwe")

            # Remap status string 'OPEN' if provided
            if data.get("status") == "OPEN" or data.get("status") == FindingStatus.OPEN:
                data["status"] = FindingStatus.UNVERIFIED

            # Assign sensible affected_component if missing
            if not data.get("affected_component"):
                data["affected_component"] = data.get("file_path") or "ApplicationScope"

        return data

    def to_report_dict(self) -> dict[str, Any]:
        """Convert to a clean dict suitable for report templates."""
        return {
            "id": self.id[:8],
            "title": self.title,
            "severity": self.severity.value,
            "confidence": f"{self.confidence:.0%}",
            "cwe": self.cwe_id,
            "cvss": self.cvss_score,
            "component": self.affected_component,
            "file": self.file_path,
            "line": self.line_number,
            "description": self.description,
            "code": self.code_snippet,
            "remediation": self.remediation,
            "frida_script": self.frida_script,
            "poc_guide": self.poc_guide,
            "status": self.status.value,
        }
