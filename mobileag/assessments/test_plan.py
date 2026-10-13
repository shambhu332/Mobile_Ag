"""Schema for a manual, scan-bound validation plan; it cannot execute testing."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Role(_StrictModel):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    purpose: str = Field(default="", max_length=300)


class Flow(_StrictModel):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=160)
    entrypoint: str = Field(default="", max_length=500)
    sensitive_operation: str = Field(default="", max_length=500)
    prerequisites: str = Field(default="", max_length=1000)


class AccountAlias(_StrictModel):
    alias: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    role_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")


class Coverage(_StrictModel):
    surface: Literal["manifest_ipc", "serialization", "files_uri_grants",
                     "storage_logging", "webview_deep_links", "network_api_auth",
                     "crypto_native", "runtime"]
    state: Literal["not_tested", "candidate", "observed", "attested",
                   "not_applicable"] = "not_tested"
    evidence_ref: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    gap_reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def evidence_or_gap(self):
        if self.state in {"observed", "attested"} and not self.evidence_ref:
            raise ValueError("Observed or attested coverage requires an evidence reference")
        if self.state == "not_applicable" and not self.gap_reason:
            raise ValueError("not_applicable requires a reason")
        return self


class EvidenceNote(_StrictModel):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    flow_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    finding_id: str | None = Field(default=None, max_length=128)
    outcome: Literal["not_tested", "observed", "not_reproduced"] = "not_tested"
    summary: str = Field(default="", max_length=2000)
    prerequisites: str = Field(default="", max_length=1000)
    steps: list[str] = Field(default_factory=list, max_length=20)
    expected: str = Field(default="", max_length=1000)
    observed: str = Field(default="", max_length=1000)
    negative_control: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def observed_record_has_context(self):
        if self.outcome in {"observed", "not_reproduced"} and (not self.steps or not (self.observed or self.summary)):
            raise ValueError("Observed outcomes require steps and a summary or observation")
        return self


class TestPlanInput(_StrictModel):
    """No credential, URL, device, or execution-scope fields are accepted."""
    expected_revision: int | None = Field(default=None, ge=0)
    roles: list[Role] = Field(default_factory=list, max_length=32)
    flows: list[Flow] = Field(default_factory=list, max_length=100)
    test_account_aliases: list[AccountAlias] = Field(default_factory=list, max_length=32)
    coverage: list[Coverage] = Field(default_factory=list, max_length=8)
    evidence: list[EvidenceNote] = Field(default_factory=list, max_length=200)
    retest_of_scan_id: str | None = Field(default=None, max_length=128)

    @field_validator("roles")
    @classmethod
    def unique_role_ids(cls, values):
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("Role IDs must be unique")
        return values

    @field_validator("flows")
    @classmethod
    def unique_flow_ids(cls, values):
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("Flow IDs must be unique")
        return values

    @field_validator("test_account_aliases")
    @classmethod
    def aliases_only(cls, values):
        aliases = [item.alias.casefold() for item in values]
        if len(aliases) != len(set(aliases)):
            raise ValueError("Test account aliases must be unique")
        return values

    @field_validator("coverage")
    @classmethod
    def unique_surfaces(cls, values):
        surfaces = [item.surface for item in values]
        if len(surfaces) != len(set(surfaces)):
            raise ValueError("Coverage surfaces must be unique")
        return values

    @field_validator("evidence")
    @classmethod
    def unique_evidence_ids(cls, values):
        ids = [item.id for item in values]
        if len(ids) != len(set(ids)):
            raise ValueError("Evidence IDs must be unique")
        return values

    def validate_references(self, finding_ids: set[str]) -> None:
        role_ids = {item.id for item in self.roles}
        flow_ids = {item.id for item in self.flows}
        evidence_ids = {item.id for item in self.evidence}
        if any(item.role_id not in role_ids for item in self.test_account_aliases):
            raise ValueError("Each test account alias must reference a plan role")
        for item in self.evidence:
            if item.flow_id is not None and item.flow_id not in flow_ids:
                raise ValueError("Evidence references a flow outside this plan")
            if item.finding_id is not None and item.finding_id not in finding_ids:
                raise ValueError("Evidence references a finding outside this scan")
        for item in self.coverage:
            if item.evidence_ref is not None and item.evidence_ref not in evidence_ids:
                raise ValueError("Coverage references evidence outside this plan")


def build_plan(scan: dict, request: TestPlanInput, revision: int) -> dict:
    if not isinstance(scan, dict) or not isinstance(scan.get("scan_id"), str):
        raise ValueError("A valid scan document is required")
    findings = scan.get("findings") if isinstance(scan.get("findings"), list) else []
    ids = {item.get("id") for item in findings if isinstance(item, dict) and isinstance(item.get("id"), str)}
    request.validate_references(ids)
    package = scan.get("package_name")
    provenance = scan.get("artifact_provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    app_info = scan.get("app_info")
    app_info = app_info if isinstance(app_info, dict) else {}
    artifact_hash = scan.get("artifact_sha256") or provenance.get("sha256")
    if not isinstance(package, str) or not package or not isinstance(artifact_hash, str) or not re.fullmatch(r"[A-Fa-f0-9]{64}", artifact_hash):
        raise ValueError("A package and valid artifact SHA-256 are required to bind the plan")
    if request.retest_of_scan_id:
        if request.retest_of_scan_id == scan.get("scan_id"):
            raise ValueError("A retest must reference a different scan")
    return {
        "schema_version": 1,
        "plan_revision": revision,
        "scan_id": scan["scan_id"],
        "scope": {"package_name": package, "artifact_sha256": artifact_hash,
                  "app_version": scan.get("version") or app_info.get("version_name")},
        "roles": [item.model_dump() for item in request.roles],
        "flows": [item.model_dump() for item in request.flows],
        "test_account_aliases": [item.model_dump() for item in request.test_account_aliases],
        "coverage": [item.model_dump() for item in request.coverage],
        "evidence": [item.model_dump() for item in request.evidence],
        "retest_of_scan_id": request.retest_of_scan_id,
        "evidence_interpretation": "manual_notes_unverified_not_execution_or_independent_proof",
        "limitations": ["Plan records do not authorize or execute device/API actions.",
                         "Account aliases only; never store credentials, cookies, tokens, or secrets.",
                         "Evidence notes are analyst-supplied and are not independently verified."],
    }
