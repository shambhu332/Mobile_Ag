"""Structured analyst evidence requirements; not an automated exploit oracle."""
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EvidenceError(ValueError):
    pass


class ConfirmationEvidence(BaseModel):
    model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
    artifact_sha256: str=Field(pattern=r'^[0-9a-f]{64}$')
    package_name: str=Field(min_length=3,max_length=256)
    app_version: str=Field(min_length=1,max_length=256)
    os_build: str=Field(min_length=3,max_length=256)
    attacker_context: Literal['ordinary_app','browser','network_peer','static_artifact']
    entry_point: str=Field(min_length=3,max_length=2000)
    attacker_control: str=Field(min_length=3,max_length=2000)
    sensitive_sink: str=Field(min_length=3,max_length=2000)
    security_boundary: str=Field(min_length=3,max_length=2000)
    observed_impact: str=Field(min_length=3,max_length=2000)
    reproduction_steps: list[str]=Field(min_length=2,max_length=30)
    positive_control: str=Field(min_length=3,max_length=2000)
    negative_control: str=Field(min_length=3,max_length=2000)
    evidence_refs: list[str]=Field(min_length=1,max_length=30)
    unprivileged_attacker_confirmed: Literal[True]
    unmodified_authorization_confirmed: Literal[True]
    synthetic_data_confirmed: Literal[True]
    scope_confirmed: Literal[True]

    @field_validator('reproduction_steps')
    @classmethod
    def steps(cls,values):
        if any(not value.strip() or len(value)>2000 for value in values):
            raise ValueError('Reproduction steps must be bounded and nonempty')
        return [value.strip() for value in values]

    @field_validator('evidence_refs')
    @classmethod
    def refs(cls,values):
        if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value) or '..' in value for value in values):
            raise ValueError('Use opaque local evidence IDs, not URLs or filesystem paths')
        return values

    @model_validator(mode='after')
    def controls(self):
        if self.os_build.lower() in {'unknown','vunknown','not_tested','not assessed'}:
            raise ValueError('Record the tested OS build, not an unknown placeholder')
        if self.positive_control==self.negative_control:
            raise ValueError('Positive and negative controls must be distinct')
        return self


def bind_confirmation(value,scan):
    if value is None:raise EvidenceError('Confirmation requires structured unprivileged reproduction evidence, not notes alone')
    try:proof=ConfirmationEvidence.model_validate(value)
    except ValueError as exc:raise EvidenceError('Structured evidence is incomplete or invalid') from exc
    for name in ('artifact_sha256','package_name'):
        if proof.model_dump()[name] != scan.get(name):raise EvidenceError('Evidence does not match this scan artifact/package')
    if proof.app_version != scan.get('version') or proof.app_version.lower() in {'unknown','vunknown','not assessed'}:
        raise EvidenceError('Evidence must match a recorded application version')
    return {'basis':'analyst_attested','independently_verified':False,'active':True,
            'limitations':['Required fields and artifact binding were checked; the tool has not independently verified the claimed exploit.'],
            'record':proof.model_dump()}
