"""Bounded operator contracts. No credential is part of a durable run model."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr

class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Capture(Contract):
    # Import is operator-provided evidence, not independently verified traffic.
    method: Literal['GET','HEAD'] = 'GET'
    url: str = Field(min_length=1,max_length=2048)
    label: str = Field(default='Observed request',max_length=64)
    ui_action_id: str | None = Field(default=None,pattern=r"^[a-f0-9]{24}$")
    response_status: int | None = Field(default=None,ge=100,le=599)
    protected: bool = False
    read_only_confirmed: Literal[True]
    # Only schema shape is retained; raw values/headers/bodies never enter storage.
    query_names: list[str] = Field(default_factory=list,max_length=20)

class CreateRun(Contract):
    serial: str = Field(min_length=1,max_length=128)
    package_name: str = Field(pattern=r'^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$',max_length=200)
    component: str = Field(max_length=240)
    environment: Literal['synthetic','dedicated_staging']
    dedicated_account_confirmed: Literal[True]
    dedicated_device_confirmed: Literal[True]
    max_steps: int = Field(default=8,ge=1,le=30)
    max_requests: int = Field(default=4,ge=0,le=10)
    request_interval_seconds: float = Field(default=1,ge=.5,le=10)
    captures: list[Capture] = Field(default_factory=list,max_length=10)
    auth_state: Literal['unknown','logged_out','logged_in','expired','insufficient_privileges'] = 'unknown'
    parent_run_id: str | None = Field(default=None,pattern=r'^auto_[a-f0-9]{32}$')

class ExecuteRun(Contract):
    revision: int = Field(ge=0)
    approved_action_ids: list[str] = Field(default_factory=list,max_length=50)
    approved_api_cases: list[str] = Field(default_factory=list,max_length=30)
    allow_back: bool = False
    confirmation: str = Field(max_length=80)
    # Supplied afresh by operator; never reuse captured/discovered credentials.
    test_authorization: SecretStr | None = None

class ImportCaptures(Contract):
    revision: int = Field(ge=0)
    captures: list[Capture] = Field(max_length=10)
