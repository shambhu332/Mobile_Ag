from typing import Literal
from pydantic import Field,SecretStr
from mobileag.automation.models import Contract,Capture

class Scope(Contract):
    devices:list[str]=Field(default_factory=list,max_length=100)
    packages:list[str]=Field(max_length=100)
    origins:list[str]=Field(default_factory=list,max_length=100)
    methods:list[str]=Field(default_factory=lambda:['GET','HEAD'],max_length=10)
    actions:list[str]=Field(default_factory=list,max_length=30)

class Assessment(Contract):
    apk_path:str=Field(max_length=1024)
    package_name:str=Field(pattern=r'^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$',max_length=200)
    scope:Scope
    authorized:Literal[True]
    scope_change_confirmed:Literal[True]
    confirmation:Literal['START SCOPED TESTS']
    api:bool=False
    dast:bool=False
    serial:str|None=Field(default=None,max_length=128)
    component:str|None=Field(default=None,max_length=240)
    dedicated_device_confirmed:bool=False
    dedicated_account_confirmed:bool=False
    install_if_absent:bool=False
    launch:bool=False
    max_steps:int=Field(default=8,ge=1,le=30)
    max_requests:int=Field(default=4,ge=0,le=10)
    captures:list[Capture]=Field(default_factory=list,max_length=10)
    api_authorization:SecretStr|None=None
    llm_provider:str|None=Field(default=None,max_length=32)
    llm_metadata_egress_confirmed:bool=False
    llm_secondary_provider:str|None=Field(default=None,min_length=1,max_length=32)
    llm_fallback_egress_confirmed:bool=False
