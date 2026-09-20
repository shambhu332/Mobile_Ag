"""
Neo4j node and relationship schemas for the attack surface graph.
"""

from dataclasses import dataclass
from typing import Optional

@dataclass
class AppNode:
    """Represents an application node in the graph."""
    package_name: str
    version: str = ""
    framework: str = ""
    scan_id: str = ""

@dataclass
class ComponentNode:
    """Represents an Android component node (Activity, Service, Receiver, Provider)."""
    name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool = False
    permission: str = ""

@dataclass 
class VulnerabilityNode:
    """Represents a vulnerability finding node."""
    finding_id: str
    title: str
    cwe: str
    severity: str
    cvss: float = 0.0
    confidence: float = 0.0

@dataclass
class APIEndpointNode:
    """Represents an API endpoint node."""
    url: str
    method: str = "GET"
    requires_auth: bool = False

@dataclass
class SecretNode:
    """Represents a discovered secret node."""
    secret_type: str  # api_key, password, crypto_key
    file_path: str = ""
    entropy: float = 0.0

# Relationship types
HAS_COMPONENT = "HAS_COMPONENT"
HAS_VULNERABILITY = "HAS_VULNERABILITY"
CALLS_API = "CALLS_API"
CONTAINS_SECRET = "CONTAINS_SECRET"
CHAINS_TO = "CHAINS_TO"
