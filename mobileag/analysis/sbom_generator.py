"""Software Bill of Materials (SBOM) Generator for Mobile Applications.

Generates standardized CycloneDX v1.5 and SPDX 2.3 SBOMs from extracted mobile dependencies,
embedded native shared libraries, and build metadata.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SbomComponent:
    name: str
    version: str
    purl: str
    component_type: str = "library"  # library, framework, operating-system
    scope: str = "required"
    description: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    licenses: List[str] = field(default_factory=list)


class MobileSbomGenerator:
    """Generates CycloneDX and SPDX SBOM representations."""

    def __init__(self, app_name: str = "MobileApp", app_version: str = "1.0.0"):
        self.app_name = app_name
        self.app_version = app_version
        self.components: List[SbomComponent] = []

    def add_component(
        self,
        name: str,
        version: str,
        purl: str,
        component_type: str = "library",
        hashes: Optional[Dict[str, str]] = None,
        licenses: Optional[List[str]] = None,
    ) -> None:
        """Add a software dependency or native library component."""
        comp = SbomComponent(
            name=name,
            version=version,
            purl=purl,
            component_type=component_type,
            hashes=hashes or {},
            licenses=licenses or [],
        )
        self.components.append(comp)

    def generate_cyclonedx_json(self) -> Dict[str, Any]:
        """Generate CycloneDX v1.5 JSON formatted SBOM."""
        serial_number = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        cyclonedx_components = []
        for c in self.components:
            comp_entry: Dict[str, Any] = {
                "type": c.component_type,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "scope": c.scope,
            }
            if c.hashes:
                comp_entry["hashes"] = [{"alg": k.upper(), "content": v} for k, v in c.hashes.items()]
            if c.licenses:
                comp_entry["licenses"] = [{"license": {"id": lic}} for lic in c.licenses]
            cyclonedx_components.append(comp_entry)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial_number,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "MobileAg",
                        "name": "MobileAg Security Scanner",
                        "version": "0.1.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self.app_name,
                    "version": self.app_version,
                },
            },
            "components": cyclonedx_components,
        }

    def generate_spdx_json(self) -> Dict[str, Any]:
        """Generate SPDX 2.3 JSON formatted SBOM."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        document_namespace = f"http://spdx.org/spdxdocs/{self.app_name}-{self.app_version}-{uuid.uuid4()}"

        spdx_packages = []
        for idx, c in enumerate(self.components, 1):
            pkg: Dict[str, Any] = {
                "SPDXID": f"SPDXRef-Package-{idx}",
                "name": c.name,
                "versionInfo": c.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c.purl,
                    }
                ],
            }
            if c.licenses:
                pkg["licenseConcluded"] = c.licenses[0]
            else:
                pkg["licenseConcluded"] = "NOASSERTION"
            spdx_packages.append(pkg)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{self.app_name} SBOM",
            "documentNamespace": document_namespace,
            "creationInfo": {
                "creators": ["Tool: MobileAg-0.1.0"],
                "created": timestamp,
            },
            "packages": spdx_packages,
        }

    def save_cyclonedx(self, output_path: str | Path) -> None:
        """Write CycloneDX JSON to disk."""
        data = self.generate_cyclonedx_json()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def save_spdx(self, output_path: str | Path) -> None:
        """Write SPDX JSON to disk."""
        data = self.generate_spdx_json()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
