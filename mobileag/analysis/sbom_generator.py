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

    def generate_cyclonedx_xml(self) -> str:
        """Generate CycloneDX v1.5 XML formatted SBOM."""
        import xml.etree.ElementTree as ET

        serial_number = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        ns = "http://cyclonedx.org/schema/bom/1.5"
        root = ET.Element("bom", {
            "xmlns": ns,
            "serialNumber": serial_number,
            "version": "1",
        })

        metadata = ET.SubElement(root, "metadata")
        ts_elem = ET.SubElement(metadata, "timestamp")
        ts_elem.text = timestamp

        tools = ET.SubElement(metadata, "tools")
        tool = ET.SubElement(tools, "tool")
        vendor = ET.SubElement(tool, "vendor")
        vendor.text = "MobileAg"
        name = ET.SubElement(tool, "name")
        name.text = "MobileAg Security Scanner"
        ver = ET.SubElement(tool, "version")
        ver.text = "0.1.0"

        app_comp = ET.SubElement(metadata, "component", {"type": "application"})
        app_name_elem = ET.SubElement(app_comp, "name")
        app_name_elem.text = self.app_name
        app_ver_elem = ET.SubElement(app_comp, "version")
        app_ver_elem.text = self.app_version

        components = ET.SubElement(root, "components")
        for c in self.components:
            comp_elem = ET.SubElement(components, "component", {"type": c.component_type})
            c_name = ET.SubElement(comp_elem, "name")
            c_name.text = c.name
            c_ver = ET.SubElement(comp_elem, "version")
            c_ver.text = c.version
            c_purl = ET.SubElement(comp_elem, "purl")
            c_purl.text = c.purl
            c_scope = ET.SubElement(comp_elem, "scope")
            c_scope.text = c.scope

            if c.hashes:
                hashes_elem = ET.SubElement(comp_elem, "hashes")
                for alg, h_val in c.hashes.items():
                    h_elem = ET.SubElement(hashes_elem, "hash", {"alg": alg.upper()})
                    h_elem.text = h_val

            if c.licenses:
                licenses_elem = ET.SubElement(comp_elem, "licenses")
                for lic in c.licenses:
                    license_elem = ET.SubElement(licenses_elem, "license")
                    id_elem = ET.SubElement(license_elem, "id")
                    id_elem.text = lic

        ET.indent(root, space="  ")
        return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")

    def save_cyclonedx_xml(self, output_path: str | Path) -> None:
        """Write CycloneDX XML to disk."""
        xml_data = self.generate_cyclonedx_xml()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(xml_data)

    def save_spdx(self, output_path: str | Path) -> None:
        """Write SPDX JSON to disk."""
        data = self.generate_spdx_json()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

