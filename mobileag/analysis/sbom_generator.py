"""Software Bill of Materials (SBOM) Generator for Mobile Applications.

Generates standardized CycloneDX v1.5 and SPDX 2.3 SBOMs from extracted mobile dependencies,
embedded native shared libraries, and build metadata.
"""
from __future__ import annotations

import json
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SbomComponent:
    name: str
    version: Optional[str]
    purl: str
    component_type: str = "library"  # library, framework, operating-system
    scope: str = "required"
    description: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    licenses: List[str] = field(default_factory=list)


class MobileSbomGenerator:
    """Generates CycloneDX and SPDX SBOM representations."""

    HASH_LENGTHS = {
        "MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128,
        "SHA3-256": 64, "SHA3-384": 96, "SHA3-512": 128,
        "BLAKE2B-256": 64, "BLAKE2B-384": 96, "BLAKE2B-512": 128, "BLAKE3": 64,
    }

    def __init__(self, app_name: str = "MobileApp", app_version: str = "1.0.0"):
        self.app_name = app_name
        self.app_version = app_version
        self.components: List[SbomComponent] = []
        self.vulnerabilities: List[Dict[str, Any]] = []

    def add_component(
        self,
        name: str,
        version: Optional[str],
        purl: str,
        component_type: str = "library",
        hashes: Optional[Dict[str, str]] = None,
        licenses: Optional[List[str]] = None,
    ) -> None:
        """Add a software dependency or native library component."""
        normalized_hashes: Dict[str, str] = {}
        for algorithm, digest in (hashes or {}).items():
            if not isinstance(algorithm, str) or not isinstance(digest, str):
                raise ValueError("SBOM hash algorithms and digests must be strings")
            canonical = re.sub(r"[-_]", "", algorithm).upper()
            canonical = {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384",
                         "SHA512": "SHA-512", "SHA3256": "SHA3-256", "SHA3384": "SHA3-384",
                         "SHA3512": "SHA3-512", "BLAKE2B256": "BLAKE2B-256",
                         "BLAKE2B384": "BLAKE2B-384", "BLAKE2B512": "BLAKE2B-512"}.get(canonical, canonical)
            expected_length = self.HASH_LENGTHS.get(canonical)
            if (expected_length is None or len(digest) != expected_length
                    or not re.fullmatch(r"[0-9a-fA-F]+", digest)):
                raise ValueError(f"Invalid or unsupported SBOM digest for {algorithm!r}")
            if canonical in normalized_hashes:
                raise ValueError(f"Duplicate SBOM hash algorithm: {canonical}")
            normalized_hashes[canonical] = digest.lower()
        comp = SbomComponent(
            name=name,
            version=version,
            purl=purl,
            component_type=component_type,
            hashes=normalized_hashes,
            licenses=licenses or [],
        )
        self.components.append(comp)

    def add_vulnerability(
        self,
        vuln_id: str,
        purl: str,
        description: str = "",
        severity: str = "medium",
        cwe_ids: Optional[List[str]] = None,
    ) -> None:
        """Attach an OSV/CVE security advisory to an inventoried component."""
        self.vulnerabilities.append({
            "id": vuln_id,
            "purl": purl,
            "description": description,
            "severity": severity,
            "cwe_ids": cwe_ids or [],
        })

    def _component_refs(self) -> list[str]:
        """Create stable, document-local unique CycloneDX component references."""
        return [f"mobileag-component-{index}-{hashlib.sha256(c.purl.encode('utf-8')).hexdigest()[:12]}"
                for index, c in enumerate(self.components, 1)]


    def generate_cyclonedx_json(self) -> Dict[str, Any]:
        """Generate CycloneDX v1.5 JSON formatted SBOM."""
        serial_number = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        cyclonedx_components = []
        component_refs = self._component_refs()
        for c, bom_ref in zip(self.components, component_refs):
            comp_entry: Dict[str, Any] = {
                "bom-ref": bom_ref,
                "type": c.component_type,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "scope": c.scope,
            }
            if c.version is None:
                comp_entry.pop("version")
            if c.hashes:
                comp_entry["hashes"] = [{"alg": k, "content": v} for k, v in c.hashes.items()]
            if c.licenses:
                comp_entry["licenses"] = [{"license": {"id": lic}} for lic in c.licenses]
            cyclonedx_components.append(comp_entry)

        res = {
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

        if self.vulnerabilities:
            cyclonedx_vulns = []
            for v in self.vulnerabilities:
                component_index = next((i for i, c in enumerate(self.components) if c.purl == v["purl"]), None)
                if component_index is None:
                    continue
                v_entry: Dict[str, Any] = {
                    "id": v["id"],
                    "description": v["description"],
                    "ratings": [{"severity": v["severity"].lower()}],
                    "affects": [{"ref": component_refs[component_index]}],
                }
                if v.get("cwe_ids"):
                    v_entry["cwes"] = [
                        int(re.sub(r"[^\d]", "", cwe))
                        for cwe in v["cwe_ids"]
                        if re.sub(r"[^\d]", "", cwe)
                    ]
                cyclonedx_vulns.append(v_entry)
            res["vulnerabilities"] = cyclonedx_vulns

        return res

    def generate_spdx_json(self) -> Dict[str, Any]:
        """Generate SPDX 2.3 JSON formatted SBOM."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        document_namespace = f"http://spdx.org/spdxdocs/{self.app_name}-{self.app_version}-{uuid.uuid4()}"

        spdx_packages = []
        for idx, c in enumerate(self.components, 1):
            pkg: Dict[str, Any] = {
                "SPDXID": f"SPDXRef-Package-{idx}",
                "name": c.name,
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
            if c.version is not None:
                pkg["versionInfo"] = c.version
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
        component_refs = self._component_refs()
        for c, bom_ref in zip(self.components, component_refs):
            comp_elem = ET.SubElement(components, "component", {"type": c.component_type, "bom-ref": bom_ref})
            c_name = ET.SubElement(comp_elem, "name")
            c_name.text = c.name
            if c.version is not None:
                c_ver = ET.SubElement(comp_elem, "version")
                c_ver.text = c.version
            c_scope = ET.SubElement(comp_elem, "scope")
            c_scope.text = c.scope
            if c.hashes:
                hashes_elem = ET.SubElement(comp_elem, "hashes")
                for alg, h_val in c.hashes.items():
                    h_elem = ET.SubElement(hashes_elem, "hash", {"alg": alg})
                    h_elem.text = h_val

            if c.licenses:
                licenses_elem = ET.SubElement(comp_elem, "licenses")
                for lic in c.licenses:
                    license_elem = ET.SubElement(licenses_elem, "license")
                    id_elem = ET.SubElement(license_elem, "id")
                    id_elem.text = lic

            # CycloneDX 1.5 component sequence places purl after hashes,
            # licenses, copyright and cpe. Keep XML output in schema order.
            c_purl = ET.SubElement(comp_elem, "purl")
            c_purl.text = c.purl

        if self.vulnerabilities:
            vulns_elem = ET.SubElement(root, "vulnerabilities")
            for v in self.vulnerabilities:
                component_index = next((i for i, c in enumerate(self.components) if c.purl == v["purl"]), None)
                if component_index is None:
                    continue
                v_elem = ET.SubElement(vulns_elem, "vulnerability")
                id_elem = ET.SubElement(v_elem, "id")
                id_elem.text = v["id"]
                ratings = ET.SubElement(v_elem, "ratings")
                rating = ET.SubElement(ratings, "rating")
                sev = ET.SubElement(rating, "severity")
                sev.text = v["severity"].lower()
                if v.get("cwe_ids"):
                    cwes_elem = ET.SubElement(v_elem, "cwes")
                    for cwe in v["cwe_ids"]:
                        digits = re.sub(r"[^\d]", "", cwe)
                        if digits:
                            ET.SubElement(cwes_elem, "cwe").text = digits
                if v.get("description"):
                    desc_elem = ET.SubElement(v_elem, "description")
                    desc_elem.text = v["description"]
                affects = ET.SubElement(v_elem, "affects")
                target = ET.SubElement(affects, "target")
                ref = ET.SubElement(target, "ref")
                ref.text = component_refs[component_index]

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

