"""Offline normative-schema checks for synthetic SBOM generator outputs."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, ValidationError
from lxml import etree
from referencing import Registry, Resource

from mobileag.analysis.sbom_generator import MobileSbomGenerator

SCHEMAS = Path(__file__).parent / "fixtures" / "sbom_schemas"
PINNED = {
    "cyclonedx-1.5/bom-1.5.schema.json": "2d956c1d05c092695457a91f3b5c57c749793c013ec224a0935807cfc8ae4480",
    "cyclonedx-1.5/bom-1.5.xsd": "0b1678d5ae893bd1736843f3c050a26910de9a8107acb337f628900728de6a53",
    "cyclonedx-1.5/spdx.schema.json": "4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359",
    "cyclonedx-1.5/jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    "cyclonedx-1.5/spdx.xsd": "cce0672755fac029279801a0244112345e493ec6e6e1b91f496c286753c11ef4",
    "spdx-2.3.schema.json": "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b",
}


def _verify_schema_pins() -> None:
    for relative, expected in PINNED.items():
        actual = hashlib.sha256((SCHEMAS / relative).read_bytes()).hexdigest()
        assert actual == expected, f"Schema fixture digest mismatch: {relative}"


def _synthetic_generator() -> MobileSbomGenerator:
    generator = MobileSbomGenerator("Synthetic Audit App", "1.2.3")
    purl = "pkg:maven/org.example/example@1.0.0"
    generator.add_component("example", "1.0.0", purl,
                            hashes={"SHA-256": "a" * 64}, licenses=["MIT"])
    generator.add_component("libsample.so", None, "pkg:generic/lib/arm64-v8a/libsample.so",
                            hashes={"SHA-256": "b" * 64})
    generator.add_vulnerability("CVE-2024-0001", purl, "Synthetic fixture advisory", "high", ["CWE-79"])
    return generator


def _cyclonedx_xml_schema() -> etree.XMLSchema:
    class PinnedImportResolver(etree.Resolver):
        def resolve(self, url, public_id, context):
            if url == "http://cyclonedx.org/schema/spdx":
                return self.resolve_filename(str(SCHEMAS / "cyclonedx-1.5" / "spdx.xsd"), context)
            return None

    parser = etree.XMLParser(no_network=True, resolve_entities=False)
    parser.resolvers.add(PinnedImportResolver())
    document = etree.parse(str(SCHEMAS / "cyclonedx-1.5" / "bom-1.5.xsd"), parser)
    return etree.XMLSchema(document)


def test_generated_json_sboms_validate_against_pinned_normative_schemas():
    _verify_schema_pins()
    generator = _synthetic_generator()
    schemas = {
        "cyclonedx": json.loads((SCHEMAS / "cyclonedx-1.5" / "bom-1.5.schema.json").read_text()),
        "spdx": json.loads((SCHEMAS / "spdx-2.3.schema.json").read_text()),
    }
    external_resources = Registry()
    for filename in ("spdx.schema.json", "jsf-0.82.schema.json"):
        resource_schema = json.loads((SCHEMAS / "cyclonedx-1.5" / filename).read_text())
        external_resources = external_resources.with_resource(
            resource_schema["$id"], Resource.from_contents(resource_schema))
    documents = {
        "cyclonedx": generator.generate_cyclonedx_json(),
        "spdx": generator.generate_spdx_json(),
    }
    for name, schema in schemas.items():
        Draft7Validator.check_schema(schema)
        validator = Draft7Validator(schema, registry=external_resources if name == "cyclonedx" else Registry())
        validator.validate(documents[name])

    invalid_cyclonedx = copy.deepcopy(documents["cyclonedx"])
    invalid_cyclonedx.pop("bomFormat")
    with pytest.raises(ValidationError):
        Draft7Validator(schemas["cyclonedx"], registry=external_resources).validate(invalid_cyclonedx)

    invalid_spdx = copy.deepcopy(documents["spdx"])
    invalid_spdx.pop("spdxVersion")
    with pytest.raises(ValidationError):
        Draft7Validator(schemas["spdx"]).validate(invalid_spdx)


def test_generated_cyclonedx_xml_validates_offline_against_pinned_xsd():
    _verify_schema_pins()
    schema = _cyclonedx_xml_schema()
    document = etree.fromstring(_synthetic_generator().generate_cyclonedx_xml().encode("utf-8"))
    assert schema.validate(document), str(schema.error_log)

    invalid_document = copy.deepcopy(document)
    invalid_document.tag = "{http://cyclonedx.org/schema/bom/1.5}notABom"
    assert not schema.validate(invalid_document)


@pytest.mark.parametrize("method, suffix", [
    ("save_cyclonedx", ".json"),
    ("save_cyclonedx_xml", ".xml"),
    ("save_spdx", ".spdx.json"),
])
def test_sbom_writers_atomically_replace_symlinks_with_private_files(tmp_path, method, suffix):
    output = tmp_path / f"artifact{suffix}"
    victim = tmp_path / "victim.txt"
    victim.write_text("unchanged")
    output.symlink_to(victim)

    saved = getattr(_synthetic_generator(), method)(output)

    assert saved == output
    assert victim.read_text() == "unchanged"
    assert not output.is_symlink()
    assert output.stat().st_size > 0
    assert os.stat(output).st_mode & 0o077 == 0


@pytest.mark.parametrize("method", ["save_cyclonedx", "save_cyclonedx_xml", "save_spdx"])
def test_sbom_writers_enforce_size_cap_before_destination_write(tmp_path, monkeypatch, method):
    import mobileag.analysis.sbom_generator as sbom_generator

    output = tmp_path / "oversized.sbom"
    monkeypatch.setattr(sbom_generator, "_MAX_SBOM_OUTPUT_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        getattr(_synthetic_generator(), method)(output)
    assert not output.exists()
