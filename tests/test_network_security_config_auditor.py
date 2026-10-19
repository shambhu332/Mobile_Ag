import tempfile
from pathlib import Path
from datetime import datetime, timedelta
import pytest

from mobileag.analysis.network_security_config_auditor import NetworkSecurityConfigAuditor


@pytest.fixture
def auditor():
    return NetworkSecurityConfigAuditor()


def test_user_trust_anchors_and_cleartext(auditor):
    """Test auditing of user trust anchors and domain-level cleartext traffic."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">api.insecure.com</domain>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>"""

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".xml") as f:
        f.write(xml_content)
        temp_path = f.name

    try:
        findings = auditor.audit_file(temp_path)
        issue_ids = [f["issue_id"] for f in findings]

        # 1. Global cleartext permitted
        assert "NSC-GLOBAL-CLEARTEXT-ALLOWED" in issue_ids
        # 2. Domain cleartext permitted
        assert "NSC-DOMAIN-CLEARTEXT-ALLOWED" in issue_ids
        # 3. User trust anchors (found in base-config and domain-config)
        user_anchor_findings = [f for f in findings if f["issue_id"] == "NSC-USER-TRUST-ANCHOR"]
        assert len(user_anchor_findings) == 2

        # Verify standard dictionary keys
        for f in findings:
            assert "issue_id" in f
            assert "cwe" in f
            assert "severity" in f
            assert "title" in f
            assert "description" in f
            assert "file_path" in f
            assert "remediation" in f
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_certificate_pinning_expiration(auditor):
    """Test auditing expired and valid certificate pinning definitions."""
    past_date = (datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d")
    future_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d")

    xml_content = f"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="{past_date}">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
    </domain-config>
    <domain-config>
        <domain includeSubdomains="true">secure.example.com</domain>
        <pin-set expiration="{future_date}">
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>"""

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".xml") as f:
        f.write(xml_content)
        temp_path = f.name

    try:
        findings = auditor.audit_file(temp_path)
        issue_ids = [f["issue_id"] for f in findings]

        assert "NSC-PINNING-EXPIRED" in issue_ids
        expired_finding = next(f for f in findings if f["issue_id"] == "NSC-PINNING-EXPIRED")
        assert past_date in expired_finding["description"]
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_locate_config_path_from_manifest(auditor):
    """Test resolution of network security configuration from AndroidManifest."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        res_xml = root / "res" / "xml"
        res_xml.mkdir(parents=True, exist_ok=True)
        config_file = res_xml / "my_custom_network_config.xml"
        config_file.write_text("<network-security-config></network-security-config>")

        manifest_file = root / "AndroidManifest.xml"
        manifest_file.write_text("""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
    <application android:networkSecurityConfig="@xml/my_custom_network_config">
    </application>
</manifest>""")

        located = auditor.locate_config_path(str(root))
        assert located is not None
        assert located.name == "my_custom_network_config.xml"


@pytest.mark.asyncio
async def test_manifest_resource_name_cannot_escape_extraction_root(auditor, tmp_path):
    root = tmp_path / "decoded"
    (root / "res" / "xml").mkdir(parents=True)
    outside_config = root / "res" / "outside.xml"
    outside_config.write_text(
        '<network-security-config><base-config cleartextTrafficPermitted="true" />'
        '</network-security-config>', encoding="utf-8")
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application android:networkSecurityConfig="@xml/../outside" />'
        '</manifest>', encoding="utf-8")

    findings = await auditor.audit_directory_async(root)

    assert findings == []
    assert auditor.coverage["static_status"] == "partial"
    assert "invalid_network_security_config_resource_name" in auditor.coverage["limitations"]


@pytest.mark.asyncio
async def test_direct_network_config_candidates_reject_symlinked_files(auditor, tmp_path):
    root = tmp_path / "decoded"
    xml_dir = root / "res" / "xml"
    xml_dir.mkdir(parents=True)
    outside = tmp_path / "outside.xml"
    outside.write_text(
        '<network-security-config><base-config cleartextTrafficPermitted="true" />'
        '</network-security-config>', encoding="utf-8")
    (xml_dir / "network_security_config.xml").symlink_to(outside)

    findings = await auditor.audit_directory_async(root)

    assert findings == []
    assert auditor.coverage["static_status"] == "partial"
    assert "network_security_config_path_outside_root_or_symlinked" in auditor.coverage["limitations"]


def test_missing_custom_resource_does_not_fall_back_to_unreferenced_default(auditor, tmp_path):
    root = tmp_path / "decoded"
    xml_dir = root / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "network_security_config.xml").write_text(
        "<network-security-config />", encoding="utf-8")
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application android:networkSecurityConfig="@xml/custom_tls" />'
        '</manifest>', encoding="utf-8")

    assert auditor.locate_config_path(str(root)) is None
    assert auditor.coverage["static_status"] == "partial"
    assert "referenced_network_security_config_not_found" in auditor.coverage["limitations"]


def test_explicit_manifest_path_must_remain_inside_extraction_root(auditor, tmp_path):
    root = tmp_path / "decoded"
    xml_dir = root / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "network_security_config.xml").write_text(
        "<network-security-config />", encoding="utf-8")
    outside_manifest = tmp_path / "AndroidManifest.xml"
    outside_manifest.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application android:networkSecurityConfig="@xml/custom_tls" />'
        '</manifest>', encoding="utf-8")

    assert auditor.locate_config_path(str(root), str(outside_manifest)) is None
    assert auditor.coverage["static_status"] == "partial"
    assert "manifest_path_outside_root_or_symlinked" in auditor.coverage["limitations"]


def test_network_security_config_rejects_dtd_and_entity_declarations(auditor, tmp_path):
    path = tmp_path / "network_security_config.xml"
    path.write_text(
        '<!DOCTYPE network-security-config [<!ENTITY domain "synthetic.example">]>'
        '<network-security-config><domain-config cleartextTrafficPermitted="true">'
        '<domain>&domain;</domain></domain-config></network-security-config>',
        encoding="utf-8",
    )

    assert auditor.audit_file(path) == []
    assert auditor.coverage["static_status"] == "partial"
    assert "configuration file could not be safely read within configured limits" in auditor.coverage["limitations"]


def test_inspect_config_structured_model(auditor, tmp_path):
    """Test inspect_config returns structured trust tree, cleartext policies, and pin-sets."""
    root = tmp_path / "decoded"
    xml_dir = root / "res" / "xml"
    xml_dir.mkdir(parents=True)
    config_file = xml_dir / "network_security_config.xml"
    config_file.write_text("""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.target.com</domain>
        <pin-set expiration="2030-01-01">
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
        </pin-set>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>""", encoding="utf-8")

    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.target.test">'
        '<application android:networkSecurityConfig="@xml/network_security_config" />'
        '</manifest>', encoding="utf-8")

    model = auditor.inspect_config(root)

    assert model["has_custom_config"] is True
    assert model["config_file"] == "network_security_config.xml"
    assert model["risk_posture"] in ("CRITICAL", "HIGH")
    assert model["base_config"]["cleartext_permitted"] is True
    assert "user" in model["base_config"]["trust_anchors"]
    assert len(model["domain_configs"]) == 1
    assert model["domain_configs"][0]["domains"] == ["api.target.com"]
    assert len(model["pin_sets"]) == 1
    assert model["pin_sets"][0]["value"] == "7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y="
    assert model["debug_overrides"]["present"] is True
    assert model["debug_overrides"]["trust_user_certs"] is True
    assert len(model["findings"]) > 0

