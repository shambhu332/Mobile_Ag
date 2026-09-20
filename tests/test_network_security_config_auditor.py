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
