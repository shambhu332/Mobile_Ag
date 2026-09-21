import tempfile
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, MagicMock

from mobileag.analysis.manifest_auditor import ManifestAuditor
from mobileag.analysis.secret_scanner import SecretScanner
from mobileag.analysis.code_reviewer import CodeReviewer
from mobileag.analysis.api_mapper import APIMapper
from mobileag.analysis.native_analyzer import NativeAnalyzer
from mobileag.analysis.dependency_scanner import DependencyScanner
from mobileag.analysis.network_security_config_auditor import NetworkSecurityConfigAuditor
from mobileag.llm.router import LLMRouter
from mobileag.llm.providers.base import LLMResponse
from mobileag.reporting.finding import Finding, Severity, FindingStatus


@pytest.fixture
def mock_router():
    """Mock LLMRouter that returns success responses."""
    router = MagicMock(spec=LLMRouter)
    router.route = AsyncMock(
        return_value=LLMResponse(
            content="REAL", model="mock-model", provider="mock", success=True
        )
    )
    return router


@pytest.mark.asyncio
async def test_manifest_auditor(mock_router):
    """Verify ManifestAuditor creates valid Finding models without ValidationError."""
    auditor = ManifestAuditor(mock_router)
    manifest_data = {
        "package_name": "com.test.app",
        "application": {
            "allowBackup": True,
            "debuggable": True,
            "usesCleartextTraffic": True,
        },
        "components": [
            {"name": "com.test.app.MainActivity", "type": "activity", "exported": True, "permission": ""},
            {"name": "com.test.app.SafeService", "type": "service", "exported": False, "permission": ""},
        ],
    }

    findings = await auditor.audit(manifest_data, "com.test.app")
    assert len(findings) >= 4
    for f in findings:
        assert isinstance(f, Finding)
        assert f.status == FindingStatus.UNVERIFIED
        assert f.cwe_id.startswith("CWE-")
        assert f.cvss_score > 0.0


@pytest.mark.asyncio
async def test_secret_scanner(mock_router):
    """Verify SecretScanner scans files and creates valid Finding objects."""
    scanner = SecretScanner(mock_router)

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        java_file = root / "Config.java"
        java_file.write_text(
            'public class Config {\n'
            '    public static final String KEY = "AIzaSyD-1234567890123456789012345678901";\n'
            '    public static final String CIPHER = "AES/ECB/PKCS5Padding";\n'
            '}\n'
        )

        findings = await scanner.scan(tmpdir)
        assert len(findings) >= 2
        for f in findings:
            assert isinstance(f, Finding)
            assert f.detection_method == "SecretScanner"


@pytest.mark.asyncio
async def test_code_reviewer(mock_router):
    """Verify CodeReviewer detects patterns and builds valid Finding instances."""
    reviewer = CodeReviewer(mock_router)

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        java_file = root / "WebActivity.java"
        java_file.write_text(
            'public class WebActivity {\n'
            '    void setup(WebView webView) {\n'
            '        webView.getSettings().setAllowFileAccess(true);\n'
            '    }\n'
            '}\n'
        )

        findings = await reviewer.review(tmpdir, {})
        assert len(findings) >= 1
        assert any(f.cwe_id == "CWE-276" for f in findings)


@pytest.mark.asyncio
async def test_api_mapper(mock_router):
    """Verify APIMapper identifies endpoints and creates valid Finding instances."""
    mapper = APIMapper(mock_router)

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        java_file = root / "ApiClient.java"
        java_file.write_text(
            'public interface ApiClient {\n'
            '    @GET("/api/v1/admin/users")\n'
            '    Call<Users> getAdminUsers();\n'
            '}\n'
        )

        endpoints, findings = await mapper.map_apis(tmpdir)
        assert len(endpoints) == 1
        assert endpoints[0]["url"] == "/api/v1/admin/users"
        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-285"


@pytest.mark.asyncio
async def test_dependency_scanner(mock_router):
    """Verify DependencyScanner parses gradle files without crashing."""
    scanner = DependencyScanner(mock_router)

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        gradle_file = root / "build.gradle"
        gradle_file.write_text(
            'dependencies {\n'
            '    implementation "com.squareup.okhttp3:okhttp:3.12.0"\n'
            '}\n'
        )

        findings = await scanner.scan(tmpdir)
        assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_manifest_auditor_fileprovider_and_permissions(mock_router):
    auditor = ManifestAuditor(mock_router)
    manifest_data = {
        "package_name": "com.test.app",
        "application": {},
        "permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ],
        "declared_permissions": [
            {"name": "com.test.app.permission.READ_INTERNAL_DATA", "protectionLevel": "normal"},
        ],
        "components": [
            {
                "name": "androidx.core.content.FileProvider",
                "type": "provider",
                "exported": True,
                "meta_data": {"android.support.FILE_PROVIDER_PATHS": "@xml/file_paths"},
            }
        ],
    }

    findings = await auditor.audit(manifest_data, "com.test.app")
    cwes = {f.cwe_id for f in findings}

    assert "CWE-22" in cwes    # Exported FileProvider
    assert "CWE-276" in cwes   # Custom permission with normal protection level
    assert "CWE-1021" in cwes  # SYSTEM_ALERT_WINDOW
    assert "CWE-250" in cwes   # REQUEST_INSTALL_PACKAGES


@pytest.mark.asyncio
async def test_secret_scanner_extended_tokens(mock_router):
    scanner = SecretScanner(mock_router)

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        java_file = root / "Secrets.java"
        gh_tok = "ghp_" + ("a" * 36)
        slack_tok = "https://hooks." + "slack.com/services/T12345678/B12345678/" + ("a" * 24)
        stripe_tok = "sk_" + "live_" + ("a" * 24)
        java_file.write_text(
            'public class Secrets {\n'
            f'    public static final String GH_PAT = "{gh_tok}";\n'
            f'    public static final String SLACK = "{slack_tok}";\n'
            f'    public static final String STRIPE = "{stripe_tok}";\n'
            '    public static final String HASH = MessageDigest.getInstance("MD5");\n'
            '}\n'
        )

        findings = await scanner.scan(tmpdir)
        titles = " ".join(f.title for f in findings)

        assert "GitHub Access Token" in titles
        assert "Slack Webhook URL" in titles
        assert "Stripe Secret Key" in titles
        assert "Insecure MD5 Hash" in titles


@pytest.mark.asyncio
async def test_native_analyzer_direct_bytes(mock_router):
    analyzer = NativeAnalyzer(mock_router)

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        lib_dir = root / "lib" / "arm64-v8a"
        lib_dir.mkdir(parents=True)
        so_file = lib_dir / "libnative-crypto.so"
        so_file.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"strcpy\x00system\x00ptrace\x00")

        findings = await analyzer.analyze(str(root))
        assert len(findings) >= 3
        cwes = {f.cwe_id for f in findings}
        assert "CWE-120" in cwes  # strcpy
        assert "CWE-78" in cwes   # system
        assert "CWE-489" in cwes  # ptrace


@pytest.mark.asyncio
async def test_network_security_config_auditor_async():
    auditor = NetworkSecurityConfigAuditor()

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        xml_dir = root / "res" / "xml"
        xml_dir.mkdir(parents=True)
        config_file = xml_dir / "network_security_config.xml"
        config_file.write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<network-security-config>\n'
            '    <base-config cleartextTrafficPermitted="true">\n'
            '        <trust-anchors>\n'
            '            <certificates src="user" />\n'
            '        </trust-anchors>\n'
            '    </base-config>\n'
            '</network-security-config>'
        )

        findings = await auditor.audit_directory_async(root)
        assert len(findings) >= 2
        cwes = {f.cwe_id for f in findings}
        assert "CWE-319" in cwes  # Cleartext
        assert "CWE-295" in cwes  # User trust anchor

