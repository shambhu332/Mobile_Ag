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
