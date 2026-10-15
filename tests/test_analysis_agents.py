import tempfile
import shutil
import subprocess
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
        # Manifest attributes/components are static review leads, not impact proof.
        assert f.severity == Severity.INFO
        assert f.cvss_score == 0.0
    backup = next(f for f in findings if f.title == "Application Data Backup Allowed")
    assert backup.metadata["check_id"] == "manifest_allow_backup"
    assert backup.metadata["proof_state"] == "not_proven"


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
            assert f.severity == Severity.INFO
            assert f.cvss_score == 0.0


@pytest.mark.asyncio
async def test_secret_scanner_includes_packaged_xml_and_javascript_resources(mock_router):
    scanner = SecretScanner(mock_router)
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "strings.xml").write_text(
            '<resources><string name="key">AKIA1234567890ABCDEF</string></resources>',
            encoding="utf-8")
        (root / "config.js").write_text(
            'const apiKey = "AIzaSyD-1234567890123456789012345678901";',
            encoding="utf-8")

        findings = await scanner.scan(tmpdir)

    paths = {finding.file_path for finding in findings if finding.cwe_id == "CWE-798"}
    assert paths == {"strings.xml", "config.js"}
    assert all("AKIA1234567890ABCDEF" not in finding.code_snippet for finding in findings)


@pytest.mark.asyncio
async def test_entropy_secret_lead_is_redacted_and_low_entropy_control_is_ignored(mock_router):
    scanner = SecretScanner(mock_router, entropy_threshold=4.5)
    with tempfile.TemporaryDirectory() as tmpdir:
        source = Path(tmpdir, "settings.properties")
        source.write_text(
            'authToken="aB3dE5gH7jK9mN2pQ4rS6tV8xY1zC0wL"\n'
            'constant="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n', encoding="utf-8")

        findings = await scanner.scan(tmpdir)

    entropy = [finding for finding in findings if "entropy heuristic" in finding.detection_method]
    assert len(entropy) == 1
    assert entropy[0].cwe_id == "CWE-Unknown"
    assert "aB3dE5gH7jK9mN2pQ4rS6tV8xY1zC0wL" not in entropy[0].code_snippet
    assert scanner.coverage["entropy_candidate_count"] == 1


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
        file_access = next(f for f in findings if "AllowFileAccess" in f.title)
        assert file_access.cwe_id == "CWE-669"
        assert file_access.severity.value == "INFO"
        assert file_access.cvss_score == 0 and file_access.status.value == "UNVERIFIED"


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
        assert endpoints[0]["requires_auth"] is None
        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-Unknown"
        assert findings[0].severity == Severity.INFO
        assert findings[0].cvss_score == 0.0


@pytest.mark.asyncio
async def test_api_mapper_requires_environment_label_in_hostname(mock_router):
    mapper = APIMapper(mock_router)
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "Urls.java").write_text(
            'String a = "https://developer.example.com/api";\n'
            'String b = "https://dev-api.example.com/v1";\n', encoding="utf-8")
        _endpoints, findings = await mapper.map_apis(tmpdir)

    staging = [finding for finding in findings if "Staging/Dev" in finding.title]
    assert len(staging) == 1
    assert "dev-api.example.com" in staging[0].title


@pytest.mark.asyncio
async def test_api_mapper_finds_route_literals_in_smali_as_unverified_inventory(mock_router):
    mapper = APIMapper(mock_router)
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "Api.smali").write_text(
            '.class public Lx/Api;\n const-string v0, "/api/v2/profile"\n',
            encoding="utf-8",
        )
        endpoints, findings = await mapper.map_apis(tmpdir)
    ep = next(e for e in endpoints if e["url"] == "/api/v2/profile")
    assert ep["method"] == "UNKNOWN"
    assert ep["evidence_type"] == "route_literal"
    assert ep["requires_auth"] is None
    assert mapper.coverage["runtime_status"] == "not_tested"
    assert mapper.coverage["proof_status"] == "not_proven"


@pytest.mark.asyncio
async def test_bounded_secret_scan_caps_candidates_and_reports_partial_coverage(mock_router):
    scanner = SecretScanner(mock_router)
    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "many.java").write_text(
            ('String key = "AKIA1234567890ABCDEF";\n' * 1001), encoding="utf-8"
        )
        findings = await scanner.scan(tmpdir)
    assert len(findings) == 1000
    assert scanner.coverage["limits_reached"] is True
    assert scanner.coverage["static_status"] == "partial"
    assert scanner.coverage["proof_status"] == "not_proven"


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


def test_dependency_inventory_understands_literal_kotlin_and_groovy_notation(tmp_path, mock_router):
    (tmp_path / "build.gradle").write_text(
        'dependencies { implementation("org.example:core:1.2.3") }\n'
        'implementation("org.example:dynamic:$version")\n'
        "implementation group: 'org.example', name: 'legacy', version: '2.0.0'\n")
    scanner = DependencyScanner(mock_router)
    results = scanner._sync_find_dependencies(tmp_path)
    assert {(g, a, v) for g, a, v, _path in results} == {
        ('org.example', 'core', '1.2.3'), ('org.example', 'legacy', '2.0.0')}
    assert scanner.coverage['unresolved_dependency_declarations'] == 1
    assert scanner.coverage['static_status'] == 'partial'


def test_dependency_inventory_ignores_gradle_line_and_block_comments(tmp_path, mock_router):
    (tmp_path / "build.gradle").write_text('''// implementation "attacker:commented:9.9.9"
/*
api("also:commented:8.8.8")
*/
def url = "https://example.invalid/not-a-comment"
dependencies {
  implementation "org.example:real-library:1.2.3"
}
''', encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    dependencies = scanner._sync_find_dependencies(tmp_path)

    assert {(group, artifact, version) for group, artifact, version, _ in dependencies} == {
        ("org.example", "real-library", "1.2.3"),
    }
    assert scanner.coverage["unresolved_dependency_declarations"] == 0


def test_dependency_inventory_reads_gradle_lockfiles_and_literal_version_catalogs(tmp_path, mock_router):
    (tmp_path / "gradle.lockfile").write_text(
        "org.example:locked-lib:3.2.1=runtimeClasspath\n"
        "empty=\n"
    )
    (tmp_path / "libs.versions.toml").write_text(
        '[versions]\n'
        'catalog-api = "2.4.0"\n'
        '[libraries]\n'
        'catalog-api = { module = "org.example:catalog-api", version.ref = "catalog-api" }\n'
        'strict-lib = { group = "org.example", name = "strict-lib", version = { strictly = "1.7.5" } }\n'
        'dynamic-lib = { module = "org.example:dynamic-lib", version = "+" }\n'
    )
    (tmp_path / "build.gradle.kts").write_text('''dependencies {
    implementation(libs.catalog.api)
    api(libs.strict.lib)
    implementation(platform(libs.dynamic.lib))
}
''', encoding="utf-8")
    pom = tmp_path / "META-INF" / "maven" / "org.example" / "pom.properties"
    pom.parent.mkdir(parents=True)
    pom.write_text("groupId=org.example\nartifactId=embedded\nversion=5.0.0\n")

    scanner = DependencyScanner(mock_router)
    dependencies = scanner._sync_find_dependencies(tmp_path)

    assert {(group, artifact, version) for group, artifact, version, _ in dependencies} == {
        ("org.example", "locked-lib", "3.2.1"),
        ("org.example", "catalog-api", "2.4.0"),
        ("org.example", "strict-lib", "1.7.5"),
        ("org.example", "embedded", "5.0.0"),
    }
    assert scanner.coverage["unresolved_dependency_declarations"] == 1
    assert scanner.coverage["dependency_metadata_parse_failures"] == 0
    assert scanner.coverage["dependencies_by_source"] == {
        "gradle_build": 0, "pom_properties": 1,
        "gradle_lockfile": 1, "version_catalog": 2,
        "npm_package_lock": 0, "yarn_lock_v1": 0, "pom_xml": 0,
    }


def test_unused_version_catalog_alias_is_not_reported_as_resolved_dependency(tmp_path, mock_router):
    (tmp_path / "libs.versions.toml").write_text('''[libraries]
unused-lib = { module = "org.example:unused-lib", version = "1.2.3" }
''', encoding="utf-8")
    (tmp_path / "build.gradle.kts").write_text('''// implementation(libs.unused.lib)
val note = "implementation(libs.unused.lib)"
''', encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    assert scanner._sync_find_dependencies(tmp_path) == []
    assert scanner.coverage["dependencies_by_source"]["version_catalog"] == 0
    assert scanner.coverage["unresolved_dependency_declarations"] == 0
    assert scanner.coverage["static_status"] == "analyzed_heuristically"


def test_bounded_maven_pom_xml_inventory_uses_literal_direct_dependencies_only(tmp_path, mock_router):
    (tmp_path / "pom.xml").write_text('''<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency><groupId>org.example</groupId><artifactId>api</artifactId><version>1.2.3</version></dependency>
    <dependency><groupId>org.example</groupId><artifactId>dynamic</artifactId><version>${revision}</version></dependency>
  </dependencies>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.example</groupId><artifactId>managed-only</artifactId><version>3.0.0</version></dependency>
  </dependencies></dependencyManagement>
  <profiles><profile><dependencies>
    <dependency><groupId>org.example</groupId><artifactId>conditional</artifactId><version>4.0.0</version></dependency>
  </dependencies></profile></profiles>
</project>''', encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    dependencies = scanner._sync_find_dependencies(tmp_path)

    assert {(group, artifact, version) for group, artifact, version, _ in dependencies} == {
        ("org.example", "api", "1.2.3"),
    }
    assert scanner.coverage["dependencies_by_source"]["pom_xml"] == 1
    assert scanner.coverage["unresolved_dependency_declarations"] == 3
    assert scanner.coverage["static_status"] == "partial"


def test_bounded_maven_pom_resolves_root_local_literal_properties_only(tmp_path, mock_router):
    (tmp_path / "pom.xml").write_text('''<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><release.version>2.4.1</release.version><cycle.a>${cycle.b}</cycle.a>
    <cycle.b>${cycle.a}</cycle.b></properties>
  <dependencies>
    <dependency><groupId>org.example</groupId><artifactId>resolved</artifactId><version>${release.version}</version></dependency>
    <dependency><groupId>org.example</groupId><artifactId>cycle</artifactId><version>${cycle.a}</version></dependency>
    <dependency><groupId>org.example</groupId><artifactId>parent</artifactId><version>${project.version}</version></dependency>
  </dependencies>
</project>''', encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    dependencies = scanner._sync_find_dependencies(tmp_path)

    assert {(group, artifact, version) for group, artifact, version, _ in dependencies} == {
        ("org.example", "resolved", "2.4.1"),
    }
    assert scanner.coverage["unresolved_dependency_declarations"] == 2
    assert scanner.coverage["static_status"] == "partial"


def test_maven_pom_rejects_doctype_and_external_entities(tmp_path, mock_router):
    (tmp_path / "pom.xml").write_text('''<!DOCTYPE project [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<project><dependencies><dependency><groupId>org.example</groupId>
<artifactId>api</artifactId><version>&x;</version></dependency></dependencies></project>''', encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    assert scanner._sync_find_dependencies(tmp_path) == []
    assert scanner.coverage["dependency_metadata_parse_failures"] == 1
    assert scanner.coverage["static_status"] == "partial"


def test_ambiguous_catalog_accessors_are_withheld_and_counted_partial(tmp_path, mock_router):
    (tmp_path / "libs.versions.toml").write_text('''[libraries]
foo-bar = { module = "org.example:first", version = "1.2.3" }
"foo.bar" = { module = "org.example:second", version = "2.3.4" }
''', encoding="utf-8")
    (tmp_path / "build.gradle").write_text('implementation(libs.foo.bar)\n', encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    assert scanner._sync_find_dependencies(tmp_path) == []
    assert scanner.coverage["unresolved_dependency_declarations"] == 1
    assert scanner.coverage["static_status"] == "partial"


def test_invalid_gradle_version_catalog_is_explicitly_partial(tmp_path, mock_router):
    (tmp_path / "libs.versions.toml").write_text('[libraries\nmalformed')
    scanner = DependencyScanner(mock_router)

    assert scanner._sync_find_dependencies(tmp_path) == []
    assert scanner.coverage["dependency_metadata_parse_failures"] == 1
    assert scanner.coverage["static_status"] == "partial"


def test_npm_package_lock_v3_inventory_is_bounded_and_partial_on_dynamic_entries(tmp_path, mock_router):
    import json
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "synthetic-rn", "lockfileVersion": 3,
        "packages": {
            "": {"name": "synthetic-rn", "version": "1.0.0"},
            "node_modules/react-native": {"version": "0.76.0"},
            "node_modules/@scope/synthetic": {"version": "2.1.0-beta.1"},
            "node_modules/workspace-lib": {"version": "file:../workspace", "link": True},
        },
    }), encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    dependencies = scanner._sync_find_dependencies(tmp_path)

    assert {(group, artifact, version) for group, artifact, version, _ in dependencies} == {
        ("npm", "react-native", "0.76.0"),
        ("npm", "@scope/synthetic", "2.1.0-beta.1"),
    }
    assert scanner.coverage["dependencies_by_source"]["npm_package_lock"] == 2
    assert scanner.coverage["unresolved_dependency_declarations"] == 1
    assert scanner.coverage["static_status"] == "partial"


def test_npm_package_lock_v1_uses_bounded_iterative_nested_dependency_walk(tmp_path, mock_router):
    import json
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "react-native": {"version": "0.64.0", "dependencies": {
                "@scope/native-addon": {"version": "1.2.3"},
                "git-dep": {"version": "git+https://example.invalid/repo", "dependencies": {}},
            }},
        },
    }), encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    dependencies = scanner._sync_find_dependencies(tmp_path)

    assert {(group, artifact, version) for group, artifact, version, _ in dependencies} == {
        ("npm", "react-native", "0.64.0"),
        ("npm", "@scope/native-addon", "1.2.3"),
    }
    assert scanner.coverage["dependencies_by_source"]["npm_package_lock"] == 2
    assert scanner.coverage["unresolved_dependency_declarations"] == 1
    assert scanner.coverage["static_status"] == "partial"


def test_malformed_npm_lockfile_version_is_partial_not_a_scanner_crash(tmp_path, mock_router):
    import json
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": {"unexpected": "object"}, "packages": {},
    }), encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    assert scanner._sync_find_dependencies(tmp_path) == []
    assert scanner.coverage["unresolved_dependency_declarations"] == 1
    assert scanner.coverage["static_status"] == "partial"


def test_yarn_v1_lockfile_inventories_scoped_selectors_and_marks_dynamic_entries_partial(tmp_path, mock_router):
    (tmp_path / "yarn.lock").write_text('''# yarn lockfile v1
"react-native@^0.76.0":
  version "0.76.0"
  resolved "https://registry.npmjs.org/react-native/-/react-native-0.76.0.tgz"
"@scope/native-addon@^2.0.0", "@scope/native-addon@~2.0.0":
  version "2.1.0"
legacy-git@^1.0.0:
  version "git+https://example.invalid/repo"
''', encoding="utf-8")
    scanner = DependencyScanner(mock_router)

    dependencies = scanner._sync_find_dependencies(tmp_path)

    assert {(group, artifact, version) for group, artifact, version, _ in dependencies} == {
        ("npm", "react-native", "0.76.0"),
        ("npm", "@scope/native-addon", "2.1.0"),
    }
    assert scanner.coverage["dependencies_by_source"]["yarn_lock_v1"] == 2
    assert scanner.coverage["unresolved_dependency_declarations"] == 1
    assert scanner.coverage["static_status"] == "partial"


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
,
            {
                "name": "com.test.app.ExportedService",
                "type": "service",
                "exported": True,
                "permission": "com.test.app.permission.READ_INTERNAL_DATA",
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
        assert analyzer.coverage["static_status"] == "analyzed_heuristically"
        assert analyzer.coverage["proof_status"] == "not_proven"
        cwes = {f.cwe_id for f in findings}
        assert "CWE-120" in cwes  # strcpy
        assert "CWE-78" in cwes   # system
        assert "CWE-489" in cwes  # ptrace
        assert analyzer.coverage["native_inventory"]["elf_parse_failures"] == 1


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc required for synthetic ELF fixture")
async def test_native_analyzer_distinguishes_elf_import_from_execution(mock_router):
    """A compiler-built ELF import is inventory evidence, never call proof."""
    analyzer = NativeAnalyzer(mock_router)
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = root / "fixture.c"
        library = root / "libfixture.so"
        source.write_text(
            "#include <string.h>\n"
            "void fixture_copy(char *dst, const char *src) { strcpy(dst, src); }\n"
        )
        subprocess.run(
            [shutil.which("gcc"), "-shared", "-fPIC", "-fno-builtin",
             "-Wl,-soname,libfixture.so", "-Wl,--build-id=sha1",
             "-o", str(library), str(source)],
            check=True, capture_output=True, text=True, timeout=30,
        )

        findings = await analyzer.analyze(str(root))

    strcpy_findings = [finding for finding in findings if "strcpy" in finding.title]
    assert len(strcpy_findings) == 1
    finding = strcpy_findings[0]
    assert finding.metadata["analysis_kind"] == "elf_dynamic_symbol_import"
    assert finding.metadata["elf_machine"]
    assert finding.metadata["elf_soname"] == "libfixture.so"
    assert len(finding.metadata["elf_build_id"]) == 40
    assert "libc.so.6" in finding.metadata["needed_libraries"]
    assert finding.metadata["function_call_observed"] is False
    assert finding.metadata["proof_state"] == "not_proven"
    assert finding.status == FindingStatus.UNVERIFIED
    assert finding.severity == Severity.INFO
    assert "does not establish a call site" in finding.description
    assert analyzer.coverage["native_inventory"]["elf_files_parsed"] == 1
    assert analyzer.coverage["native_inventory"]["elf_dynamic_functions_seen"] > 0
    record = analyzer.coverage["native_inventory"]["libraries"][0]
    assert record["sha256"] and record["soname"] == "libfixture.so"
    assert record["build_id"] == finding.metadata["elf_build_id"]
    assert record["relative_path"] == "libfixture.so"
    assert "strcpy" in record["undefined_function_import_names"]
    assert len(record["undefined_function_import_names"]) <= 64
    assert record["undefined_function_import_names_truncated"] is False


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


@pytest.mark.asyncio
async def test_manifest_findings_require_effective_component_context(mock_router):
    auditor = ManifestAuditor(mock_router)
    weak_permission = "org.example.permission.ACCESS"
    unused = {
        "application": {},
        "components": [{"name": "org.example.Provider", "type": "provider", "exported": True,
                        "permission": "org.example.permission.SIGNATURE",
                        "meta_data": {"android.support.FILE_PROVIDER_PATHS": "@xml/paths"}}],
        "declared_permissions": [{"name": weak_permission, "protectionLevel": "normal"}],
    }
    findings = await auditor.audit(unused, "org.example")
    assert not any(f.cwe_id in {"CWE-22", "CWE-276"} for f in findings)

    used_weak = {
        "application": {},
        "components": [{"name": "org.example.ExportedService", "type": "service", "exported": True,
                        "permission": weak_permission}],
        "declared_permissions": [{"name": weak_permission, "protectionLevel": "normal"}],
    }
    findings = await auditor.audit(used_weak, "org.example")
    weak = [f for f in findings if f.cwe_id == "CWE-276"]
    assert len(weak) == 1 and weak[0].status == FindingStatus.UNVERIFIED
