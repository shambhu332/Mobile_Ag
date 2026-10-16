"""Test suite for accuracy improvements: Native JNI analyzer, path-sensitive sanitizers, and dynamic verification loop."""
import os
import tempfile
from unittest.mock import MagicMock, patch

from mobileag.analysis.native_jni_bridge import NativeJniAnalyzer
from mobileag.filters.sanitizer_check import SanitizerFilter
from mobileag.dast.verification_loop import DynamicVerificationLoop, DynamicVerificationOutcome
from mobileag.reporting.finding import Finding, FindingStatus, Severity


def test_native_jni_analyzer():
    with tempfile.TemporaryDirectory() as tmp_dir:
        arm_dir = os.path.join(tmp_dir, "lib", "arm64-v8a")
        os.makedirs(arm_dir)

        # Create mock ELF binary with JNI exported symbols and libc dangerous calls
        mock_elf = (
            b"\x7fELF"
            + b"\x00" * 40
            + b"Java_com_example_app_NativeSecurity_executeCommand"
            + b"\x00" * 20
            + b"system"
            + b"\x00" * 10
            + b"sqlite3_exec"
            + b"\x00" * 50
        )

        so_path = os.path.join(arm_dir, "libsecurity.so")
        with open(so_path, "wb") as f:
            f.write(mock_elf)

        analyzer = NativeJniAnalyzer()
        res = analyzer.audit_library(so_path)

        assert res.library_name == "libsecurity.so"
        assert res.architecture == "arm64-v8a"
        assert len(res.exported_jni_functions) == 1
        assert res.exported_jni_functions[0].java_class == "com.example.app.NativeSecurity"
        assert res.exported_jni_functions[0].java_method == "executeCommand"
        assert "system" in res.imported_dangerous_symbols
        assert "sqlite3_exec" in res.imported_dangerous_symbols
        assert len(res.findings) >= 2


def test_native_jni_analyzer_does_not_follow_direct_library_symlink(tmp_path):
    target = tmp_path / "synthetic.elf"
    target.write_bytes(b"\x7fELF" + b"\x00" * 40 + b"system\x00")
    link = tmp_path / "libcandidate.so"
    link.symlink_to(target)

    result = NativeJniAnalyzer().audit_library(link)

    assert result.imported_dangerous_symbols == []
    assert result.findings == []


def test_sanitizer_filter_path_sensitive_guards():
    mock_router = MagicMock()
    filter_engine = SanitizerFilter(router=mock_router)

    # 1. Path traversal with canonicalization guard
    safe_path_code = """
    File f = new File(baseDir, userInput);
    if (!f.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
        throw new SecurityException("Traversal attempt");
    }
    FileInputStream fis = new FileInputStream(f);
    """
    score, reason = filter_engine._pattern_check(safe_path_code, "CWE-22")
    assert score <= 0.2
    assert "Canonical path" in reason

    # 2. XSS / Open redirect with host allowlist guard
    safe_url_code = """
    Uri uri = Uri.parse(targetUrl);
    if (!uri.getHost().equals("trusted.bank.com")) {
        finish();
        return;
    }
    webView.loadUrl(targetUrl);
    """
    score, reason = filter_engine._pattern_check(safe_url_code, "CWE-79")
    assert score <= 0.2
    assert "Host/Origin allowlist guard" in reason

    # 3. SQL injection with parameterized arguments
    safe_sql_code = """
    String query = "SELECT * FROM users WHERE id = ?";
    String[] selectionArgs = new String[]{ userId };
    db.rawQuery(query, selectionArgs);
    """
    score, reason = filter_engine._pattern_check(safe_sql_code, "CWE-89")
    assert score <= 0.2
    assert "Parameterized SQL arguments" in reason


def test_dynamic_verification_loop():
    finding = Finding(
        id="DEEP_LINK_VULN_01",
        title="Deep Link Arbitrary Redirection",
        description="Deep link scheme accepts untrusted redirect param",
        severity=Severity.HIGH,
        status=FindingStatus.UNVERIFIED,
        cwe_id="CWE-601",
        file_path="RouterActivity.java",
        metadata={"uri_scheme": "bankapp://auth?redirect=https://attacker.com"},
    )

    verifier = DynamicVerificationLoop()

    # Case 1: Verification probe succeeds on device
    mock_success = MagicMock()
    mock_success.returncode = 0
    mock_success.stdout = "Starting: Intent { act=android.intent.action.VIEW dat=bankapp://auth... }\nStatus: ok\n"
    mock_success.stderr = ""

    with patch("subprocess.run", return_value=mock_success):
        outcome = verifier.verify_finding(finding, target_package="com.example.bank")
        assert outcome.verified is True
        assert outcome.verdict == "CONFIRMED"

        updated = verifier.apply_verification_to_finding(finding, outcome)
        assert updated.status == FindingStatus.CONFIRMED
        assert "dynamic_verification" in updated.metadata

    # Case 2: Verification probe blocked by Android OS permission gate
    mock_blocked = MagicMock()
    mock_blocked.returncode = 1
    mock_blocked.stdout = ""
    mock_blocked.stderr = "java.lang.SecurityException: Permission Denial: starting Intent not exported from uid 1000\n"

    finding2 = Finding(
        id="INTENT_RED_02",
        title="Intent Redirection",
        description="Unexported component call",
        severity=Severity.HIGH,
        status=FindingStatus.UNVERIFIED,
        cwe_id="CWE-926",
        file_path="VulnerableActivity.java",
    )

    with patch("subprocess.run", return_value=mock_blocked):
        outcome2 = verifier.verify_finding(finding2, target_package="com.example.bank")
        assert outcome2.verified is False
        assert outcome2.verdict == "BLOCKED_BY_OS"

        updated2 = verifier.apply_verification_to_finding(finding2, outcome2)
        assert len(updated2.false_positive_reasons) > 0
        assert "Android OS enforced permission denial" in updated2.false_positive_reasons[0]
