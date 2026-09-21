import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from mobileag.analysis.binary_protection_auditor import BinaryProtectionAuditor
from mobileag.analysis.react_native_scanner import ReactNativeScanner
from mobileag.analysis.code_reviewer import CodeReviewer


@pytest.fixture
def binary_auditor():
    return BinaryProtectionAuditor()


@pytest.fixture
def rn_scanner():
    return ReactNativeScanner()


@pytest.fixture
def code_reviewer():
    return CodeReviewer()


def test_binary_protection_auditor_flags(binary_auditor):
    """Test ELF hardening flag evaluation on mock binary headers."""
    # Create a mock ELFFile with missing canary, missing RELRO, and executable stack
    mock_elf = MagicMock()
    mock_elf.header = {"e_type": "ET_EXEC"}  # Not PIE

    # Symbol tables without canary
    mock_dynsym = MagicMock()
    mock_dynsym.iter_symbols.return_value = []
    mock_elf.get_section_by_name.side_effect = lambda name: mock_dynsym if name in [".dynsym", ".symtab"] else None

    # Stack segment marked executable (PF_X = 1)
    mock_stack_seg = {"p_type": "PT_GNU_STACK", "p_flags": 0x7}  # RWX
    mock_elf.iter_segments.return_value = [mock_stack_seg]

    with tempfile.NamedTemporaryFile(suffix=".so") as tmp_so:
        with patch("mobileag.analysis.binary_protection_auditor.ELFFile", return_value=mock_elf):
            findings = binary_auditor.audit_library_file(Path(tmp_so.name))
            issue_ids = [f["issue_id"] for f in findings]

            assert "BIN-NO-STACK-CANARY" in issue_ids
            assert "BIN-EXECUTABLE-STACK" in issue_ids
            assert "BIN-NO-RELRO" in issue_ids
            assert "BIN-NO-PIE" in issue_ids


def test_react_native_scanner_secrets_and_routes(rn_scanner):
    """Test React Native bundle scanner for secrets and endpoints."""
    stripe_key = "sk_" + "test_" + "1234567890abcdef12345678"
    bundle_content = f"""
    var config = {{
        awsKey: "AKIAIOSFODNN7EXAMPLE",
        googleKey: "AIzaSyD-1234567890123456789012345678901",
        stripe: "{stripe_key}",
        devUrl: "https://staging.internal.api.target.com/v1",
        localhost: "http://localhost:8081",
        adminPath: "/api/v1/admin/debug"
    }};
    """

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".bundle") as f:
        f.write(bundle_content)
        path = f.name

    try:
        findings = rn_scanner.scan_bundle_file(path)
        issue_ids = [f["issue_id"] for f in findings]

        assert "RN-SECRET-AWS-ACCESS-KEY" in issue_ids
        assert "RN-SECRET-GOOGLE-API-KEY" in issue_ids
        assert "RN-SECRET-STRIPE-SECRET-KEY" in issue_ids
        assert "RN-URL-INTERNAL-STAGING/DEV-URL" in issue_ids
        assert "RN-URL-LOCALHOST-REFERENCE" in issue_ids
        assert "RN-PRIVILEGED-ROUTES-EXPOSED" in issue_ids
    finally:
        Path(path).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_code_reviewer_scope_aware_analyses(code_reviewer):
    """Test scope-aware detection for Intent Redirection, PendingIntent, TrustManager, and Biometrics."""
    source_code = """
    package com.target.app;

    import android.app.PendingIntent;
    import android.content.Intent;
    import android.content.Context;
    import javax.net.ssl.X509TrustManager;
    import java.security.cert.X509Certificate;
    import javax.net.ssl.HostnameVerifier;
    import javax.net.ssl.SSLSession;
    import androidx.biometric.BiometricPrompt;

    public class VulnerableActivity {

        // 1. Intent Redirection
        public void onHandleIntent(Intent incoming) {
            Intent forward = (Intent) incoming.getParcelableExtra("target_intent");
            startActivity(forward);
        }

        // 2. PendingIntent missing FLAG_IMMUTABLE
        public void setupNotification(Context ctx) {
            Intent i = new Intent();
            PendingIntent pi = PendingIntent.getActivity(ctx, 0, i, 0);
        }

        // 3. Android 13+ dynamic receiver without exported flag
        public void register(Context ctx) {
            ctx.registerReceiver(myReceiver, intentFilter);
        }

        // 4. Broken TrustManager
        public void setupTrust() {
            X509TrustManager tm = new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // Empty body
                }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            };
        }

        // 4b. Permissive HostnameVerifier
        public void setupVerifier() {
            HostnameVerifier hv = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
        }

        // 5. Biometric authenticate without CryptoObject
        public void auth(BiometricPrompt prompt, BiometricPrompt.PromptInfo info) {
            prompt.authenticate(info);
        }
    }
    """

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        java_file = root / "VulnerableActivity.java"
        java_file.write_text(source_code)

        findings = await code_reviewer.review(tmpdir, {})
        cwe_set = {f.cwe_id for f in findings}

        # Intent Redirection (CWE-927)
        assert "CWE-927" in cwe_set
        # PendingIntent / Dynamic Receiver (CWE-926)
        assert "CWE-926" in cwe_set
        # Broken TrustManager (CWE-295)
        assert "CWE-295" in cwe_set
        # Permissive HostnameVerifier (CWE-297)
        assert "CWE-297" in cwe_set
        # Biometric Auth without CryptoObject (CWE-287)
        assert "CWE-287" in cwe_set


@pytest.mark.asyncio
async def test_code_reviewer_keystore_and_intent_extras(code_reviewer):
    """Test Keystore UserAuthenticationRequired audit (CWE-305) and Intent extra extraction."""
    source_code = """
    package com.target.app;
    import android.security.keystore.KeyGenParameterSpec;
    import android.security.keystore.KeyProperties;
    import android.content.Intent;

    public class SecurityService {
        public void generateKey() {
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder("key_alias",
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build();
        }

        public void process(Intent intent) {
            String token = intent.getStringExtra("auth_token_param");
            int userId = intent.getIntExtra("user_id_key", 0);
            boolean isRoot = intent.getBooleanExtra("is_admin", false);
        }
    }
    """

    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = Path(tmpdir) / "SecurityService.java"
        java_file.write_text(source_code)

        findings = await code_reviewer.review(tmpdir, {})
        cwe_set = {f.cwe_id for f in findings}
        assert "CWE-305" in cwe_set

        extras = code_reviewer.extract_intent_extras(source_code)
        assert "auth_token_param" in extras
        assert "user_id_key" in extras
        assert "is_admin" in extras

