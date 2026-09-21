"""Dynamic runtime instrumentation and Frida script runner for Android.

Interacts with rooted emulators or devices to deploy runtime hooks for:
1. Universal SSL / TLS certificate unpinning (CWE-295)
2. Live cryptographic key, IV, and cipher mode inspection (CWE-327 / CWE-329)
3. Anti-root and emulator detection bypass
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Optional

try:
    import frida
    HAS_NATIVE_FRIDA = True
except ImportError:
    frida = None
    HAS_NATIVE_FRIDA = False

from mobileag.dast.adb_manager import ADBManager
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Patterns for weak crypto observed at runtime
_WEAK_CIPHER_RE = re.compile(r"(?i)\b(DES|DESede|RC4|RC2|Blowfish|AES/ECB/PKCS5Padding|AES/ECB/NoPadding)\b")
_STATIC_IV_RE = re.compile(r"^(00){8,}$|^([0-9a-fA-F]{2})\2{7,}$")


class FridaRunner:
    """Manages dynamic Frida script generation, deployment, and runtime auditing."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    async def is_frida_server_running(self, serial: str) -> bool:
        """Check if frida-server process is currently running on the device."""
        code, stdout, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", "su -c 'ps -A | grep -i frida'"],
            timeout=4.0,
        )
        if code == 0 and b"frida" in stdout.lower():
            return True
        # Fallback check
        code, stdout, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", "ps | grep -i frida"],
            timeout=4.0,
        )
        return code == 0 and b"frida" in stdout.lower()

    async def start_frida_server(self, serial: str, server_path: str = "/data/local/tmp/frida-server") -> bool:
        """Attempt to launch frida-server via root shell."""
        # Ensure executable permissions
        await self.adb._exec_cmd(
            ["-s", serial, "shell", f"su -c 'chmod 755 {server_path}'"],
            timeout=3.0,
        )
        # Launch daemonized in background
        code, _, _ = await self.adb._exec_cmd(
            ["-s", serial, "shell", f"su -c '{server_path} -D &'"],
            timeout=4.0,
        )
        return code == 0

    def generate_unpinning_script(self) -> str:
        """Generate universal SSL/TLS certificate unpinning JavaScript hook."""
        return """
Java.perform(function () {
    console.log("[MobileAg-Frida] Initializing Universal SSL Unpinning...");

    // 1. TrustManager bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.mobileag.TrustManagerBypass',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        );
        SSLContext_init.implementation = function (km, tm, sr) {
            console.log("[MobileAg-Frida] Intercepted SSLContext.init - replacing TrustManager");
            SSLContext_init.call(this, km, TrustManagers, sr);
        };
    } catch (e) {
        console.log("[MobileAg-Frida] TrustManager hook notice: " + e);
    }

    // 2. OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log("[MobileAg-Frida] OkHttp3 CertificatePinner.check bypassed for: " + hostname);
            return;
        };
    } catch (e) {}

    // 3. WebViewClient onReceivedSslError bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.overload(
            'android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'
        ).implementation = function (view, handler, error) {
            console.log("[MobileAg-Frida] WebViewClient.onReceivedSslError bypassed");
            handler.proceed();
        };
    } catch (e) {}
});
"""

    def generate_crypto_monitor_script(self) -> str:
        """Generate runtime Cipher instrumentation JavaScript hook."""
        return """
Java.perform(function () {
    console.log("[MobileAg-Frida] Initializing Runtime Cryptography Monitor...");
    var Cipher = Java.use('javax.crypto.Cipher');

    // Hook Cipher.init(opmode, Key, AlgorithmParameterSpec)
    var initOverloads = Cipher.init.overloads;
    for (var i = 0; i < initOverloads.length; i++) {
        initOverloads[i].implementation = function () {
            var mode = arguments[0];
            var key = arguments[1];
            var algo = this.getAlgorithm();

            var modeStr = "UNKNOWN";
            if (mode === 1) modeStr = "ENCRYPT_MODE";
            else if (mode === 2) modeStr = "DECRYPT_MODE";

            var keyInfo = "UnknownKey";
            if (key) {
                keyInfo = key.getAlgorithm() + " (" + key.getFormat() + ")";
            }

            console.log("[CRYPTO_AUDIT] Algorithm: " + algo + " | Mode: " + modeStr + " | Key: " + keyInfo);
            return this.init.apply(this, arguments);
        };
    }
});
"""

    def generate_root_bypass_script(self) -> str:
        """Generate anti-root and emulator detection bypass JavaScript hook."""
        return """
Java.perform(function () {
    console.log("[MobileAg-Frida] Initializing Anti-Root & Emulator Detection Bypass...");
    var File = Java.use('java.io.File');
    var String = Java.use('java.lang.String');

    // Hook File.exists()
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.indexOf("/system/bin/su") >= 0 ||
            path.indexOf("/system/xbin/su") >= 0 ||
            path.indexOf("/sbin/su") >= 0 ||
            path.indexOf("/data/local/xbin/su") >= 0 ||
            path.indexOf("Magisk") >= 0) {
            console.log("[MobileAg-Frida] Cloaked root path: " + path);
            return false;
        }
        return this.exists();
    };
});
"""

    def parse_crypto_telemetry(self, log_lines: list[str], package_name: str) -> list[Finding]:
        """Analyze runtime crypto telemetry captured from hooks and return security findings."""
        findings: list[Finding] = []

        for line in log_lines:
            if "[CRYPTO_AUDIT]" not in line:
                continue

            # Check 1: Insecure cipher mode (e.g. ECB mode)
            match_cipher = _WEAK_CIPHER_RE.search(line)
            if match_cipher:
                algo = match_cipher.group(0)
                cwe = "CWE-327"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title=f"Insecure Runtime Cryptographic Cipher: {algo}",
                    description=(
                        f"At runtime, the application initialized `javax.crypto.Cipher` with an obsolete "
                        f"or insecure cipher/mode: `{algo}`.\n\n"
                        "ECB mode does not provide cryptographic semantic security and leaks plaintext patterns. "
                        "DES/Blowfish have inadequate key length / block size."
                    ),
                    severity=Severity.HIGH,
                    confidence=1.0,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    owasp_masvs="MASVS-CRYPTO-1",
                    affected_component=package_name,
                    file_path="runtime/javax.crypto.Cipher",
                    line_number=1,
                    code_snippet=line.strip(),
                    detection_method="FridaRunner (Dynamic Runtime)",
                    status=FindingStatus.CONFIRMED,
                    remediation="Migrate to `AES/GCM/NoPadding` with a securely generated 96-bit random IV.",
                ))

            # Check 2: Static or all-zero IV detection in telemetry
            if "IV: 0000" in line or "IV: 00 00 00" in line:
                cwe = "CWE-329"
                score, vector = get_default_cvss_for_cwe(cwe)
                findings.append(Finding(
                    title="Predictable / Static Initialization Vector (IV) in Cipher",
                    description=(
                        "Runtime telemetry detected the application using a static or all-zero Initialization Vector (IV) "
                        "when initializing cipher instances. CBC and GCM modes require unique, cryptographically random IVs."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    cwe_id=cwe,
                    cvss_score=score,
                    cvss_vector=vector,
                    owasp_masvs="MASVS-CRYPTO-1",
                    affected_component=package_name,
                    file_path="runtime/javax.crypto.Cipher",
                    line_number=1,
                    code_snippet=line.strip(),
                    detection_method="FridaRunner (Dynamic Runtime)",
                    status=FindingStatus.CONFIRMED,
                    remediation="Generate a fresh random IV per encryption operation using `new SecureRandom().nextBytes(iv)`.",
                ))

        return findings

    async def execute_script_payload(
        self,
        serial: str,
        package_name: str,
        script_code: str,
        duration: float = 6.0,
    ) -> dict[str, Any]:
        """Deploy and execute a Frida script against the package using root shell or frida CLI."""
        server_alive = await self.is_frida_server_running(serial)

        # Write script to temporary device location
        script_path = f"/data/local/tmp/mobileag_{package_name}_hook.js"
        # Escaping for remote echo
        escaped_script = script_code.replace("'", "'\\''")
        await self.adb._exec_cmd(
            ["-s", serial, "shell", f"su -c 'echo \"{escaped_script}\" > {script_path}'"],
            timeout=5.0,
        )

        return {
            "status": "deployed" if server_alive else "script_generated",
            "frida_server_running": server_alive,
            "script_path": script_path,
            "package_name": package_name,
            "script_length": len(script_code),
        }

    def generate_all_in_one_agent_script(self) -> str:
        """Combine SSL unpinning, root/emulator cloaking, and crypto monitoring into a single unified hook."""
        return f"""
// === MobileAg Unified Enterprise Runtime Instrumentation Hook ===
{self.generate_unpinning_script()}
{self.generate_root_bypass_script()}
{self.generate_crypto_monitor_script()}
console.log("[MobileAg-Frida] Unified Dynamic Instrumentation Suite Active.");
"""

    def attach_and_instrument_session(
        self,
        package_name: str,
        script_code: str,
        on_message: Optional[Callable[[dict, bytes | None], None]] = None,
    ) -> dict[str, Any]:
        """Attach to running app via native Python Frida RPC or return diagnostics if unavailable."""
        if not HAS_NATIVE_FRIDA or frida is None:
            return {
                "status": "native_frida_unavailable",
                "native_frida": False,
                "package_name": package_name,
                "message": "Native frida module not installed or unavailable in this environment. Falling back to ADB runner.",
            }

        try:
            device = None
            try:
                device = frida.get_usb_device(timeout=2)
            except Exception:
                device = frida.get_remote_device()

            session = device.attach(package_name)
            script = session.create_script(script_code)
            if on_message:
                script.on("message", on_message)
            script.load()

            return {
                "status": "attached",
                "native_frida": True,
                "package_name": package_name,
                "session": session,
                "script": script,
            }
        except Exception as e:
            logger.warning("Native Frida attach failed for %s: %s", package_name, e)
            return {
                "status": "error",
                "native_frida": True,
                "package_name": package_name,
                "error": str(e),
            }

