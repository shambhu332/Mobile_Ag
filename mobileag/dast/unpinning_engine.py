"""Multi-engine TLS/SSL Unpinning Orchestrator and Frida Script Synthesizer.

Generates universal Frida scripts targeting Java TrustManager/OkHttp, native BoringSSL/OpenSSL,
and Flutter libflutter.so memory offsets.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class UnpinningConfig:
    target_package: str
    bypass_java: bool = True
    bypass_okhttp: bool = True
    bypass_boringssl: bool = True
    bypass_flutter: bool = True
    flutter_offset: Optional[str] = None


class UnpinningEngine:
    """Orchestrates runtime TLS/SSL certificate pin bypassing."""

    UNIVERSAL_JAVA_PAYLOAD = """
// Java TrustManager & OkHttp bypass
Java.perform(function() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.mobileag.bypass.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    SSLContext_init.implementation = function(km, tm, sr) {
        console.log('[MobileAg] Bypassing SSLContext.init TrustManager check');
        SSLContext_init.call(this, km, TrustManagers, sr);
    };

    // OkHttp3 CertificatePinner check bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[MobileAg] Bypassing OkHttp3 CertificatePinner.check(' + hostname + ')');
        };
    } catch (e) {}

    // WebViewClient onReceivedSslError bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[MobileAg] Bypassing WebView onReceivedSslError');
            handler.proceed();
        };
    } catch (e) {}
});
"""

    NATIVE_BORINGSSL_PAYLOAD = """
// Native BoringSSL / OpenSSL SSL_CTX_set_custom_verify bypass
Interceptor.attach(Module.findExportByName(null, "SSL_CTX_set_custom_verify") || ptr(0), {
    onEnter: function(args) {
        console.log('[MobileAg] Hooking SSL_CTX_set_custom_verify: enforcing SSL_VERIFY_NONE');
        args[1] = ptr(0); // SSL_VERIFY_NONE
    }
});

Interceptor.attach(Module.findExportByName(null, "SSL_set_custom_verify") || ptr(0), {
    onEnter: function(args) {
        console.log('[MobileAg] Hooking SSL_set_custom_verify: enforcing SSL_VERIFY_NONE');
        args[1] = ptr(0);
    }
});
"""

    FLUTTER_PATTERN_PAYLOAD = """
// Flutter libflutter.so pattern-scan bypass
function hookFlutter() {
    var libflutter = Process.findModuleByName("libflutter.so");
    if (!libflutter) return;
    console.log('[MobileAg] Found libflutter.so at ' + libflutter.base);

    // Scan for ssl_crypto_x509_session_verify_cert_chain pattern
    // ARM64 pattern typically: 0xFF 0x03 0x01 0xD1 ... (sub sp, sp, #... / return 0)
    Memory.scan(libflutter.base, libflutter.size, "ff 03 01 d1 fd 7b 02 a9", {
        onMatch: function(address, size) {
            console.log('[MobileAg] Discovered SSL verification routine candidate in Flutter: ' + address);
            // Replace routine with immediate return 1 (verification succeeded)
            Interceptor.attach(address, {
                onLeave: function(retval) {
                    retval.replace(ptr(1));
                }
            });
        },
        onComplete: function() {}
    });
}
setTimeout(hookFlutter, 1500);
"""

    def generate_script(self, config: UnpinningConfig) -> str:
        """Compose a unified Frida unpinning script based on configuration."""
        script_parts = [
            f"/* MobileAg Universal SSL/TLS Unpinning Harness for {config.target_package} */",
            "console.log('[MobileAg] Initializing TLS/SSL Pinning Bypass Harness...');",
        ]

        if config.bypass_java or config.bypass_okhttp:
            script_parts.append(self.UNIVERSAL_JAVA_PAYLOAD.strip())

        if config.bypass_boringssl:
            script_parts.append(self.NATIVE_BORINGSSL_PAYLOAD.strip())

        if config.bypass_flutter:
            script_parts.append(self.FLUTTER_PATTERN_PAYLOAD.strip())

        return "\n\n".join(script_parts) + "\n"
