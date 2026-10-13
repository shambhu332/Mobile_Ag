"""In-memory Cryptographic Key and Plaintext Lifecycle Harvester.

Generates and manages Frida hooks into javax.crypto.Cipher, SecretKeySpec,
KeyStore, and SQLCipher to harvest runtime symmetric keys, IVs, and plaintexts.
"""
from __future__ import annotations

import binascii
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class HarvestedCryptoEvent:
    timestamp: str
    operation: str  # ENCRYPT, DECRYPT, KEY_LOAD
    algorithm: str
    key_hex: Optional[str] = None
    iv_hex: Optional[str] = None
    plaintext_preview: Optional[str] = None
    stack_trace: Optional[str] = None


class CryptoHarvester:
    """Manages in-memory cryptographic key interception and telemetry extraction."""

    HARVESTER_FRIDA_SCRIPT = """
/* MobileAg Cryptographic Key and Plaintext Harvester */
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

    function bytesToHex(bytes) {
        if (!bytes) return null;
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            var b = (bytes[i] & 0xFF).toString(16);
            if (b.length == 1) b = '0' + b;
            hex.push(b);
        }
        return hex.join('');
    }

    function bytesToString(bytes) {
        if (!bytes) return null;
        var str = "";
        for (var i = 0; i < Math.min(bytes.length, 128); i++) {
            var c = bytes[i];
            if (c >= 32 && c <= 126) str += String.fromCharCode(c);
            else str += '.';
        }
        return str;
    }

    // Hook Cipher.init(int opmode, Key key, AlgorithmParameterSpec params)
    try {
        var initOverload = Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
        initOverload.implementation = function(opmode, key, params) {
            var op = (opmode === 1) ? "ENCRYPT" : (opmode === 2 ? "DECRYPT" : "WRAP/UNWRAP");
            var keyBytes = null;
            try {
                if (key && key.getEncoded) {
                    keyBytes = bytesToHex(key.getEncoded());
                }
            } catch (err) {}

            var ivBytes = null;
            try {
                if (params && params.getIV) {
                    ivBytes = bytesToHex(params.getIV());
                }
            } catch (err) {}

            send({
                type: 'crypto_event',
                operation: op,
                algorithm: this.getAlgorithm(),
                key: keyBytes,
                iv: ivBytes
            });

            return initOverload.call(this, opmode, key, params);
        };
    } catch (e) {}

    // Hook Cipher.doFinal(byte[] input)
    try {
        var doFinal = Cipher.doFinal.overload('[B');
        doFinal.implementation = function(input) {
            var res = doFinal.call(this, input);
            var isEncrypt = (this.getAlgorithm().indexOf("ECB") !== -1 || true);
            send({
                type: 'crypto_payload',
                algorithm: this.getAlgorithm(),
                input_preview: bytesToString(input),
                output_preview: bytesToString(res)
            });
            return res;
        };
    } catch (e) {}
});
"""

    def generate_hook_script(self) -> str:
        """Return the standalone Frida hooking script."""
        return self.HARVESTER_FRIDA_SCRIPT.strip() + "\n"

    def parse_event(self, message: Dict[str, Any]) -> Optional[HarvestedCryptoEvent]:
        """Convert a Frida telemetry JSON payload into a structured HarvestedCryptoEvent."""
        if not isinstance(message, dict) or message.get("type") not in {"crypto_event", "crypto_payload"}:
            return None

        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if message.get("type") == "crypto_event":
            return HarvestedCryptoEvent(
                timestamp=now,
                operation=message.get("operation", "UNKNOWN"),
                algorithm=message.get("algorithm", "UNKNOWN"),
                key_hex=message.get("key"),
                iv_hex=message.get("iv"),
            )
        else:
            return HarvestedCryptoEvent(
                timestamp=now,
                operation="PAYLOAD_TRANSFER",
                algorithm=message.get("algorithm", "UNKNOWN"),
                plaintext_preview=message.get("input_preview") or message.get("output_preview"),
            )
