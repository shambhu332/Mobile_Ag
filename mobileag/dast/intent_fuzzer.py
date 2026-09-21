"""Autonomous Intent, Deep Link, and IPC Fuzzer for Android DAST.

Executes exported activities, services, deep-link URI schemes, content providers,
and post-execution storage forensics via ADB while actively observing the logcat stream
for unhandled runtime exceptions (CWE-755) and credential/token leakage (CWE-532).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager
from mobileag.dast.logcat_auditor import LogcatAuditor
from mobileag.dast.provider_auditor import ProviderAuditor
from mobileag.dast.storage_auditor import StorageAuditor
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)


class IntentFuzzer:
    """Exerciser and fuzzer for Android IPC components, URI schemes, and storage forensics."""

    def __init__(
        self,
        adb: Optional[ADBManager] = None,
        auditor: Optional[LogcatAuditor] = None,
        storage_auditor: Optional[StorageAuditor] = None,
        provider_auditor: Optional[ProviderAuditor] = None,
    ) -> None:
        self.adb = adb or ADBManager()
        self.auditor = auditor or LogcatAuditor()
        self.storage_auditor = storage_auditor or StorageAuditor(adb=self.adb)
        self.provider_auditor = provider_auditor or ProviderAuditor(adb=self.adb)

    async def exercise_component(
        self,
        serial: str,
        package_name: str,
        component_name: str,
        action: Optional[str] = None,
        data_uri: Optional[str] = None,
        extra_args: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Launch a specific component via `am start` and monitor for crash/leak."""
        full_comp = component_name if "/" in component_name else f"{package_name}/{component_name}"

        cmd_args = ["-s", serial, "shell", "am", "start", "-W"]
        if action:
            cmd_args.extend(["-a", action])
        if data_uri:
            cmd_args.extend(["-d", data_uri])
        if not action and not data_uri:
            cmd_args.extend(["-n", full_comp])
        if extra_args:
            cmd_args.extend(extra_args)

        # Clear logcat before execution to isolate runtime trace
        await self.adb.clear_logcat(serial)

        result: dict[str, Any] = {
            "component": full_comp,
            "action": action,
            "data_uri": data_uri,
            "crashed": False,
            "crash_exception": None,
            "findings": [],
            "raw_output": "",
        }

        try:
            code, stdout, stderr = await self.adb._exec_cmd(cmd_args, timeout=3.0)
            out_text = stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")
            result["raw_output"] = out_text.strip()
            if code != 0 and "timed out" in out_text:
                return result

            # Small delay to capture asynchronous runtime exceptions on Android main thread
            await asyncio.sleep(0.5)

            # Retrieve logcat dump
            logs = await self.adb.get_logcat_dump(serial, filter_pkg=package_name, lines=150)
            if not logs:
                logs = await self.adb.get_logcat_dump(serial, lines=150)

            # Audit logs for CWE-532 (leakage) and CWE-755 (fatal crashes)
            findings = self.auditor.audit_lines(logs, package_name=package_name)
            result["findings"] = findings

            for f in findings:
                if f.cwe_id == "CWE-755":
                    result["crashed"] = True
                    result["crash_exception"] = f.title
                    f.affected_component = full_comp

        except Exception as e:
            logger.warning("Error exercising component %s: %s", full_comp, e)
            result["raw_output"] = f"Execution error: {e}"

        return result

    async def fuzz_activity_intents(
        self,
        serial: str,
        package_name: str,
        activities: list[str],
        targeted_extras: Optional[dict[str, list[str]]] = None,
    ) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Systematically exercise activities with empty, null, boundary, and SAST-bound extras."""
        results: list[dict[str, Any]] = []
        all_findings: list[Finding] = []

        base_payloads = [
            ("Standard Empty Launch", []),
            ("Empty String Extra", ["--es", "query", ""]),
            ("Null Key Extra", ["--es", "target_url", "null"]),
            ("Boundary Length Extra", ["--es", "payload", "A" * 512]),
            ("Special Character Extra", ["--es", "command", "\"'<>&;()"]),
        ]

        for act in activities:
            # Check if SAST extracted specific Intent extra keys for this activity
            act_clean = act.split("/")[-1] if "/" in act else act
            matched_extras = (targeted_extras or {}).get(act) or (targeted_extras or {}).get(act_clean) or []

            current_payloads = list(base_payloads)
            # Add hybrid SAST-targeted extra mutations
            for key in matched_extras:
                current_payloads.append((f"SAST-Bound Extra '{key}' (Canary)", ["--es", key, "http://127.0.0.1:8080/canary"]))
                current_payloads.append((f"SAST-Bound Extra '{key}' (Empty)", ["--es", key, ""]))
                current_payloads.append((f"SAST-Bound Extra '{key}' (Boundary)", ["--es", key, "B" * 256]))

            for test_name, extras in current_payloads:
                res = await self.exercise_component(
                    serial=serial,
                    package_name=package_name,
                    component_name=act,
                    extra_args=extras,
                )
                res["test_name"] = test_name
                results.append(res)
                all_findings.extend(res["findings"])

                # If the component crashed on standard/empty launch, skip further mutations
                if res["crashed"]:
                    break

        return results, all_findings

    async def fuzz_deeplinks(
        self,
        serial: str,
        package_name: str,
        deeplinks: list[str],
    ) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Exercise deep links and custom URI schemes to test intent handling."""
        results: list[dict[str, Any]] = []
        all_findings: list[Finding] = []

        for uri in deeplinks:
            # Test 1: Base URI invocation
            res = await self.exercise_component(
                serial=serial,
                package_name=package_name,
                component_name="",
                action="android.intent.action.VIEW",
                data_uri=uri,
            )
            res["test_name"] = "Base Deep Link VIEW"
            results.append(res)
            all_findings.extend(res["findings"])

            # Test 2: Injected query string testing
            delim = "&" if "?" in uri else "?"
            fuzzed_uri = f"{uri}{delim}redirect=https://audit.local&id=0&payload=test"
            res_fuzz = await self.exercise_component(
                serial=serial,
                package_name=package_name,
                component_name="",
                action="android.intent.action.VIEW",
                data_uri=fuzzed_uri,
            )
            res_fuzz["test_name"] = "Fuzzed Parameter Deep Link"
            results.append(res_fuzz)
            all_findings.extend(res_fuzz["findings"])

        return results, all_findings

    async def run_full_dast_suite(
        self,
        serial: str,
        package_name: str,
        apk_path: Optional[str] = None,
        activities: Optional[list[str]] = None,
        deeplinks: Optional[list[str]] = None,
        authorities: Optional[list[str]] = None,
        targeted_extras: Optional[dict[str, list[str]]] = None,
        audit_storage: bool = True,
    ) -> dict[str, Any]:
        """Execute the comprehensive dynamic assessment pipeline against target device."""
        suite_report: dict[str, Any] = {
            "device_serial": serial,
            "package_name": package_name,
            "status": "running",
            "stages": [],
            "findings": [],
            "crashes_detected": 0,
            "leaks_detected": 0,
            "storage_flaws_detected": 0,
            "provider_flaws_detected": 0,
            "tests_run": 0,
            "screenshot_b64": None,
        }

        # 1. Device Verification & Root Status
        devs = await self.adb.list_devices()
        target_dev = next((d for d in devs if d.serial == serial), None)
        suite_report["stages"].append({
            "stage": "Device Verification",
            "model": target_dev.model if target_dev else "Unknown",
            "is_rooted": target_dev.is_rooted if target_dev else False,
            "android_version": target_dev.android_version if target_dev else "Unknown",
        })

        # 2. APK Installation (if path supplied)
        if apk_path:
            install_res = await self.adb.install_apk(serial, apk_path, grant_permissions=True)
            suite_report["stages"].append({
                "stage": "APK Installation",
                "result": install_res.get("status"),
                "details": install_res.get("output"),
            })

        target_activities = activities or [f"{package_name}.MainActivity"]
        target_deeplinks = deeplinks or []
        target_authorities = authorities or []

        # 3. Activity Intent Fuzzing (with hybrid extras binding)
        act_results, act_findings = await self.fuzz_activity_intents(
            serial=serial,
            package_name=package_name,
            activities=target_activities,
            targeted_extras=targeted_extras,
        )
        suite_report["tests_run"] += len(act_results)
        suite_report["findings"].extend([f.to_dict() for f in act_findings])

        # 4. Deep Link Exercising
        if target_deeplinks:
            dl_results, dl_findings = await self.fuzz_deeplinks(
                serial=serial,
                package_name=package_name,
                deeplinks=target_deeplinks,
            )
            suite_report["tests_run"] += len(dl_results)
            suite_report["findings"].extend([f.to_dict() for f in dl_findings])

        # 5. Content Provider IPC Auditing
        if target_authorities:
            prov_results, prov_findings = await self.provider_auditor.audit_providers(
                serial=serial,
                package_name=package_name,
                authorities=target_authorities,
            )
            suite_report["tests_run"] += len(prov_results)
            suite_report["provider_flaws_detected"] = len(prov_findings)
            suite_report["findings"].extend([f.to_dict() for f in prov_findings])

        # 6. Post-Execution Storage Sandbox Forensics
        if audit_storage:
            storage_res = await self.storage_auditor.audit_all_storage(serial, package_name)
            suite_report["storage_flaws_detected"] = storage_res["total_storage_findings"]
            suite_report["findings"].extend(storage_res["findings"])

        # 7. Capture Final Screenshot
        screenshot = await self.adb.capture_screenshot(serial)
        if screenshot:
            import base64
            suite_report["screenshot_b64"] = base64.b64encode(screenshot).decode("utf-8")

        # Compute summary stats
        crashes = [f for f in suite_report["findings"] if f.get("cwe_id") == "CWE-755"]
        leaks = [f for f in suite_report["findings"] if f.get("cwe_id") == "CWE-532"]
        suite_report["crashes_detected"] = len(crashes)
        suite_report["leaks_detected"] = len(leaks)
        suite_report["status"] = "completed"

        return suite_report
