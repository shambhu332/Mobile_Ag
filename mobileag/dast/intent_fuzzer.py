"""Autonomous Intent, Deep Link, and IPC Fuzzer for Android DAST.

Executes exported activities, services, deep-link URI schemes, content providers,
and post-execution storage forensics via ADB while actively observing the logcat stream
for unhandled runtime exceptions (CWE-755) and credential/token leakage (CWE-532).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager
from mobileag.dast.deeplink_fuzzer import DeepLinkFuzzer
from mobileag.dast.logcat_auditor import LogcatAuditor
from mobileag.dast.memory_forensics import MemoryForensicsAuditor
from mobileag.dast.provider_auditor import ProviderAuditor
from mobileag.dast.storage_auditor import StorageAuditor
from mobileag.dast.ui_crawler import UICrawler
from mobileag.dast.runtime_evidence import new_lines
from mobileag.security.privacy import redact
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
        deeplink_fuzzer: Optional[DeepLinkFuzzer] = None,
        ui_crawler: Optional[UICrawler] = None,
        memory_auditor: Optional[MemoryForensicsAuditor] = None,
    ) -> None:
        self.adb = adb or ADBManager()
        self.auditor = auditor or LogcatAuditor()
        self.storage_auditor = storage_auditor or StorageAuditor(adb=self.adb)
        self.provider_auditor = provider_auditor or ProviderAuditor(adb=self.adb)
        self.deeplink_fuzzer = deeplink_fuzzer or DeepLinkFuzzer(adb=self.adb)
        self.ui_crawler = ui_crawler or UICrawler(adb=self.adb)
        self.memory_auditor = memory_auditor or MemoryForensicsAuditor(adb=self.adb)


    async def exercise_component(
        self,
        serial: str,
        package_name: str,
        component_name: str,
        action: Optional[str] = None,
        data_uri: Optional[str] = None,
        extra_args: Optional[list[str]] = None,
        guard=None,
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

        # Do not destroy the device-wide log buffer during a diagnostic.
        if (action or data_uri) and package_name:
            cmd_args.extend(["-p", package_name])

        result: dict[str, Any] = {
            "component": full_comp,
            "action": action,
            "data_uri": redact(data_uri),
            "crashed": False,
            "crash_exception": None,
            "findings": [],
            "raw_output": "",
        }

        def checked_guard():
            if not callable(guard):
                raise PermissionError("Device diagnostic scope guard is required")
            try:
                allowed = guard()
            except Exception as exc:
                raise PermissionError("Device diagnostic approval revoked") from exc
            if inspect.isawaitable(allowed):
                close = getattr(allowed, "close", None)
                if callable(close):
                    close()
                raise PermissionError("Device diagnostic scope guard must be synchronous")
            if allowed is False:
                raise PermissionError("Device diagnostic approval revoked")

        try:
            checked_guard()
            before = await self.adb.get_logcat_dump(serial, lines=150, guard=checked_guard)
            checked_guard()
            code, stdout, stderr = await self.adb._exec_cmd(cmd_args, timeout=3.0)
            checked_guard()
            out_text = stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")
            result["raw_output"] = redact(out_text.strip())
            if code != 0 or "Error:" in out_text:
                return result

            # Small delay to capture asynchronous runtime exceptions on Android main thread
            await asyncio.sleep(0.5)

            checked_guard()
            logs = await self.adb.get_logcat_dump(serial, lines=150, guard=checked_guard)
            checked_guard()
            findings = self.auditor.audit_lines(new_lines(before, logs), package_name=package_name)
            result["findings"] = findings

            for f in findings:
                if f.cwe_id == "CWE-755":
                    result["crashed"] = True
                    result["crash_exception"] = f.title
                    f.affected_component = full_comp

        except PermissionError:
            raise
        except Exception as e:
            logger.warning("Error exercising component %s: %s", full_comp, e)
            result["raw_output"] = redact(f"Execution error: {e}")

        return result

    async def fuzz_activity_intents(
        self,
        serial: str,
        package_name: str,
        activities: list[str],
        targeted_extras: Optional[dict[str, list[str]]] = None,
        guard=None,
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

        for act in activities[:30]:
            # Check if SAST extracted specific Intent extra keys for this activity
            act_clean = act.split("/")[-1] if "/" in act else act
            matched_extras = (targeted_extras or {}).get(act) or (targeted_extras or {}).get(act_clean) or []

            current_payloads = list(base_payloads)
            # Add hybrid SAST-targeted extra mutations
            for key in matched_extras[:20]:
                current_payloads.append((f"SAST-Bound Extra '{key}' (Canary)", ["--es", key, "http://127.0.0.1:8080/canary"]))
                current_payloads.append((f"SAST-Bound Extra '{key}' (Empty)", ["--es", key, ""]))
                current_payloads.append((f"SAST-Bound Extra '{key}' (Boundary)", ["--es", key, "B" * 256]))

            for test_name, extras in current_payloads:
                res = await self.exercise_component(
                    serial=serial,
                    package_name=package_name,
                    component_name=act,
                    extra_args=extras,
                    guard=guard,
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
        guard=None,
        synthetic_data_confirmed: bool = False,
    ) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Exercise deep links and custom URI schemes via DeepLinkFuzzer."""
        return await self.deeplink_fuzzer.fuzz_deep_links(
            serial=serial,
            package_name=package_name,
            deep_links=deeplinks,
            guard=guard,
            synthetic_data_confirmed=synthetic_data_confirmed,
        )

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
        audit_memory: bool = False,
        crawl_ui: bool = False,
    ) -> dict[str, Any]:
        """Deprecated: use individually authorized workbench diagnostics instead.

        This legacy composition had implicit root probes, permission grants and
        unrelated screenshot capture, and no per-stage revocation boundary.
        Fail before any device command rather than silently widening approval.
        """
        raise PermissionError("Legacy full DAST suite disabled; use explicitly scoped workbench actions")
