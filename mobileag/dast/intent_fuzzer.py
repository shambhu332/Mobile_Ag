"""Autonomous Intent, Deep Link, and IPC Fuzzer for Android DAST.

Executes exported activities, services, deep-link URI schemes, content providers,
and post-execution storage forensics via ADB while actively observing the logcat stream
for unhandled runtime exceptions (CWE-755) and credential/token leakage (CWE-532).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
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

    MAX_COMPONENT_CASES = 30
    _SERIAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
    _PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")
    _COMPONENT_CLASS_RE = re.compile(r"(?:\.[A-Za-z_$][A-Za-z0-9_.$]*|[A-Za-z][A-Za-z0-9_.$]*)\Z")
    _ACTION_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,255}\Z")

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
        *,
        component_type: str = "activity",
        synthetic_data_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Dispatch one exact component with inert test inputs and observe target logs.

        Activity Manager output is reduced to a bounded status; it is never
        copied into durable evidence. ADB shell is a privileged diagnostic
        caller, not an ordinary third-party-app reproduction.
        """
        if synthetic_data_confirmed is not True:
            raise PermissionError("Researcher-controlled target and synthetic test data must be confirmed")
        if (not isinstance(serial, str) or not self._SERIAL_RE.fullmatch(serial)
                or not isinstance(package_name, str) or not self._PACKAGE_RE.fullmatch(package_name)
                or not isinstance(component_type, str) or component_type not in {"activity", "service", "receiver"}
                or not isinstance(component_name, str) or len(component_name) > 512):
            raise ValueError("IPC dispatch target is invalid or exceeds limits")
        full_comp = ""
        if component_name:
            if component_name.count("/") > 1:
                raise ValueError("IPC component name is invalid")
            if "/" in component_name:
                component_package, class_name = component_name.split("/", 1)
                if component_package != package_name:
                    raise ValueError("IPC component must belong to the approved package")
            else:
                component_package, class_name = package_name, component_name
            if (not self._COMPONENT_CLASS_RE.fullmatch(class_name)
                    or (not class_name.startswith(".") and not class_name.startswith(package_name + "."))):
                raise ValueError("IPC component name is invalid")
            full_comp = f"{component_package}/{class_name}"
        elif component_type != "activity" or not (action or data_uri):
            raise ValueError("An explicit component or activity action/data URI is required")
        if action is not None and (not isinstance(action, str) or not self._ACTION_RE.fullmatch(action)):
            raise ValueError("Intent action is invalid or exceeds limits")
        if data_uri is not None and (not isinstance(data_uri, str) or not data_uri or len(data_uri) > 8192
                or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in data_uri)):
            raise ValueError("Intent data URI is invalid or exceeds limits")
        if extra_args is not None:
            if (not isinstance(extra_args, list) or len(extra_args) > 96 or len(extra_args) % 3 != 0
                    or any(not isinstance(extra_args[i], str) or extra_args[i] != "--es"
                           or not isinstance(extra_args[i + 1], str)
                           or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", extra_args[i + 1])
                           or not isinstance(extra_args[i + 2], str) or len(extra_args[i + 2]) > 512
                           or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in extra_args[i + 2])
                           for i in range(0, len(extra_args), 3))):
                raise ValueError("Only bounded synthetic string extras are supported")

        operation = {"activity": "start", "service": "startservice", "receiver": "broadcast"}[component_type]
        cmd_args = ["-s", serial, "shell", "am", operation]
        if component_type == "activity":
            cmd_args.append("-W")
        if action:
            cmd_args.extend(["-a", action])
        if data_uri:
            cmd_args.extend(["-d", data_uri])
        if full_comp:
            cmd_args.extend(["-n", full_comp])
        if extra_args:
            cmd_args.extend(extra_args)

        # Do not destroy the device-wide log buffer during a diagnostic.
        if (action or data_uri) and package_name:
            cmd_args.extend(["-p", package_name])

        result: dict[str, Any] = {
            "component": full_comp or "[implicit activity intent]",
            "component_type": component_type,
            "action": action,
            "data_uri": redact(data_uri),
            "crashed": False,
            "crash_exception": None,
            "findings": [],
            "dispatch_status": "not_attempted",
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
            if code != 0 or "Error:" in out_text:
                result["dispatch_status"] = "rejected_or_failed"
                return result
            result["dispatch_status"] = "accepted_by_activity_manager"

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
        except Exception:
            logger.warning("IPC component observation failed; diagnostic output withheld")
            result["dispatch_status"] = "observation_unavailable"

        return result

    async def fuzz_activity_intents(
        self,
        serial: str,
        package_name: str,
        activities: list[str],
        targeted_extras: Optional[dict[str, list[str]]] = None,
        guard=None,
        *,
        synthetic_data_confirmed: bool = False,
    ) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Systematically exercise activities with empty, null, boundary, and SAST-bound extras."""
        if synthetic_data_confirmed is not True:
            raise PermissionError("Researcher-controlled target and synthetic test data must be confirmed")
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
                    synthetic_data_confirmed=synthetic_data_confirmed,
                )
                res["test_name"] = test_name
                results.append(res)
                all_findings.extend(res["findings"])

                # If the component crashed on standard/empty launch, skip further mutations
                if res["crashed"]:
                    break

        return results, all_findings

    async def fuzz_service_and_receiver_components(
        self,
        serial: str,
        package_name: str,
        *,
        services: Optional[list[str]] = None,
        receivers: Optional[list[str]] = None,
        guard=None,
        synthetic_data_confirmed: bool = False,
    ) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Make one bounded explicit synthetic dispatch to each named component.

        The caller must source names from the exact reviewed APK/manifest and
        obtain per-run approval. These are shell-caller observations only.
        """
        if synthetic_data_confirmed is not True:
            raise PermissionError("Researcher-controlled target and synthetic test data must be confirmed")
        if (not isinstance(services, (list, tuple)) or not isinstance(receivers, (list, tuple))
                or not isinstance(serial, str) or not self._SERIAL_RE.fullmatch(serial)
                or not isinstance(package_name, str) or not self._PACKAGE_RE.fullmatch(package_name)):
            raise ValueError("Service and receiver component lists are required")
        if len(services) + len(receivers) > self.MAX_COMPONENT_CASES:
            raise ValueError("IPC component dispatch budget exceeded")
        # Validate the complete batch before the first device operation.
        all_components = [(kind, item) for kind, items in (("service", services), ("receiver", receivers))
                          for item in items]
        if any(not isinstance(item, str) or not item or len(item) > 512 for _, item in all_components):
            raise ValueError("IPC component name is invalid or exceeds limits")
        if len({(kind, item) for kind, item in all_components}) != len(all_components):
            raise ValueError("Duplicate IPC component names are not allowed")
        for _, item in all_components:
            normalized = item.split("/", 1)[1] if "/" in item and item.count("/") == 1 else item
            component_package = item.split("/", 1)[0] if "/" in item and item.count("/") == 1 else package_name
            if (item.count("/") > 1 or component_package != package_name
                    or not self._COMPONENT_CLASS_RE.fullmatch(normalized)
                    or (not normalized.startswith(".") and not normalized.startswith(package_name + "."))):
                raise ValueError("IPC component must be valid and belong to the approved package")
        results: list[dict[str, Any]] = []
        findings: list[Finding] = []
        for component_type, components in (("service", services), ("receiver", receivers)):
            for component in components:
                result = await self.exercise_component(
                    serial, package_name, component,
                    extra_args=["--es", "mobileag_canary", "synthetic"],
                    guard=guard, component_type=component_type,
                    synthetic_data_confirmed=synthetic_data_confirmed,
                )
                result["test_name"] = "synthetic_explicit_component_dispatch"
                results.append(result)
                findings.extend(result["findings"])
        return results, findings

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
