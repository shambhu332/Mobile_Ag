"""Closed-Loop Dynamic Verification Engine (Zero False-Positive Engine).

Connects static candidate findings with live ADB device execution. Runs targeted,
non-destructive verification probes on connected devices/emulators and inspects
Logcat, Activity Manager, and window states to establish exploitability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from mobileag.generators.poc_apk_synthesizer import ExploitPocSynthesizer
from mobileag.reporting.finding import Finding


@dataclass
class DynamicVerificationOutcome:
    finding_id: str
    verified: bool
    verdict: str  # REVIEW_REQUIRED: generated PoC templates are never executed
    evidence_output: str
    logcat_markers: List[str] = field(default_factory=list)
    execution_attempted: bool = False


class DynamicVerificationLoop:
    """Review-only adapter; generated PoC templates are not runnable commands."""

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path
        self.poc_synthesizer = ExploitPocSynthesizer()

    def verify_finding(
        self,
        finding: Finding,
        target_package: str,
        device_serial: Optional[str] = None,
        timeout: float = 6.0,
    ) -> DynamicVerificationOutcome:
        """Return an explicit review gate without executing generated commands.

        The old implementation passed free-form generated command strings to
        ``adb shell`` and treated successful dispatch as exploit confirmation.
        Generated PoCs are review-only artifacts, so this adapter deliberately
        performs no device action until a separate structured, scoped probe
        interface is implemented.
        """
        return DynamicVerificationOutcome(
            finding_id=finding.id,
            verified=False,
            verdict="REVIEW_REQUIRED",
            evidence_output=(
                "No device action performed: generated PoC templates are review-only, "
                "and command dispatch is not proof of impact. Use an independently "
                "reviewed, scope-bound test procedure."
            ),
            execution_attempted=False,
        )

    def apply_verification_to_finding(
        self,
        finding: Finding,
        outcome: DynamicVerificationOutcome,
    ) -> Finding:
        """Do not convert caller-supplied observations into a security verdict."""
        # Until observations are tied to an authenticated device session, scope
        # snapshot, bounded raw evidence, and review event, mutation is unsafe.
        return finding
