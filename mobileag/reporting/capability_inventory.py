"""Honest framework and binary-format capability inventory for reports.

This is a statement of bounded implementation scope plus per-scan execution
metadata. It is not a benchmark, format detector, or completeness assertion.
"""
from __future__ import annotations


_CAPABILITIES = {
    "java_kotlin": ("partial", "taint", "Java/Kotlin sources are scanned by bounded lexical/AST engines; engine coverage is partial."),
    "smali": ("partial", "smali_call_graph", "Bounded Smali call-graph review; not a complete DEX semantic analysis."),
    "native_jni": ("inventory_only", "native", "Bounded ELF identity/import and byte-string inventory; no full disassembly, call graph, or JNI dataflow proof."),
    "react_native": ("partial", "react_native", "Bounded React Native heuristics; not a complete JavaScript bundle analysis."),
    "hybrid_webview": ("partial", "android_surface.categories.webview", "Lexical WebView review; origin/bridge reachability is not fully resolved."),
    "flutter": ("detection_only", None, "Framework signature detection only; Dart/Flutter security analysis is not implemented."),
    "xamarin": ("detection_only", None, "Framework signature detection only; managed assemblies are not analyzed."),
    "cordova": ("detection_only", None, "Framework signature detection only; JavaScript application analysis is not implemented."),
    "unity": ("detection_only", None, "Framework signature detection only; managed/IL2CPP analysis is not implemented."),
    "split_apk_aab": ("manifest_indicator_only", "split_manifest", "A single decoded APK manifest may expose a split name; split-set completeness, AAB ingestion, and cross-split analysis are not measured."),
    "multidex": ("input_inventory_only", "ingestion_inventory.apk_archive", "Root DEX class descriptors and regular Apktool Smali directives are compared per DEX when bounded parsing permits; agreement does not establish bytecode decoding or analysis completeness."),
    "obfuscation": ("partial", "code_review", "Obfuscation indicators and bounded source review do not establish recovered semantic coverage."),
}

_FRAMEWORK_NAMES = {
    "react_native": "React Native",
    "flutter": "Flutter",
    "xamarin": "Xamarin",
    "cordova": "Cordova",
    "unity": "Unity",
}


def _at_path(root: dict, path: str | None):
    value = root
    if not path:
        return None
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value if isinstance(value, dict) else None


def capability_inventory(coverage: dict | None, framework_info: dict | None = None) -> dict:
    """Report declared bounded support separately from actual scan coverage."""
    coverage = coverage if isinstance(coverage, dict) else {}
    framework_info = framework_info if isinstance(framework_info, dict) else {}
    raw_detected = framework_info.get("detected_frameworks")
    if isinstance(raw_detected, list) and all(isinstance(item, str) for item in raw_detected):
        detected_frameworks = set(raw_detected)
        detection_recorded = True
    else:
        # Backward-compatible reports only carried one selected framework.
        selected = framework_info.get("framework")
        detection_recorded = isinstance(selected, str) and selected not in {"", "not_recorded", "Unknown"}
        detected_frameworks = {selected} if detection_recorded and selected != "Native" else set()
    detection_coverage = framework_info.get("coverage", {})
    detector_coverage_recorded = (isinstance(detection_coverage, dict) and
                                  detection_coverage.get("static_status") in
                                  {"analyzed_heuristically", "partial", "not_analyzed"})
    detector_truncated = (isinstance(detection_coverage, dict) and
                          (detection_coverage.get("static_status") == "partial" or
                           detection_coverage.get("static_status") == "not_analyzed" or
                           detection_coverage.get("limits_reached") is True or
                           (type(detection_coverage.get("source_files_skipped")) is int and
                            detection_coverage["source_files_skipped"] > 0)))
    rows = {}
    for name, (support, path, limitation) in _CAPABILITIES.items():
        execution = _at_path(coverage, path)
        input_execution = execution
        if (path or "").startswith("android_surface.categories."):
            # AndroidSurfaceAnalyzer shares one bounded traversal across its
            # categories; path-level skip/limit counters live on the parent.
            input_execution = _at_path(coverage, "android_surface") or execution
        summaries = (execution.get("same_file_parameter_summary", {})
                     if execution and isinstance(execution.get("same_file_parameter_summary", {}), dict)
                     else {})
        status = execution.get("static_status") if execution else None
        extraction_status = execution.get("dex_extraction_status") if execution and name == "multidex" else None
        class_comparison = execution.get("dex_class_output_comparison", {}) if execution and name == "multidex" else {}
        if name == "split_apk_aab" and execution:
            run_state = ("single_apk_split_attribute_observed" if execution.get("is_split_manifest")
                         else "single_apk_attribute_absent_set_not_assessed")
        elif extraction_status == "matched":
            run_state = "input_inventory_matched_not_analysis"
        elif extraction_status == "mismatch":
            run_state = "input_inventory_mismatch"
        elif extraction_status == "incomplete_or_ambiguous_mapping":
            run_state = "incomplete_or_ambiguous_inventory"
        elif extraction_status == "not_applicable":
            run_state = "not_applicable"
        elif name == "multidex" and execution and execution.get("status") == "measured_input_inventory":
            run_state = "input_inventory_only"
        elif not execution:
            run_state = "not_tested"
        elif status in {"completed", "analyzed", "analyzed_heuristically", "completed_heuristically"}:
            run_state = "analyzed_bounded"
        elif status in {"partial", "fallback_lexical"}:
            run_state = "analyzed_partial"
        elif status == "not_applicable":
            run_state = "not_applicable"
        elif status in {"not_started", "not_tested", "not_selected"}:
            run_state = "not_tested"
        else:
            run_state = "incomplete_or_skipped"
        descriptor_comparison = (execution.get("dex_class_descriptor_comparison", {})
                                 if execution and name == "multidex" else {})
        if not isinstance(descriptor_comparison, dict):
            descriptor_comparison = {}
        rows[name] = {
            "support_level": support,
            "framework_signature_state": (
                "detected" if _FRAMEWORK_NAMES.get(name) in detected_frameworks else
                "detection_incomplete" if detection_recorded and detector_coverage_recorded and detector_truncated and name in _FRAMEWORK_NAMES else
                "signature_not_detected" if detection_recorded and detector_coverage_recorded and not detector_truncated and name in _FRAMEWORK_NAMES else
                "not_recorded"
            ),
            "execution_state": run_state,
            "static_status": status or "not_recorded",
            "input_inventory_status": extraction_status or "not_recorded",
            "dex_class_output_comparison_status": class_comparison.get("status") if isinstance(class_comparison, dict) else None,
            "dex_class_output_count_delta": class_comparison.get("count_delta") if isinstance(class_comparison, dict) else None,
            "dex_class_descriptor_comparison_status": descriptor_comparison.get("status"),
            "dex_classes_missing_from_smali": descriptor_comparison.get("missing_from_smali_count"),
            "dex_classes_extra_in_smali": descriptor_comparison.get("extra_smali_count"),
            "dex_class_descriptor_comparison_by_member": descriptor_comparison.get("per_member", {}),
            "source_files_skipped": input_execution.get("source_files_skipped") if input_execution else None,
            "source_file_skip_reasons": (input_execution.get("source_file_skip_reasons", {})
                                          if input_execution and isinstance(input_execution.get("source_file_skip_reasons", {}), dict)
                                          else {}),
            "limit_reasons": (input_execution.get("limit_reasons", {})
                              if input_execution and isinstance(input_execution.get("limit_reasons", {}), dict)
                              else {}),
            "same_file_parameter_summary": {
                key: summaries[key] for key in (
                    "direct_summaries", "transitive_summaries",
                    "files_with_transitive_summaries", "round_limit_files",
                    "candidate_limit_files",
                    "max_rounds_per_file", "proof_status",
                ) if key in summaries
            },
            "coverage_path": path,
            "limitations": [limitation],
            "evidence_state": "not_tested",
            "proof_status": "not_proven",
        }
    detected = framework_info.get("framework", "not_recorded")
    return {
        "schema_version": 1,
        "detected_framework_hint": detected,
        "framework_detection_evidence": framework_info.get("detection_evidence", []),
        "framework_detection_notes": framework_info.get("analysis_notes", []),
        "framework_detection_inventory_state": (
            "incomplete" if detector_truncated else "complete_within_detector_limits"
            if isinstance(detection_coverage, dict) and detection_coverage.get("static_status") == "analyzed_heuristically"
            else "not_recorded"
        ),
        "formats": rows,
        "exhaustive": False,
        "security_verdict": "not_established",
        "limitations": [
            "Support labels describe implemented bounded behavior, not measured recall or accuracy.",
            "Detection of a framework does not mean its application code was analyzed.",
            "No absence-of-findings or unsupported-format result means the app is safe.",
        ],
    }
