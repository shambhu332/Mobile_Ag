from mobileag.ingestion.framework_detector import FrameworkDetector
from mobileag.reporting.capability_inventory import capability_inventory


def test_framework_detector_returns_coverage_for_missing_input(tmp_path):
    detector = FrameworkDetector()

    for source in (None, "", str(tmp_path / "missing")):
        result = detector.detect(source)
        assert result["framework"] == "Unknown"
        assert result["coverage"]["static_status"] == "not_analyzed"
        assert result["coverage"]["proof_status"] == "not_proven"
        assert result["coverage"]["exhaustive"] is False


def test_framework_detector_preserves_multiple_signature_hits(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "index.android.bundle").write_bytes(b"synthetic")
    (tmp_path / "lib" / "arm64-v8a").mkdir(parents=True)
    (tmp_path / "lib" / "arm64-v8a" / "libflutter.so").write_bytes(b"synthetic")

    result = FrameworkDetector().detect(str(tmp_path))

    assert result["framework"] == "Flutter"  # historical last-match singular hint
    assert result["detected_frameworks"] == ["React Native", "Flutter"]
    assert set(result["detection_evidence"]) == {
        "assets/index.android.bundle", "lib/*/libflutter.so"
    }


def test_capability_inventory_separates_framework_signature_from_analysis():
    report = capability_inventory(
        {"react_native": {"static_status": "not_started"}},
        {"framework": "React Native", "detected_frameworks": ["React Native", "Flutter"],
         "coverage": {"static_status": "analyzed_heuristically", "limits_reached": False,
                      "source_files_skipped": 0}},
    )
    formats = report["formats"]

    assert formats["react_native"]["framework_signature_state"] == "detected"
    assert formats["react_native"]["execution_state"] == "not_tested"
    assert formats["flutter"]["framework_signature_state"] == "detected"
    assert formats["flutter"]["execution_state"] == "not_tested"
    assert formats["unity"]["framework_signature_state"] == "signature_not_detected"
    assert formats["flutter"]["proof_status"] == "not_proven"
    assert report["exhaustive"] is False


def test_missing_framework_signature_is_not_negative_when_inventory_was_incomplete():
    report = capability_inventory({}, {
        "framework": "Native", "detected_frameworks": [],
        "coverage": {"static_status": "partial", "limits_reached": True,
                     "source_files_skipped": 0},
    })
    assert report["framework_detection_inventory_state"] == "incomplete"
    assert report["formats"]["flutter"]["framework_signature_state"] == "detection_incomplete"


def test_complete_empty_framework_inventory_can_report_signature_not_detected():
    report = capability_inventory({}, {
        "framework": "Native", "detected_frameworks": [],
        "coverage": {"static_status": "analyzed_heuristically", "limits_reached": False,
                     "source_files_skipped": 0},
    })
    assert report["framework_detection_inventory_state"] == "complete_within_detector_limits"
    assert report["formats"]["flutter"]["framework_signature_state"] == "signature_not_detected"


def test_capability_inventory_marks_missing_framework_detection_unknown():
    formats = capability_inventory({}, {})["formats"]
    assert all(formats[name]["framework_signature_state"] == "not_recorded"
               for name in ("react_native", "flutter", "xamarin", "cordova", "unity"))
