from mobileag.analysis.crypto_api_auditor import CryptoApiMetadataAuditor


def test_crypto_audit_records_allowlisted_algorithms_without_source_values(tmp_path):
    source = tmp_path / "Crypto.java"
    source.write_text('''class Crypto {
  // Cipher.getInstance("CommentSecretValue")
  void run() {
    Cipher.getInstance("AES/GCM/NoPadding");
    Cipher.getInstance("AES/GCM/NoPadding");
    MessageDigest.getInstance("SHA-256");
    Cipher.getInstance("syntheticSecretValue");
    Cipher.getInstance(algorithmFromConfig);
  }
}
''')

    result = CryptoApiMetadataAuditor().audit_directory(tmp_path)

    assert result["coverage"]["static_status"] == "partial"
    assert result["coverage"]["factory_call_count"] == 5
    assert result["coverage"]["literal_algorithm_call_count"] == 3
    assert result["coverage"]["unmodeled_call_count"] == 2
    assert result["coverage"]["candidate_count"] == 3
    assert result["coverage"]["runtime_status"] == "not_tested"
    assert result["coverage"]["proof_status"] == "not_proven"
    assert result["inventory"] == [
        {"api": "java.security.MessageDigest", "algorithm": "SHA-256", "call_count": 1,
         "locations": [{"file": "Crypto.java", "line": 6}]},
        {"api": "javax.crypto.Cipher", "algorithm": "AES/GCM/NoPadding", "call_count": 2,
         "locations": [{"file": "Crypto.java", "line": 4}, {"file": "Crypto.java", "line": 5}]},
    ]
    serialized = repr(result)
    assert "syntheticSecretValue" not in serialized
    assert "CommentSecretValue" not in serialized
    assert "algorithmFromConfig" not in serialized


def test_crypto_audit_fails_closed_for_missing_or_symlink_source_roots(tmp_path):
    auditor = CryptoApiMetadataAuditor()
    assert auditor.audit_directory(None)["coverage"]["static_status"] == "not_analyzed"

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Crypto.java").write_text('Cipher.getInstance("AES/GCM/NoPadding");')
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    assert auditor.audit_directory(link)["coverage"]["static_status"] == "incomplete"


def test_crypto_audit_reports_heuristic_completion_when_all_calls_are_modeled(tmp_path):
    (tmp_path / "Crypto.kt").write_text('Cipher.getInstance("AES/GCM/NoPadding")')
    result = CryptoApiMetadataAuditor().audit_directory(tmp_path)
    assert result["coverage"]["static_status"] == "analyzed_heuristically"
    assert result["coverage"]["unmodeled_call_count"] == 0


def test_crypto_audit_propagates_partial_inventory_coverage(tmp_path):
    (tmp_path / "Crypto.java").write_text('Cipher.getInstance("AES/GCM/NoPadding");')
    (tmp_path / "Skipped.java").symlink_to(tmp_path / "Crypto.java")

    result = CryptoApiMetadataAuditor().audit_directory(tmp_path)

    assert result["coverage"]["static_status"] == "partial"
    assert result["coverage"]["source_files_skipped"] == 1
    assert result["coverage"]["exhaustive"] is False


def test_cryptography_review_surface_counts_only_static_crypto_candidates():
    from mobileag.reporting.coverage import review_surface_ledger

    row = review_surface_ledger({"crypto_metadata": {
        "static_status": "analyzed_heuristically", "runtime_status": "not_tested",
        "candidate_count": 2, "proof_status": "not_proven", "exhaustive": False,
    }})["surfaces"]["cryptography_native"]

    assert row["analysis_state"] == "analyzed"
    assert row["candidate_evidence_paths"] == ["crypto_metadata"]
    assert row["evidence_state"] == "candidate"
    assert row["proof_status"] == "not_proven"
