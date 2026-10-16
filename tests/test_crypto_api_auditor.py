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
         "locations": [{"file": "Crypto.java", "line": 6}], "locations_truncated": False},
        {"api": "javax.crypto.Cipher", "algorithm": "AES/GCM/NoPadding", "call_count": 2,
         "locations": [{"file": "Crypto.java", "line": 4}, {"file": "Crypto.java", "line": 5}],
         "locations_truncated": False},
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


def test_crypto_audit_resolves_only_adjacent_smali_string_factory_calls(tmp_path):
    (tmp_path / "Crypto.smali").write_text('''
.class public Lfixture/Crypto;
.method public run()V
    .locals 3
    # Cipher.getInstance("CommentSecretValue")
    const-string v0, "AES/GCM/NoPadding"
    .line 8
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    const-string v1, "syntheticSecretValue"
    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    const-string v2, "AES/ECB/PKCS5Padding"
    move-object v2, v0
    invoke-static {v2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
.end method
''')

    result = CryptoApiMetadataAuditor().audit_directory(tmp_path)

    assert result["coverage"]["static_status"] == "partial"
    assert result["coverage"]["smali_factory_call_count"] == 3
    assert result["coverage"]["factory_call_count"] == 3
    assert result["coverage"]["literal_algorithm_call_count"] == 1
    assert result["coverage"]["unmodeled_call_count"] == 2
    assert result["inventory"] == [{
        "api": "javax.crypto.Cipher", "algorithm": "AES/GCM/NoPadding", "call_count": 1,
        "locations": [{"file": "Crypto.smali", "line": 8}], "locations_truncated": False,
    }]
    assert "syntheticSecretValue" not in repr(result)
    assert "AES/ECB/PKCS5Padding" not in repr(result)


def test_crypto_audit_marks_truncated_source_location_samples_partial(tmp_path):
    (tmp_path / "Crypto.java").write_text('''
Cipher.getInstance("AES/GCM/NoPadding");
Cipher.getInstance("AES/GCM/NoPadding");
''')
    auditor = CryptoApiMetadataAuditor()
    auditor.MAX_LOCATIONS_PER_RECORD = 1

    result = auditor.audit_directory(tmp_path)

    assert result["coverage"]["static_status"] == "partial"
    assert result["coverage"]["location_samples_truncated_count"] == 1
    assert result["inventory"][0]["call_count"] == 2
    assert result["inventory"][0]["locations"] == [{"file": "Crypto.java", "line": 2}]
    assert result["inventory"][0]["locations_truncated"] is True


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
