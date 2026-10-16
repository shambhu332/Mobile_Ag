"""Tests for newly implemented blueprint modules: FileProvider, Unpinning, CryptoHarvester, ProviderFuzzer, and BolaFuzzer."""
import pytest
from mobileag.analysis.fileprovider_auditor import FileProviderAuditor
from mobileag.dast.unpinning_engine import UnpinningEngine, UnpinningConfig
from mobileag.dast.crypto_harvester import CryptoHarvester
from mobileag.dast.provider_fuzzer import ContentProviderFuzzer
from mobileag.dast.bola_fuzzer import BolaFuzzer


def test_fileprovider_auditor_detects_dangerous_root_path():
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <paths xmlns:android="http://schemas.android.com/apk/res/android">
        <root-path name="root" path="." />
        <external-path name="ext" path="." />
        <files-path name="internal_files" path="safe_dir/" />
    </paths>
    """
    auditor = FileProviderAuditor()
    result = auditor.audit_xml_content(xml_content, "res/xml/file_paths.xml")

    assert len(result.entries) == 3
    assert len(result.findings) == 2  # root-path and external-path with "."
    assert any(f.metadata.get("tag") == "root-path" and f.severity == "HIGH" for f in result.findings)
    assert any(f.metadata.get("tag") == "external-path" and f.severity == "MEDIUM" for f in result.findings)
    assert all("does not establish exposure" in finding.description for finding in result.findings)
    assert all("unauthorized third-party apps" not in finding.description for finding in result.findings)

    # A root-relative subdirectory is not the whole filesystem and should not
    # inherit the broad-root finding solely because of its tag.
    narrow = '<paths><root-path name="limited" path="cache/mobileag/" /></paths>'
    assert FileProviderAuditor().audit_xml_content(narrow).findings == []
    first_id = result.findings[0].id
    second_id = auditor.audit_xml_content(xml_content, "res/xml/file_paths.xml").findings[0].id
    assert first_id == second_id


def test_openapi_export_replaces_symlink_atomically_with_private_file(tmp_path):
    import json
    import os
    from mobileag.dast.api_cataloger import MobileApiCataloger

    victim = tmp_path / "victim.txt"
    victim.write_text("unchanged")
    output = tmp_path / "openapi.json"
    output.symlink_to(victim)

    saved = MobileApiCataloger().save_openapi(output)

    assert saved == output
    assert victim.read_text() == "unchanged"
    assert not output.is_symlink()
    assert json.loads(output.read_text())["openapi"] == "3.0.0"
    assert os.stat(output).st_mode & 0o077 == 0


def test_openapi_export_size_cap_fails_before_destination_write(tmp_path, monkeypatch):
    import pytest
    import mobileag.dast.api_cataloger as api_cataloger

    output = tmp_path / "openapi.json"
    monkeypatch.setattr(api_cataloger, "_MAX_OPENAPI_BYTES", 10)
    with pytest.raises(ValueError, match="size limit"):
        api_cataloger.MobileApiCataloger().save_openapi(output)
    assert not output.exists()


def test_api_catalog_retains_bounded_owned_request_snapshot():
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    request = CapturedRequest(
        "POST", "https://api.example.test/v1/profile", headers={"X-Test": "before"},
        query_params={"page": "1"}, body='{"name":"before"}',
        response_body='{"status":"before"}', response_headers={"X-Response": "before"},
    )
    catalog = MobileApiCataloger()
    catalog.ingest_request(request)

    request.method = "DELETE"
    request.url = "https://attacker.invalid/changed"
    request.headers["X-Test"] = "after"
    request.query_params["page"] = "changed"
    request.body = "after"
    request.response_body = "after"
    request.response_headers["X-Response"] = "after"

    captured = catalog.captured_requests[0]
    assert captured.method == "POST"
    assert captured.url == "https://api.example.test/v1/profile"
    assert captured.headers == {"X-Test": "before"}
    assert captured.query_params == {"page": "1"}
    assert captured.body == '{"name":"before"}'
    assert captured.response_body == '{"status":"before"}'
    assert captured.response_headers == {"X-Response": "before"}
    assert catalog.export_har_json()["log"]["entries"][0]["request"]["method"] == "POST"


def test_api_json_schema_samples_large_objects_without_materializing_all_items():
    from mobileag.dast.api_cataloger import MobileApiCataloger

    class BoundedIterationDict(dict):
        visited = 0

        def items(self):
            for item in super().items():
                self.visited += 1
                yield item

    value = BoundedIterationDict((f"key-{index}", "sample") for index in range(10_000))
    schema = MobileApiCataloger._json_schema(value)

    assert len(schema["properties"]) == 100
    assert schema["x-mobileag-truncated-properties"] is True
    assert value.visited == 100


def test_fileprovider_parent_path_is_review_candidate_not_exploit_claim():
    result = FileProviderAuditor().audit_xml_content(
        '<paths><files-path name="reports" path="reports/../" />'
        '<files-path name="literal-dots" path="images.." /></paths>')

    assert len(result.findings) == 1
    candidate = result.findings[0]
    assert candidate.title == "Review FileProvider Parent-Path Segment (files-path)"
    assert candidate.severity == "INFO"
    assert candidate.status == "UNVERIFIED"
    assert "canonicalization" in candidate.metadata["risk_reason"]


@pytest.mark.parametrize("path", ["", "."])
def test_fileprovider_flags_broad_external_media_root_as_unverified_candidate(path):
    result = FileProviderAuditor().audit_xml_content(
        f'<paths><external-media-path name="media" path="{path}" /></paths>')

    assert len(result.findings) == 1
    candidate = result.findings[0]
    assert candidate.metadata["tag"] == "external-media-path"
    assert candidate.status == "UNVERIFIED"
    assert "external-media-path" in candidate.metadata["risk_reason"]


@pytest.mark.parametrize("tag", ["files-path", "cache-path"])
@pytest.mark.parametrize("path", ["", "."])
def test_fileprovider_broad_internal_roots_are_info_candidates(tag, path):
    result = FileProviderAuditor().audit_xml_content(
        f'<paths><{tag} name="all" path="{path}" /></paths>')

    assert len(result.findings) == 1
    candidate = result.findings[0]
    assert candidate.severity == "INFO"
    assert candidate.status == "UNVERIFIED"
    assert "app's internal" in candidate.metadata["risk_reason"]


@pytest.mark.parametrize("path", ["./", ".//.", "///"])
def test_fileprovider_normalizes_equivalent_broad_root_spellings(path):
    result = FileProviderAuditor().audit_xml_content(
        f'<paths><files-path name="all" path="{path}" /></paths>')

    assert len(result.findings) == 1
    assert result.findings[0].severity == "INFO"
    assert result.findings[0].status == "UNVERIFIED"


def test_fileprovider_resource_scan_is_bounded_unique_and_reports_parse_errors(tmp_path):
    xml_dir = tmp_path / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "paths.xml").write_text('<paths><root-path name="root" path="." /></paths>')
    (xml_dir / "broken.xml").write_text('<paths><root-path name="broken"')
    # This non-FileProvider file must not consume matching-file byte budget.
    unrelated = tmp_path / "assets" / "xml"
    unrelated.mkdir(parents=True)
    (unrelated / "ignored.xml").write_text('x' * (2 * 1024 * 1024 + 1))

    auditor = FileProviderAuditor()
    results = auditor.audit_resource_directory(str(tmp_path))

    assert len(results) == 2  # No recursive/direct-glob duplicates.
    broken = next(result for result in results if result.xml_path.endswith("broken.xml"))
    assert broken.parse_status == "invalid"
    assert broken.error_code == "xml_parse_error"
    paths_result = next(result for result in results if result.xml_path.endswith("paths.xml"))
    assert len(paths_result.findings) == 1
    assert auditor.coverage["static_status"] == "analyzed_heuristically"
    assert auditor.coverage["fileprovider_xml_candidates"] == 2
    assert auditor.coverage["fileprovider_xml_parse_errors"] == 1
    assert auditor.coverage["fileprovider_xml_error_codes"] == {"xml_parse_error": 1}


def test_fileprovider_resource_scan_reports_oversized_candidate_as_partial(tmp_path):
    xml_dir = tmp_path / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "huge.xml").write_bytes(b"<paths>" + b"x" * (2 * 1024 * 1024))

    auditor = FileProviderAuditor()
    assert auditor.audit_resource_directory(str(tmp_path)) == []
    assert auditor.coverage["static_status"] == "partial"
    assert auditor.coverage["source_file_skip_reasons"]["file_size_limit"] == 1


def test_fileprovider_parser_bounds_direct_xml_input_and_validates_root():
    auditor = FileProviderAuditor()
    too_large = auditor.audit_xml_content(" " * (FileProviderAuditor.MAX_XML_CHARS + 1))
    assert too_large.parse_status == "invalid"
    assert too_large.error_code == "xml_size_limit"
    wrong_root = auditor.audit_xml_content('<not-paths><root-path name="root" path="." /></not-paths>')
    assert wrong_root.parse_status == "invalid"
    assert wrong_root.error_code == "unexpected_root_element"


def test_fileprovider_parser_caps_path_entries_and_marks_partial_coverage():
    xml = "<paths>" + "<files-path name='n' path='subdir'/>" * (
        FileProviderAuditor.MAX_PATH_ENTRIES + 1) + "</paths>"

    result = FileProviderAuditor().audit_xml_content(xml)

    assert result.parse_status == "partial"
    assert result.error_code == "xml_path_entry_limit"
    assert len(result.entries) == FileProviderAuditor.MAX_PATH_ENTRIES


def test_fileprovider_parser_does_not_retain_oversized_path_attributes():
    oversized_path = "x" * (FileProviderAuditor.MAX_ATTRIBUTE_CHARS + 1)
    result = FileProviderAuditor().audit_xml_content(
        f"<paths><root-path name='root' path='{oversized_path}'/></paths>")

    assert result.parse_status == "partial"
    assert result.error_code == "xml_path_attribute_limit"
    assert result.entries == []
    assert result.findings == []


def test_fileprovider_streaming_parse_discards_candidates_if_tail_is_malformed():
    result = FileProviderAuditor().audit_xml_content(
        "<paths><root-path name='root' path='.'/></paths><broken>")

    assert result.parse_status == "invalid"
    assert result.error_code == "xml_parse_error"
    assert result.entries == []
    assert result.findings == []


def test_fileprovider_parser_rejects_non_string_input():
    result = FileProviderAuditor().audit_xml_content(None)

    assert result.parse_status == "invalid"
    assert result.error_code == "xml_input_type"


def test_fileprovider_streaming_parser_caps_nested_xml_depth():
    nested = "<x>" * FileProviderAuditor.MAX_XML_DEPTH + "</x>" * FileProviderAuditor.MAX_XML_DEPTH
    result = FileProviderAuditor().audit_xml_content(f"<paths><files-path name='n' path='x'>{nested}</files-path></paths>")

    assert result.parse_status == "partial"
    assert result.error_code == "xml_depth_limit"


@pytest.mark.parametrize("declaration", [
    '<!DOCTYPE paths [<!ENTITY marker "synthetic">]>',
    '<!DOCTYPE paths SYSTEM "file:///tmp/researcher-controlled-nonexistent">',
])
def test_fileprovider_parser_rejects_dtds_and_entities(declaration):
    payload = f'{declaration}<paths><root-path name="root" path="." /></paths>'
    result = FileProviderAuditor().audit_xml_content(payload)

    assert result.parse_status == "invalid"
    assert result.error_code == "xml_dtd_entity_rejected"
    assert result.entries == []
    assert result.findings == []


def test_unpinning_engine_refuses_bypass_generation():
    engine = UnpinningEngine()
    config = UnpinningConfig(target_package="org.example.synthetic")
    with pytest.raises(NotImplementedError, match="TLS verification bypass generation is disabled"):
        engine.generate_script(config)


def test_crypto_harvester_refuses_scripts_and_discards_sensitive_fields():
    harvester = CryptoHarvester()
    with pytest.raises(NotImplementedError, match="raw key, IV, and plaintext collection is out of scope"):
        harvester.generate_hook_script()

    event = harvester.parse_event({
        "type": "crypto_event",
        "operation": "ENCRYPT",
        "algorithm": "AES/CBC/PKCS5Padding",
        "key": "00112233445566778899aabbccddeeff",
        "iv": "0102030405060708090a0b0c0d0e0f10",
    })
    assert event is not None
    assert event.operation == "ENCRYPT"
    assert event.algorithm == "AES/CBC/PKCS5Padding"
    assert not hasattr(event, "key_hex")
    assert not hasattr(event, "iv_hex")
    assert "00112233445566778899aabbccddeeff" not in repr(event)

    sqlcipher_event = harvester.parse_event({
        "type": "crypto_event",
        "operation": "SQLCIPHER_KEY",
        "algorithm": "SQLCipher-256",
        "key": "SecretDbPassword123",
    })
    assert sqlcipher_event is not None
    assert "SecretDbPassword123" not in repr(sqlcipher_event)
    assert harvester.parse_event({"type": "crypto_payload", "input_preview": "synthetic plaintext"}) is None
    assert sqlcipher_event.operation == "SQLCIPHER_KEY"



def test_provider_fuzzer_traversal_and_sqli_payloads():
    fuzzer = ContentProviderFuzzer(adb_path="echo")
    scope = lambda: None
    results = fuzzer.fuzz_provider_traversal(
        "com.example.provider", "com.example.app", serial="synthetic-device", guard=scope,
        synthetic_data_confirmed=True,
    )
    assert len(results) == len(ContentProviderFuzzer.TRAVERSAL_PAYLOADS)
    assert all("mobileag_synthetic_canary" in r.target_uri for r in results)

    sqli_results = fuzzer.fuzz_provider_sqli(
        "com.example.provider", serial="synthetic-device", guard=scope,
        synthetic_data_confirmed=True,
    )
    assert len(sqli_results) == 2 * len(ContentProviderFuzzer.SQLI_PROBES)
    assert {item.action for item in sqli_results} == {"selection", "projection"}


def test_provider_fuzzer_requires_scoped_device_and_quotes_remote_shell_arguments(monkeypatch):
    import io
    import shlex
    import subprocess

    fuzzer = ContentProviderFuzzer(adb_path="adb")
    called = []
    class FakeProcess:
        def __init__(self, *args, **kwargs):
            called.append((args, kwargs))
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"Permission Denial")
        def wait(self, timeout=None):
            return 1
        def kill(self):
            pass

    monkeypatch.setattr(subprocess, "Popen", FakeProcess)
    blocked = fuzzer.fuzz_provider_traversal("com.example.provider", "com.example.app")
    assert len(blocked) == 1 and blocked[0].status == "BLOCKED_SCOPE"
    invalid = fuzzer.fuzz_provider_traversal("provider; id", "com.example.app",
                                             serial="synthetic-device", guard=lambda: None)
    assert len(invalid) == 1 and invalid[0].status == "INVALID_INPUT"
    assert called == []

    unconfirmed_traversal = fuzzer.fuzz_provider_traversal(
        "com.example.provider", "com.example.app", serial="synthetic-device", guard=lambda: None,
    )
    unconfirmed_query = fuzzer.fuzz_provider_sqli(
        "com.example.provider", serial="synthetic-device", guard=lambda: None,
    )
    assert [result.status for result in unconfirmed_traversal] == ["BLOCKED_SYNTHETIC_SCOPE"]
    assert [result.status for result in unconfirmed_query] == ["BLOCKED_SYNTHETIC_SCOPE"]
    assert called == []

    guarded_calls = []
    def guard():
        guarded_calls.append(True)

    results = fuzzer.fuzz_provider_traversal(
        "com.example.provider", "com.example.app", serial="synthetic-device", guard=guard,
        synthetic_data_confirmed=True,
    )
    assert len(results) == len(ContentProviderFuzzer.TRAVERSAL_PAYLOADS)
    assert len(called) == len(ContentProviderFuzzer.TRAVERSAL_PAYLOADS)
    assert len(guarded_calls) == len(called)
    command = called[0][0][0]
    assert command[:4] == ["adb", "-s", "synthetic-device", "shell"]
    remote_args = shlex.split(command[4])
    assert remote_args[:2] == ["content", "read"]


def test_provider_fuzzer_honors_explicit_scope_guard_denial(monkeypatch):
    import subprocess
    from mobileag.dast.provider_fuzzer import ContentProviderFuzzer

    def forbidden_process(*args, **kwargs):
        raise AssertionError("denied provider probe must not launch ADB")

    monkeypatch.setattr(subprocess, "Popen", forbidden_process)
    fuzzer = ContentProviderFuzzer(adb_path="adb")
    guard_calls = []

    def deny_scope():
        guard_calls.append(True)
        return False

    traversal = fuzzer.fuzz_provider_traversal(
        "com.example.provider", "com.example.app", serial="synthetic-device", guard=deny_scope,
        synthetic_data_confirmed=True,
    )
    sql = fuzzer.fuzz_provider_sqli(
        "com.example.provider", serial="synthetic-device", guard=deny_scope,
        synthetic_data_confirmed=True,
    )
    assert traversal and all(result.status == "BLOCKED_SCOPE" for result in traversal)
    assert sql and all(result.status == "BLOCKED_SCOPE" for result in sql)
    assert len(guard_calls) == len(traversal) + len(sql)


def test_bola_fuzzer_candidate_extraction_and_discrepancy():
    fuzzer = BolaFuzzer()
    url = "https://api.example.com/v1/users/usr_98472/orders?account_id=acc_1122"
    candidates = fuzzer.extract_resource_candidates(url)
    assert "usr_98472" in candidates
    assert "acc_1122" in candidates


def test_bola_candidate_extraction_fails_closed_on_unbounded_or_malformed_urls():
    fuzzer = BolaFuzzer()
    over_limit_query = "&".join(f"account_id={i}" for i in range(101))
    assert fuzzer.extract_resource_candidates(
        f"https://api.example.com/v1/orders/order_1?{over_limit_query}"
    ) == []
    assert fuzzer.extract_resource_candidates("https://[malformed/v1/orders/order_1") == []
    assert fuzzer.extract_resource_candidates("https://api.example.com:70000/orders/order_1") == []
    assert fuzzer.extract_resource_candidates("x" * 8193) == []

    candidates = fuzzer.extract_resource_candidates(
        "https://api.example.com/v1/orders/order_1?account_id=acc_1122"
    )
    assert candidates == ["order_1", "acc_1122"]


def test_bola_candidate_extraction_omits_credential_bearing_query_values():
    fuzzer = BolaFuzzer()
    candidates = fuzzer.extract_resource_candidates(
        "https://api.example.com/v1/users/user_123"
        "?user_id=user_456&accountId=acc_789&user_token=synthetic-token"
        "&accessToken=second-token&authorization=Bearer-secret&author_id=writer_1"
    )

    assert candidates == ["user_123", "user_456", "acc_789", "writer_1"]


def test_bola_candidate_extraction_rejects_query_id_control_and_whitespace_values():
    candidates = BolaFuzzer().extract_resource_candidates(
        "https://api.example.com/v1/orders/order_1"
        "?order_id=valid_123&account_id=bad%0aInjected&user_id=two%20words"
    )

    assert candidates == ["order_1", "valid_123"]


def test_bola_candidate_query_keys_use_identifier_tokens_not_substrings():
    candidates = BolaFuzzer().extract_resource_candidates(
        "https://api.example.test/v1/resources?grid=blue&valid_id=item_123&orderId=order_456"
    )

    assert candidates == ["item_123", "order_456"]


def test_bola_result_redacts_short_credentials_in_sensitive_path_segments():
    import json

    fuzzer = BolaFuzzer()
    endpoint = (
        "https://synthetic-user:synthetic-password@api.example.test/v1/auth/%74oken/short-live-secret"
        "?access_token=query-secret#fragment-secret"
    )
    result = fuzzer.evaluate_response_discrepancy(
        endpoint=endpoint, method="GET", resource_id="short-live-secret",
        status_code=200, response_body="synthetic response",
    )

    assert result.endpoint == "https://api.example.test/v1/auth/%74oken/{redacted}"
    serialized = json.dumps(result.__dict__)
    for secret in (
        "synthetic-user", "synthetic-password", "short-live-secret",
        "query-secret", "fragment-secret",
    ):
        assert secret not in serialized


def test_bola_response_evidence_hash_is_bounded_and_marks_truncation():
    import hashlib

    fuzzer = BolaFuzzer()
    response = "a" * (BolaFuzzer.MAX_RESPONSE_CHARS + 10) + "synthetic-canary"
    result = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/orders/order_1", method="GET", resource_id="order_1",
        status_code=200, response_body=response, user_a_marker="synthetic-canary",
    )
    assert result.response_hash_status == "truncated"
    assert result.response_sha256 == hashlib.sha256(
        ("a" * BolaFuzzer.MAX_RESPONSE_CHARS).encode()
    ).hexdigest()
    assert result.marker_observed is False
    assert result.is_vulnerable is False

    invalid = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/orders/order_1", method="GET", resource_id="order_1",
        status_code=200, response_body=None, user_a_marker="canary",
    )
    assert invalid.response_sha256 == ""
    assert invalid.response_hash_status == "invalid_input"


def test_bola_evaluator_sanitizes_method_status_and_bounds_canary_input():
    result = BolaFuzzer().evaluate_response_discrepancy(
        endpoint="/v1/orders/order_1", method="GET\r\nX-Leak: synthetic",
        resource_id="order_1", status_code="200", response_body="canary",
        user_a_marker="canary",
    )
    assert result.method == "UNKNOWN"
    assert result.status_code == 0
    assert result.is_vulnerable is False
    assert result.candidate_observed is False
    assert result.proof_status == "not_proven"
    assert "Invalid HTTP status" in result.evidence_reason

    oversized_marker = BolaFuzzer().evaluate_response_discrepancy(
        endpoint="/v1/orders/order_1", method="GET", resource_id="order_1",
        status_code=200, response_body="x" * 1000, user_a_marker="x" * 1000,
    )
    assert oversized_marker.marker_observed is False
    assert oversized_marker.candidate_observed is False


def test_bola_dual_session_observation_requires_a_control_and_b_canary_match():
    fuzzer = BolaFuzzer()
    positive = fuzzer.evaluate_dual_session_observations(
        endpoint="https://api.example.test/v1/orders/order_1?account=synthetic",
        method="GET", resource_id="order_1",
        account_a_status=200, account_a_response_body='{"canary":"synthetic-account-a-marker"}',
        account_b_status=206, account_b_response_body='{"canary":"synthetic-account-a-marker"}',
        account_a_marker="synthetic-account-a-marker",
    )
    assert positive.is_vulnerable is False
    assert positive.candidate_observed is True
    assert positive.proof_status == "not_proven"
    assert positive.reference_marker_observed is True
    assert positive.marker_observed is True
    assert positive.comparison_status == "canary_observed_in_both_responses"
    assert "synthetic-account-a-marker" not in positive.evidence_reason

    missing_control = fuzzer.evaluate_dual_session_observations(
        endpoint="/v1/orders/order_1", method="GET", resource_id="order_1",
        account_a_status=200, account_a_response_body='{"canary":"other"}',
        account_b_status=200, account_b_response_body='{"canary":"synthetic-account-a-marker"}',
        account_a_marker="synthetic-account-a-marker",
    )
    assert missing_control.is_vulnerable is False
    assert missing_control.comparison_status == "reference_not_established"

    denied = fuzzer.evaluate_dual_session_observations(
        endpoint="/v1/orders/order_1", method="GET", resource_id="order_1",
        account_a_status=200, account_a_response_body='{"canary":"synthetic-account-a-marker"}',
        account_b_status=403, account_b_response_body='{"error":"denied"}',
        account_a_marker="synthetic-account-a-marker",
    )
    assert denied.is_vulnerable is False
    assert denied.comparison_status == "canary_not_observed_in_b_response"

    # Positive test: User B receives User A's data
    res_vuln = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/users/usr_98472",
        method="GET",
        resource_id="usr_98472",
        status_code=200,
        response_body='{"user_id": "usr_98472", "email": "victim@example.com"}',
        user_a_marker="victim@example.com",
    )
    assert res_vuln.is_vulnerable is False
    assert res_vuln.candidate_observed is True
    assert res_vuln.proof_status == "not_proven"
    assert res_vuln.marker_observed is True
    assert "victim@example.com" not in res_vuln.evidence_reason
    assert res_vuln.response_body_preview == ""
    assert len(res_vuln.response_sha256) == 64

    safe_record = fuzzer.evaluate_response_discrepancy(
        endpoint="https://alice:synthetic-pass@api.example.test/v1/users/usr_98472?access_token=synthetic-token",
        method="GET",
        resource_id="usr_98472",
        status_code=200,
        response_body="{\"email\":\"synthetic@example.test\"}",
        user_a_marker="synthetic@example.test",
    )
    assert safe_record.endpoint == "https://api.example.test/v1/users/{id1}"
    assert safe_record.resource_id == "[REDACTED]"
    assert "synthetic-pass" not in safe_record.endpoint
    assert "synthetic-token" not in safe_record.endpoint
    assert "usr_98472" not in safe_record.endpoint

    # Negative test: 403 Forbidden
    res_safe = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/users/usr_98472",
        method="GET",
        resource_id="usr_98472",
        status_code=403,
        response_body='{"error": "Forbidden"}',
    )
    assert res_safe.is_vulnerable is False

    # HTTP 200 with arbitrary response content is not enough to prove BOLA.
    ambiguous = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/orders/order_123", method="GET", resource_id="order_123",
        status_code=200, response_body='{"status":"ok","id":"order_123"}',
    )
    assert ambiguous.is_vulnerable is False
    assert ambiguous.marker_observed is False
    assert "ownership and confidentiality are unverified" in ambiguous.evidence_reason


def test_provider_fuzzer_success_is_observation_not_vulnerability(monkeypatch):
    import io
    import json
    import mobileag.dast.provider_fuzzer as provider_module

    class FakeProcess:
        def __init__(self, *args, **kwargs):
            self.stdout = io.BytesIO(
                b"Row: 0 _id=1 name=synthetic-provider-private-value " + b"x" * 100_000
            )
            self.stderr = io.BytesIO(b"")
        def wait(self, timeout=None):
            return 0
        def kill(self):
            pass

    monkeypatch.setattr(provider_module.subprocess, "Popen", FakeProcess)
    fuzzer = ContentProviderFuzzer(adb_path="adb")
    scope_guard = lambda: None
    traversal = fuzzer.fuzz_provider_traversal(
        "com.example.provider", "com.example.app", serial="synthetic-device", guard=scope_guard,
        synthetic_data_confirmed=True,
    )
    sql = fuzzer.fuzz_provider_sqli(
        "com.example.provider", serial="synthetic-device", guard=scope_guard,
        synthetic_data_confirmed=True,
    )
    assert traversal[0].status == "OBSERVED_READABLE"
    assert sql[0].status == "QUERY_RESULT_OBSERVED"
    assert all("VULNERABLE" not in item.status for item in traversal + sql)
    assert all(not item.output_snippet for item in traversal + sql)
    assert all(item.output_truncated for item in traversal + sql)
    assert all(item.output_bytes_observed > 100_000 for item in traversal + sql)
    assert "synthetic-provider-private-value" not in json.dumps([item.__dict__ for item in traversal + sql])


def test_provider_sqli_permission_denial_precedes_sql_error_wording(monkeypatch):
    import io
    import mobileag.dast.provider_fuzzer as provider_module

    class FakeProcess:
        def __init__(self, *args, **kwargs):
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"SecurityException: SQLite syntax error")
        def wait(self, timeout=None):
            return 1
        def kill(self):
            pass

    monkeypatch.setattr(provider_module.subprocess, "Popen", FakeProcess)
    results = ContentProviderFuzzer(adb_path="adb").fuzz_provider_sqli(
        "com.example.provider", serial="synthetic-device", guard=lambda: None,
        synthetic_data_confirmed=True,
    )

    assert results
    assert all(result.status == "ACCESS_DENIED" for result in results)
    assert all(result.output_snippet == "" for result in results)


def test_provider_fuzzer_sqli_covers_projection_and_selection_with_shell_quoting(monkeypatch):
    import io
    import shlex
    import subprocess
    from mobileag.dast.provider_fuzzer import ContentProviderFuzzer

    commands = []
    class FakeProcess:
        def __init__(self, *args, **kwargs):
            commands.append(args[0])
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")
        def wait(self, timeout=None):
            return 1
        def kill(self):
            pass

    monkeypatch.setattr(subprocess, "Popen", FakeProcess)
    fuzzer = ContentProviderFuzzer(adb_path="adb")
    results = fuzzer.fuzz_provider_sqli(
        "com.example.provider", projection_param="name); SELECT synthetic",
        serial="synthetic-device", guard=lambda: None, synthetic_data_confirmed=True,
    )
    assert len(results) == 2 * len(fuzzer.SQLI_PROBES)
    assert {result.action for result in results} == {"selection", "projection"}
    parsed_commands = [shlex.split(command[4]) for command in commands]
    assert any("--where" in command for command in parsed_commands)
    assert any("--projection" in command for command in parsed_commands)
    assert any("name); SELECT synthetic" in command for command in parsed_commands)
    assert len(commands) == len(results)


def test_poc_synthesizer_task_hijacking_and_provider_sqli():
    from mobileag.generators.poc_apk_synthesizer import ExploitPocSynthesizer
    from mobileag.reporting.finding import Finding, Severity

    synth = ExploitPocSynthesizer()

    # 1. Task Hijacking
    f_task = Finding(
        id="TASK_AFFINITY_HIJACK",
        title="Task Affinity Hijacking Risk: com.example.app.LoginActivity",
        description="Task affinity mismatch",
        severity=Severity.HIGH,
        cwe_id="CWE-1021",
        affected_component="com.example.app.LoginActivity",
        metadata={"task_affinity": "com.example.target.affinity"}
    )
    poc_task = synth.synthesize(f_task, "com.example.target")
    assert poc_task is None

    # 2. ContentProvider SQL Injection
    f_sqli = Finding(
        id="CONTENT_PROVIDER_SQLI",
        title="ContentProvider SQL Injection Vulnerability",
        description="Unsanitized query projection",
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        affected_component="com.example.target.DataProvider",
        metadata={"authority": "com.example.target.provider"}
    )
    poc_sqli = synth.synthesize(f_sqli, "com.example.target")
    assert poc_sqli is None
    # Unverified candidate findings must not produce executable guidance.


def test_traffic_auditor_catalog_and_shadow_api():
    from mobileag.dast.traffic_auditor import TrafficAuditor, HTTPTransaction

    auditor = TrafficAuditor()
    txs = [
        HTTPTransaction(
            url="https://api.example.com/v1/users/me?include_orders=true",
            method="GET",
            request_headers={"Authorization": "Bearer sample_token"},
            response_status=200,
        ),
        HTTPTransaction(
            url="https://api.example.com/v1/hidden/debug",
            method="POST",
            request_headers={},
            response_status=200,
        ),
    ]

    cataloger = auditor.catalog_traffic(txs, title="Sample App APIs")
    openapi = cataloger.export_openapi_json()
    assert openapi["openapi"] == "3.0.0"
    assert "/v1/users/me" in openapi["paths"]
    assert "/v1/hidden/debug" in openapi["paths"]

    # Detect shadow API not declared in static attack surface
    declared = ["https://api.example.com/v1/users/me"]
    shadow_findings = auditor.find_shadow_apis(txs, declared)
    assert len(shadow_findings) == 1
    assert "/v1/hidden/debug" in shadow_findings[0].affected_component


def test_traffic_audit_recognizes_ipv4_and_ipv6_loopback_hosts():
    from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor

    auditor = TrafficAuditor()
    loopback_http = auditor.audit_transactions([
        HTTPTransaction(url="http://localhost/v1/items"),
        HTTPTransaction(url="http://127.0.0.2/v1/items"),
        HTTPTransaction(url="http://[::1]/v1/items"),
    ])
    assert not any(f.cwe_id == "CWE-319" for f in loopback_http)
    loopback_https = auditor.audit_transactions([HTTPTransaction(url="https://[::1]/v1/items")])
    assert not any(f.cwe_id == "CWE-16" for f in loopback_https)
    external_http = auditor.audit_transactions([HTTPTransaction(url="http://192.0.2.3/v1/items")])
    assert any(f.cwe_id == "CWE-319" for f in external_http)


def test_traffic_audit_reports_incomplete_query_review_after_field_cap():
    from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor

    query = "&".join(f"q{i}=x" for i in range(256)) + "&access_token=synthetic-query-secret"
    findings = TrafficAuditor().audit_transactions([
        HTTPTransaction(url=f"https://api.example.test/v1/items?{query}")
    ])
    coverage = [f for f in findings if f.detection_method == "TrafficAuditor (Coverage Limit)"]
    assert len(coverage) == 1
    assert coverage[0].metadata == {"analysis_state": "incomplete", "max_query_fields": 256}
    assert not any(f.cwe_id == "CWE-598" for f in findings)
    assert "synthetic-query-secret" not in str(coverage[0].model_dump(mode="json"))


def test_traffic_audit_findings_do_not_retain_credentials_or_dynamic_path_values():
    import json
    from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor

    secrets = ("alice", "synthetic-password", "987654321", "person@example.invalid",
               "synthetic-query-secret", "synthetic-cookie-value", "synthetic-header-marker")
    tx = HTTPTransaction(
        url=("http://alice:synthetic-password@api.example.test/accounts/987654321/"
             "person@example.invalid?token=synthetic-query-secret"),
        method="GET",
        response_headers={"Set-Cookie": "session_id=synthetic-cookie-value; Path=/",
                          "Cache-Control": "private, max-age=0, synthetic-header-marker"},
        response_body='{"ssn":"123-45-6789"}',
    )
    findings = TrafficAuditor().audit_transactions([tx])
    assert {finding.cwe_id for finding in findings} >= {"CWE-319", "CWE-598", "CWE-524", "CWE-639"}
    rendered = json.dumps([finding.to_dict() for finding in findings])
    for secret in secrets:
        assert secret not in rendered
    assert "/accounts/{id1}/{id2}" in rendered


def test_shadow_api_review_normalizes_ids_and_never_exports_url_secrets():
    import json
    from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor

    secret_id = "AbCdEf0123456789GhIjKlMnOpQrStUv"
    secret_query = "synthetic-private-token-value"
    txs = [
        HTTPTransaction(
            url=f"https://alice:synthetic-password@api.example.test/v1/orders/{secret_id}?token={secret_query}",
            method="GET"),
        HTTPTransaction(
            url=f"https://alice:synthetic-password@api.example.test/v1/orders/{secret_id}?token={secret_query}",
            method="POST"),
        HTTPTransaction(url="https://[malformed/v1/bad", method="GET"),
        HTTPTransaction(url="ftp://api.example.test/v1/not-http", method="GET"),
    ]
    declared = [{"method": "GET", "url": "https://api.example.test/v1/orders/{orderId}"}]

    findings = TrafficAuditor().find_shadow_apis(txs, declared)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.metadata["method"] == "POST"
    assert finding.affected_component == "/v1/orders/{id1}"
    serialized = json.dumps({
        "title": finding.title, "description": finding.description,
        "path": finding.file_path, "metadata": finding.metadata,
    })
    for secret in ("alice", "synthetic-password", secret_id, secret_query):
        assert secret not in serialized
    assert finding.status.value == "UNVERIFIED"

    same_path_other_origin = HTTPTransaction(
        url=f"https://other.example.test/v1/orders/{secret_id}", method="GET")
    host_findings = TrafficAuditor().find_shadow_apis(
        [same_path_other_origin], ["https://api.example.test/v1/orders/{orderId}"])
    assert len(host_findings) == 1
    assert host_findings[0].metadata["origin"] == "https://other.example.test"

    default_port_match = TrafficAuditor().find_shadow_apis(
        [HTTPTransaction(url="https://api.example.test:443/v1/orders/123", method="GET")],
        ["https://api.example.test/v1/orders/{orderId}"])
    assert default_port_match == []


def test_openapi_catalog_keeps_hosts_separate_and_drops_userinfo():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest("GET", "https://alice:secret@api-one.example/v1/items"))
    catalog.ingest_request(CapturedRequest("GET", "https://api-two.example/v1/items"))
    spec = catalog.export_openapi_json()
    operation = spec["paths"]["/v1/items"]["get"]
    assert operation["servers"] == [
        {"url": "https://api-one.example"}, {"url": "https://api-two.example"}
    ]
    assert "alice" not in json.dumps(spec)
    assert "secret" not in json.dumps(spec)


def test_openapi_catalog_formats_ipv6_server_origins():
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "GET", "https://[2001:db8::1]:8443/v1/items"))
    spec = catalog.export_openapi_json()
    operation = spec["paths"]["/v1/items"]["get"]
    assert operation["servers"] == [{"url": "https://[2001:db8::1]:8443"}]


def test_openapi_catalog_tracks_malformed_and_unsupported_urls_without_crashing():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    bad_requests = [
        CapturedRequest("GET", "https://[malformed?token=synthetic-secret"),
        CapturedRequest("GET", "https://api.example.test:70000/v1/bad"),
        CapturedRequest("GET", "ftp://api.example.test/v1/unsupported"),
    ]
    for request in bad_requests:
        catalog.ingest_request(request)
    catalog.ingest_request(CapturedRequest("GET", "https://api.example.test/v1/good"))

    spec = catalog.export_openapi_json()
    limits = spec["x-mobileag-capture-limits"]
    assert limits["invalidURLs"] == 3
    assert limits["unmodeledRequests"] == 3
    assert list(spec["paths"]) == ["/v1/good"]
    har = catalog.export_har_json()
    assert "synthetic-secret" not in json.dumps(har)
    assert len(har["log"]["entries"]) == 4


def test_openapi_catalog_rejects_unbounded_query_metadata():
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    too_many_url_fields = "&".join(f"k{i}=v" for i in range(101))
    catalog.ingest_request(CapturedRequest("GET", f"https://api.example.test/v1/items?{too_many_url_fields}"))
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/items", query_params={f"k{i}": "v" for i in range(101)}
    ))
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/items", query_params={"x" * 257: "v"}
    ))
    catalog.ingest_request(CapturedRequest("GET", "https://api.example.test/v1/good?search=ok"))

    spec = catalog.export_openapi_json()
    assert spec["x-mobileag-capture-limits"]["unmodeledRequests"] == 3
    assert list(spec["paths"]) == ["/v1/good"]


def test_openapi_catalog_bounds_har_retention_without_discarding_endpoint_model(monkeypatch):
    import mobileag.dast.api_cataloger as api_cataloger

    monkeypatch.setattr(api_cataloger, "_MAX_CAPTURE_BYTES", 800)
    catalog = api_cataloger.MobileApiCataloger()
    request = api_cataloger.CapturedRequest(
        "POST", "https://api.example.test/v1/items", body="x" * 100,
    )
    catalog.ingest_request(request)
    catalog.ingest_request(request)

    spec = catalog.export_openapi_json()
    limits = spec["x-mobileag-capture-limits"]
    assert len(catalog.captured_requests) == 1
    assert limits["omittedRequests"] == 1
    assert limits["maxCaptureBytes"] == 800
    assert limits["capturedBytesEstimate"] <= 800
    assert "/v1/items" in spec["paths"]
    assert len(catalog.export_har_json()["log"]["entries"]) == 1

    monkeypatch.setattr(api_cataloger, "_MAX_CAPTURE_REQUEST_BYTES", 200)
    oversized = api_cataloger.MobileApiCataloger()
    oversized.ingest_request(request)
    oversized_spec = oversized.export_openapi_json()
    assert oversized.captured_requests == []
    assert oversized_spec["x-mobileag-capture-limits"]["omittedRequests"] == 1
    assert "/v1/items" in oversized_spec["paths"]


def test_har_exports_redacted_observed_response_headers():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/profile",
        response_status=200,
        response_headers={
            "Content-Type": "application/json",
            "Set-Cookie": "session_id=synthetic-response-cookie; Path=/; Secure",
            "X-Session-ID": "synthetic-namespaced-session",
            "X-Request-Trace": "synthetic-trace-id",
        },
    ))
    har = catalog.export_har_json()
    headers = har["log"]["entries"][0]["response"]["headers"]
    assert {item["name"] for item in headers} == {
        "Content-Type", "Set-Cookie", "X-Session-ID", "X-Request-Trace"
    }
    assert "synthetic-response-cookie" not in json.dumps(har)
    assert "synthetic-namespaced-session" not in json.dumps(har)
    assert "synthetic-trace-id" in json.dumps(har)


def test_har_export_validates_content_type_and_does_not_echo_parameters():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "POST", "https://api.example.test/v1/upload",
        headers={"Content-Type": "application/json; boundary=synthetic-private-boundary"},
        body="{}",
        response_headers={"Content-Type": "application/x-synthetic-mime-secret"},
        response_body="{}",
    ))
    entry = catalog.export_har_json()["log"]["entries"][0]
    exported = json.dumps(entry)
    assert "synthetic-private-boundary" not in exported
    assert "synthetic-mime-secret" not in exported
    assert entry["request"]["postData"]["mimeType"] == "application/octet-stream"
    assert {h["value"] for h in entry["request"]["headers"] if h["name"] == "Content-Type"} == {
        "application/octet-stream"
    }
    assert {h["value"] for h in entry["response"]["headers"] if h["name"] == "Content-Type"} == {
        "application/octet-stream"
    }


def test_har_rejects_unsupported_method_before_retaining_request():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "SECRET-METHOD", "https://api.example.test/v1/items",
        body="synthetic body that must not be captured",
    ))
    limits = catalog.export_openapi_json()["x-mobileag-capture-limits"]
    assert limits["unmodeledRequests"] == limits["omittedRequests"] == 1
    assert catalog.captured_requests == []
    assert catalog.endpoints == {}
    assert json.loads(json.dumps(catalog.export_har_json()))["log"]["entries"] == []


def test_api_capture_catalog_preserves_response_headers_for_redacted_har():
    from types import SimpleNamespace
    from mobileag.web.app import _captured_api_catalog

    tx = SimpleNamespace(
        method="GET", url="https://api.example.test/v1/profile",
        request_headers={}, request_body=None, response_status=200,
        response_body=None,
        response_headers={"Set-Cookie": "session_id=synthetic-response-cookie"},
    )
    har = _captured_api_catalog([tx], "test").export_har_json()
    rendered = str(har)
    assert "Set-Cookie" in rendered
    assert "synthetic-response-cookie" not in rendered


def test_openapi_catalog_counts_non_string_and_overlong_urls_as_invalid():
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest("GET", None))  # type: ignore[arg-type]
    catalog.ingest_request(CapturedRequest("GET", "https://api.example.test/" + "x" * 8193))
    limits = catalog.export_openapi_json()["x-mobileag-capture-limits"]
    assert limits["invalidURLs"] == 2
    assert limits["unmodeledRequests"] == 2
    assert limits["omittedRequests"] == 2
    assert catalog.captured_requests == []


def test_openapi_catalog_normalizes_default_http_ports():
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest("GET", "https://api.example.test:443/v1/items"))
    catalog.ingest_request(CapturedRequest("GET", "https://api.example.test/v1/items"))
    catalog.ingest_request(CapturedRequest("GET", "http://api.example.test:80/v1/other"))
    spec = catalog.export_openapi_json()
    item_servers = spec["paths"]["/v1/items"]["get"]["servers"]
    other_servers = spec["paths"]["/v1/other"]["get"]["servers"]
    assert item_servers == [{"url": "https://api.example.test"}]
    assert other_servers == [{"url": "http://api.example.test"}]


def test_openapi_catalog_templates_identifier_paths_and_keeps_query_signatures():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/orders/94821?expand=items&page=1"))
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/orders/550e8400-e29b-41d4-a716-446655440000?expand=items&page=2"))
    # A distinct query signature is retained for deduplication, then merged into
    # the single OpenAPI operation with the union of observed parameter names.
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/orders/31415?sort=recent"))

    spec = catalog.export_openapi_json()
    operation = spec["paths"]["/v1/orders/{id1}"]["get"]
    assert {p["name"] for p in operation["parameters"] if p["in"] == "query"} == {
        "expand", "page", "sort",
    }
    path_params = [p for p in operation["parameters"] if p["in"] == "path"]
    assert path_params == [{"name": "id1", "in": "path", "required": True,
                            "schema": {"type": "string"}}]
    encoded = json.dumps(spec)
    assert "94821" not in encoded
    assert "550e8400-e29b-41d4-a716-446655440000" not in encoded
    assert "31415" not in encoded



def test_openapi_catalog_redacts_token_shaped_opaque_path_segments():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    sample_a = "AbCdEf0123456789GhIjKlMnOpQrStUv"
    sample_b = "ZaYxWv9876543210UtSrQpOnMlKjIhGf"
    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest("GET", f"https://api.example.test/v1/sessions/{sample_a}"))
    catalog.ingest_request(CapturedRequest("GET", f"https://api.example.test/v1/sessions/{sample_b}"))

    spec = catalog.export_openapi_json()
    assert "/v1/sessions/{id1}" in spec["paths"]
    encoded = json.dumps(spec)
    assert sample_a not in encoded and sample_b not in encoded


def test_openapi_catalog_redacts_short_and_percent_encoded_token_like_segments():
    from mobileag.dast.api_cataloger import MobileApiCataloger

    assert MobileApiCataloger._path_template("/v1/users/AbC123xy") == "/v1/users/{id1}"
    assert MobileApiCataloger._path_template("/v1/users/Ab%31Cd%32Ef") == "/v1/users/{id1}"


def test_openapi_catalog_redacts_digit_bearing_prefixed_resource_ids():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/users/usr_98472/orders/order_123"))
    spec = catalog.export_openapi_json()
    assert "/v1/users/{id1}/orders/{id2}" in spec["paths"]
    encoded = json.dumps(spec)
    assert "usr_98472" not in encoded and "order_123" not in encoded
    # Hard negatives: ordinary route words without digits remain literal.
    assert MobileApiCataloger._path_template("/v1/users/me") == "/v1/users/me"
    assert MobileApiCataloger._path_template("/v1/orders/recent") == "/v1/orders/recent"
    assert MobileApiCataloger._path_template("/v1/resource/item-00005-slug") == "/v1/resource/item-00005-slug"
    # Percent-encoded ASCII is decoded for classification, not route output.
    assert MobileApiCataloger._path_template("/v1/users/%75sr%5F98472") == "/v1/users/{id1}"


def test_openapi_schema_redacts_dynamic_json_object_keys():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    private_email = "synthetic.user@example.invalid"
    private_id = "f0e1d2c3b4a5968778695a4b3c2d1e0f"
    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/directory",
        response_body=json.dumps({private_email: {"token": "synthetic-secret"},
                                  private_id: {"active": True}}),
    ))

    spec = catalog.export_openapi_json()
    encoded = json.dumps(spec)
    assert private_email not in encoded and private_id not in encoded
    assert "synthetic-secret" not in encoded
    schema = spec["paths"]["/v1/directory"]["get"]["responses"]["200"][
        "content"]["application/json"]["schema"]
    assert schema["x-mobileag-redacted-dynamic-keys"] is True


def test_captured_traffic_can_be_exported_as_observed_openapi_inventory():
    import json
    from mobileag.web.app import _captured_api_catalog
    from mobileag.dast.traffic_auditor import HTTPTransaction

    txs = [
        HTTPTransaction(url="https://api-a.example.test/v1/items?limit=2", method="POST",
                        request_body='{"account":"synthetic-private-marker","enabled":true}',
                        response_status=200, response_body='{"ok":true,"count":4}'),
        HTTPTransaction(url="https://api-b.example.test/v1/items?limit=3", method="POST",
                        response_status=403, response_body='{}'),
    ]
    spec = _captured_api_catalog(txs, "Synthetic observed traffic").export_openapi_json()
    operation = spec["paths"]["/v1/items"]["post"]
    assert spec["openapi"] == "3.0.0"
    assert len(operation["servers"]) == 2
    assert set(operation["responses"]) == {"200", "403"}
    assert operation["x-mobileag-inferred-from-capture"] is True
    req_schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert req_schema["properties"]["account"]["type"] == "string"
    assert req_schema["properties"]["enabled"]["type"] == "boolean"
    assert "synthetic-private-marker" not in json.dumps(spec)


def test_traffic_catalog_adapters_do_not_preparse_unbounded_or_malformed_queries():
    from mobileag.web.app import _captured_api_catalog
    from mobileag.dast.traffic_auditor import HTTPTransaction, TrafficAuditor

    many_fields = "&".join(f"q{i}=x" for i in range(101))
    transactions = [
        HTTPTransaction(url=f"https://api.example.test/v1/large?{many_fields}"),
        HTTPTransaction(url="https://[malformed/v1/not-modeled"),
        HTTPTransaction(url="https://api.example.test/v1/good?search=synthetic"),
    ]
    for catalog in (
        TrafficAuditor().catalog_traffic(transactions),
        _captured_api_catalog(transactions, "Synthetic bounded capture"),
    ):
        spec = catalog.export_openapi_json()
        limits = spec["x-mobileag-capture-limits"]
        assert limits["unmodeledRequests"] == 2
        assert limits["invalidURLs"] == 1
        assert list(spec["paths"]) == ["/v1/good"]


def test_openapi_export_is_normatively_validated_and_rejects_invalid_documents():
    import pytest
    from openapi_spec_validator import validate
    from openapi_spec_validator.validation.exceptions import OpenAPIValidationError
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger("Synthetic API", "1.0.0")
    catalog.ingest_request(CapturedRequest("GET", "https://api.example.test/v1/items"))
    document = catalog.export_openapi_json()
    validate(document)

    with pytest.raises(OpenAPIValidationError):
        validate({"openapi": "3.0.0", "info": {"title": "missing version"}, "paths": {}})


def test_dependency_scanner_sbom_generation():
    from mobileag.analysis.dependency_scanner import DependencyScanner

    scanner = DependencyScanner()
    scanner._last_dependencies = [
        ("com.squareup.okhttp3", "okhttp", "4.9.3", "build.gradle"),
        ("com.google.code.gson", "gson", "2.8.9", "build.gradle"),
    ]

    generator = scanner.generate_sbom("BankingApp", "2.1.0")
    cyclone = generator.generate_cyclonedx_json()
    assert cyclone["bomFormat"] == "CycloneDX"
    assert len(cyclone["components"]) == 2
    purls = [c["purl"] for c in cyclone["components"]]
    assert "pkg:maven/com.squareup.okhttp3/okhttp@4.9.3" in purls
    assert "pkg:maven/com.google.code.gson/gson@2.8.9" in purls


def test_call_graph_and_taint_pending_intent():
    from mobileag.analysis.call_graph import SMALI_DERIVED_SOURCES, SMALI_SINKS, SMALI_SOURCES
    from mobileag.analysis.taint_engine import _SINK_SPECS, _SOURCE_PATTERNS

    assert "Landroid/app/PendingIntent;->send" in SMALI_SINKS
    assert "Landroid/content/Intent;->getScheme" in SMALI_DERIVED_SOURCES
    assert "Landroid/content/Intent;->getStringExtra" in SMALI_DERIVED_SOURCES
    assert "Landroid/content/Intent;->getStringExtra" not in SMALI_SOURCES
    assert "Landroid/net/Uri;->getScheme" in SMALI_DERIVED_SOURCES

    sink_types = [s["type"] for s in _SINK_SPECS]
    assert "PENDING_INTENT_FORWARDING" in sink_types

    source_names = [s[0] for s in _SOURCE_PATTERNS]
    assert "JS_INTERFACE_BRIDGE" in source_names


def test_cyclonedx_xml_generation(tmp_path):
    from mobileag.analysis.sbom_generator import MobileSbomGenerator
    import xml.etree.ElementTree as ET

    gen = MobileSbomGenerator(app_name="SecureBank", app_version="3.5.0")
    gen.add_component(
        name="okhttp",
        version="4.9.3",
        purl="pkg:maven/com.squareup.okhttp3/okhttp@4.9.3",
        hashes={"sha256": "a" * 64},
        licenses=["Apache-2.0"],
    )

    xml_text = gen.generate_cyclonedx_xml()
    assert "bom" in xml_text
    assert '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"' in xml_text
    assert "<name>SecureBank</name>" in xml_text
    assert "<name>okhttp</name>" in xml_text
    assert "<purl>pkg:maven/com.squareup.okhttp3/okhttp@4.9.3</purl>" in xml_text
    assert f'<hash alg="SHA-256">{"a" * 64}</hash>' in xml_text
    assert "<id>Apache-2.0</id>" in xml_text

    # Verify parseability
    root = ET.fromstring(xml_text)
    assert root.tag.endswith("bom")
    assert root.attrib.get("version") == "1"

    # Test file saving
    xml_file = tmp_path / "sbom.xml"
    gen.save_cyclonedx_xml(xml_file)
    assert xml_file.is_file()
    assert xml_file.stat().st_size > 0


def test_har_exporter(tmp_path):
    from mobileag.dast.api_cataloger import MobileApiCataloger, CapturedRequest
    import json

    cataloger = MobileApiCataloger(title="Payment APIs", version="2.0.0")
    req = CapturedRequest(
        method="POST",
        url="https://api.payment.com/v2/charge",
        headers={"Content-Type": "application/json", "Authorization": "Bearer tok_123"},
        query_params={"dry_run": "false"},
        body='{"amount": 5000, "currency": "USD"}',
        response_status=201,
        response_body='{"status": "success", "charge_id": "ch_9841"}',
    )
    cataloger.ingest_request(req)

    har_data = cataloger.export_har_json()
    assert har_data["log"]["version"] == "1.2"
    assert har_data["log"]["creator"]["name"] == "MobileAg Dynamic Traffic Auditor"
    assert len(har_data["log"]["entries"]) == 1

    entry = har_data["log"]["entries"][0]
    assert entry["request"]["method"] == "POST"
    assert entry["request"]["url"] == "https://api.payment.com/v2/charge"
    assert entry["request"]["postData"]["text"] == '{"amount": 5000, "currency": "USD"}'
    assert "tok_123" not in json.dumps(entry)
    assert any(h["name"] == "Authorization" and h["value"] == "[REDACTED]" for h in entry["request"]["headers"])
    assert entry["response"]["status"] == 201
    assert "ch_9841" in entry["response"]["content"]["text"]

    # Test saving HAR
    har_file = tmp_path / "traffic.har"
    cataloger.save_har(har_file)
    assert har_file.is_file()
    with open(har_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["log"]["version"] == "1.2"


def test_har_save_replaces_symlink_atomically_with_private_file(tmp_path):
    import json
    import os
    from mobileag.dast.api_cataloger import MobileApiCataloger

    victim = tmp_path / "victim.txt"
    victim.write_text("unchanged")
    output = tmp_path / "traffic.har"
    output.symlink_to(victim)

    MobileApiCataloger().save_har(output)

    assert not output.is_symlink()
    assert victim.read_text() == "unchanged"
    assert json.loads(output.read_text())["log"]["version"] == "1.2"
    assert os.stat(output).st_mode & 0o077 == 0


def test_har_save_enforces_output_cap_before_destination_write(tmp_path, monkeypatch):
    import pytest
    import mobileag.dast.api_cataloger as api_cataloger

    output = tmp_path / "oversized.har"
    monkeypatch.setattr(api_cataloger, "_MAX_HAR_OUTPUT_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        api_cataloger.MobileApiCataloger().save_har(output)
    assert not output.exists()


def test_har_exporter_redacts_auth_fields_in_url_and_bodies():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        method="POST",
        url="https://api.example.test/path?access_token=syntheticUrlSecret",
        headers={"Authorization": "Bearer syntheticBearerCredential"},
        query_params={"refresh_token": "syntheticRefreshSecret", "page": "1"},
        body='{"password":"syntheticPassword","amount":3}',
        response_body='{"access_token":"syntheticResponseToken","ok":true}',
    ))
    har = catalog.export_har_json()
    exported = json.dumps(har)
    for secret in ("syntheticUrlSecret", "syntheticBearerCredential", "syntheticRefreshSecret",
                   "syntheticPassword", "syntheticResponseToken"):
        assert secret not in exported
    entry = har["log"]["entries"][0]
    assert json.loads(entry["request"]["postData"]["text"])["amount"] == 3
    assert {q["name"]: q["value"] for q in entry["request"]["queryString"]}["page"] == "1"


def test_web_export_endpoints_cyclonedx_xml_spdx_har():
    from fastapi.testclient import TestClient
    from mobileag.web.app import app, ACTIVE_SCANS
    import xml.etree.ElementTree as ET

    scan_id = "test_scan_export_001"
    ACTIVE_SCANS[scan_id] = {
        "id": scan_id,
        "scan_id": scan_id,
        "app_name": "DemoApp",
        "version": "1.0.0",
        "status": "running",
        "findings": [],
        "stats": {},
        "agent_telemetry": [],
        "api_endpoints": [
            {"method": "GET", "url": "https://api.demo.com/v1/profile"}
        ],
        "components": [],
        "deep_links": [],
        "attack_surface_graph": {},
        "dependencies": [
            {"name": "retrofit", "version": "2.9.0", "purl": "pkg:maven/com.squareup.retrofit2/retrofit@2.9.0"}
        ],
    }

    client = TestClient(app, headers={"Authorization": "Bearer " + app.state.auth_token})

    # 1. CycloneDX XML
    res_xml = client.get(f"/api/scans/{scan_id}/cyclonedx.xml")
    assert res_xml.status_code == 200
    assert "application/xml" in res_xml.headers.get("content-type", "")
    root = ET.fromstring(res_xml.text)
    assert root.tag.endswith("bom")
    assert "retrofit" in res_xml.text

    # 2. SPDX JSON
    res_spdx = client.get(f"/api/scans/{scan_id}/spdx")
    assert res_spdx.status_code == 200
    spdx_json = res_spdx.json()
    assert spdx_json["spdxVersion"] == "SPDX-2.3"
    assert spdx_json["name"] == "DemoApp SBOM"

    # 3. HAR JSON
    res_har = client.get(f"/api/scans/{scan_id}/har")
    assert res_har.status_code == 200
    har_json = res_har.json()
    assert har_json["log"]["version"] == "1.2"
    assert len(har_json["log"]["entries"]) == 1
    assert har_json["log"]["entries"][0]["request"]["url"] == "https://api.demo.com/v1/profile"


def test_token_session_auditor_jwt_claims_and_entropy():
    import base64
    import json
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    auditor = MobileTokenSessionAuditor()

    # 1. JWT with 'none' algorithm and missing exp
    hdr_none = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT",
        "jwk": {"k": "synthetic-header-secret-123"}}).encode()).decode().rstrip("=")
    pay_plain = base64.urlsafe_b64encode(json.dumps({"sub": "user123", "password": "supersecretpassword"}).encode()).decode().rstrip("=")
    jwt_insecure = f"{hdr_none}.{pay_plain}.sig"

    findings = auditor.audit_token(jwt_insecure,
                                   context_url="https://researcher:pass@api.example.test/me?sessionid=query-secret-123#frag-secret")
    cwe_ids = [f.cwe_id for f in findings]
    assert "CWE-347" in cwe_ids  # alg none
    assert "CWE-613" in cwe_ids  # missing exp
    assert "CWE-312" in cwe_ids  # password in payload
    serialized = json.dumps([finding.model_dump(mode="json") for finding in findings])
    assert "synthetic-header-secret-123" not in serialized
    assert "supersecretpassword" not in serialized
    assert "query-secret-123" not in serialized
    assert "frag-secret" not in serialized
    assert "researcher:pass" not in serialized
    assert "api.example.test/me" in serialized
    alg_finding = next(f for f in findings if f.cwe_id == "CWE-347")
    assert alg_finding.status.value == "UNVERIFIED"
    assert "Verification Not Established" in alg_finding.title
    assert "jwk" not in json.dumps(alg_finding.metadata)
    assert "raw_token" not in auditor.decode_jwt(jwt_insecure)
    decoded = auditor.decode_jwt(jwt_insecure)
    assert decoded["header"] == {"alg": "none"}
    assert decoded["payload"]["sensitive_claim_names"] == ["password"]
    assert "supersecretpassword" not in json.dumps(decoded)
    assert auditor._safe_context_url(
        "https://api.example.test/reset/abCDef01234567890123456789012345?x=secret#frag") == (
            "https://api.example.test/reset/[REDACTED]")

    # 2. Low entropy token
    low_ent_findings = auditor.audit_token("aaaaaaaaaaaaaaaa")
    assert any(f.cwe_id == "CWE-330" for f in low_ent_findings)

    # Malformed claim roots and excessive attacker-controlled token strings
    # are treated as non-decodable input rather than raising or parsing as JWT.
    json_list = base64.urlsafe_b64encode(b"[]").decode().rstrip("=")
    valid_object = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
    assert auditor.decode_jwt(f"{json_list}.{valid_object}.sig") is None
    assert auditor.decode_jwt(f"{valid_object}.{json_list}.sig") is None
    duplicate_header = base64.urlsafe_b64encode(b'{"alg":"none","alg":"HS256"}').decode().rstrip("=")
    duplicate_payload = base64.urlsafe_b64encode(b'{"exp":1,"exp":253402300799}').decode().rstrip("=")
    assert auditor.decode_jwt(f"{duplicate_header}.{valid_object}.sig") is None
    assert auditor.decode_jwt(f"{valid_object}.{duplicate_payload}.sig") is None
    assert auditor.audit_token("x" * (auditor.MAX_TOKEN_CHARS + 1)) == []

    # A present but non-numeric exp is not misreported as an absent claim.
    pay_invalid_exp = base64.urlsafe_b64encode(json.dumps({"exp": True}).encode()).decode().rstrip("=")
    invalid_exp = auditor.audit_token(f"{valid_object}.{pay_invalid_exp}.sig")
    assert not any(f.title == "JWT Token Missing Expiration Claim" for f in invalid_exp)


def test_token_session_auditor_rejects_nonfinite_and_out_of_range_time_claims():
    import base64
    import json
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    auditor = MobileTokenSessionAuditor()
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    header = encode({"alg": "HS256"})
    for exp in (float("inf"), float("-inf"), float("nan"), 253402300800, True):
        token = f"{header}.{encode({'exp': exp})}.signature"
        parsed = auditor.decode_jwt(token)
        assert parsed is not None
        assert parsed["payload"]["has_exp_claim"] is True
        assert "exp" not in parsed["payload"]

    valid = auditor.decode_jwt(f"{header}.{encode({'exp': 253402300799})}.signature")
    assert valid is not None
    assert valid["payload"]["exp"] == 253402300799


def test_token_session_auditor_bounds_header_review_and_marks_ambiguous_auth():
    from mobileag.dast.api_cataloger import CapturedRequest
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    auditor = MobileTokenSessionAuditor()
    oversized_headers = {f"X-Test-{i}": "value" for i in range(100)}
    oversized_headers["Authorization"] = "Bearer synthetic-hidden-token"
    auditor.audit_transactions([CapturedRequest(
        "GET", "https://api.example.invalid/profile", headers=oversized_headers,
    )])
    assert auditor.last_coverage["status"] == "partial"
    assert auditor.last_coverage["header_input_incomplete_transactions"] == 1
    assert auditor.last_coverage["max_headers_per_transaction"] == 100
    assert "synthetic-hidden-token" not in str(auditor.last_coverage)

    oversized_value = "synthetic-oversized-token-" + "x" * 65_536
    auditor.audit_transactions([CapturedRequest(
        "GET", "https://api.example.invalid/profile",
        headers={"Authorization": oversized_value},
    )])
    assert auditor.last_coverage["status"] == "partial"
    assert auditor.last_coverage["header_input_incomplete_transactions"] == 1
    assert oversized_value not in str(auditor.last_coverage)

    auditor.audit_transactions([CapturedRequest(
        "GET", "https://api.example.invalid/profile",
        headers={"Authorization": "Bearer synthetic-one", "authorization": "Bearer synthetic-two"},
    )])
    assert auditor.last_coverage["status"] == "partial"
    assert auditor.last_coverage["header_input_incomplete_transactions"] == 1
    assert auditor.last_coverage["duplicate_authorization_header_transactions"] == 1
    assert "synthetic-one" not in str(auditor.last_coverage)
    assert "synthetic-two" not in str(auditor.last_coverage)


def test_token_session_auditor_opt_in_hmac_verification_is_local_and_bounded():
    import base64
    import hashlib
    import hmac
    import json
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    auditor = MobileTokenSessionAuditor()
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    for alg, digest in (("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)):
        key = b"synthetic-research-only-hmac-key".ljust(digest().digest_size, b"x")
        header = encode(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
        payload = encode(json.dumps({"sub": "synthetic"}, separators=(",", ":")).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = encode(hmac.new(key, signing_input, digest).digest())
        token = f"{header}.{payload}.{signature}"

        verified = auditor.verify_hmac_jwt_signature(token, key)
        assert verified == {
            "status": "valid_for_supplied_key", "algorithm": alg,
            "key_source": "researcher_supplied", "server_acceptance": "not_tested",
        }
        wrong_key = b"different-synthetic-key".ljust(digest().digest_size, b"y")
        assert auditor.verify_hmac_jwt_signature(token, wrong_key)["status"] == "invalid_for_supplied_key"
        assert auditor.verify_hmac_jwt_signature(token, None)["status"] == "not_tested"

        altered_payload = encode(b'{"sub":"changed"}')
        altered = f"{header}.{altered_payload}.{signature}"
        assert auditor.verify_hmac_jwt_signature(altered, key)["status"] == "invalid_for_supplied_key"
        assert auditor.verify_hmac_jwt_signature(token, b"short")["status"] == "key_too_short"

    unsupported_header = encode(b'{"alg":"RS256"}')
    payload = encode(b'{"sub":"synthetic"}')
    assert auditor.verify_hmac_jwt_signature(
        f"{unsupported_header}.{payload}.AA", key
    )["status"] == "unsupported_algorithm"
    assert auditor.verify_hmac_jwt_signature(f"{unsupported_header}.{payload}.", key)["status"] == "unsupported_algorithm"
    assert auditor.verify_hmac_jwt_signature(f"{unsupported_header}.{payload}.AA", b"x" * 4097)["status"] == "invalid_key"
    assert auditor.verify_hmac_jwt_signature("not.a.jwt", key)["status"] == "invalid_compact_token"
    hs256_header = encode(b'{"alg":"HS256"}')
    min_key = b"k" * hashlib.sha256().digest_size
    assert auditor.verify_hmac_jwt_signature(f"{hs256_header}.{payload}.", min_key)["status"] == "missing_signature"
    critical_header = encode(b'{"alg":"HS256","crit":["b64"],"b64":false}')
    assert auditor.verify_hmac_jwt_signature(
        f"{critical_header}.{payload}.AA", min_key
    )["status"] == "unsupported_header_parameters"
    duplicate_header = encode(b'{"alg":"HS256","alg":"HS512"}')
    assert auditor.verify_hmac_jwt_signature(
        f"{duplicate_header}.{payload}.AA", min_key
    )["status"] == "invalid_compact_token"
    assert "synthetic-research-only-hmac-key" not in json.dumps(
        auditor.verify_hmac_jwt_signature(token, key)
    )


def test_token_session_hmac_verifier_matches_rfc7515_hs256_vector():
    import base64
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    # RFC 7515 Appendix A.1 JWS example; fixed public test vector, not a secret.
    key_b64 = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
    token = (
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    result = MobileTokenSessionAuditor().verify_hmac_jwt_signature(token, key)
    assert result["status"] == "valid_for_supplied_key"
    assert result["algorithm"] == "HS256"
    assert result["server_acceptance"] == "not_tested"


def test_token_session_auditor_transactions_and_logout_reuse():
    import json
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    auditor = MobileTokenSessionAuditor()
    txs = [
        # 1. Cleartext HTTP transmission with token
        CapturedRequest(
            method="GET",
            url="http://insecure.example.com/api/profile",
            headers={"Authorization": "Bearer secret_session_token_xyz_123"},
        ),
        # 2. Token in query parameter
        CapturedRequest(
            method="GET",
            url="https://api.example.com/data?auth_token=super_secret_query_tok_123",
        ),
        # 3. Logout request
        CapturedRequest(
            method="POST",
            url="https://api.example.com/logout",
            headers={"Authorization": "Bearer tok_to_revoke_123"},
            response_status=200,
        ),
        # 4. Token reused after logout
        CapturedRequest(
            method="GET",
            url="https://api.example.com/v1/dashboard",
            headers={"Authorization": "Bearer tok_to_revoke_123"},
            response_status=200,
        ),
    ]

    findings = auditor.audit_transactions(txs)
    cwe_ids = [f.cwe_id for f in findings]
    assert "CWE-319" in cwe_ids  # Cleartext HTTP
    assert "CWE-598" in cwe_ids  # Query token
    assert "CWE-613" in cwe_ids  # Logout reuse
    serialized = json.dumps([finding.model_dump(mode="json") for finding in findings])
    assert "secret_session_token_xyz_123" not in serialized
    assert "super_secret_query_tok_123" not in serialized


def test_token_session_auditor_recognizes_credential_query_key_aliases():
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    keys = ("refresh-token", "id_token", "X-Amz-Security-Token", "client_secret",
            "accessToken", "api-key", "cookie", "user_session", "secret_key",
            "privateKey", "password")
    requests = [CapturedRequest(method="GET", url=f"https://api.example.invalid/path?{key}=synthetic-secret")
                for key in keys]
    requests.append(CapturedRequest(method="GET", url="https://api.example.invalid/path?tokenizer=not-a-token"))
    findings = MobileTokenSessionAuditor().audit_transactions(requests)
    leaks = [finding for finding in findings if finding.cwe_id == "CWE-598"]
    assert len(leaks) == len(keys)
    assert all("synthetic-secret" not in finding.description for finding in leaks)
    assert all("?" not in finding.affected_component for finding in leaks)


def test_blank_sensitive_query_parameter_is_not_cleartext_credential_evidence():
    from mobileag.dast.api_cataloger import CapturedRequest
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    auditor = MobileTokenSessionAuditor()
    blank_findings = auditor.audit_transactions([
        CapturedRequest("GET", "http://api.example.invalid/path?access_token="),
        CapturedRequest("GET", "http://api.example.invalid/path?session_id=%20"),
    ])
    assert len([finding for finding in blank_findings if finding.cwe_id == "CWE-598"]) == 2
    assert not any(finding.cwe_id == "CWE-319" for finding in blank_findings)

    nonempty_findings = auditor.audit_transactions([
        CapturedRequest("GET", "http://api.example.invalid/path?refresh_token=synthetic-token-value"),
    ])
    assert {finding.cwe_id for finding in nonempty_findings} >= {"CWE-598", "CWE-319"}
    assert auditor.last_coverage["status"] == "complete_for_supplied_input"


def test_token_session_auditor_marks_query_credentials_on_cleartext_http():
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    findings = MobileTokenSessionAuditor().audit_transactions([
        CapturedRequest(method="GET", url="http://api.example.invalid/path?access_token=short")
    ])
    cwes = [finding.cwe_id for finding in findings]
    assert "CWE-598" in cwes
    assert "CWE-319" in cwes
    assert all("short" not in finding.description for finding in findings)


def test_token_session_auditor_reports_url_userinfo_without_echoing_credentials():
    import json
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    findings = MobileTokenSessionAuditor().audit_transactions([
        CapturedRequest(method="GET", url="https://synthetic-user:synthetic-password@api.example.invalid/v1/profile")
    ])
    credential_leads = [finding for finding in findings if finding.cwe_id == "CWE-522"]
    assert len(credential_leads) == 1
    serialized = json.dumps([finding.model_dump(mode="json") for finding in findings])
    assert "synthetic-user" not in serialized
    assert "synthetic-password" not in serialized
    cleartext = MobileTokenSessionAuditor().audit_transactions([
        CapturedRequest(method="GET", url="http://synthetic-user:synthetic-password@api.example.invalid/profile")
    ])
    assert {finding.cwe_id for finding in cleartext} >= {"CWE-522", "CWE-319"}


def test_token_session_auditor_bounds_findings_and_reports_partial_coverage():
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    query = "&".join("access_token=x" for _ in range(256))
    transactions = [CapturedRequest(method="GET", url=f"https://api.example.invalid/path?{query}")
                    for _ in range(100)]
    auditor = MobileTokenSessionAuditor()
    findings = auditor.audit_transactions(transactions)
    assert len(findings) == auditor.MAX_FINDINGS
    assert auditor.last_coverage["finding_cap_reached"] is True
    assert auditor.last_coverage["status"] == "partial"
    assert auditor.last_coverage["transactions_omitted"] > 0


def test_token_session_auditor_marks_over_limit_query_parse_as_partial():
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    query = "&".join([f"field{i}=x" for i in range(256)] + ["access_token=synthetic-secret"])
    auditor = MobileTokenSessionAuditor()
    findings = auditor.audit_transactions([
        CapturedRequest(method="GET", url=f"https://api.example.invalid/path?{query}")
    ])
    assert not any(finding.cwe_id == "CWE-598" for finding in findings)
    assert auditor.last_coverage["status"] == "partial"
    assert auditor.last_coverage["query_parse_incomplete_transactions"] == 1


def test_token_session_auditor_does_not_call_unauthorized_responses_successful_reuse():
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    token = "synthetic-session-token-98765"
    transactions = [
        CapturedRequest(method="POST", url="https://api.example.test/logout",
                        headers={"Authorization": f"Bearer {token}"}, response_status=204),
        CapturedRequest(method="GET", url="https://api.example.test/account",
                        headers={"AUTHORIZATION": f"Bearer {token}"}, response_status=401),
    ]
    findings = MobileTokenSessionAuditor().audit_transactions(transactions)
    assert not any(f.cwe_id == "CWE-613" for f in findings)


def test_api_security_tester_get_token_auditor():
    from mobileag.dast.api_security_tester import APISecurityTester
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    tester = APISecurityTester()
    auditor = tester.get_token_auditor()
    assert isinstance(auditor, MobileTokenSessionAuditor)


def test_sbom_vulnerability_attachment():
    from mobileag.analysis.sbom_generator import MobileSbomGenerator
    import xml.etree.ElementTree as ET

    gen = MobileSbomGenerator(app_name="VulnApp", app_version="1.0.0")
    gen.add_component(
        name="okhttp",
        version="3.12.0",
        purl="pkg:maven/com.squareup.okhttp3/okhttp@3.12.0",
    )
    gen.add_vulnerability(
        vuln_id="CVE-2021-0341",
        purl="pkg:maven/com.squareup.okhttp3/okhttp@3.12.0",
        description="Certificate hostname verification bypass vulnerability.",
        severity="high",
        cwe_ids=["CWE-295"],
    )

    # Check CycloneDX JSON
    cdx_json = gen.generate_cyclonedx_json()
    assert "vulnerabilities" in cdx_json
    assert cdx_json["vulnerabilities"][0]["id"] == "CVE-2021-0341"
    assert cdx_json["vulnerabilities"][0]["ratings"][0]["severity"] == "high"
    component_ref = cdx_json["components"][0]["bom-ref"]
    assert cdx_json["vulnerabilities"][0]["affects"][0]["ref"] == component_ref

    # Check CycloneDX XML
    cdx_xml = gen.generate_cyclonedx_xml()
    assert "<vulnerabilities>" in cdx_xml
    assert "<id>CVE-2021-0341</id>" in cdx_xml
    root = ET.fromstring(cdx_xml)
    assert any(child.tag.endswith("vulnerabilities") for child in root)
    component = next(el for el in root.iter() if el.tag.endswith("component") and el.get("type") == "library")
    target_ref = next(el.text for el in root.iter() if el.tag.endswith("ref"))
    assert target_ref == component.get("bom-ref")
    assert "<scope>required</scope>" in cdx_xml


def test_web_endpoint_token_audit():
    from fastapi.testclient import TestClient
    from mobileag.web.app import app, ACTIVE_SCANS

    scan_id = "test_scan_tokens_002"
    ACTIVE_SCANS[scan_id] = {
        "id": scan_id,
        "scan_id": scan_id,
        "status": "running",
        "app_name": "TokenTestApp",
        "api_endpoints": [
            {
                "method": "GET",
                "url": "http://api.insecure.com/users",
                "headers": {"Authorization": "Bearer weak_cleartext_token_abc"},
            }
        ],
    }

    client = TestClient(app, headers={"Authorization": "Bearer " + app.state.auth_token})
    res = client.get(f"/api/scans/{scan_id}/tokens/audit")
    assert res.status_code == 200
    data = res.json()
    assert data["token_findings_count"] >= 1
    assert any(f["cwe_id"] == "CWE-319" for f in data["findings"])




