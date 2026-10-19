"""Unit tests for ApkSignatureAuditor: schemes, certificates, and vulnerability audits."""

import datetime
import io
import zipfile
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from mobileag.analysis.apk_signature_auditor import (
    ApkSignatureAuditor,
    CertificateDetails,
    APK_SIG_BLOCK_MAGIC,
    ID_APK_SIGNATURE_SCHEME_V2,
)
from mobileag.reporting.finding import Severity


def create_synthetic_cert(
    cn="Synthetic Cert",
    key_size=2048,
    hash_algorithm=hashes.SHA256(),
    days_valid=365,
    is_debug=False,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subj_name = "CN=Android Debug,O=Android,C=US" if is_debug else f"CN={cn}"
    subject = x509.Name.from_rfc4514_string(subj_name)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hash_algorithm)
    )
    return key, cert


def build_pkcs7_der(key, cert) -> bytes:
    builder = pkcs7.PKCS7SignatureBuilder()
    builder = builder.set_data(b"synthetic manifest digest")
    builder = builder.add_signer(cert, key, hashes.SHA256())
    return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])


def test_v1_only_triggers_janus_vulnerability_on_min_sdk_26(tmp_path):
    apk_file = tmp_path / "janus_sample.apk"
    key, cert = create_synthetic_cert("Janus Test App", key_size=2048)
    p7_der = build_pkcs7_der(key, cert)

    # Create synthetic APK with META-INF (v1 only)
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", p7_der)

    auditor = ApkSignatureAuditor(min_sdk_version=21)
    res = auditor.audit(apk_file)

    assert res.schemes["v1"] is True
    assert res.schemes["v2"] is False
    assert res.schemes["v3"] is False
    assert res.janus_vulnerable is True
    assert len(res.certificates) == 1
    assert "Janus Test App" in res.certificates[0].subject

    titles = [v["title"] for v in res.vulnerabilities]
    assert any("Janus" in t for t in titles)


def test_v1_only_does_not_trigger_janus_on_min_sdk_28(tmp_path):
    apk_file = tmp_path / "modern_sample.apk"
    key, cert = create_synthetic_cert("Modern Test App", key_size=2048)
    p7_der = build_pkcs7_der(key, cert)

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("META-INF/CERT.RSA", p7_der)

    auditor = ApkSignatureAuditor(min_sdk_version=28)
    res = auditor.audit(apk_file)

    assert res.schemes["v1"] is True
    assert res.janus_vulnerable is False
    titles = [v["title"] for v in res.vulnerabilities]
    assert not any("Janus" in t for t in titles)
    # But it should warn about missing modern schemes v2/v3
    assert any("Missing Signature Scheme" in t for t in titles)


def test_debug_certificate_detection(tmp_path):
    apk_file = tmp_path / "debug_sample.apk"
    key, cert = create_synthetic_cert(is_debug=True, key_size=2048)
    p7_der = build_pkcs7_der(key, cert)

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("META-INF/CERT.RSA", p7_der)

    auditor = ApkSignatureAuditor(min_sdk_version=28)
    res = auditor.audit(apk_file)

    assert len(res.certificates) == 1
    assert res.certificates[0].is_debug is True
    titles = [v["title"] for v in res.vulnerabilities]
    assert any("Debug Certificate" in t for t in titles)


def test_weak_rsa_key_and_sha1_detection(tmp_path):
    apk_file = tmp_path / "weak_crypto_sample.apk"
    key, cert = create_synthetic_cert("Weak App", key_size=1024, hash_algorithm=hashes.SHA256())
    p7_der = build_pkcs7_der(key, cert)

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("META-INF/CERT.RSA", p7_der)

    auditor = ApkSignatureAuditor(min_sdk_version=28)
    res = auditor.audit(apk_file)

    assert res.certificates[0].key_size == 1024

    titles = [v["title"] for v in res.vulnerabilities]
    assert any("Weak RSA Key" in t for t in titles)

    # Test weak hash algorithm detection via direct certificate details evaluation
    res.certificates.append(CertificateDetails(
        subject="CN=Legacy MD5 App",
        issuer="CN=Legacy MD5 App",
        serial_number="1234",
        signature_algorithm="MD5",
        key_type="RSA",
        key_size=2048,
        not_valid_before="2020-01-01T00:00:00",
        not_valid_after="2040-01-01T00:00:00",
        sha256_fingerprint="abc",
        sha1_fingerprint="def",
    ))
    res.certificates.append(CertificateDetails(
        subject="CN=Legacy SHA1 App",
        issuer="CN=Legacy SHA1 App",
        serial_number="5678",
        signature_algorithm="SHA1",
        key_type="RSA",
        key_size=2048,
        not_valid_before="2020-01-01T00:00:00",
        not_valid_after="2040-01-01T00:00:00",
        sha256_fingerprint="123",
        sha1_fingerprint="456",
    ))
    findings = auditor._evaluate_vulnerabilities(res)
    eval_titles = [f.title for f in findings]
    assert any("Broken Hash Algorithm" in t for t in eval_titles)
    assert any("Deprecated SHA-1 Hash" in t for t in eval_titles)


def test_audit_findings_returns_finding_objects(tmp_path):
    apk_file = tmp_path / "findings_test.apk"
    key, cert = create_synthetic_cert("Finding App", key_size=1024)
    p7_der = build_pkcs7_der(key, cert)

    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("META-INF/CERT.RSA", p7_der)

    auditor = ApkSignatureAuditor(min_sdk_version=21)
    findings = auditor.audit_findings(apk_file)

    assert len(findings) >= 2
    assert all(hasattr(f, "title") and hasattr(f, "severity") for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_apk_signing_block_v2_parsing(tmp_path):
    import struct
    apk_file = tmp_path / "v2_signed.apk"

    # 1. Base ZIP with a manifest
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
    zip_bytes = buf.getvalue()

    # Find EOCD in base zip
    eocd_idx = zip_bytes.rfind(b"\x50\x4b\x05\x06")
    cd_offset = struct.unpack_from("<I", zip_bytes, eocd_idx + 16)[0]

    # Contents before CD
    pre_cd = zip_bytes[:cd_offset]
    cd_and_eocd = zip_bytes[cd_offset:]

    # Construct APK Signing Block:
    # Pair: len (uint64), ID (uint32), value
    pair_id = struct.pack("<I", ID_APK_SIGNATURE_SCHEME_V2)
    pair_val = b"\x00" * 32  # minimal dummy signer block
    pair_len = 4 + len(pair_val)
    pair_data = struct.pack("<Q", pair_len) + pair_id + pair_val

    # Total block size: 8 + len(pair_data) + 8 + 16
    block_size = len(pair_data) + 24
    signing_block = (
        struct.pack("<Q", block_size)
        + pair_data
        + struct.pack("<Q", block_size)
        + APK_SIG_BLOCK_MAGIC
    )

    # In cd_and_eocd, adjust EOCD cd_offset to point after signing block
    new_cd_offset = cd_offset + len(signing_block)
    cd_part = zip_bytes[cd_offset:eocd_idx]
    eocd_part = bytearray(zip_bytes[eocd_idx:])
    struct.pack_into("<I", eocd_part, 16, new_cd_offset)

    full_apk = pre_cd + signing_block + cd_part + bytes(eocd_part)
    apk_file.write_bytes(full_apk)

    auditor = ApkSignatureAuditor(min_sdk_version=28)
    res = auditor.audit(apk_file)

    assert res.signing_block_found is True
    assert res.schemes["v2"] is True

