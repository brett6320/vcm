"""Load CA/cert key material from uploaded files: PEM bundles or PKCS#12.

Returns normalized PEM strings so the rest of the PKI code (import_ca, etc.)
stays PEM-only. Private keys are re-serialized *unencrypted* PEM in memory and
handed straight to the KEK-wrapping importer — they are never written to disk.
"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

_CERT_MARK = b"-----BEGIN CERTIFICATE-----"
_KEY_MARKS = (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
              b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----")


def _key_to_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def looks_like_p12(filename: str, data: bytes) -> bool:
    """PKCS#12 is DER (binary); PEM starts with an ASCII armor line."""
    name = (filename or "").lower()
    if name.endswith((".p12", ".pfx")):
        return True
    return not data.lstrip().startswith(b"-----BEGIN")


def load_pkcs12(data: bytes, password: str | None) -> tuple[str, str | None]:
    """Return (cert_pem, key_pem) from a PKCS#12 blob. key_pem is None if absent."""
    pw = password.encode() if password else None
    key, cert, _chain = pkcs12.load_key_and_certificates(data, pw)
    if cert is None:
        raise ValueError("PKCS#12 file contains no certificate")
    return _cert_to_pem(cert), (_key_to_pem(key) if key is not None else None)


def load_pem(data: bytes) -> tuple[str, str | None]:
    """Split a PEM bundle into (cert_pem, key_pem). Uses the first cert found."""
    text = data.decode(errors="ignore")
    if _CERT_MARK.decode() not in text:
        raise ValueError("No PEM certificate found in upload")
    cert = _cert_to_pem(x509.load_pem_x509_certificate(data))
    key_pem = None
    for mark in _KEY_MARKS:
        i = data.find(mark)
        if i != -1:
            key = serialization.load_pem_private_key(data[i:], password=None)
            key_pem = _key_to_pem(key)
            break
    return cert, key_pem


def load_material(filename: str, data: bytes, password: str | None) -> tuple[str, str | None]:
    """Dispatch on file shape → (cert_pem, key_pem)."""
    if looks_like_p12(filename, data):
        return load_pkcs12(data, password)
    return load_pem(data)
