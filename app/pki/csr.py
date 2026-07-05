"""CSR parsing/validation and optional server-side keypair+CSR creation.

Note: this is for *appliance* (end-entity) keys only. Appliance private keys may
be generated and handed back once for device install; CA keys are never exported.
"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from . import keys


def parse_csr(pem: str) -> x509.CertificateSigningRequest:
    csr = x509.load_pem_x509_csr(pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("CSR self-signature is invalid")
    return csr


def csr_summary(csr: x509.CertificateSigningRequest) -> dict:
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [g.value if hasattr(g, "value") else str(g) for g in san.value]
    except x509.ExtensionNotFound:
        sans = []
    return {"subject": csr.subject.rfc4514_string(), "san": sans}


def generate_leaf_keypair_and_csr(dn: dict[str, str], key_type: str, key_params: str,
                                  san_dns: list[str] | None = None):
    """Returns (private_key_pem, csr). Private key PEM is returned to the caller
    exactly once (never persisted)."""
    key = keys.generate_key(key_type, key_params)
    oid_map = {
        "CN": NameOID.COMMON_NAME, "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME, "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME, "L": NameOID.LOCALITY_NAME,
    }
    name = x509.Name([x509.NameAttribute(oid_map[k], v) for k, v in dn.items()
                      if k in oid_map and v])
    builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]), critical=False
        )
    csr = builder.sign(key, hashes.SHA384())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return key_pem, csr
