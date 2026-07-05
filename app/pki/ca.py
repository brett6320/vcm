"""Certificate Authority operations: create roots/intermediates/issuing CAs and
sign end-entity (appliance) certificates from CSRs.

Design invariants:
  * CA private keys live only KEK-encrypted in the DB (`CertAuthority.key_enc`).
  * A key is decrypted transiently for one signing operation, then dropped.
  * No function here returns or serializes a CA/end-entity *private* key.
"""
from __future__ import annotations

from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import CAType, CertAuthority, Certificate, CertStatus, utcnow
from . import keys


def _hash_for(key):
    # Ed/EC/RSA: SHA-384 is a sound default; None required for Ed25519 (not used here).
    return hashes.SHA384()


def _name_from_dn(dn: dict[str, str]) -> x509.Name:
    oid_map = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
    }
    attrs = [x509.NameAttribute(oid_map[k], v) for k, v in dn.items() if k in oid_map and v]
    return x509.Name(attrs)


def dn_to_str(name: x509.Name) -> str:
    return name.rfc4514_string()


def _next_serial(db: Session, ca: CertAuthority) -> int:
    serial = ca.serial_counter
    ca.serial_counter += 1
    db.add(ca)
    return serial


# --------------------------------------------------------------------------- #
# CA creation
# --------------------------------------------------------------------------- #
def create_ca(
    db: Session,
    *,
    name: str,
    dn: dict[str, str],
    ca_type: CAType,
    key_type: str,
    key_params: str,
    valid_days: int,
    parent: CertAuthority | None = None,
    path_len: int | None = None,
) -> CertAuthority:
    if ca_type != CAType.root and parent is None:
        raise ValueError("Intermediate/issuing CA requires a parent CA")
    if ca_type == CAType.root and parent is not None:
        raise ValueError("Root CA cannot have a parent")

    key = keys.generate_key(key_type, key_params)
    subject = _name_from_dn(dn)
    now = utcnow()
    not_after = now + timedelta(days=valid_days)

    if parent:
        issuer_key = keys.unwrap_private_key(parent.key_enc)
        issuer_name = x509.load_pem_x509_certificate(parent.cert_pem.encode()).subject
        serial = _next_serial(db, parent)
    else:
        issuer_key = key
        issuer_name = subject
        serial = 1

    # issuing CAs are pathlen:0 (may only sign leaves) unless overridden
    if path_len is None:
        path_len = 0 if ca_type == CAType.issuing else None

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if parent:
        issuer_cert = x509.load_pem_x509_certificate(parent.cert_pem.encode())
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )

    cert = builder.sign(issuer_key, _hash_for(issuer_key))

    ca = CertAuthority(
        name=name,
        ca_type=ca_type,
        parent_id=parent.id if parent else None,
        subject_dn=dn_to_str(subject),
        cert_pem=cert.public_bytes(serialization_encoding()).decode(),
        key_enc=keys.wrap_private_key(key),
        key_type=key_type,
        key_params=key_params,
        not_before=now,
        not_after=not_after,
        path_len=path_len,
    )
    db.add(ca)
    db.flush()
    return ca


def serialization_encoding():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.PEM


# --------------------------------------------------------------------------- #
# Chain helpers
# --------------------------------------------------------------------------- #
def chain_pem(db: Session, ca: CertAuthority) -> str:
    """Return CA cert + all issuers up to the root, in leaf->root order."""
    parts: list[str] = [ca.cert_pem.strip()]
    cur = ca
    while cur.parent_id:
        cur = db.get(CertAuthority, cur.parent_id)
        if not cur:
            break
        parts.append(cur.cert_pem.strip())
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# Public hierarchy (lineage tree) — never includes private key material
# --------------------------------------------------------------------------- #
def build_hierarchy(db: Session, *, include_pem: bool = False) -> list[dict]:
    """Return the full CA tree (root → intermediate → issuing) with issued leaf
    certs nested under their issuing CA. Public data only."""
    cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
    certs = db.execute(select(Certificate).order_by(Certificate.id)).scalars().all()

    ca_children: dict[int | None, list[CertAuthority]] = {}
    for ca in cas:
        ca_children.setdefault(ca.parent_id, []).append(ca)
    leaves: dict[int, list[Certificate]] = {}
    for c in certs:
        leaves.setdefault(c.ca_id, []).append(c)

    def leaf_node(c: Certificate) -> dict:
        n = {"kind": "certificate", "id": c.id, "serial": c.serial,
             "subject": c.subject_dn, "san": c.san, "status": c.status.value,
             "not_before": c.not_before.isoformat(), "not_after": c.not_after.isoformat()}
        if include_pem:
            n["cert_pem"] = c.cert_pem
        return n

    def ca_node(ca: CertAuthority) -> dict:
        n = {"kind": "ca", "id": ca.id, "name": ca.name, "ca_type": ca.ca_type.value,
             "subject": ca.subject_dn, "parent_id": ca.parent_id,
             "key": f"{ca.key_type}:{ca.key_params}", "path_len": ca.path_len,
             "not_before": ca.not_before.isoformat(), "not_after": ca.not_after.isoformat(),
             "cas": [ca_node(ch) for ch in ca_children.get(ca.id, [])],
             "certificates": [leaf_node(c) for c in leaves.get(ca.id, [])]}
        if include_pem:
            n["cert_pem"] = ca.cert_pem
        return n

    return [ca_node(r) for r in ca_children.get(None, [])]


# --------------------------------------------------------------------------- #
# End-entity signing from CSR
# --------------------------------------------------------------------------- #
def sign_csr(
    db: Session,
    *,
    issuing_ca: CertAuthority,
    csr: x509.CertificateSigningRequest,
    valid_days: int,
    san_dns: list[str] | None = None,
    san_ip: list[str] | None = None,
) -> Certificate:
    if issuing_ca.ca_type == CAType.root:
        raise ValueError("Refusing to issue leaf certs directly from a root CA")
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    issuer_key = keys.unwrap_private_key(issuing_ca.key_enc)
    issuer_cert = x509.load_pem_x509_certificate(issuing_ca.cert_pem.encode())
    now = utcnow()
    not_after = now + timedelta(days=valid_days)
    serial = _next_serial(db, issuing_ca)

    san_list: list[x509.GeneralName] = []
    for d in san_dns or []:
        san_list.append(x509.DNSName(d))
    import ipaddress as _ip

    for i in san_ip or []:
        san_list.append(x509.IPAddress(_ip.ip_address(i)))

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, key_agreement=True,
                content_commitment=False, data_encipherment=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
    )
    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    cert = builder.sign(issuer_key, _hash_for(issuer_key))

    row = Certificate(
        ca_id=issuing_ca.id,
        serial=format(serial, "x"),
        subject_dn=dn_to_str(csr.subject),
        san=",".join((san_dns or []) + (san_ip or [])) or None,
        cert_pem=cert.public_bytes(serialization_encoding()).decode(),
        csr_pem=csr.public_bytes(serialization_encoding()).decode(),
        status=CertStatus.active,
        not_before=now,
        not_after=not_after,
    )
    db.add(row)
    db.flush()
    return row
