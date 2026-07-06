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
from sqlalchemy import delete, func, select
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
    if parent is not None and not parent.key_enc:
        raise ValueError(
            f"Parent CA '{parent.name}' has no private key available to sign — "
            "it was imported cert-only. Import its key or choose another parent."
        )

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
# Import an existing CA (cert + optional private key)
# --------------------------------------------------------------------------- #
def import_ca(
    db: Session,
    *,
    name: str,
    cert_pem: str,
    key_pem: str | None = None,
    ca_type_override: CAType | None = None,
) -> CertAuthority:
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    # Must be a CA certificate.
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            raise ValueError("Certificate is not a CA (BasicConstraints CA=false)")
        path_len = bc.path_length
    except x509.ExtensionNotFound:
        bc, path_len = None, None

    key = None
    key_enc = b""
    key_type, key_params = _describe_public_key(cert.public_key())
    if key_pem and key_pem.strip():
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
        # The private key must correspond to the certificate's public key.
        if (key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
                != cert.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)):
            raise ValueError("Private key does not match the certificate's public key")
        key_type, key_params = _describe_private_key(key)
        key_enc = keys.wrap_private_key(key)

    self_signed = cert.subject == cert.issuer
    if ca_type_override is not None:
        ca_type = ca_type_override
    elif self_signed:
        ca_type = CAType.root
    elif path_len == 0:
        ca_type = CAType.issuing
    else:
        ca_type = CAType.intermediate

    # Link to an existing parent CA whose subject matches this cert's issuer.
    parent = None
    if not self_signed:
        for existing in db.execute(select(CertAuthority)).scalars():
            if x509.load_pem_x509_certificate(existing.cert_pem.encode()).subject == cert.issuer:
                parent = existing
                break

    ca = CertAuthority(
        name=name,
        ca_type=ca_type,
        parent_id=parent.id if parent else None,
        subject_dn=dn_to_str(cert.subject),
        cert_pem=cert.public_bytes(serialization_encoding()).decode(),
        key_enc=key_enc,
        key_type=key_type,
        key_params=key_params,
        # Start well above typical externally-issued serials to avoid collisions.
        serial_counter=0x1000000,
        not_before=_aware(cert.not_valid_before_utc),
        not_after=_aware(cert.not_valid_after_utc),
        path_len=path_len,
    )
    db.add(ca)
    db.flush()
    return ca


def _aware(dt):
    from datetime import timezone
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _describe_public_key(pub):
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ec", pub.curve.name
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa", str(pub.key_size)
    return "unknown", ""


def _describe_private_key(key):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ec", key.curve.name
    if isinstance(key, rsa.RSAPrivateKey):
        return "rsa", str(key.key_size)
    return "unknown", ""


# --------------------------------------------------------------------------- #
# Chain helpers
def _descendant_cas(db: Session, ca: CertAuthority) -> list[CertAuthority]:
    """All CAs beneath `ca` (children, grandchildren, …), deepest first."""
    all_cas = db.execute(select(CertAuthority)).scalars().all()
    by_parent: dict[int | None, list[CertAuthority]] = {}
    for c in all_cas:
        by_parent.setdefault(c.parent_id, []).append(c)
    out: list[CertAuthority] = []

    def walk(node: CertAuthority) -> None:
        for child in by_parent.get(node.id, []):
            walk(child)
            out.append(child)  # children appended after their own descendants

    walk(ca)
    return out


def delete_ca(db: Session, ca: CertAuthority, *, cascade: bool = False) -> dict:
    """Delete a CA. Refuses a CA that still has child CAs or issued certificates
    unless `cascade` is set, in which case the whole subtree (child CAs + their
    issued certs) is removed too. Returns a summary of what was deleted."""
    descendants = _descendant_cas(db, ca)
    subtree_ids = [ca.id] + [d.id for d in descendants]
    cert_count = db.execute(
        select(func.count()).select_from(Certificate)
        .where(Certificate.ca_id.in_(subtree_ids))
    ).scalar_one()

    if (descendants or cert_count) and not cascade:
        raise ValueError(
            f"CA '{ca.name}' still has {len(descendants)} sub-CA(s) and "
            f"{cert_count} issued certificate(s). Enable cascade to delete the "
            "whole subtree, or remove those first."
        )

    # Delete issued certs in the subtree, then CAs deepest-first, then the CA.
    if cert_count:
        db.execute(delete(Certificate).where(Certificate.ca_id.in_(subtree_ids)))
    for d in descendants:  # already deepest-first
        db.delete(d)
    db.delete(ca)
    db.flush()
    return {"ca": ca.name, "sub_cas": len(descendants), "certs": int(cert_count)}


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
