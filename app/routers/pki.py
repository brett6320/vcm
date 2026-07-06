from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from ..config import get_settings
from ..db import get_db
from ..models import CAType, CertAuthority, Certificate, CertStatus, User, classify_expiry, utcnow
from ..pki import ca as ca_ops
from ..pki import csr as csr_ops
from ..pki import material
from ..security.deps import audit, current_user, require_admin
from ..templates_env import render

router = APIRouter(prefix="/pki", tags=["pki"])
cfg = get_settings()


@router.get("")
def pki_home(request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
    certs = db.execute(
        select(Certificate).order_by(Certificate.id.desc()).limit(50)
    ).scalars().all()
    hierarchy = ca_ops.build_hierarchy(db)
    return render(request, "pki.html", cas=cas, certs=certs, ca_types=list(CAType),
                  hierarchy=hierarchy)


@router.get("/tree.json")
def pki_tree_json(include_pem: bool = False, db: Session = Depends(get_db),
                  user: User = Depends(current_user)):
    """Public PKI hierarchy with clear lineage. Never contains private keys."""
    return {"hierarchy": ca_ops.build_hierarchy(db, include_pem=include_pem)}


@router.post("/ca")
def create_ca(request: Request, name: str = Form(...), cn: str = Form(...),
              org: str = Form(""), country: str = Form(""), ca_type: str = Form(...),
              parent_id: str = Form(""), valid_days: int = Form(3650),
              key_type: str = Form("ec"), key_params: str = Form("secp384r1"),
              db: Session = Depends(get_db), user: User = Depends(require_admin)):
    parent = db.get(CertAuthority, int(parent_id)) if parent_id else None
    dn = {"CN": cn, "O": org, "C": country}
    try:
        ca = ca_ops.create_ca(db, name=name, dn={k: v for k, v in dn.items() if v},
                              ca_type=CAType(ca_type), key_type=key_type, key_params=key_params,
                              valid_days=valid_days, parent=parent)
    except (ValueError, TypeError) as e:
        db.rollback()
        cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
        return render(request, "pki.html", error=f"Create CA failed: {e}", cas=cas, certs=[],
                      ca_types=list(CAType), hierarchy=ca_ops.build_hierarchy(db))
    if ca.pending:
        audit(db, request, "pki.ca_csr_created", f"{ca.ca_type.value}:{name}", user=user)
        return RedirectResponse(f"/pki/ca/{ca.id}", status_code=303)
    audit(db, request, "pki.ca_create", f"{ca.ca_type.value}:{name}", user=user)
    return RedirectResponse("/pki", status_code=303)


@router.get("/ca/{ca_id}")
def ca_detail(ca_id: int, request: Request, db: Session = Depends(get_db),
              user: User = Depends(current_user)):
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    parent = db.get(CertAuthority, ca.parent_id) if ca.parent_id else None
    chain = None if ca.pending else ca_ops.chain_pem(db, ca)
    return render(request, "ca_detail.html", ca=ca, parent=parent, chain=chain)


@router.get("/ca/{ca_id}/csr")
def ca_csr(ca_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ca = db.get(CertAuthority, ca_id)
    if not ca or not ca.csr_pem:
        raise HTTPException(404, "No pending CSR for this CA")
    return PlainTextResponse(ca.csr_pem, media_type="application/pkcs10",
                             headers={"Content-Disposition":
                                      f'attachment; filename="{ca.name}.csr"'})


@router.post("/ca/{ca_id}/complete")
async def complete_ca(ca_id: int, request: Request, cert_pem: str = Form(""),
                      cert_file: UploadFile | None = File(None),
                      allow_non_ca: str = Form(""),
                      db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Upload the externally-signed certificate for a pending CA."""
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    try:
        # This flow only ever expects a certificate (PEM or DER) — never a key
        # or a PKCS#12 bundle — so decode it directly rather than sniffing p12.
        if cert_file is not None and cert_file.filename:
            cert_pem = material.load_cert(await cert_file.read())
        if not cert_pem.strip():
            raise ValueError("Provide the signed certificate (paste PEM or upload a file)")
        ca_ops.complete_pending_ca(db, ca, cert_pem, allow_non_ca=bool(allow_non_ca))
    except (ValueError, TypeError) as e:
        db.rollback()
        parent = db.get(CertAuthority, ca.parent_id) if ca.parent_id else None
        return render(request, "ca_detail.html", ca=ca, parent=parent, chain=None,
                      error=f"Could not complete CA: {e}")
    audit(db, request, "pki.ca_completed", ca.name, user=user)
    return RedirectResponse(f"/pki/ca/{ca.id}", status_code=303)


@router.post("/ca/{ca_id}/new-csr")
def regenerate_csr(ca_id: int, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    """Generate a fresh key + CSR for a pending CA, reusing its create data."""
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    try:
        ca_ops.regenerate_pending_csr(db, ca)
    except ValueError as e:
        db.rollback()
        parent = db.get(CertAuthority, ca.parent_id) if ca.parent_id else None
        return render(request, "ca_detail.html", ca=ca, parent=parent, chain=None, error=str(e))
    audit(db, request, "pki.ca_csr_regenerated", ca.name, user=user)
    return RedirectResponse(f"/pki/ca/{ca.id}", status_code=303)


@router.post("/ca/{ca_id}/discard")
def discard_pending_ca(ca_id: int, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    """Delete an incomplete (pending) CA. Allowed without the usual unlock/name
    gate since a pending CA is never usable and has no dependents."""
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    if not ca.pending:
        raise HTTPException(409, "Only pending CAs can be discarded here")
    name = ca.name
    db.delete(ca)
    db.flush()
    audit(db, request, "pki.ca_discarded", name, user=user)
    return RedirectResponse("/pki", status_code=303)


@router.post("/ca/import")
async def import_ca(request: Request, name: str = Form(...), cert_pem: str = Form(""),
                    key_pem: str = Form(""), ca_type: str = Form(""),
                    cert_file: UploadFile | None = File(None),
                    p12_password: str = Form(""),
                    db: Session = Depends(get_db), user: User = Depends(require_admin)):
    override = CAType(ca_type) if ca_type else None
    try:
        # An uploaded file (PEM or PKCS#12) takes precedence over pasted PEM.
        if cert_file is not None and cert_file.filename:
            data = await cert_file.read()
            up_cert, up_key = material.load_material(cert_file.filename, data,
                                                     p12_password or None)
            cert_pem = up_cert
            key_pem = up_key or key_pem
        if not cert_pem.strip():
            raise ValueError("Provide a certificate (paste PEM or upload a file)")
        ca = ca_ops.import_ca(db, name=name, cert_pem=cert_pem, key_pem=key_pem or None,
                              ca_type_override=override)
    except Exception as e:  # noqa: BLE001
        db.rollback()
        cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
        return render(request, "pki.html", error=f"Import failed: {e}", cas=cas, certs=[],
                      ca_types=list(CAType), hierarchy=ca_ops.build_hierarchy(db))
    audit(db, request, "pki.ca_import",
          f"{ca.ca_type.value}:{name}{'' if ca.has_private_key else ' (no key)'}", user=user)
    return RedirectResponse("/pki", status_code=303)


@router.post("/ca/{ca_id}/delete")
def delete_ca(ca_id: int, request: Request, confirm_name: str = Form(""),
              cascade: str = Form(""), db: Session = Depends(get_db),
              user: User = Depends(require_admin)):
    """Delete a CA (admin-only). Requires re-typing the CA name. Refuses a CA
    that still has sub-CAs or issued certs unless 'cascade' is checked, which
    removes the whole subtree. This deletes the CA and its private key."""
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")

    def _back(error: str):
        cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
        certs = db.execute(
            select(Certificate).order_by(Certificate.id.desc()).limit(50)).scalars().all()
        return render(request, "pki.html", error=error, cas=cas, certs=certs,
                      ca_types=list(CAType), hierarchy=ca_ops.build_hierarchy(db))

    if ca.locked:
        return _back(f"CA '{ca.name}' is locked. Unlock it before deleting.")
    if confirm_name.strip() != ca.name:
        return _back("CA name confirmation did not match — nothing was deleted.")
    try:
        summary = ca_ops.delete_ca(db, ca, cascade=bool(cascade))
    except ValueError as e:
        return _back(str(e))
    audit(db, request, "pki.ca_delete",
          f"{summary['ca']} (+{summary['sub_cas']} sub-CA, {summary['certs']} certs)", user=user)
    return RedirectResponse("/pki", status_code=303)


@router.post("/ca/{ca_id}/lock")
def lock_ca(ca_id: int, request: Request, locked: str = Form(""),
            db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Toggle delete-protection on a CA (admin-only)."""
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    ca.locked = bool(locked)
    db.flush()
    audit(db, request, "pki.ca_lock" if ca.locked else "pki.ca_unlock", ca.name, user=user)
    return RedirectResponse("/pki", status_code=303)


@router.get("/ca/{ca_id}/chain")
def ca_chain(ca_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    if ca.pending:
        raise HTTPException(409, "CA is pending its signed certificate")
    return PlainTextResponse(ca_ops.chain_pem(db, ca), media_type="application/x-pem-file")


@router.get("/ca/{ca_id}/cert")
def ca_cert(ca_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    if ca.pending or not ca.cert_pem:
        raise HTTPException(409, "CA is pending its signed certificate")
    return PlainTextResponse(ca.cert_pem, media_type="application/x-pem-file")


@router.post("/sign")
async def sign_csr(request: Request, issuing_ca_id: int = Form(...), csr_pem: str = Form(""),
                   csr_file: UploadFile | None = File(None),
                   valid_days: int = Form(825), san_dns: str = Form(""),
                   db: Session = Depends(get_db), user: User = Depends(current_user)):
    def _err(msg: str):
        db.rollback()
        cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
        return render(request, "pki.html", error=msg, cas=cas, certs=[],
                      ca_types=list(CAType), hierarchy=ca_ops.build_hierarchy(db))

    issuing = db.get(CertAuthority, issuing_ca_id)
    if not issuing:
        return _err("Issuing CA not found")
    try:
        # An uploaded CSR file takes precedence over pasted PEM.
        if csr_file is not None and csr_file.filename:
            csr_pem = (await csr_file.read()).decode(errors="ignore")
        if not csr_pem.strip():
            raise ValueError("Provide a CSR (paste PEM or upload a file)")
        csr = csr_ops.parse_csr(csr_pem)
        dns = [d.strip() for d in san_dns.split(",") if d.strip()]
        cert = ca_ops.sign_csr(db, issuing_ca=issuing, csr=csr, valid_days=valid_days,
                               san_dns=dns)
    except Exception as e:  # noqa: BLE001
        return _err(str(e))
    audit(db, request, "pki.sign_csr", f"serial={cert.serial}", user=user)
    return RedirectResponse(f"/pki/cert/{cert.id}", status_code=303)


def _san_from_cert(cert: x509.Certificate) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    names = [g.value if hasattr(g, "value") else str(g) for g in ext.value]
    return ",".join(str(n) for n in names) or None


@router.post("/cert/import")
async def import_cert(request: Request, cert_pem: str = Form(""),
                      cert_file: UploadFile | None = File(None),
                      signing_ca_id: str = Form(""), ca_prompted: str = Form(""),
                      db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Import a leaf (end-entity) certificate for observation only. Tracked for
    expiry but not managed — VCM cannot renew/revoke it. Accepts pasted PEM or an
    uploaded PEM/DER file. The signing CA is auto-detected when possible; if not,
    the operator is prompted to pick it and the choice is validated."""
    def _err(msg: str):
        db.rollback()
        cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
        certs = db.execute(
            select(Certificate).order_by(Certificate.id.desc()).limit(50)).scalars().all()
        return render(request, "pki.html", error=msg, cas=cas, certs=certs,
                      ca_types=list(CAType), hierarchy=ca_ops.build_hierarchy(db))

    try:
        if cert_file is not None and cert_file.filename:
            cert_pem = material.load_cert(await cert_file.read())
        if not cert_pem.strip():
            raise ValueError("Provide a certificate (paste PEM or upload a file)")
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        if _is_ca_cert(cert):
            raise ValueError("This is a CA certificate — import it under 'Import existing CA'.")
        # Identity is the fingerprint — refuse the same cert twice (managed or observed).
        fp = cert.fingerprint(hashes.SHA256()).hex()
        dupe = db.execute(
            select(Certificate).where(Certificate.fingerprint == fp)).scalar_one_or_none()
        if dupe is not None:
            raise ValueError(f"This certificate is already tracked (serial {dupe.serial}).")

        # Determine the signing CA: auto-detect, else prompt, else validate the choice.
        ca_id = None
        auto = ca_ops.find_issuer_ca(db, cert)
        if auto is not None:
            ca_id = auto.id
        elif not ca_prompted:
            cas = db.execute(select(CertAuthority).where(CertAuthority.pending.is_(False))
                             .order_by(CertAuthority.name)).scalars().all()
            return render(request, "cert_import_ca.html", cert_pem=cert_pem, cas=cas,
                          subject=cert.subject.rfc4514_string(),
                          issuer=cert.issuer.rfc4514_string())
        elif signing_ca_id and signing_ca_id != "external":
            chosen = db.get(CertAuthority, int(signing_ca_id))
            chosen_cert = (x509.load_pem_x509_certificate(chosen.cert_pem.encode())
                           if chosen and chosen.cert_pem else None)
            if chosen_cert is None or not ca_ops.verify_signed_by(cert, chosen_cert):
                raise ValueError(
                    "The selected CA did not sign this certificate. Pick the correct "
                    "issuer, or choose 'External CA (not in VCM)' to observe it unlinked.")
            ca_id = chosen.id
        # else: signing_ca_id == "external" (or blank after prompt) -> observe unlinked.

        not_after = ca_ops._aware(cert.not_valid_after_utc)
        status = CertStatus.expired if classify_expiry(not_after) == "expired" \
            else CertStatus.active
        row = Certificate(
            ca_id=ca_id, managed=False, source="imported",
            serial=format(cert.serial_number, "x"),
            subject_dn=cert.subject.rfc4514_string(),
            san=_san_from_cert(cert),
            cert_pem=cert.public_bytes(ca_ops.serialization_encoding()).decode(),
            fingerprint=fp,
            status=status,
            not_before=ca_ops._aware(cert.not_valid_before_utc),
            not_after=not_after,
        )
        db.add(row)
        db.flush()
    except Exception as e:  # noqa: BLE001
        return _err(f"Import failed: {e}")
    audit(db, request, "pki.cert_import", f"serial={row.serial}:{row.subject_dn}", user=user)
    return RedirectResponse(f"/pki/cert/{row.id}", status_code=303)


def _is_ca_cert(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


@router.get("/cert/{cert_id}")
def cert_detail(cert_id: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(404, "Not found")
    fullchain = cert.cert_pem if cert.ca is None \
        else cert.cert_pem + "\n" + ca_ops.chain_pem(db, cert.ca)
    # Candidate managed certs to supersede an observed cert with (renewal link).
    managed_certs = []
    if not cert.managed and not cert.is_superseded:
        managed_certs = db.execute(
            select(Certificate).where(Certificate.managed.is_(True),
                                      Certificate.id != cert.id)
            .order_by(Certificate.id.desc())).scalars().all()
    return render(request, "cert.html", cert=cert, fullchain=fullchain,
                  managed_certs=managed_certs)


@router.get("/cert/{cert_id}/pem")
def cert_pem(cert_id: int, fmt: str = "cert", db: Session = Depends(get_db),
             user: User = Depends(current_user)):
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(404, "Not found")
    body = cert.cert_pem if fmt == "cert" else cert.cert_pem + "\n" + ca_ops.chain_pem(db, cert.ca)
    return PlainTextResponse(body, media_type="application/x-pem-file")


@router.post("/cert/{cert_id}/delete")
def delete_cert(cert_id: int, request: Request, confirm_serial: str = Form(""),
                db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Permanently delete an issued certificate. Admin-only; the operator must
    re-type the certificate serial to confirm (guards against wrong-row deletes).
    Removes only the issued leaf record — CAs are never touched here."""
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(404, "Not found")

    def _back(error: str):
        fullchain = cert.cert_pem if cert.ca is None \
            else cert.cert_pem + "\n" + ca_ops.chain_pem(db, cert.ca)
        return render(request, "cert.html", cert=cert, fullchain=fullchain, error=error)

    if cert.locked:
        return _back("This certificate is locked. Unlock it before deleting.")
    if confirm_serial.strip() != cert.serial:
        return _back("Serial confirmation did not match — nothing was deleted.")
    serial, subject = cert.serial, cert.subject_dn
    db.delete(cert)
    db.flush()
    audit(db, request, "pki.cert_delete", f"{serial}:{subject}", user=user)
    return RedirectResponse("/pki", status_code=303)


@router.post("/cert/{cert_id}/lock")
def lock_cert(cert_id: int, request: Request, locked: str = Form(""),
              db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Toggle delete-protection on an issued certificate (admin-only)."""
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(404, "Not found")
    cert.locked = bool(locked)
    db.flush()
    audit(db, request, "pki.cert_lock" if cert.locked else "pki.cert_unlock",
          cert.serial, user=user)
    return RedirectResponse(f"/pki/cert/{cert.id}", status_code=303)


@router.post("/cert/{cert_id}/replace")
def replace_cert(cert_id: int, request: Request, replacement_id: str = Form(""),
                 db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Mark an observed (imported) certificate as superseded by a managed cert on
    renewal. Sets replaced_by_id and drops the observed cert from expiry metrics.
    Posting an empty replacement_id clears the link."""
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(404, "Not found")

    def _back(error: str):
        fullchain = cert.cert_pem if cert.ca is None \
            else cert.cert_pem + "\n" + ca_ops.chain_pem(db, cert.ca)
        managed_certs = db.execute(
            select(Certificate).where(Certificate.managed.is_(True),
                                      Certificate.id != cert.id)
            .order_by(Certificate.id.desc())).scalars().all()
        return render(request, "cert.html", cert=cert, fullchain=fullchain,
                      managed_certs=managed_certs, error=error)

    if cert.managed:
        return _back("Only observed (imported) certificates can be superseded this way.")
    if not replacement_id.strip():
        cert.replaced_by_id = None
        db.flush()
        audit(db, request, "pki.cert_unsupersede", cert.serial, user=user)
        return RedirectResponse(f"/pki/cert/{cert.id}", status_code=303)
    repl = db.get(Certificate, int(replacement_id))
    if not repl or not repl.managed:
        return _back("Choose an existing managed certificate to supersede this one.")
    if repl.id == cert.id:
        return _back("A certificate cannot replace itself.")
    cert.replaced_by_id = repl.id
    db.flush()
    audit(db, request, "pki.cert_supersede",
          f"{cert.serial} -> {repl.serial}", user=user)
    return RedirectResponse(f"/pki/cert/{cert.id}", status_code=303)
