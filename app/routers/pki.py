from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import CAType, CertAuthority, Certificate, User
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
        cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
        return render(request, "pki.html", error=f"Create CA failed: {e}", cas=cas, certs=[],
                      ca_types=list(CAType), hierarchy=ca_ops.build_hierarchy(db))
    audit(db, request, "pki.ca_create", f"{ca.ca_type.value}:{name}", user=user)
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

    if confirm_name.strip() != ca.name:
        return _back("CA name confirmation did not match — nothing was deleted.")
    try:
        summary = ca_ops.delete_ca(db, ca, cascade=bool(cascade))
    except ValueError as e:
        return _back(str(e))
    audit(db, request, "pki.ca_delete",
          f"{summary['ca']} (+{summary['sub_cas']} sub-CA, {summary['certs']} certs)", user=user)
    return RedirectResponse("/pki", status_code=303)


@router.get("/ca/{ca_id}/chain")
def ca_chain(ca_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    return PlainTextResponse(ca_ops.chain_pem(db, ca), media_type="application/x-pem-file")


@router.get("/ca/{ca_id}/cert")
def ca_cert(ca_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    ca = db.get(CertAuthority, ca_id)
    if not ca:
        raise HTTPException(404, "Not found")
    return PlainTextResponse(ca.cert_pem, media_type="application/x-pem-file")


@router.post("/sign")
def sign_csr(request: Request, issuing_ca_id: int = Form(...), csr_pem: str = Form(...),
             valid_days: int = Form(825), san_dns: str = Form(""),
             db: Session = Depends(get_db), user: User = Depends(current_user)):
    issuing = db.get(CertAuthority, issuing_ca_id)
    if not issuing:
        return render(request, "pki.html", error="Issuing CA not found",
                      cas=db.execute(select(CertAuthority)).scalars().all(), certs=[],
                      ca_types=list(CAType))
    try:
        csr = csr_ops.parse_csr(csr_pem)
        dns = [d.strip() for d in san_dns.split(",") if d.strip()]
        cert = ca_ops.sign_csr(db, issuing_ca=issuing, csr=csr, valid_days=valid_days,
                               san_dns=dns)
    except Exception as e:  # noqa: BLE001
        cas = db.execute(select(CertAuthority)).scalars().all()
        return render(request, "pki.html", error=str(e), cas=cas, certs=[],
                      ca_types=list(CAType))
    audit(db, request, "pki.sign_csr", f"serial={cert.serial}", user=user)
    return RedirectResponse(f"/pki/cert/{cert.id}", status_code=303)


@router.get("/cert/{cert_id}")
def cert_detail(cert_id: int, request: Request, db: Session = Depends(get_db),
                user: User = Depends(current_user)):
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(404, "Not found")
    fullchain = cert.cert_pem + "\n" + ca_ops.chain_pem(db, cert.ca)
    return render(request, "cert.html", cert=cert, fullchain=fullchain)


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
    if confirm_serial.strip() != cert.serial:
        fullchain = cert.cert_pem + "\n" + ca_ops.chain_pem(db, cert.ca)
        return render(request, "cert.html", cert=cert, fullchain=fullchain,
                      error="Serial confirmation did not match — nothing was deleted.")
    serial, subject = cert.serial, cert.subject_dn
    db.delete(cert)
    db.flush()
    audit(db, request, "pki.cert_delete", f"{serial}:{subject}", user=user)
    return RedirectResponse("/pki", status_code=303)
