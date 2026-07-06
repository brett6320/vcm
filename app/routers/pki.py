from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import CAType, CertAuthority, Certificate, User
from ..pki import ca as ca_ops
from ..pki import csr as csr_ops
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
    ca = ca_ops.create_ca(db, name=name, dn={k: v for k, v in dn.items() if v},
                          ca_type=CAType(ca_type), key_type=key_type, key_params=key_params,
                          valid_days=valid_days, parent=parent)
    audit(db, request, "pki.ca_create", f"{ca.ca_type.value}:{name}", user=user)
    return RedirectResponse("/pki", status_code=303)


@router.post("/ca/import")
def import_ca(request: Request, name: str = Form(...), cert_pem: str = Form(...),
              key_pem: str = Form(""), ca_type: str = Form(""),
              db: Session = Depends(get_db), user: User = Depends(require_admin)):
    override = CAType(ca_type) if ca_type else None
    try:
        ca = ca_ops.import_ca(db, name=name, cert_pem=cert_pem, key_pem=key_pem or None,
                              ca_type_override=override)
    except Exception as e:  # noqa: BLE001
        cas = db.execute(select(CertAuthority).order_by(CertAuthority.id)).scalars().all()
        return render(request, "pki.html", error=f"Import failed: {e}", cas=cas, certs=[],
                      ca_types=list(CAType), hierarchy=ca_ops.build_hierarchy(db))
    audit(db, request, "pki.ca_import",
          f"{ca.ca_type.value}:{name}{'' if ca.has_private_key else ' (no key)'}", user=user)
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
