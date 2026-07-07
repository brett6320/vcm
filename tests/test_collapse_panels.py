"""Template smoke tests for collapse-by-default non-essential panels (#77)."""
import base64
import itertools
import json
import os
import re

os.environ.setdefault("VCM_SECRET_KEY", "test-secret")
os.environ.setdefault("VCM_KEK_B64", base64.b64encode(os.urandom(32)).decode())
os.environ.setdefault("VCM_DATABASE_URL", "sqlite:///:memory:")

import pyotp  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (  # noqa: E402
    Role, Site, User, Vendor, VpnConnection,
)
from app.security.passwords import hash_password  # noqa: E402
from app.srx.model import Endpoint, VpnProfile  # noqa: E402


def _login(c, user):
    c.post("/login", data={"username": user, "password": "pw123456"})
    sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>",
                    c.get("/mfa/enroll").text).group(1)
    c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})


def _collapse_default_headings(html):
    """Headings of cards marked collapse-default, tag-stripped and trimmed."""
    out = []
    for m in re.finditer(r'<div class="card collapse-default">\s*<h[234]>(.*?)</h[234]>',
                         html, re.S):
        out.append(re.sub(r"<.*?>", "", m.group(1)).strip())
    return out


_counter = itertools.count()


def _setup():
    init_db()
    # The in-memory DB is shared across the session; use a unique site name.
    name = f"ColSite{next(_counter)}"
    with SessionLocal() as db:
        if not db.query(User).filter_by(username="coladm").first():
            db.add(User(username="coladm", password_hash=hash_password("pw123456"),
                        role=Role.admin))
        st = Site(name=name, vendor=Vendor.juniper_srx, source="test")
        db.add(st)
        db.flush()
        prof = VpnProfile(name="col", vendor="juniper_srx",
                          local=Endpoint("l", "1.1.1.1", "", ["10.1.0.0/24"]),
                          remote=Endpoint("r", "2.2.2.2", "", ["10.2.0.0/24"]))
        conn = VpnConnection(site_id=st.id, name="col",
                             params_json=json.dumps(prof.to_dict()),
                             generated_config="set security ike proposal p")
        db.add(conn)
        db.commit()
        return st.id, conn.id


def test_connection_page_collapses_non_essential_panels():
    _sid, cid = _setup()
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        _login(c, "coladm")
        page = c.get(f"/connections/{cid}").text
    marked = _collapse_default_headings(page)
    assert "Rename connection" in marked
    assert "Danger zone" in marked
    assert "Far-end (peer) configuration" in marked
    # Essential read panels stay expanded (not marked).
    assert not any("Proposals" in h for h in marked)
    assert "Parameters" not in marked


def test_pki_page_collapses_forms_keeps_hierarchy_open():
    _setup()
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        _login(c, "coladm")
        page = c.get("/pki").text
    marked = _collapse_default_headings(page)
    assert "Create CA" in marked
    assert "Import existing CA" in marked
    assert "Sign appliance CSR" in marked
    # Certificate hierarchy and the recent-certs list stay open.
    assert "Certificate hierarchy" not in marked
    assert "Recent certificates" not in marked


def test_site_page_collapses_actions_keeps_connection_list_open():
    sid, _cid = _setup()
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        _login(c, "coladm")
        page = c.get(f"/sites/{sid}").text
    marked = _collapse_default_headings(page)
    assert any("Add a connection" in h for h in marked)
    assert "Danger zone" in marked
    assert not any("VPN connections" in h for h in marked)


def test_collapsible_js_supports_default_marker():
    js = open(os.path.join(os.path.dirname(__file__), "..", "app", "static",
                           "collapsible.js")).read()
    assert "collapse-default" in js
    assert "data-collapse-default" in js
