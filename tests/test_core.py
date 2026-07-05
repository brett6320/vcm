import base64
import os

os.environ.setdefault("VCM_SECRET_KEY", "test-secret")
os.environ.setdefault("VCM_KEK_B64", base64.b64encode(os.urandom(32)).decode())
os.environ.setdefault("VCM_DATABASE_URL", "sqlite:///:memory:")

from app.pki import ca as ca_ops, csr as csr_ops, keys  # noqa: E402
from app.models import CAType  # noqa: E402
from app.srx import generators, importer  # noqa: E402
from app.srx.model import Endpoint, Phase1, Phase2, VpnProfile, all_warnings  # noqa: E402
from app.srx.proposals import rate_proposal  # noqa: E402


def _mk_profile(**over):
    p1 = Phase1(**over.get("p1", {}))
    p2 = Phase2(**over.get("p2", {}))
    return VpnProfile(
        name="siteA", vendor=over.get("vendor", "juniper_srx"),
        local=Endpoint("local", "198.51.100.1", "loc", ["10.1.0.0/24"]),
        remote=Endpoint("remote", "203.0.113.1", "rem", ["10.2.0.0/24"]),
        phase1=p1, phase2=p2,
    )


def test_warns_on_insecure():
    w = rate_proposal("3des", "sha1", "2", "ikev1")
    kinds = {x["kind"] for x in w}
    assert {"encryption", "integrity", "dh-group", "ike-version"} <= kinds


def test_warnings_not_duplicated():
    # IKEv1 + a weak algo shared across P1/P2 must appear once each, not twice.
    p = _mk_profile(p1={"ike_version": "ikev1", "integrity": "sha1"},
                    p2={"integrity": "sha1"})
    messages = [x["message"] for x in all_warnings(p)]
    assert len(messages) == len(set(messages)), messages
    ike = [m for m in messages if "ikev1" in m.lower() or "ikev2" in m.lower()]
    assert len(ike) == 1, ike


def test_strong_profile_no_warnings():
    assert all_warnings(_mk_profile()) == []


def test_srx_generation_and_roundtrip():
    p = _mk_profile(p1={"encryption": "aes-256-cbc"})
    cfg = generators.generate(p)
    assert "set security ike proposal" in cfg
    back = importer.import_config(cfg)
    assert back.vendor == "juniper_srx"
    assert back.phase1.encryption == "aes-256-cbc"


def test_all_vendors_generate():
    for v in ("juniper_srx", "digi", "cradlepoint", "pfsense", "fortinet",
              "palo_alto", "cisco_firepower", "strongswan", "mikrotik"):
        cfg = generators.generate(_mk_profile(vendor=v))
        assert cfg.strip()


def test_strongswan_and_mikrotik_roundtrip():
    # strongSwan uses swanctl (like pfSense) but must detect as strongswan
    ss = generators.generate(_mk_profile(vendor="strongswan"))
    assert "connections {" in ss and "strongSwan" in ss
    back = importer.import_config(ss)
    assert back.vendor == "strongswan"
    # MikroTik RouterOS
    p = _mk_profile(vendor="mikrotik", p1={"encryption": "aes-256-cbc", "dh_group": "20"})
    mt = generators.generate(p)
    assert mt.startswith("# ---- MikroTik") and "/ip ipsec" in mt
    b2 = importer.import_config(mt)
    assert b2.vendor == "mikrotik"
    assert b2.phase1.encryption == "aes-256-cbc"
    assert b2.phase1.dh_group == "20"
    assert b2.remote.public_ip == "203.0.113.1"


def test_new_vendor_roundtrips():
    for v in ("fortinet", "palo_alto", "cisco_firepower"):
        p = _mk_profile(vendor=v, p1={"encryption": "aes-256-cbc", "dh_group": "20"})
        cfg = generators.generate(p)
        back = importer.import_config(cfg)
        assert back.vendor == v, f"{v} detected as {back.vendor}"
        assert back.phase1.encryption == "aes-256-cbc", v
        assert back.phase1.dh_group == "20", v
        assert back.remote.public_ip == "203.0.113.1", v


JUNOS_STRUCTURED = """# Model: srx300
system { host-name FW-A; }
security {
    ike {
        proposal P1 {
            authentication-method rsa-signatures;
            dh-group group20;
            authentication-algorithm sha-256;
            encryption-algorithm aes-256-cbc;
        }
        proposal P1PSK {
            authentication-method pre-shared-keys;
            dh-group group14; authentication-algorithm sha1; encryption-algorithm aes-128-cbc;
        }
        policy POLC { proposals P1; certificate { local-certificate fw; } }
        policy POLP { proposals P1PSK; pre-shared-key ascii-text TOPSECRET; }
        gateway GW1 { ike-policy POLC; address 203.0.113.5;
            local-identity hostname a.example; remote-identity hostname b.example; }
        gateway GW2 { ike-policy POLP; address 198.51.100.9; version v2-only;
            local-identity hostname a.example; }
    }
    ipsec {
        proposal IP1 { protocol esp; authentication-algorithm hmac-sha-256-128;
            encryption-algorithm aes-256-cbc; }
        policy IPP { perfect-forward-secrecy { keys group19; } proposals IP1; }
        vpn TUN-A { bind-interface st0.0; ike { gateway GW1; ipsec-policy IPP; } }
        inactive: vpn TUN-OFF { bind-interface st0.1; ike { gateway GW1; ipsec-policy IPP; } }
        vpn TUN-B { bind-interface st0.2; ike { gateway GW2;
            proxy-identity { local 10.1.0.0/24; remote 10.2.0.0/24; } ipsec-policy IPP; } }
    }
}
"""


def test_junos_structured_multi_connection_import():
    from app.srx import importer
    assert importer.detect_vendor(JUNOS_STRUCTURED) == "juniper_srx"
    assert importer.is_structured_junos(JUNOS_STRUCTURED)
    site = importer.import_site(JUNOS_STRUCTURED)
    assert site["vendor"] == "juniper_srx" and site["model"] == "srx300"
    assert site["hostname"] == "FW-A"
    names = {c["profile"].name for c in site["connections"]}
    assert names == {"TUN-A", "TUN-B"}          # inactive TUN-OFF excluded
    by = {c["profile"].name: c for c in site["connections"]}
    a = by["TUN-A"]["profile"]
    assert a.phase1.encryption == "aes-256-cbc" and a.phase1.integrity == "sha256"
    assert a.phase1.dh_group == "20" and a.phase1.auth_method == "certificate"
    assert a.phase1.ike_version == "ikev1" and a.remote.public_ip == "203.0.113.5"
    assert a.phase2.pfs_group == "19" and a.phase2.integrity == "sha256"  # hmac normalized
    b = by["TUN-B"]["profile"]
    assert b.phase1.auth_method == "psk" and b.phase1.ike_version == "ikev2"
    assert b.local.protected_subnets == ["10.1.0.0/24"]
    assert b.remote.protected_subnets == ["10.2.0.0/24"]
    # PSK secret must never be persisted in the stored config excerpt
    assert "TOPSECRET" not in by["TUN-B"]["config"]
    assert "<redacted>" in by["TUN-B"]["config"]


def test_import_extracts_only_vpn_sections():
    # SRX: VPN lines mixed with unrelated system/interface config.
    p = _mk_profile()
    vpn = generators.generate(p)
    noisy = ("set system host-name fw1\n"
             "set system login user bob authentication plain-text-password secret123\n"
             "set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.9/24\n"
             + vpn)
    kept = importer.extract_vpn_sections(noisy, "juniper_srx")
    assert "host-name" not in kept
    assert "plain-text-password" not in kept
    assert "ge-0/0/1" not in kept
    assert "set security ike proposal" in kept

    # pfSense: only connections/secrets blocks retained.
    pf = generators.generate(_mk_profile(vendor="pfsense"))
    noisy_pf = "system {\n  hostname = fw2\n}\n" + pf + "\nunrelated { x = 1 }\n"
    kept_pf = importer.extract_vpn_sections(noisy_pf, "pfsense")
    assert "hostname" not in kept_pf
    assert "unrelated" not in kept_pf
    assert "connections {" in kept_pf


def test_pfsense_roundtrip():
    p = _mk_profile(vendor="pfsense", p1={"encryption": "aes-256-gcm", "dh_group": "20"})
    cfg = generators.generate(p)
    assert "esp_proposals" in cfg
    back = importer.import_config(cfg)
    assert back.vendor == "pfsense"
    assert back.phase1.encryption == "aes-256-gcm"
    assert back.phase1.dh_group == "20"


def test_peer_mirror_is_compatible():
    p = _mk_profile()
    peer = p.mirror("siteA-peer")
    assert peer.phase1.encryption == p.phase1.encryption
    assert peer.local.public_ip == p.remote.public_ip


def test_ike_id_suggestions():
    from app.srx import suggest
    # certificate auth -> FQDN-style, deterministic
    p = _mk_profile()
    p.local.id = ""
    p.remote.id = ""
    suggest.fill_ike_ids(p)
    assert p.local.id.endswith(".vpn.local") and "sitea" in p.local.id
    assert p.local.id != p.remote.id
    # psk auth with public IP -> IP-type id
    p2 = _mk_profile(p1={"auth_method": "psk"})
    p2.local.id = ""
    suggest.fill_ike_ids(p2)
    assert p2.local.id == "198.51.100.1"


def test_hierarchy_lineage_no_private_keys():
    from app.db import SessionLocal, init_db
    from app.models import CAType
    init_db()
    with SessionLocal() as db:
        root = ca_ops.create_ca(db, name="h-root", dn={"CN": "HR"}, ca_type=CAType.root,
                                key_type="ec", key_params="secp384r1", valid_days=3650)
        inter = ca_ops.create_ca(db, name="h-int", dn={"CN": "HI"},
                                 ca_type=CAType.intermediate, key_type="ec",
                                 key_params="secp384r1", valid_days=2000, parent=root)
        ca_ops.create_ca(db, name="h-iss", dn={"CN": "HS"}, ca_type=CAType.issuing,
                         key_type="ec", key_params="secp384r1", valid_days=1000, parent=inter)
        db.commit()
        tree = ca_ops.build_hierarchy(db, include_pem=True)
        node = next(n for n in tree if n["name"] == "h-root")
        assert node["cas"][0]["name"] == "h-int"
        assert node["cas"][0]["cas"][0]["name"] == "h-iss"
        blob = str(tree)
        assert "PRIVATE" not in blob and "key_enc" not in blob


def test_notify_backends_disabled_by_default():
    from app import notify
    ok, detail = notify.send_email("a@b.com", "s", "b")
    assert not ok and "not configured" in detail
    ok, detail = notify.send_sms("+15551230000", "hi")
    assert not ok and "not configured" in detail
    assert not notify.email_enabled() and not notify.sms_enabled()


def test_forced_password_change_flow():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role
    from app.security.passwords import hash_password
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="newop").first():
                db.add(User(username="newop", password_hash=hash_password("temp1234"),
                            role=Role.operator, must_change_password=True))
                db.commit()
        r = c.post("/login", data={"username": "newop", "password": "temp1234"},
                   follow_redirects=False)
        assert r.headers["location"] == "/account/first-password"
        # dashboard blocked until the password is changed
        assert c.get("/", follow_redirects=False).headers["location"] == "/account/first-password"
        assert "incorrect" in c.post("/account/first-password",
            data={"current": "wrong", "new": "brandnew99", "confirm": "brandnew99"}).text
        assert "differ" in c.post("/account/first-password",
            data={"current": "temp1234", "new": "temp1234", "confirm": "temp1234"}).text
        r = c.post("/account/first-password",
                   data={"current": "temp1234", "new": "brandnew99", "confirm": "brandnew99"},
                   follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/"
        # flag cleared → the next gate is MFA enrollment (prod default)
        assert c.get("/", follow_redirects=False).headers["location"] == "/mfa/enroll"


def test_multiple_passkeys_per_user():
    from app.db import SessionLocal, init_db
    from app.models import User, WebAuthnCredential
    init_db()
    with SessionLocal() as db:
        u = User(username="pk-user", password_hash="x")
        db.add(u)
        db.flush()
        db.add(WebAuthnCredential(user_id=u.id, name="laptop",
                                  credential_id=b"cred-1", public_key=b"k1"))
        db.add(WebAuthnCredential(user_id=u.id, name="yubikey",
                                  credential_id=b"cred-2", public_key=b"k2"))
        db.commit()
        db.refresh(u)
        assert len(u.credentials) == 2
        assert {c.name for c in u.credentials} == {"laptop", "yubikey"}
        assert u.has_mfa


def test_pki_hierarchy_and_csr_sign():
    from app.db import SessionLocal, init_db
    init_db()
    with SessionLocal() as db:
        root = ca_ops.create_ca(db, name="root", dn={"CN": "Test Root"},
                                ca_type=CAType.root, key_type="ec",
                                key_params="secp384r1", valid_days=3650)
        issuing = ca_ops.create_ca(db, name="issue", dn={"CN": "Test Issuing"},
                                   ca_type=CAType.issuing, key_type="ec",
                                   key_params="secp384r1", valid_days=1825, parent=root)
        key_pem, csr = csr_ops.generate_leaf_keypair_and_csr(
            {"CN": "srx1.example.com"}, "ec", "secp256r1", ["srx1.example.com"])
        cert = ca_ops.sign_csr(db, issuing_ca=issuing, csr=csr, valid_days=825,
                               san_dns=["srx1.example.com"])
        db.commit()
        assert "BEGIN CERTIFICATE" in cert.cert_pem
        chain = ca_ops.chain_pem(db, issuing)
        assert chain.count("BEGIN CERTIFICATE") == 2  # issuing + root
        # never export CA private key
        assert not hasattr(cert, "key_pem")
