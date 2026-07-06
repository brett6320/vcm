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


def test_rename_syntax_per_vendor():
    from app.srx import rename
    p = _mk_profile()
    # Juniper: atomic rename statements
    j = rename.rename_config("juniper_srx", p, "old", "new")
    assert "rename security ipsec vpn vpn-old to vpn-new" in j
    # Fortinet
    f = rename.rename_config("fortinet", p, "old", "new")
    assert "rename old to new" in f
    # MikroTik
    m = rename.rename_config("mikrotik", p, "old", "new")
    assert "/ip ipsec peer set [find name=old] name=new" in m
    # Palo
    pa = rename.rename_config("palo_alto", p, "old", "new")
    assert "rename network tunnel ipsec old to new" in pa
    # Cisco: delete/recreate guidance
    c = rename.rename_config("cisco_firepower", p, "old", "new")
    assert "no access-list old_acl" in c
    # regenerating under a new name renames objects in the config too
    p.name = "new"
    assert "vpn-new" in generators.generate(p) and "vpn-old" not in generators.generate(p)


def test_vendor_options_use_platform_terminology():
    from app.srx import proposals
    fort = proposals.vendor_options("fortinet")
    enc_labels = {o["label"]: o["value"] for o in fort["encryption"]}
    assert enc_labels.get("aes256") == "aes-256-cbc"       # Fortinet's own keyword
    assert enc_labels.get("aes256gcm") == "aes-256-gcm"
    # Only supported algos are offered — Cradlepoint has no 'des' mapping
    crad = {o["value"] for o in proposals.vendor_options("cradlepoint")["encryption"]}
    assert "des" not in crad
    palo = proposals.vendor_options("palo_alto")
    pl = {o["label"]: o["value"] for o in palo["dh_groups"]}
    assert pl.get("group20") == "20"
    mt = proposals.vendor_options("mikrotik")
    ml = {o["label"] for o in mt["dh_groups"]}
    assert "ecp384" in ml  # MikroTik terminology


def test_bgp_optional_and_per_platform():
    from app.srx.model import Bgp
    # Off by default → no BGP in output
    p = _mk_profile()
    assert "bgp" not in generators.generate(p).lower()
    # Enabled on a BGP-capable platform (Juniper)
    p.bgp = Bgp(enabled=True, local_as="65001", peer_as="65002", peer_ip="169.254.0.2",
                networks=["10.1.0.0/24"])
    cfg = generators.generate(p)
    assert "autonomous-system 65001" in cfg and "peer-as 65002" in cfg
    assert "neighbor 169.254.0.2" in cfg
    # Cisco form
    c = _mk_profile(vendor="cisco_firepower")
    c.bgp = Bgp(enabled=True, local_as="65001", peer_as="65002", peer_ip="169.254.0.2")
    assert "router bgp 65001" in generators.generate(c)
    # Non-BGP platform (Digi) → note, not config
    d = _mk_profile(vendor="digi")
    d.bgp = Bgp(enabled=True, local_as="65001", peer_as="65002", peer_ip="169.254.0.2")
    out = generators.generate(d)
    assert "not supported" in out.lower()
    # mirror swaps ASNs and neighbor/local for the far end
    m = p.mirror("peer")
    assert m.bgp.local_as == "65002" and m.bgp.peer_as == "65001"


AWS_CONFIG = """Amazon Web Services
VPN Connection Configuration

IPSec Tunnel #1
================
#1: Internet Key Exchange Configuration
   - Encryption Algorithm     : AES-256
   - Authentication Algorithm : SHA-256
   - Perfect Forward Secrecy  : Diffie-Hellman Group 20
   - Pre-Shared Key           : someverysecretkey
#3: Tunnel Interface Configuration
   Outside IP Addresses:
   - Customer Gateway         : 203.0.113.5
   - Virtual Private Gateway  : 52.10.20.30
#4: Border Gateway Protocol (BGP) Configuration
   - Customer Gateway ASN         : 65000
   - Virtual Private Gateway ASN  : 64512
   - Neighbor IP Address          : 169.254.10.1
"""


def test_aws_import_only_and_far_end():
    from app.models import Vendor
    from app.srx import importer, generators
    assert Vendor.aws.import_only and Vendor.azure.import_only
    assert Vendor.juniper_srx not in [v for v in Vendor if v.import_only]
    site = importer.import_site(AWS_CONFIG)
    assert site["vendor"] == "aws"
    prof = site["connections"][0]["profile"]
    assert prof.remote.public_ip == "52.10.20.30"
    assert prof.phase1.encryption == "aes-256-cbc" and prof.phase1.integrity == "sha256"
    assert prof.phase1.dh_group == "20"
    assert prof.bgp.enabled and prof.bgp.peer_as == "64512" and prof.bgp.local_as == "65000"
    assert site["connections"][0]["review"]  # flagged for review
    # PSK is not stored
    assert "someverysecretkey" not in str(prof.to_dict())
    # far-end (on-prem) config generates from the mirrored profile
    peer = prof.mirror("onprem")
    peer.vendor = "juniper_srx"
    assert "set security ike" in generators.generate(peer)
    # generating for AWS itself just returns a note
    assert "managed by AWS" in generators.generate(prof)


def test_interface_and_tunnel_ip_inputs():
    p = _mk_profile()
    p.tunnel_interface = "st0.5"
    p.wan_interface = "ge-0/0/3.0"
    p.tunnel_ip = "169.254.0.1/30"
    cfg = generators.generate(p)
    assert "bind-interface st0.5" in cfg
    assert "external-interface ge-0/0/3.0" in cfg
    assert "set interfaces st0.5 family inet address 169.254.0.1/30" in cfg
    # Palo honours interfaces too
    pa = _mk_profile(vendor="palo_alto")
    pa.wan_interface = "ethernet1/2"; pa.tunnel_interface = "tunnel.7"
    pc = generators.generate(pa)
    assert "local-address interface ethernet1/2" in pc and "tunnel-interface tunnel.7" in pc


def test_srx_uses_hostname_identities():
    p = _mk_profile()
    p.local.id = "hq.vpn.local"
    p.remote.id = "dc.vpn.local"
    cfg = generators.generate(p)
    assert "local-identity hostname hq.vpn.local" in cfg
    assert "remote-identity hostname dc.vpn.local" in cfg
    assert "distinguished-name" not in cfg
    # IP-form ID -> inet; DN-form -> distinguished-name
    p.local.id = "203.0.113.1"; p.remote.id = "CN=fw.example.com"
    cfg = generators.generate(p)
    assert "local-identity inet 203.0.113.1" in cfg
    assert "remote-identity distinguished-name" in cfg


def test_srx_traffic_selectors_by_peer_platform():
    ts_line = "vpn-siteA traffic-selector ts0 local-ip"
    # Route-based peer (another SRX) → no traffic-selector config lines
    p = _mk_profile()
    p.remote_vendor = "juniper_srx"
    out = generators.generate(p)
    assert ts_line not in out and "route-based" in out
    # pfSense peer REQUIRES matching traffic-selectors (policy-based)
    p.remote_vendor = "pfsense"
    out = generators.generate(p)
    assert "traffic-selector ts0 local-ip 10.1.0.0/24" in out
    assert "REQUIRED" in out and "MUST match" in out
    # AWS peer → traffic-selector config present
    p.remote_vendor = "aws"
    assert "traffic-selector ts0 local-ip 10.1.0.0/24" in generators.generate(p)
    # Fortinet/Palo are route-based (VTI) → omit selectors
    p.remote_vendor = "fortinet"
    assert ts_line not in generators.generate(p)
    # Unspecified → safe default includes them
    p.remote_vendor = ""
    assert ts_line in generators.generate(p)


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

    # strongSwan swanctl: only connections/secrets blocks retained.
    ss = generators.generate(_mk_profile(vendor="strongswan"))
    noisy_ss = "system {\n  hostname = fw2\n}\n" + ss + "\nunrelated { x = 1 }\n"
    kept_ss = importer.extract_vpn_sections(noisy_ss, "strongswan")
    assert "hostname" not in kept_ss
    assert "unrelated" not in kept_ss
    assert "connections {" in kept_ss


def test_pfsense_gui_output():
    # pfSense is GUI/config.xml-driven, so we emit the GUI field values.
    p = _mk_profile(vendor="pfsense", p1={"encryption": "aes-256-gcm", "dh_group": "20"})
    p.wan_interface = "WAN"
    cfg = generators.generate(p)
    assert "VPN > IPsec > Tunnels" in cfg
    assert "Key Exchange version : IKEv2" in cfg
    assert "Encryption Algorithm : AES256-GCM" in cfg   # AEAD, no separate hash
    assert "Key length: 128 bits (ICV)" in cfg          # GCM ICV length present
    assert "DH Group             : 20" in cfg
    assert "Interface            : WAN" in cfg
    # CBC shows key length + hash
    p2 = _mk_profile(vendor="pfsense", p1={"encryption": "aes-256-cbc", "integrity": "sha256"})
    c2 = generators.generate(p2)
    assert "AES" in c2 and "Key length: 256 bits" in c2 and "Hash                 : SHA256" in c2


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


def test_connection_name_slugified():
    from app.routers.sites import _slug
    assert _slug("HQ to DC") == "HQ-to-DC"
    assert _slug("  spaced  name ") == "spaced-name"
    assert _slug("ok_name.1-2") == "ok_name.1-2"
    assert _slug("weird/@#chars!") == "weird-chars"


def test_edit_connection():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role, VpnConnection
    from app.security.passwords import hash_password
    import pyotp, re, json
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="ed").first():
                db.add(User(username="ed", password_hash=hash_password("pw123456"),
                            role=Role.admin))
                db.commit()
        c.post("/login", data={"username": "ed", "password": "pw123456"})
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})
        r = c.post("/sites/generate", data=dict(name="EE", vendor="juniper_srx",
                   local_ip="1.1.1.1", remote_ip="2.2.2.2", local_subnets="10.1.0.0/24",
                   remote_subnets="10.2.0.0/24", auth_method="certificate"),
                   follow_redirects=False)
        cid = int(r.headers["location"].split("/")[-1])
        # edit form pre-fills current values
        assert 'value="2.2.2.2"' in c.get(f"/connections/{cid}/edit").text
        # change the remote IP + P1 encryption
        r = c.post(f"/connections/{cid}/edit", data=dict(
            local_ip="1.1.1.1", remote_ip="9.9.9.9", local_subnets="10.1.0.0/24",
            remote_subnets="10.9.0.0/24", auth_method="certificate",
            p1_enc="aes-256-cbc", p1_integ="sha256", p1_dh="14",
            p1_ver="ikev2", p2_enc="aes-256-cbc", p2_integ="sha256", p2_pfs="14"),
            follow_redirects=False)
        assert r.status_code == 303
        with SessionLocal() as db:
            conn = db.get(VpnConnection, cid)
            p = json.loads(conn.params_json)
            assert p["remote"]["public_ip"] == "9.9.9.9"
            assert p["phase1"]["encryption"] == "aes-256-cbc"
            assert "aes-256-cbc" in conn.generated_config       # regenerated
            assert conn.name == "EE-vpn"                          # name unchanged


def test_change_remote_device_on_connection():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role, VpnConnection
    from app.security.passwords import hash_password
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="dev").first():
                db.add(User(username="dev", password_hash=hash_password("pw123456"),
                            role=Role.admin))
                db.commit()
        import pyotp, re
        c.post("/login", data={"username": "dev", "password": "pw123456"})
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})
        g = dict(local_ip="198.51.100.1", remote_ip="203.0.113.1",
                 local_subnets="10.1.0.0/24", remote_subnets="10.2.0.0/24",
                 auth_method="certificate")
        r = c.post("/sites/generate", data=dict(name="HQ", vendor="juniper_srx", **g),
                   follow_redirects=False)
        cid = r.headers["location"].split("/")[-1]
        # build far-end on a new site DC1
        c.post(f"/connections/{cid}/peer",
               data=dict(target="new", new_site_name="DC1", peer_vendor="juniper_srx",
                         peer_public_ip="203.0.113.1"))
        with SessionLocal() as db:
            conn = db.get(VpnConnection, int(cid))
            first_peer = conn.peer_connection_id
            assert first_peer is not None
        # re-point to a different new far-end DC2
        c.post(f"/connections/{cid}/peer",
               data=dict(target="new", new_site_name="DC2", peer_vendor="palo_alto",
                         peer_public_ip="203.0.113.9"))
        with SessionLocal() as db:
            conn = db.get(VpnConnection, int(cid))
            assert conn.peer_connection_id is not None
            assert conn.peer_connection_id != first_peer          # remote changed
            old = db.get(VpnConnection, first_peer)
            assert old.peer_connection_id is None                 # old peer unlinked
        # unpair
        c.post(f"/connections/{cid}/unpair")
        with SessionLocal() as db:
            assert db.get(VpnConnection, int(cid)).peer_connection_id is None


def test_login_returns_to_targeted_page():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role
    from app.security.passwords import hash_password
    import pyotp, re
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="nav").first():
                db.add(User(username="nav", password_hash=hash_password("pw123456"),
                            role=Role.admin))
                db.commit()
        # hit a protected page unauthenticated -> redirected to /login?next=...
        r = c.get("/admin/backups", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login?next=%2Fadmin%2Fbackups"
        # login carries next through MFA and lands back on the target
        c.post("/login", data={"username": "nav", "password": "pw123456",
                               "next": "/admin/backups"}, follow_redirects=False)
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        r = c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()},
                   follow_redirects=False)
        assert r.headers["location"] == "/admin/backups"
        # open-redirect targets are ignored
        from app.security.deps import safe_next
        assert safe_next("//evil.com") is None
        assert safe_next("https://evil.com") is None
        assert safe_next("/sites") == "/sites"


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


def test_schema_sync_adds_missing_columns():
    import tempfile
    from sqlalchemy import create_engine, inspect, text
    import app.models  # noqa: F401  register tables
    from app.db import add_missing_columns
    dbf = tempfile.mktemp(suffix=".db")
    eng = create_engine(f"sqlite:///{dbf}", future=True)
    try:
        with eng.begin() as c:
            c.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR, "
                           "password_hash VARCHAR, role VARCHAR, disabled BOOLEAN, "
                           "totp_secret_enc BLOB, totp_confirmed BOOLEAN, created_at DATETIME)"))
            c.execute(text("INSERT INTO users (id, username, password_hash) VALUES (1,'a','x')"))
        add_missing_columns(eng)
        cols = {c["name"] for c in inspect(eng).get_columns("users")}
        assert {"first_name", "last_name", "email", "phone",
                "must_change_password"} <= cols
        with eng.begin() as c:
            # existing row survives; boolean default applied
            val = c.execute(text("SELECT must_change_password FROM users WHERE id=1")).scalar()
            assert not val
    finally:
        os.path.exists(dbf) and os.remove(dbf)


def test_backup_restore_roundtrip():
    from app.db import SessionLocal, init_db
    from app.models import User, Role, Backup
    from app.security.passwords import hash_password
    from app import backup as bk
    init_db()
    with SessionLocal() as db:
        # baseline state
        db.query(User).delete()
        db.add(User(username="keep", password_hash=hash_password("x"), role=Role.admin,
                    email="keep@example.com"))
        db.commit()
        snap = bk.create_backup(db, note="t", by="tester")
        db.commit()
        payload, ver = snap.payload, snap.version
        assert ver >= 1
        # mutate: add a user, change existing
        db.add(User(username="temp", password_hash=hash_password("y"), role=Role.operator))
        db.query(User).filter_by(username="keep").update({"email": "changed@example.com"})
        db.commit()
        assert db.query(User).count() == 2
        # payload is encrypted (username not in plaintext bytes)
        assert b"keep" not in payload
        # restore
        state, sha = bk.decode_payload(payload)
        assert sha == snap.sha256
        bk.restore_state(db, state)
        db.commit()
        users = {u.username: u for u in db.query(User).all()}
        assert set(users) == {"keep"}                       # temp removed
        assert users["keep"].email == "keep@example.com"    # change reverted
        # backup history preserved across restore
        assert db.query(Backup).count() >= 1


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
