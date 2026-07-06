import pytest
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
    # Route-based peer (another SRX) → no selectors
    p = _mk_profile()
    p.remote_vendor = "juniper_srx"
    out = generators.generate(p)
    assert "ike proxy-identity local" not in out and "traffic-selector ts" not in out
    assert "route-based" in out
    # pfSense peer, single subnet pair → proxy-identity (must match peer Phase 2)
    p.remote_vendor = "pfsense"
    out = generators.generate(p)
    assert "ike proxy-identity local 10.1.0.0/24" in out
    assert "ike proxy-identity remote 10.2.0.0/24" in out
    assert "proxy-identity service any" in out
    assert "REQUIRED" in out and "MUST match" in out
    # Multiple subnet pairs → traffic-selectors
    pm = _mk_profile()
    pm.remote_vendor = "pfsense"
    pm.local.protected_subnets = ["10.1.0.0/24", "10.3.0.0/24"]
    pm.remote.protected_subnets = ["10.2.0.0/24", "10.4.0.0/24"]
    om = generators.generate(pm)
    assert "traffic-selector ts0 local-ip 10.1.0.0/24" in om
    assert "traffic-selector ts1 local-ip 10.3.0.0/24" in om
    # Fortinet/Palo are route-based (VTI) → omit selectors
    p.remote_vendor = "fortinet"
    assert "ike proxy-identity local" not in generators.generate(p)
    # Unspecified → safe default includes selectors
    p.remote_vendor = ""
    assert "ike proxy-identity local" in generators.generate(p)


PFSENSE_BACKUP = """<?xml version="1.0"?>
<pfsense>
  <system><hostname>KKDDS-PFS</hostname></system>
  <aliases><alias><name>ignoreme</name></alias></aliases>
  <ipsec>
    <phase1>
      <ikeid>1</ikeid>
      <iketype>ikev2</iketype>
      <interface>wan</interface>
      <remote-gateway>47.207.52.21</remote-gateway>
      <authentication_method>pre_shared_key</authentication_method>
      <pre-shared-key>SUPERSECRETKEY</pre-shared-key>
      <encryption><item>
        <encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm>
        <hash-algorithm>sha256</hash-algorithm><dhgroup>14</dhgroup>
      </item></encryption>
      <lifetime>28800</lifetime>
      <descr>HESTIA</descr>
    </phase1>
    <phase2>
      <ikeid>1</ikeid><mode>tunnel</mode>
      <localid><type>network</type><address>192.168.0.0</address><netbits>19</netbits></localid>
      <remoteid><type>network</type><address>172.23.0.0</address><netbits>16</netbits></remoteid>
      <encryption-algorithm-option><name>aes</name><keylen>256</keylen></encryption-algorithm-option>
      <hash-algorithm-option>hmac_sha256</hash-algorithm-option><pfsgroup>14</pfsgroup>
    </phase2>
    <phase1>
      <ikeid>2</ikeid><iketype>ikev1</iketype>
      <remote-gateway>47.207.52.25</remote-gateway>
      <encryption><item>
        <encryption-algorithm><name>aes256gcm</name><keylen>256</keylen></encryption-algorithm>
        <dhgroup>20</dhgroup>
      </item></encryption>
      <descr>LIBERTAS</descr>
    </phase1>
    <phase2>
      <ikeid>2</ikeid>
      <localid><type>network</type><address>10.1.0.0</address><netbits>24</netbits></localid>
      <remoteid><type>network</type><address>10.2.0.0</address><netbits>24</netbits></remoteid>
      <encryption-algorithm-option><name>aes256gcm</name><keylen>256</keylen></encryption-algorithm-option>
      <pfsgroup>20</pfsgroup>
    </phase2>
  </ipsec>
</pfsense>"""


def test_pfsense_backup_import():
    from app.srx import importer
    assert importer.detect_vendor(PFSENSE_BACKUP) == "pfsense"
    assert importer.is_pfsense_backup(PFSENSE_BACKUP)
    site = importer.import_site(PFSENSE_BACKUP)
    assert site["vendor"] == "pfsense" and site["hostname"] == "KKDDS-PFS"
    names = {c["profile"].name for c in site["connections"]}
    assert names == {"HESTIA", "LIBERTAS"}          # one connection per phase1
    by = {c["profile"].name: c for c in site["connections"]}
    h = by["HESTIA"]["profile"]
    assert h.remote.public_ip == "47.207.52.21"
    assert h.phase1.ike_version == "ikev2" and h.phase1.auth_method == "psk"
    assert h.phase1.encryption == "aes-256-cbc" and h.phase1.integrity == "sha256"
    assert h.phase1.dh_group == "14"
    assert h.local.protected_subnets == ["192.168.0.0/19"]
    assert h.remote.protected_subnets == ["172.23.0.0/16"]
    assert h.phase2.pfs_group == "14"
    l = by["LIBERTAS"]["profile"]
    assert l.phase1.encryption == "aes-256-gcm" and l.phase1.dh_group == "20"
    # only IPsec is used; unrelated sections and the PSK are not stored
    blob = str([c["config"] for c in site["connections"]])
    assert "SUPERSECRETKEY" not in blob and "ignoreme" not in blob


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
        # change the remote IP + P1 encryption (confirm=1 skips the diff-approval gate)
        r = c.post(f"/connections/{cid}/edit", data=dict(
            local_ip="1.1.1.1", remote_ip="9.9.9.9", local_subnets="10.1.0.0/24",
            remote_subnets="10.9.0.0/24", auth_method="certificate",
            p1_enc="aes-256-cbc", p1_integ="sha256", p1_dh="14",
            p1_ver="ikev2", p2_enc="aes-256-cbc", p2_integ="sha256", p2_pfs="14",
            confirm="1"),
            follow_redirects=False)
        assert r.status_code == 303
        with SessionLocal() as db:
            conn = db.get(VpnConnection, cid)
            p = json.loads(conn.params_json)
            assert p["remote"]["public_ip"] == "9.9.9.9"
            assert p["phase1"]["encryption"] == "aes-256-cbc"
            assert "aes-256-cbc" in conn.generated_config       # regenerated
            assert conn.name == "EE-vpn"                          # name unchanged


def test_infer_peers_suggest_only():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role, VpnConnection
    from app.security.passwords import hash_password
    import pyotp, re
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="inf").first():
                db.add(User(username="inf", password_hash=hash_password("pw123456"),
                            role=Role.admin))
                db.commit()
        c.post("/login", data={"username": "inf", "password": "pw123456"})
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})
        # Two independently-created connections that are actually each other's peer
        rA = c.post("/sites/generate", data=dict(name="A", vendor="juniper_srx",
                    local_ip="203.0.113.1", remote_ip="203.0.113.2",
                    local_subnets="10.1.0.0/24", remote_subnets="10.2.0.0/24",
                    auth_method="certificate"), follow_redirects=False)
        aid = int(rA.headers["location"].split("/")[-1])
        c.post("/sites/generate", data=dict(name="B", vendor="pfsense",
               local_ip="203.0.113.2", remote_ip="203.0.113.1",
               local_subnets="10.2.0.0/24", remote_subnets="10.1.0.0/24",
               auth_method="certificate"), follow_redirects=False)
        # A's page suggests B (not auto-linked)
        page = c.get(f"/connections/{aid}").text
        assert "Suggested peer" in page and "public IPs match both ways" in page
        with SessionLocal() as db:
            assert db.get(VpnConnection, aid).peer_connection_id is None   # NOT linked yet
        # find B's id and confirm the pairing
        import re as _re
        bid = int(_re.search(r'name="peer_id" value="(\d+)"', page).group(1))
        c.post(f"/connections/{aid}/pair-confirm", data={"peer_id": bid, "confirm": "1"})
        with SessionLocal() as db:
            a = db.get(VpnConnection, aid)
            assert a.peer_connection_id == bid                            # linked on confirm
            assert db.get(VpnConnection, bid).peer_connection_id == aid


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


def test_import_ca():
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops, csr as csr_ops
    from app.models import CAType
    from cryptography.hazmat.primitives import serialization
    init_db()
    with SessionLocal() as db:
        # Build an external root + issuing pair outside VCM, export PEMs.
        root = ca_ops.create_ca(db, name="ext-root-src", dn={"CN": "Ext Root"},
                                ca_type=CAType.root, key_type="ec",
                                key_params="secp384r1", valid_days=3650)
        issuing = ca_ops.create_ca(db, name="ext-iss-src", dn={"CN": "Ext Issuing"},
                                   ca_type=CAType.issuing, key_type="ec",
                                   key_params="secp384r1", valid_days=1825, parent=root)
        root_cert = root.cert_pem
        iss_cert = issuing.cert_pem
        iss_key = ca_ops.keys.unwrap_private_key(issuing.key_enc).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        db.commit()

    with SessionLocal() as db2:
        from app.models import CertAuthority as _CA
        db2.query(_CA).delete()   # clean slate (shared in-memory DB across tests)
        db2.commit()
        # Import the root cert-only (no key) -> can't sign
        r = ca_ops.import_ca(db2, name="imported-root", cert_pem=root_cert)
        assert r.ca_type == CAType.root and not r.has_private_key
        # Import the issuing CA with its key -> links to imported root, can sign
        iss = ca_ops.import_ca(db2, name="imported-iss", cert_pem=iss_cert, key_pem=iss_key)
        assert iss.ca_type == CAType.issuing and iss.has_private_key
        assert iss.parent_id == r.id                      # issuer matched -> linked
        # Wrong key is rejected
        import pytest
        _, other_csr = csr_ops.generate_leaf_keypair_and_csr({"CN": "x"}, "ec", "secp256r1")
        wrong_key = ca_ops.keys.generate_key("ec", "secp256r1").private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        with pytest.raises(ValueError):
            ca_ops.import_ca(db2, name="bad", cert_pem=iss_cert, key_pem=wrong_key)
        # The imported issuing CA can sign a CSR
        kp, csr = csr_ops.generate_leaf_keypair_and_csr({"CN": "srx9"}, "ec", "secp256r1")
        cert = ca_ops.sign_csr(db2, issuing_ca=iss, csr=csr, valid_days=365)
        assert "BEGIN CERTIFICATE" in cert.cert_pem
        db2.commit()


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


def test_infer_bgp_mirrors_pair():
    from app.srx import suggest
    from app.srx.model import Bgp
    near = _mk_profile()
    near.tunnel_ip = "169.254.10.1/30"
    peer = _mk_profile()
    peer.tunnel_ip = "169.254.10.2/30"
    peer.bgp = Bgp(enabled=True, local_as="65002", peer_as="65001")

    b = suggest.infer_bgp(near, peer)
    assert b.enabled
    assert b.local_as == "65001" and b.peer_as == "65002"
    assert b.local_ip == "169.254.10.1" and b.peer_ip == "169.254.10.2"
    assert b.networks == ["10.1.0.0/24"]

    # Peer side mirrors.
    b2 = suggest.infer_bgp(peer, near)
    assert b2.local_as == "65002" and b2.peer_as == "65001"
    assert b2.peer_ip == "169.254.10.1"


def test_infer_bgp_none_when_no_data():
    from app.srx import suggest
    near = _mk_profile()
    peer = _mk_profile()
    assert suggest.infer_bgp(near, peer) is None


def test_admin_delete_certificate_requires_serial():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role, Certificate, CAType, utcnow
    from app.pki import ca as ca_ops
    from app.security.passwords import hash_password
    import pyotp, re, datetime
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="del").first():
                db.add(User(username="del", password_hash=hash_password("pw123456"),
                            role=Role.admin))
                db.commit()
            root = ca_ops.create_ca(db, name="delroot", dn={"CN": "Del Root"},
                                    ca_type=CAType.root, key_type="ec",
                                    key_params="secp256r1", valid_days=3650)
            now = utcnow()
            cert = Certificate(ca_id=root.id, serial="DEADBEEF", subject_dn="CN=leaf",
                               cert_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
                               not_before=now, not_after=now + datetime.timedelta(days=1))
            db.add(cert)
            db.commit()
            cid = cert.id
        c.post("/login", data={"username": "del", "password": "pw123456"})
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})

        # Wrong serial: nothing deleted, error shown.
        r = c.post(f"/pki/cert/{cid}/delete", data={"confirm_serial": "NOPE"})
        assert "did not match" in r.text
        with SessionLocal() as db:
            assert db.get(Certificate, cid) is not None

        # Correct serial: deleted.
        r = c.post(f"/pki/cert/{cid}/delete", data={"confirm_serial": "DEADBEEF"},
                   follow_redirects=False)
        assert r.status_code == 303
        with SessionLocal() as db:
            assert db.get(Certificate, cid) is None


def test_load_material_p12_and_pem():
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs12
    from app.pki import material

    key = ec.generate_private_key(ec.SECP256R1())
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    cert = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2034, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))

    # Password-protected PKCS#12 → cert + key.
    blob = pkcs12.serialize_key_and_certificates(
        b"ca", key, cert, None, serialization.BestAvailableEncryption(b"secret"))
    assert material.looks_like_p12("ca.p12", blob)
    c, k = material.load_material("ca.p12", blob, "secret")
    assert c.startswith("-----BEGIN CERTIFICATE") and k.startswith("-----BEGIN PRIVATE KEY")

    # Wrong password fails clearly.
    with pytest.raises(Exception):
        material.load_material("ca.p12", blob, "wrong")

    # PEM bundle and cert-only PEM.
    pem = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    c2, k2 = material.load_material("ca.pem", pem, None)
    assert k2.startswith("-----BEGIN PRIVATE KEY")
    c3, k3 = material.load_material("c.pem", cert.public_bytes(serialization.Encoding.PEM), None)
    assert c3.startswith("-----BEGIN CERTIFICATE") and k3 is None


def test_create_ca_under_keyless_parent_generates_csr():
    # A cert-only (offline-key) parent can't sign locally, so creating a child
    # under it yields a *pending* CA with a CSR to be signed externally.
    from cryptography import x509
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops
    from app.models import CAType, CertAuthority
    init_db()
    with SessionLocal() as db:
        db.query(CertAuthority).delete()
        db.commit()
        root = ca_ops.create_ca(db, name="realroot", dn={"CN": "Real Root"},
                                ca_type=CAType.root, key_type="ec",
                                key_params="secp256r1", valid_days=3650)
        cert_pem = root.cert_pem
        db.query(CertAuthority).delete()
        db.commit()
        keyless = ca_ops.import_ca(db, name="offline", cert_pem=cert_pem, key_pem=None)
        assert not keyless.has_private_key
        sub = ca_ops.create_ca(db, name="sub", dn={"CN": "Sub"}, ca_type=CAType.intermediate,
                               key_type="ec", key_params="secp256r1", valid_days=365,
                               parent=keyless)
        assert sub.pending and sub.csr_pem and sub.cert_pem == ""
        assert not sub.can_sign
        # The CSR is valid and CA-requesting.
        csr = x509.load_pem_x509_csr(sub.csr_pem.encode())
        assert csr.is_signature_valid
        bc = csr.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True


def test_delete_ca_refuses_nonempty_and_cascades():
    import pytest, datetime
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops
    from app.models import CAType, CertAuthority, Certificate, utcnow
    init_db()
    with SessionLocal() as db:
        db.query(Certificate).delete()
        db.query(CertAuthority).delete()
        db.commit()
        root = ca_ops.create_ca(db, name="troot", dn={"CN": "T Root"}, ca_type=CAType.root,
                                key_type="ec", key_params="secp256r1", valid_days=3650)
        sub = ca_ops.create_ca(db, name="tsub", dn={"CN": "T Sub"},
                               ca_type=CAType.issuing, key_type="ec",
                               key_params="secp256r1", valid_days=1825, parent=root)
        root.locked = False; sub.locked = False   # CAs are locked by default
        now = utcnow()
        db.add(Certificate(ca_id=sub.id, serial="AA01", subject_dn="CN=leaf",
                           cert_pem="x", not_before=now,
                           not_after=now + datetime.timedelta(days=1)))
        db.commit()

        # Refuses to delete a root that has a sub-CA + cert without cascade.
        with pytest.raises(ValueError, match="cascade"):
            ca_ops.delete_ca(db, root, cascade=False)
        assert db.get(CertAuthority, root.id) is not None

        # Cascade removes the whole subtree and its issued certs.
        summary = ca_ops.delete_ca(db, root, cascade=True)
        assert summary["sub_cas"] == 1 and summary["certs"] == 1
        db.commit()
        assert db.query(CertAuthority).count() == 0
        assert db.query(Certificate).count() == 0


def test_delete_ca_leaf_no_cascade_needed():
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops
    from app.models import CAType, CertAuthority, Certificate
    init_db()
    with SessionLocal() as db:
        db.query(Certificate).delete()
        db.query(CertAuthority).delete()
        db.commit()
        root = ca_ops.create_ca(db, name="lonely", dn={"CN": "Lonely"}, ca_type=CAType.root,
                                key_type="ec", key_params="secp256r1", valid_days=3650)
        root.locked = False   # CAs are locked by default; unlock to delete
        db.commit()
        rid = root.id
        ca_ops.delete_ca(db, root)   # empty → no cascade required
        db.commit()
        assert db.get(CertAuthority, rid) is None


def test_locked_ca_and_cert_block_deletion():
    import pytest, datetime
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops
    from app.models import CAType, CertAuthority, Certificate, utcnow
    init_db()
    with SessionLocal() as db:
        db.query(Certificate).delete()
        db.query(CertAuthority).delete()
        db.commit()
        root = ca_ops.create_ca(db, name="lroot", dn={"CN": "L Root"}, ca_type=CAType.root,
                                key_type="ec", key_params="secp256r1", valid_days=3650)
        sub = ca_ops.create_ca(db, name="lsub", dn={"CN": "L Sub"}, ca_type=CAType.issuing,
                               key_type="ec", key_params="secp256r1", valid_days=1825,
                               parent=root)
        sub.locked = False   # isolate the lock behaviour under test (CAs default locked)
        now = utcnow()
        cert = Certificate(ca_id=sub.id, serial="LK01", subject_dn="CN=leaf", cert_pem="x",
                           not_before=now, not_after=now + datetime.timedelta(days=1))
        db.add(cert)
        db.commit()

        # A locked CA cannot be deleted.
        root.locked = True
        db.commit()
        with pytest.raises(ValueError, match="locked"):
            ca_ops.delete_ca(db, root, cascade=True)

        # Unlock the CA, but a locked descendant cert still blocks a cascade.
        root.locked = False
        cert.locked = True
        db.commit()
        with pytest.raises(ValueError, match="locked certificate"):
            ca_ops.delete_ca(db, root, cascade=True)

        # Unlock everything → cascade succeeds.
        cert.locked = False
        db.commit()
        summary = ca_ops.delete_ca(db, root, cascade=True)
        db.commit()
        assert summary["sub_cas"] == 1 and summary["certs"] == 1
        assert db.query(CertAuthority).count() == 0


def test_cert_lock_blocks_delete_route_two_step():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role, Certificate, CAType, utcnow
    from app.pki import ca as ca_ops
    from app.security.passwords import hash_password
    import pyotp, re, datetime
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="lk").first():
                db.add(User(username="lk", password_hash=hash_password("pw123456"),
                            role=Role.admin))
                db.commit()
            root = ca_ops.create_ca(db, name="lkroot", dn={"CN": "LK Root"},
                                    ca_type=CAType.root, key_type="ec",
                                    key_params="secp256r1", valid_days=3650)
            now = utcnow()
            cert = Certificate(ca_id=root.id, serial="C0FFEE", subject_dn="CN=leaf",
                               cert_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
                               not_before=now, not_after=now + datetime.timedelta(days=1))
            db.add(cert)
            db.commit()
            cid = cert.id
        c.post("/login", data={"username": "lk", "password": "pw123456"})
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})

        # Lock it (step-0). Delete with correct serial must now be refused.
        c.post(f"/pki/cert/{cid}/lock", data={"locked": "1"})
        r = c.post(f"/pki/cert/{cid}/delete", data={"confirm_serial": "C0FFEE"})
        assert "locked" in r.text.lower()
        with SessionLocal() as db:
            assert db.get(Certificate, cid) is not None

        # Step 1: unlock. Step 2: delete.
        c.post(f"/pki/cert/{cid}/lock", data={"locked": ""})
        r = c.post(f"/pki/cert/{cid}/delete", data={"confirm_serial": "C0FFEE"},
                   follow_redirects=False)
        assert r.status_code == 303
        with SessionLocal() as db:
            assert db.get(Certificate, cid) is None


def _sign_ca_csr(csr, issuer_key, issuer_cert):
    # Test helper: emulate the parent's offline signer turning a CA CSR into a cert.
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    return (x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(issuer_cert.subject)
            .public_key(csr.public_key()).serial_number(4242)
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(issuer_key, hashes.SHA256()))


def test_pending_ca_complete_with_signed_cert():
    import datetime, pytest
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops
    from app.models import CAType, CertAuthority, Certificate
    init_db()
    with SessionLocal() as db:
        db.query(Certificate).delete()
        db.query(CertAuthority).delete()
        db.commit()
        # Offline parent: build its key+cert externally, import cert-only.
        pkey = ec.generate_private_key(ec.SECP256R1())
        pname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline Root")])
        pcert = (x509.CertificateBuilder().subject_name(pname).issuer_name(pname)
                 .public_key(pkey.public_key()).serial_number(1)
                 .not_valid_before(datetime.datetime(2024, 1, 1))
                 .not_valid_after(datetime.datetime(2034, 1, 1))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                 .sign(pkey, hashes.SHA256()))
        parent = ca_ops.import_ca(
            db, name="offline-root",
            cert_pem=pcert.public_bytes(serialization.Encoding.PEM).decode(), key_pem=None)

        sub = ca_ops.create_ca(db, name="pend-sub", dn={"CN": "Pend Sub"},
                               ca_type=CAType.issuing, key_type="ec",
                               key_params="secp256r1", valid_days=365, parent=parent)
        assert sub.pending

        # Wrong cert (different key) is rejected.
        wrong = _sign_ca_csr(x509.load_pem_x509_csr(sub.csr_pem.encode()), pkey, pcert)
        badkey = ec.generate_private_key(ec.SECP256R1())
        bad_csr = (x509.CertificateSigningRequestBuilder()
                   .subject_name(pname)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                   .sign(badkey, hashes.SHA256()))
        bad_cert = _sign_ca_csr(bad_csr, pkey, pcert)
        with pytest.raises(ValueError, match="public key does not match"):
            ca_ops.complete_pending_ca(db, sub, bad_cert.public_bytes(
                serialization.Encoding.PEM).decode())

        # Correct signed cert completes the CA.
        ca_ops.complete_pending_ca(db, sub, wrong.public_bytes(
            serialization.Encoding.PEM).decode())
        assert not sub.pending and sub.csr_pem is None and sub.can_sign


def test_side_by_side_diff_helper():
    from app.srx.diff import side_by_side, changed
    rows = side_by_side("a\nb\nc", "a\nB\nc\nd")
    kinds = [r["kind"] for r in rows]
    assert "equal" in kinds and "replace" in kinds and "insert" in kinds
    # replaced line shows both sides
    rep = [r for r in rows if r["kind"] == "replace"][0]
    assert rep["left"] == "b" and rep["right"] == "B"
    # inserted line has empty left
    ins = [r for r in rows if r["kind"] == "insert"][0]
    assert ins["left"] == "" and ins["right"] == "d"
    assert changed("x", "y") and not changed("x\n", "x")


def test_edit_connection_requires_diff_approval():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role, VpnConnection
    from app.security.passwords import hash_password
    import pyotp, re, json
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="df").first():
                db.add(User(username="df", password_hash=hash_password("pw123456"),
                            role=Role.admin))
                db.commit()
        c.post("/login", data={"username": "df", "password": "pw123456"})
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})
        r = c.post("/sites/generate", data=dict(name="DF", vendor="juniper_srx",
                   local_ip="1.1.1.1", remote_ip="2.2.2.2", local_subnets="10.1.0.0/24",
                   remote_subnets="10.2.0.0/24", auth_method="certificate"),
                   follow_redirects=False)
        cid = int(r.headers["location"].split("/")[-1])

        base = dict(local_ip="1.1.1.1", remote_ip="9.9.9.9", local_subnets="10.1.0.0/24",
                    remote_subnets="10.9.0.0/24", auth_method="certificate",
                    p1_enc="aes-256-cbc", p1_integ="sha256", p1_dh="14", p1_ver="ikev2",
                    p2_enc="aes-256-cbc", p2_integ="sha256", p2_pfs="14")

        # Step 1: submit edit → get the diff approval page, NOT applied yet.
        r = c.post(f"/connections/{cid}/edit", data=base)
        assert "Proposed" in r.text and "Approve" in r.text
        with SessionLocal() as db:
            assert json.loads(db.get(VpnConnection, cid).params_json)["remote"]["public_ip"] == "2.2.2.2"

        # Step 2: approve → applied.
        r = c.post(f"/connections/{cid}/edit", data={**base, "confirm": "1"},
                   follow_redirects=False)
        assert r.status_code == 303
        with SessionLocal() as db:
            assert json.loads(db.get(VpnConnection, cid).params_json)["remote"]["public_ip"] == "9.9.9.9"


def test_reimport_offers_update_then_updates():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role, Site, VpnConnection
    from app.security.passwords import hash_password
    import pyotp, re, json
    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="imp").first():
                db.add(User(username="imp", password_hash=hash_password("pw123456"),
                            role=Role.admin))
                db.commit()
        c.post("/login", data={"username": "imp", "password": "pw123456"})
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})

        cfg = ("set security ike proposal P authentication-method rsa-signatures\n"
               "set security ike proposal P encryption-algorithm aes-256-cbc\n"
               "set security ipsec vpn vpn-t1 ike gateway gw\n")
        # Give it a stable name so the re-import matches by name.
        r = c.post("/sites/import", data={"name": "SiteRX", "config_text": cfg},
                   follow_redirects=False)
        assert r.status_code == 303
        sid = int(r.headers["location"].split("/")[-1])
        with SessionLocal() as db:
            n_before = db.query(VpnConnection).filter_by(site_id=sid).count()
            n_sites = db.query(Site).count()

        # Re-import same name → review page (update vs duplicate), nothing new yet.
        r = c.post("/sites/import", data={"name": "SiteRX", "config_text": cfg})
        assert "Update" in r.text and "duplicate" in r.text.lower()
        with SessionLocal() as db:
            assert db.query(Site).count() == n_sites          # no new site created

        # Choose update → stays one site, connections upserted (not duplicated).
        r = c.post("/sites/import", data={"name": "SiteRX", "config_text": cfg,
                   "action": "update"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == f"/sites/{sid}"
        with SessionLocal() as db:
            assert db.query(Site).count() == n_sites
            assert db.query(VpnConnection).filter_by(site_id=sid).count() == n_before

        # Choose duplicate → a new site is created.
        r = c.post("/sites/import", data={"name": "SiteRX", "config_text": cfg,
                   "action": "duplicate"}, follow_redirects=False)
        assert r.status_code == 303
        with SessionLocal() as db:
            assert db.query(Site).count() == n_sites + 1


def test_load_cert_pem_der_and_leading_text():
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from app.pki import material

    key = ec.generate_private_key(ec.SECP256R1())
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
    cert = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm)
            .public_key(key.public_key()).serial_number(7)
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    der = cert.public_bytes(serialization.Encoding.DER)

    assert material.load_cert(pem).startswith("-----BEGIN CERTIFICATE")
    assert material.load_cert(der).startswith("-----BEGIN CERTIFICATE")
    # PEM with a leading text dump (openssl 'Bag Attributes' style) is still PEM.
    noisy = b"Bag Attributes: none\nsubject=CN=Leaf\n" + pem
    assert not material.looks_like_p12("cert.pem", noisy)
    assert material.load_cert(noisy).startswith("-----BEGIN CERTIFICATE")
    # A .pem name is never treated as p12 even with odd bytes.
    assert not material.looks_like_p12("x.pem", b"\xef\xbb\xbf-----BEGIN CERTIFICATE-----")


def test_complete_pending_ca_allow_non_ca_override():
    import datetime, pytest
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops
    from app.models import CAType, CertAuthority, Certificate
    init_db()
    with SessionLocal() as db:
        db.query(Certificate).delete()
        db.query(CertAuthority).delete()
        db.commit()
        pkey = ec.generate_private_key(ec.SECP256R1())
        pname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Off Root")])
        pcert = (x509.CertificateBuilder().subject_name(pname).issuer_name(pname)
                 .public_key(pkey.public_key()).serial_number(1)
                 .not_valid_before(datetime.datetime(2024, 1, 1))
                 .not_valid_after(datetime.datetime(2034, 1, 1))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                 .sign(pkey, hashes.SHA256()))
        parent = ca_ops.import_ca(db, name="offroot",
                                  cert_pem=pcert.public_bytes(serialization.Encoding.PEM).decode(),
                                  key_pem=None)
        sub = ca_ops.create_ca(db, name="pend", dn={"CN": "Pend"}, ca_type=CAType.issuing,
                               key_type="ec", key_params="secp256r1", valid_days=365,
                               parent=parent)
        csr = x509.load_pem_x509_csr(sub.csr_pem.encode())
        # Sign WITHOUT BasicConstraints (a common signer mistake).
        noca = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(pcert.subject)
                .public_key(csr.public_key()).serial_number(99)
                .not_valid_before(datetime.datetime(2024, 1, 1))
                .not_valid_after(datetime.datetime(2030, 1, 1))
                .sign(pkey, hashes.SHA256()))
        pem = noca.public_bytes(serialization.Encoding.PEM).decode()

        with pytest.raises(ValueError, match="Basic Constraints"):
            ca_ops.complete_pending_ca(db, sub, pem)
        assert sub.pending
        # Override accepts it.
        ca_ops.complete_pending_ca(db, sub, pem, allow_non_ca=True)
        assert not sub.pending and sub.can_sign


def test_pending_ca_regenerate_csr_and_discard():
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops
    from app.models import CAType, CertAuthority, Certificate
    from cryptography import x509
    import datetime
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    init_db()
    with SessionLocal() as db:
        db.query(Certificate).delete()
        db.query(CertAuthority).delete()
        db.commit()
        pkey = ec.generate_private_key(ec.SECP256R1())
        pn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "R")])
        pc = (x509.CertificateBuilder().subject_name(pn).issuer_name(pn)
              .public_key(pkey.public_key()).serial_number(1)
              .not_valid_before(datetime.datetime(2024, 1, 1))
              .not_valid_after(datetime.datetime(2034, 1, 1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
              .sign(pkey, hashes.SHA256()))
        parent = ca_ops.import_ca(db, name="r", cert_pem=pc.public_bytes(
            serialization.Encoding.PEM).decode(), key_pem=None)
        sub = ca_ops.create_ca(db, name="p", dn={"CN": "P"}, ca_type=CAType.issuing,
                               key_type="ec", key_params="secp256r1", valid_days=1, parent=parent)
        old_csr, old_key = sub.csr_pem, sub.key_enc
        ca_ops.regenerate_pending_csr(db, sub)
        assert sub.csr_pem != old_csr and sub.key_enc != old_key and sub.pending
        # subject preserved
        assert "CN=P" in x509.load_pem_x509_csr(sub.csr_pem.encode()).subject.rfc4514_string()
        # discard removes it
        sid = sub.id
        db.delete(sub); db.flush()
        assert db.get(CertAuthority, sid) is None


def test_dynamic_and_fqdn_endpoint_generation():
    from app.srx import generators as g
    from app.srx.model import VpnProfile, Endpoint

    def mk(rip, vendor, rid="peer.example.com", ver="ikev2"):
        p = VpnProfile(name="t", vendor=vendor,
                       local=Endpoint("l", "198.51.100.1", "loc", ["10.1.0.0/24"]),
                       remote=Endpoint("r", rip, rid, ["10.2.0.0/24"]))
        p.phase1.ike_version = ver
        return p

    # Palo: ip / fqdn / dynamic keywords
    assert "peer-address fqdn vpn.dyn.example.com" in g.generate(mk("vpn.dyn.example.com", "palo_alto"))
    assert "peer-address dynamic" in g.generate(mk("", "palo_alto"))
    assert "peer-address ip 203.0.113.1" in g.generate(mk("203.0.113.1", "palo_alto"))

    # Fortinet: ddns vs dynamic dial-up
    fort_fqdn = g.generate(mk("vpn.dyn.example.com", "fortinet"))
    assert "set type ddns" in fort_fqdn and 'set remotegw-ddns "vpn.dyn.example.com"' in fort_fqdn
    fort_dyn = g.generate(mk("", "fortinet"))
    assert "set type dynamic" in fort_dyn and "set peertype any" in fort_dyn

    # MikroTik: FQDN keeps /32; dynamic is passive wildcard
    assert "address=vpn.dyn.example.com/32" in g.generate(mk("vpn.dyn.example.com", "mikrotik"))
    assert "address=0.0.0.0/0 passive=yes" in g.generate(mk("", "mikrotik"))

    # SRX: dynamic hostname; IKEv1 dynamic/FQDN needs aggressive mode
    srx_dyn = g.generate(mk("", "juniper_srx"))
    assert "dynamic hostname peer.example.com" in srx_dyn
    assert "mode aggressive" in g.generate(mk("vpn.dyn.example.com", "juniper_srx", ver="ikev1"))
    assert "mode aggressive" not in g.generate(mk("vpn.dyn.example.com", "juniper_srx", ver="ikev2"))

    # strongSwan: %any + trap for dynamic
    ss = g.generate(mk("", "strongswan"))
    assert "remote_addrs = %any" in ss and "start_action = trap" in ss

    # pfSense: dynamic -> 0.0.0.0
    assert "Remote Gateway       : 0.0.0.0" in g.generate(mk("", "pfsense"))


def test_aws_azure_reject_dynamic_endpoint():
    from app.srx.model import VpnProfile, Endpoint, all_warnings

    def endpoint_warn(p):
        return [w for w in all_warnings(p) if w["kind"] == "endpoint"]

    # Customer gateway (local) is a DDNS hostname, far-end is AWS -> flagged.
    p = VpnProfile(name="t", vendor="juniper_srx",
                   local=Endpoint("l", "vpn.ddns.example.com", "loc", ["10.1.0.0/24"]),
                   remote=Endpoint("r", "52.10.20.30", "rem", ["10.2.0.0/24"]))
    p.remote_vendor = "aws"
    ws = endpoint_warn(p)
    assert ws and ws[0]["severity"] == "broken" and "static public IP" in ws[0]["message"]

    # Azure site with a blank (dynamic) customer address -> flagged.
    p2 = VpnProfile(name="t", vendor="azure",
                    local=Endpoint("l", "203.0.113.1", "loc", ["10.1.0.0/24"]),
                    remote=Endpoint("r", "", "rem", ["10.2.0.0/24"]))
    assert endpoint_warn(p2)

    # No cloud involved -> a hostname endpoint is fine, no endpoint warning.
    p3 = VpnProfile(name="t", vendor="juniper_srx",
                    local=Endpoint("l", "203.0.113.1", "loc", ["10.1.0.0/24"]),
                    remote=Endpoint("r", "vpn.x.com", "rem", ["10.2.0.0/24"]))
    assert not endpoint_warn(p3)

    # Cloud + static customer IP -> no warning.
    p4 = VpnProfile(name="t", vendor="juniper_srx",
                    local=Endpoint("l", "203.0.113.5", "loc", ["10.1.0.0/24"]),
                    remote=Endpoint("r", "52.10.20.30", "rem", ["10.2.0.0/24"]))
    p4.remote_vendor = "aws"
    assert not endpoint_warn(p4)


def test_import_captures_bgp_and_tunnel():
    from app.srx import generators as g, importer as imp
    from app.srx.model import VpnProfile, Endpoint, Bgp
    p = VpnProfile(name="hq", vendor="juniper_srx",
                   local=Endpoint("l", "198.51.100.1", "hq.vpn.local", ["10.1.0.0/24"]),
                   remote=Endpoint("r", "203.0.113.1", "dc.vpn.local", ["10.2.0.0/24"]))
    p.tunnel_interface = "st0.5"; p.tunnel_ip = "169.254.0.1/30"; p.wan_interface = "ge-0/0/0.0"
    p.bgp = Bgp(enabled=True, local_as="65001", peer_as="65002", peer_ip="169.254.0.2",
                local_ip="169.254.0.1", networks=["10.1.0.0/24"])
    prof = imp.import_config(g.generate(p))
    assert prof.bgp.enabled and prof.bgp.local_as == "65001" and prof.bgp.peer_as == "65002"
    assert prof.bgp.peer_ip == "169.254.0.2" and prof.bgp.networks == ["10.1.0.0/24"]
    assert prof.tunnel_interface == "st0.5" and prof.tunnel_ip == "169.254.0.1/30"

    # Cisco and Fortinet BGP parse (incl. network prefixes)
    for vendor, las in [("cisco_firepower", "65010"), ("fortinet", "65030")]:
        c = VpnProfile(name="x", vendor=vendor,
                       local=Endpoint("l", "1.1.1.1", "", ["10.1.0.0/24"]),
                       remote=Endpoint("r", "2.2.2.2", "", ["10.2.0.0/24"]))
        c.bgp = Bgp(enabled=True, local_as=las, peer_as="65099", peer_ip="169.254.9.2",
                    networks=["10.1.0.0/24"])
        b = imp.parse_bgp(g.generate(c), vendor)
        assert b.enabled and b.local_as == las and b.peer_ip == "169.254.9.2"
        assert b.networks == ["10.1.0.0/24"]


def test_relationships_page_and_tunnel_correlation():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role, Site, VpnConnection, Vendor
    from app.srx.model import VpnProfile, Endpoint
    from app.security.passwords import hash_password
    import pyotp, re, json

    def _mkconn(db, site, name, lip, rip, lsub, rsub, tunnel):
        prof = VpnProfile(name=name, vendor=site.vendor.value,
                          local=Endpoint("l", lip, "", [lsub]),
                          remote=Endpoint("r", rip, "", [rsub]))
        prof.tunnel_ip = tunnel
        c = VpnConnection(site_id=site.id, name=name, params_json=json.dumps(prof.to_dict()),
                          generated_config="")
        db.add(c); db.flush(); return c

    with TestClient(app, client=("127.0.0.1", 1)) as c:
        with SessionLocal() as db:
            if not db.query(User).filter_by(username="rel").first():
                db.add(User(username="rel", password_hash=hash_password("pw123456"),
                            role=Role.admin))
            sa = Site(name="RelA", vendor=Vendor.juniper_srx, source="test")
            sb = Site(name="RelB", vendor=Vendor.juniper_srx, source="test")
            db.add_all([sa, sb]); db.flush()
            # Two ends of a tunnel: mirrored IPs/subnets + same /30 tunnel subnet.
            _mkconn(db, sa, "a-t", "198.51.100.1", "203.0.113.1", "10.1.0.0/24",
                    "10.2.0.0/24", "169.254.0.1/30")
            _mkconn(db, sb, "b-t", "203.0.113.1", "198.51.100.1", "10.2.0.0/24",
                    "10.1.0.0/24", "169.254.0.2/30")
            db.commit()
        c.post("/login", data={"username": "rel", "password": "pw123456"})
        sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
        c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})

        r = c.get("/connections/relationships")
        assert r.status_code == 200
        assert "a-t" in r.text and "b-t" in r.text
        assert "tunnel IPs share a subnet" in r.text
        assert "Review" in r.text


def test_ca_identity_is_fingerprint_not_name():
    import pytest
    from app.db import SessionLocal, init_db
    from app.pki import ca as ca_ops
    from app.models import CAType, CertAuthority
    init_db()
    with SessionLocal() as db:
        db.query(CertAuthority).delete(); db.commit()
        # Same NAME, different certs → allowed; the second name is auto-deduplicated.
        a = ca_ops.create_ca(db, name="Root", dn={"CN": "Root A"}, ca_type=CAType.root,
                             key_type="ec", key_params="secp256r1", valid_days=3650)
        b = ca_ops.create_ca(db, name="Root", dn={"CN": "Root B"}, ca_type=CAType.root,
                             key_type="ec", key_params="secp256r1", valid_days=3650)
        db.commit()
        assert a.name == "Root" and b.name == "Root-2"
        assert a.fingerprint and b.fingerprint and a.fingerprint != b.fingerprint

        # Importing the SAME cert twice → rejected by fingerprint, whatever the name.
        pem = a.cert_pem
        db.query(CertAuthority).filter(CertAuthority.id.in_([a.id, b.id])).delete(
            synchronize_session=False)
        db.commit()
        imported = ca_ops.import_ca(db, name="Whatever", cert_pem=pem, key_pem=None)
        assert imported.fingerprint == ca_ops.cert_fingerprint(pem)
        with pytest.raises(ValueError, match="already present"):
            ca_ops.import_ca(db, name="A Different Name", cert_pem=pem, key_pem=None)
        assert db.query(CertAuthority).count() == 1


def _make_leaf_pem(cn="leaf.example.com", days_valid=200, san=None):
    """Build a self-signed end-entity (CA:FALSE) cert PEM for import tests."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm)
         .public_key(key.public_key()).serial_number(0xABCDEF)
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=days_valid))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in san]), False)
    cert = b.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_expiry_classification_boundaries():
    import datetime
    from app.models import classify_expiry, utcnow
    now = utcnow()
    day = datetime.timedelta(days=1)
    # Already past not_after -> expired
    assert classify_expiry(now - day, now) == "expired"
    # Within 30 days (inclusive) -> critical
    assert classify_expiry(now + 5 * day, now) == "critical"
    assert classify_expiry(now + 30 * day - datetime.timedelta(hours=1), now) == "critical"
    # Between 30 and 90 days -> warning
    assert classify_expiry(now + 31 * day, now) == "warning"
    assert classify_expiry(now + 90 * day - datetime.timedelta(hours=1), now) == "warning"
    # Beyond 90 days -> ok
    assert classify_expiry(now + 120 * day, now) == "ok"


def _admin_client(username):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import User, Role
    from app.security.passwords import hash_password
    import pyotp, re
    c = TestClient(app, client=("127.0.0.1", 1))
    c.__enter__()
    with SessionLocal() as db:
        if not db.query(User).filter_by(username=username).first():
            db.add(User(username=username, password_hash=hash_password("pw123456"),
                        role=Role.admin))
            db.commit()
    c.post("/login", data={"username": username, "password": "pw123456"})
    sec = re.search(r"Secret: <code>([A-Z2-7]+)</code>", c.get("/mfa/enroll").text).group(1)
    c.post("/mfa/enroll/totp", data={"code": pyotp.TOTP(sec).now()})
    return c


def test_import_leaf_cert_is_observed():
    from app.db import SessionLocal
    from app.models import Certificate
    c = _admin_client("leafimp")
    try:
        pem = _make_leaf_pem(cn="obs.example.com", days_valid=200, san=["obs.example.com"])
        r = c.post("/pki/cert/import", data={"cert_pem": pem}, follow_redirects=False)
        assert r.status_code == 303
        cid = int(r.headers["location"].split("/")[-1])
        with SessionLocal() as db:
            cert = db.get(Certificate, cid)
            assert cert.managed is False and cert.source == "imported"
            assert cert.ca_id is None
            assert "obs.example.com" in cert.subject_dn
            assert cert.san and "obs.example.com" in cert.san
            assert cert.expiry_status == "ok"
        # A CA cert is rejected by the leaf import.
        from app.pki import ca as ca_ops
        with SessionLocal() as db:
            root = ca_ops.create_ca(db, name="leafimp-ca", dn={"CN": "X"},
                                    ca_type=ca_ops.CAType.root, key_type="ec",
                                    key_params="secp256r1", valid_days=3650)
            ca_pem = root.cert_pem
            db.commit()
        r = c.post("/pki/cert/import", data={"cert_pem": ca_pem})
        assert "CA certificate" in r.text
    finally:
        c.__exit__(None, None, None)


def test_dashboard_shows_expiring_counts_and_supersede_excludes():
    import datetime
    from app.db import SessionLocal
    from app.models import Certificate, CertStatus, utcnow
    c = _admin_client("dashexp")
    try:
        now = utcnow()
        with SessionLocal() as db:
            db.query(Certificate).delete()
            db.commit()
            crit = Certificate(ca_id=None, managed=False, source="imported", serial="C1",
                               subject_dn="CN=crit", cert_pem="x", status=CertStatus.active,
                               not_before=now, not_after=now + datetime.timedelta(days=10))
            warn = Certificate(ca_id=None, managed=False, source="imported", serial="W1",
                               subject_dn="CN=warn", cert_pem="x", status=CertStatus.active,
                               not_before=now, not_after=now + datetime.timedelta(days=60))
            okc = Certificate(ca_id=None, managed=True, source="issued", serial="OK1",
                              subject_dn="CN=ok", cert_pem="x", status=CertStatus.active,
                              not_before=now, not_after=now + datetime.timedelta(days=300))
            db.add_all([crit, warn, okc])
            db.commit()
            crit_id, warn_id, ok_id = crit.id, warn.id, okc.id
        page = c.get("/").text
        assert "Expiring soon" in page
        assert "CN=crit" in page and "CN=warn" in page
        assert "CN=ok" not in page   # >90 days out, not listed

        # Supersede the critical observed cert with the managed one -> excluded.
        r = c.post(f"/pki/cert/{crit_id}/replace", data={"replacement_id": str(ok_id)},
                   follow_redirects=False)
        assert r.status_code == 303
        with SessionLocal() as db:
            assert db.get(Certificate, crit_id).replaced_by_id == ok_id
        page2 = c.get("/").text
        assert "CN=crit" not in page2      # superseded -> dropped from metrics
        assert "CN=warn" in page2          # still tracked
    finally:
        c.__exit__(None, None, None)
