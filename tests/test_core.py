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
    for v in ("juniper_srx", "digi", "cradlepoint", "pfsense"):
        cfg = generators.generate(_mk_profile(vendor=v))
        assert cfg.strip()


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
