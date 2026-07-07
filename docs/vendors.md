# VPN vendors, crypto & config generation

Source: `app/models.py` (`Vendor`), `app/srx/*`.

## Vendor matrix

The `Vendor` enum defines every supported platform. "Generatable" vendors get
config emitted; "import-only" cloud gateways are provider-managed (VCM imports
their config and generates the on-prem far end). Only **tested** vendors are
validated end-to-end; the rest are best-effort and show *"(untested)"* in the UI.

| Vendor (enum) | Label | Generate? | Import? | Tested? | Generator style |
| --- | --- | --- | --- | --- | --- |
| `juniper_srx` | Juniper SRX | ✅ | ✅ | ✅ | Junos `set`-style |
| `cradlepoint` | Cradlepoint | ✅ | ✅ | ✅ | NCOS `config set` |
| `digi` | Digi | ✅ | ✅ | — | Digi Remote Manager CLI |
| `pfsense` | pfSense | ✅ | ✅ | — | GUI field values (VPN > IPsec > Tunnels) |
| `strongswan` | strongSwan | ✅ | ✅ | — | `swanctl.conf` |
| `mikrotik` | MikroTik | ✅ | ✅ | — | RouterOS `/ip ipsec` CLI |
| `fortinet` | Fortinet | ✅ | ✅ | — | FortiOS CLI |
| `palo_alto` | Palo Alto | ✅ | ✅ | — | PAN-OS `set` CLI |
| `cisco_firepower` | Cisco Firepower | ✅ | ✅ | — | FlexConfig / ASA-style |
| `tplink_er` | TP-Link ER (Omada) | ✅ | ✅ | — | Omada controller GUI field values |
| `aws` | AWS VPN Gateway | ❌ (note only) | ✅ | — | import-only |
| `azure` | Azure VPN Gateway | ❌ (note only) | ✅ | — | import-only |

`generatable_vendors()` returns everything except `aws`/`azure`. Generating for
an import-only vendor returns a note telling you to import the provider config
and generate the far end instead.

The `Vendor.label` property appends *"(untested)"* to every vendor except the
two in `_TESTED_VENDORS` (`juniper_srx`, `cradlepoint`), and `Vendor.import_only`
is `True` for the `_IMPORT_ONLY_VENDORS` set (`aws`, `azure`).

### TP-Link ER (Omada) — platform constraints

The `tplink_er` generator (`gen_tplink_er`) emits the exact field values an
operator types under **Settings → VPN → IPsec Policy** in the Omada controller
(there is no useful device CLI), much like the pfSense generator. Because of the
platform, the generator is deliberately restrictive:

- **PSK only** — site-to-site IPsec has no certificate option; a `certificate`
  auth method is downgraded to PSK with an inline note.
- **Policy-based only** — Local Networks / Remote Subnets, no route-based/VTI
  tunnel interface.
- **No AEAD/GCM ciphers and no ECP (elliptic-curve) DH groups** — only CBC
  AES/3DES/DES, MD5/SHA1/SHA256 and DH groups 1/2/5/14/15/16 negotiate; anything
  else is flagged in an `OMADA COMPATIBILITY` block listing each unsupported
  choice.
- **No BGP/dynamic routing** over the tunnel.

Untested end-to-end — treat the output as a best-effort starting point.

## The vendor-neutral profile

`app/srx/model.py` `VpnProfile` holds:

- `local` / `remote` **Endpoint** (public IP, IKE ID, protected subnets).
- **Phase1** (IKE version, encryption, integrity, DH group, lifetime, auth method
  `certificate|psk`, DPD seconds).
- **Phase2** (encryption, integrity, PFS group, lifetime, protocol `esp`).
- Optional **Bgp** (over-tunnel peering).
- Interface hints: `tunnel_interface`, `wan_interface`, `tunnel_ip`,
  `remote_vendor` (the far-end platform, which drives SRX selectors).

`mirror()` produces the peer profile by swapping `local`/`remote` and BGP
ASNs/addresses while keeping crypto identical, guaranteeing a compatible far end.

## Crypto catalog & ratings

`app/srx/proposals.py` catalogs IKE/IPsec algorithms with a security rating
(`broken` / `weak` / `acceptable` / `strong`) and, per algorithm, how each vendor
spells it. `rate_proposal()` returns structured warnings for anything `broken` or
`weak`; `all_warnings()` (in `model.py`) also flags **PSK auth** and de-duplicates
identical warnings across Phase 1 and Phase 2.

| Category | `broken` | `weak` | `acceptable` | `strong` |
| --- | --- | --- | --- | --- |
| Encryption | `des` | `3des` | `aes-128-cbc`, `aes-192-cbc` | `aes-256-cbc`, `aes-128-gcm`, `aes-256-gcm` |
| Integrity | `md5` | `sha1` | — | `sha256`, `sha384`, `sha512` |
| DH groups | `1` | `2`, `5` | `14`, `15` | `16`, `19`, `20`, `21` |
| IKE version | — | `ikev1` | — | `ikev2` |
| Auth method | — | `psk` | — | `certificate` |

Warnings surface three ways: as structured data on connection pages, as an inline
`# ===== SECURITY WARNINGS =====` banner appended to generated config, and via the
rated `<select>` menus (strong options first). Menus use each platform's own
keyword (e.g. Fortinet `aes256gcm`, MikroTik `ecp384`) while the stored value
stays canonical, and only algorithms a platform supports are offered.

## SRX traffic selectors

The SRX generator decides selectors from the **far-end** platform
(`remote_vendor`), because that determines whether the peer negotiates specific
traffic selectors:

- **Route-based VTI peers** — `juniper_srx`, `fortinet`, `palo_alto` — rely on
  `st0` routing; **no** proxy-identity/traffic-selectors are emitted (a note
  explains why).
- **Policy-based peers** — pfSense/strongSwan, AWS, Azure, Cisco, MikroTik, Digi,
  Cradlepoint, TP-Link ER (Omada) — need selectors: a single subnet pair emits a
  classic `proxy-identity`; multiple pairs emit numbered `traffic-selector
  ts0/ts1/…` stanzas. An inline note states they **must match** the peer's Phase 2.
- **Unspecified** far end — selectors are included as a safe default.

IKE identity type is chosen by the ID's shape: a DN (`CN=…`) →
`distinguished-name`, an IP → `inet`, otherwise `hostname` (FQDN).

## Endpoint address kinds (static / DDNS / dynamic)

`addr_kind()` classifies each endpoint's public address as **`ip`** (a literal
IPv4/IPv6), **`fqdn`** (a DNS/DDNS hostname), or **`dynamic`** (blank — the peer
has no fixed address, so this side must be the responder / accept `%any`). Every
generator adapts:

- A **DDNS hostname** is placed straight in the peer/remote-gateway field where
  the platform re-resolves it (SRX `dynamic hostname`, FortiOS `set type ddns`,
  pfSense/MikroTik/PAN-OS bare hostname, Omada Remote ID "Name"), and IKEv1 +
  FQDN/dynamic peers switch to **aggressive mode** where required.
- A **dynamic** (blank) peer forces responder/passive matching by IKE ID
  (`%any`, `0.0.0.0`, `start_action = trap`, Omada "Responder Mode", etc.).
- **AWS/Azure caveat** — `all_warnings()` (`app/srx/model.py`) emits a `broken`
  warning when the endpoint facing an AWS/Azure gateway (the on-prem *customer
  gateway*) is dynamic/DDNS: those clouds **require a static public IP** and do
  not accept a hostname.

## Defaults, IKE-ID suggestion, BGP inference

- **Defaults** (`app/srx/defaults.py`) — an admin edits app-wide Phase 1/Phase 2
  defaults (`/admin/defaults`), applied to new connections; blank form fields fall
  back to them.
- **IKE IDs** (`app/srx/suggest.py`) — blank IDs are auto-filled deterministically:
  certificate auth → an FQDN-style `<name>-<side>.vpn.local`; PSK → the public IP
  when it's an IP, else a synthetic FQDN.
- **Peer inference** — `_suggest_peers` (in `app/routers/sites.py`) proposes likely
  peers for an unpaired connection when public IPs match both ways and/or protected
  subnets mirror; **pairing requires user confirmation** (`pair-confirm`).
- **BGP inference** (`suggest.infer_bgp`) — infers over-tunnel BGP for a paired
  connection from tunnel-interface IPs and either side's existing ASNs, mirroring
  the peer. Emitted only for BGP-capable platforms (`app/srx/bgp.py`: Juniper,
  Cisco, Fortinet, Palo Alto, MikroTik, pfSense/FRR); others get a note.

## Both-sides generation & pairing

From a connection you can:

- **View / download the far end** (`/connections/{id}/far-end[.txt]`) — a mirrored
  config computed on the fly (not persisted), optionally for a chosen peer vendor.
- **Build a persisted far end** (`POST /connections/{id}/peer`) — create a new
  far-end connection (on a new or existing site) **or** update an existing
  connection to match, linking the two via `peer_connection_id`. Re-pairing drops
  the previous pairing first.
- **Rename** (`POST /connections/{id}/rename`) — regenerates config under the new
  name and emits the device's in-place rename syntax where supported
  (`app/srx/rename.py`: Juniper/Fortinet/Palo/MikroTik do atomic renames;
  swanctl/Digi/Cradlepoint/Cisco get delete-and-recreate guidance).

Connection names are slugified to safe config identifiers (letters, digits,
`_.-`; other characters become hyphens) and are unique within a site.

## Import

`POST /sites/import` (paste or upload). Uploads are read by
`config_from_upload()` first: a **ZIP backup** (detected by the `PK` magic or a
`.zip` name — e.g. a **Digi Remote Manager ZIP backup**) is unpacked to its
config-bearing member, otherwise the bytes are decoded as text. `import_site()`
in `app/srx/importer.py` then:

1. **Detects the vendor** from tell-tale markers (`detect_vendor`).
2. Parses one or more connections into `VpnProfile`s, reverse-mapping vendor
   keywords back to canonical algorithm ids, and **captures BGP-over-tunnel and
   tunnel-interface info** where the source config carries it.
3. **Extracts only VPN-relevant sections** (`extract_vpn_sections`) so unrelated —
   possibly sensitive — device state is not persisted.
4. **Redacts secrets** before storage: SRX `pre-shared-key`/`encrypted-password`,
   and pfSense `<pre-shared-key>` are replaced with `<redacted>`.

Notable importers:

- **Structured (curly-brace) Junos** — one connection per `vpn` stanza; skips
  `inactive:` stanzas; normalizes `hmac-sha-256-128` → `sha-256`.
- **pfSense `config.xml` backup** — one connection per `<phase1>`, joined to its
  `<phase2>` entries by `ikeid` for protected subnets; only the `<ipsec>` section
  is used.
- **Digi** — from a pasted CLI config or an unpacked ZIP backup.
- **TP-Link ER (Omada)** — parses the GUI field-value block the generator emits;
  auth is fixed to `psk` (Omada site-to-site has no certificate option).
- **AWS / Azure** — best-effort parse of the provider's download; flagged
  `needs_review` because the sample proposal values may not match the tunnel's
  real policy. BGP ASNs/neighbor are extracted where present.

Imports that can't parse endpoint details are flagged `needs_review` with a note
so the shown parameters aren't trusted blindly.

### Re-import: update-or-duplicate, with a diff

When an import matches an existing site (same name/hostname, or a shared local
public IP on any connection — `_match_import_site`), VCM shows a **side-by-side
before/after diff** and lets you choose **update** (upsert connections in place,
matched by name) or **duplicate** (create a new site). The full original device
config is preserved verbatim in `VpnConnection.imported_config` and is **never
regenerated or overwritten**. When an importer's excerpt omits BGP that the
profile captured, `_imported_config()` appends the generated BGP so **BGP /
prefix-lists survive** the import/update/diff round-trip rather than silently
dropping out.
</content>
