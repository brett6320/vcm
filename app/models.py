from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _enum_col(enum_cls):
    # Store the enum *value* (not name) as a VARCHAR; round-trips back to the enum
    # on read so `.value` works everywhere in templates/logic.
    return SAEnum(enum_cls, native_enum=False, length=24,
                  values_callable=lambda e: [m.value for m in e])


def utcnow() -> datetime:
    # Timezone-aware UTC. Postgres timestamptz round-trips aware datetimes; SQLite
    # drops tzinfo on read, so comparisons must coerce naive values to UTC (see
    # ensure_aware). Storing aware-UTC keeps Postgres correct.
    return datetime.now(timezone.utc)


def ensure_aware(dt: datetime) -> datetime:
    """Treat a naive datetime (e.g. read back from SQLite) as UTC."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


class Role(str, enum.Enum):
    operator = "operator"
    admin = "admin"


class CAType(str, enum.Enum):
    root = "root"
    intermediate = "intermediate"
    issuing = "issuing"


class CertStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    expired = "expired"


class Vendor(str, enum.Enum):
    juniper_srx = "juniper_srx"
    digi = "digi"
    cradlepoint = "cradlepoint"
    pfsense = "pfsense"
    cisco_firepower = "cisco_firepower"
    fortinet = "fortinet"
    palo_alto = "palo_alto"
    strongswan = "strongswan"
    mikrotik = "mikrotik"
    aws = "aws"
    azure = "azure"

    @property
    def label(self) -> str:
        base = _VENDOR_LABELS.get(self.value, self.value)
        return base if self.tested else f"{base} (untested)"

    @property
    def tested(self) -> bool:
        return self.value in _TESTED_VENDORS

    @property
    def import_only(self) -> bool:
        # Cloud gateways: config is provider-managed. We import their config and
        # generate the far-end (on-prem) side — we never emit a config for them.
        return self.value in _IMPORT_ONLY_VENDORS


_VENDOR_LABELS = {
    "juniper_srx": "Juniper SRX",
    "digi": "Digi",
    "cradlepoint": "Cradlepoint",
    "pfsense": "pfSense",
    "cisco_firepower": "Cisco Firepower",
    "fortinet": "Fortinet",
    "palo_alto": "Palo Alto",
    "strongswan": "strongSwan",
    "mikrotik": "MikroTik",
    "aws": "AWS VPN Gateway",
    "azure": "Azure VPN Gateway",
}

# Only these are validated end-to-end; the rest are generated best-effort.
_TESTED_VENDORS = {"juniper_srx", "cradlepoint"}
# Import-only cloud gateways (no config generation).
_IMPORT_ONLY_VENDORS = {"aws", "azure"}


def generatable_vendors() -> list["Vendor"]:
    return [v for v in Vendor if not v.import_only]


# --------------------------------------------------------------------------- #
# Identity & access
# --------------------------------------------------------------------------- #
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(_enum_col(Role), default=Role.operator)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Contact / identity
    first_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(32), nullable=True)  # E.164 for SMS
    # Force a password change on next login (e.g. admin-created accounts).
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    # TOTP secret, AES-GCM encrypted at rest (nonce||ct). Nullable until enrolled.
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    totp_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    credentials: Mapped[list["WebAuthnCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def has_mfa(self) -> bool:
        return self.totp_confirmed or any(c for c in self.credentials)

    @property
    def display_name(self) -> str:
        full = " ".join(x for x in (self.first_name, self.last_name) if x)
        return full or self.username


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(64), default="passkey")
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, index=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship(back_populates="credentials")


class WebAuthnChallenge(Base):
    """Short-lived registration/authentication challenges."""

    __tablename__ = "webauthn_challenges"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(16))  # "register" | "auth"
    challenge: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # random token
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    mfa_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Where to send the user once fully authenticated (the originally-requested page).
    next_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    user: Mapped[User] = relationship()


class Backup(Base):
    """A versioned, encrypted snapshot of application state (AES-256-GCM via KEK)."""

    __tablename__ = "backups"

    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64))       # of plaintext, integrity check
    size: Mapped[int] = mapped_column(Integer)            # plaintext size
    payload: Mapped[bytes] = mapped_column(LargeBinary)   # encrypted snapshot


class IPAllowEntry(Base):
    __tablename__ = "ip_allowlist"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64))  # e.g. 203.0.113.0/24 or 2001:db8::/32
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------- #
# PKI
# --------------------------------------------------------------------------- #
class CertAuthority(Base):
    __tablename__ = "cert_authorities"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    ca_type: Mapped[CAType] = mapped_column(_enum_col(CAType))
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("cert_authorities.id"), nullable=True
    )
    subject_dn: Mapped[str] = mapped_column(String(512))
    # Empty while a CA is pending: we hold the key + CSR but no signed cert yet.
    cert_pem: Mapped[str] = mapped_column(Text)
    # Private key wrapped with KEK (AES-256-GCM: nonce||ciphertext). Never exported.
    key_enc: Mapped[bytes] = mapped_column(LargeBinary)
    key_type: Mapped[str] = mapped_column(String(16))  # ec|rsa
    key_params: Mapped[str] = mapped_column(String(32))  # curve name or bit size
    serial_counter: Mapped[int] = mapped_column(Integer, default=1)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    path_len: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Delete-protection: a locked CA must be unlocked before it can be deleted.
    # CAs are locked by default — deletion is a deliberate two-step action.
    locked: Mapped[bool] = mapped_column(Boolean, default=True)
    # Pending CA: key + CSR generated, awaiting an externally-signed cert upload.
    pending: Mapped[bool] = mapped_column(Boolean, default=False)
    csr_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    parent: Mapped["CertAuthority | None"] = relationship(remote_side=[id])

    @property
    def has_private_key(self) -> bool:
        # Imported CAs may be cert-only (key kept offline) — those can't sign.
        return bool(self.key_enc)

    @property
    def can_sign(self) -> bool:
        # Usable as an issuer only with a private key AND a signed cert in hand.
        return bool(self.key_enc) and bool(self.cert_pem) and not self.pending


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    ca_id: Mapped[int] = mapped_column(ForeignKey("cert_authorities.id"))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id"), nullable=True)
    serial: Mapped[str] = mapped_column(String(64), index=True)
    subject_dn: Mapped[str] = mapped_column(String(512))
    san: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    cert_pem: Mapped[str] = mapped_column(Text)
    csr_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[CertStatus] = mapped_column(_enum_col(CertStatus), default=CertStatus.active)
    # Delete-protection: a locked cert must be unlocked before it can be deleted.
    locked: Mapped[bool] = mapped_column(Boolean, default=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    ca: Mapped[CertAuthority] = relationship()


# --------------------------------------------------------------------------- #
# VPN sites & defaults
# --------------------------------------------------------------------------- #
class Defaults(Base):
    """Singleton-ish key/value store for app-wide VPN/PKI defaults (JSON blob)."""

    __tablename__ = "defaults"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    value_json: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Site(Base):
    """A device / firewall. Holds one or more VPN connections (tunnels)."""

    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    vendor: Mapped[Vendor] = mapped_column(_enum_col(Vendor))
    model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="generated")  # generated|imported
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    connections: Mapped[list["VpnConnection"]] = relationship(
        back_populates="site", cascade="all, delete-orphan",
        foreign_keys="VpnConnection.site_id",
    )


class VpnConnection(Base):
    """A single VPN tunnel on a site. A site may have many."""

    __tablename__ = "vpn_connections"
    __table_args__ = (UniqueConstraint("site_id", "name", name="uq_conn_site_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128), index=True)
    # Full parameter set as JSON (endpoints, proposals, subnets, PKI refs, etc.)
    params_json: Mapped[str] = mapped_column(Text)
    generated_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="generated")  # generated|imported
    # Set when an import could not be fully parsed — the shown params are not trustworthy.
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    review_note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The paired far-end connection (on this or another site), if built.
    peer_connection_id: Mapped[int | None] = mapped_column(
        ForeignKey("vpn_connections.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    site: Mapped[Site] = relationship(back_populates="connections", foreign_keys=[site_id])


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (UniqueConstraint("id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
