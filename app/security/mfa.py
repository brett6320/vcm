"""MFA: TOTP (pyotp) and WebAuthn passkeys (webauthn lib)."""
from __future__ import annotations

import base64
import io

import pyotp
import qrcode

from ..config import get_settings
from ..models import User
from . import crypto


# --------------------------- TOTP --------------------------------------- #
def new_totp_secret() -> str:
    return pyotp.random_base32()


def encrypt_totp_secret(secret: str) -> bytes:
    return crypto.encrypt(secret.encode())


def decrypt_totp_secret(user: User) -> str | None:
    if not user.totp_secret_enc:
        return None
    return crypto.decrypt(user.totp_secret_enc).decode()


def totp_uri(username: str, secret: str) -> str:
    issuer = get_settings().rp_name
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def totp_qr_data_uri(uri: str) -> str:
    # SVG factory avoids a hard Pillow dependency for PNG rendering.
    import qrcode.image.svg

    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/svg+xml;base64,{b64}"


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1)


# --------------------------- WebAuthn ----------------------------------- #
# Thin wrappers over the `webauthn` package so routers stay clean.
from webauthn import (  # noqa: E402
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes  # noqa: E402
from webauthn.helpers.structs import (  # noqa: E402
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def registration_options(user: User, existing_cred_ids: list[bytes]):
    s = get_settings()
    opts = generate_registration_options(
        rp_id=s.rp_id,
        rp_name=s.rp_name,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.username,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=cid) for cid in existing_cred_ids
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return opts


def verify_registration(credential: dict, challenge: bytes):
    s = get_settings()
    return verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=s.rp_id,
        expected_origin=s.rp_origin,
    )


def authentication_options(cred_ids: list[bytes]):
    s = get_settings()
    return generate_authentication_options(
        rp_id=s.rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=cid) for cid in cred_ids],
        user_verification=UserVerificationRequirement.PREFERRED,
    )


def verify_authentication(credential: dict, challenge: bytes, public_key: bytes, sign_count: int):
    s = get_settings()
    return verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=s.rp_id,
        expected_origin=s.rp_origin,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
    )


__all__ = [
    "new_totp_secret",
    "encrypt_totp_secret",
    "decrypt_totp_secret",
    "totp_uri",
    "totp_qr_data_uri",
    "verify_totp",
    "registration_options",
    "verify_registration",
    "authentication_options",
    "verify_authentication",
    "options_to_json",
    "base64url_to_bytes",
]
