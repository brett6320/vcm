"""Private-key generation and (de)serialization. Private keys are ALWAYS stored
KEK-encrypted and are never emitted through any route — only certs/chains are."""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..security import crypto

_CURVES = {
    "secp256r1": ec.SECP256R1,
    "secp384r1": ec.SECP384R1,
    "secp521r1": ec.SECP521R1,
}


def generate_key(key_type: str, params: str):
    key_type = key_type.lower()
    if key_type == "ec":
        curve = _CURVES.get(params.lower())
        if not curve:
            raise ValueError(f"Unsupported EC curve: {params}")
        return ec.generate_private_key(curve())
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=int(params))
    raise ValueError(f"Unsupported key type: {key_type}")


def wrap_private_key(key, aad: bytes | None = None) -> bytes:
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return crypto.encrypt(der, aad)


def unwrap_private_key(blob: bytes, aad: bytes | None = None):
    der = crypto.decrypt(blob, aad)
    return serialization.load_der_private_key(der, password=None)


def public_key_pem(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
