"""Symmetric envelope encryption for secrets at rest (CA keys, TOTP seeds).

Uses AES-256-GCM with the app KEK. Stored blob layout: nonce(12) || ciphertext||tag.
The KEK never leaves the process; CA *private keys* are only ever decrypted in
memory for signing and are never returned through any API.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import get_settings

_NONCE = 12


def _kek() -> bytes:
    return get_settings().kek_bytes()


def encrypt(plaintext: bytes, aad: bytes | None = None) -> bytes:
    nonce = os.urandom(_NONCE)
    ct = AESGCM(_kek()).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(blob: bytes, aad: bytes | None = None) -> bytes:
    nonce, ct = blob[:_NONCE], blob[_NONCE:]
    return AESGCM(_kek()).decrypt(nonce, ct, aad)
