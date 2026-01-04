from __future__ import annotations
import hmac, hashlib, secrets, struct
from typing import Tuple

# Authenticated symmetric encryption with a simple HMAC-based stream cipher (for learning).
# NOT intended for production use.
#
# - Key derivation: SHA-256(password) -> 32 bytes
# - Encryption: keystream blocks = HMAC(key_stream, nonce||counter)
# - Auth tag: HMAC(key_auth, nonce||ciphertext) (16 bytes)

def derive_keys(psk: str) -> Tuple[bytes, bytes]:
    master = hashlib.sha256(psk.encode("utf-8")).digest()
    key_stream = hmac.new(master, b"stream", hashlib.sha256).digest()
    key_auth   = hmac.new(master, b"auth", hashlib.sha256).digest()
    return key_stream, key_auth

def _keystream(key_stream: bytes, nonce: bytes, nbytes: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        block = hmac.new(key_stream, nonce + struct.pack("!I", counter), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:nbytes])

def encrypt(psk: str, plaintext: bytes) -> bytes:
    key_stream, key_auth = derive_keys(psk)
    nonce = secrets.token_bytes(12)
    ks = _keystream(key_stream, nonce, len(plaintext))
    ct = bytes([a ^ b for a, b in zip(plaintext, ks)])
    tag = hmac.new(key_auth, nonce + ct, hashlib.sha256).digest()[:16]
    return nonce + tag + ct

def decrypt(psk: str, blob: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("ciphertext too short")
    key_stream, key_auth = derive_keys(psk)
    nonce = blob[:12]
    tag = blob[12:28]
    ct = blob[28:]
    exp = hmac.new(key_auth, nonce + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, exp):
        raise ValueError("auth failed")
    ks = _keystream(key_stream, nonce, len(ct))
    return bytes([a ^ b for a, b in zip(ct, ks)])
