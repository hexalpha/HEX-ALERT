"""RFC 6238 TOTP with authenticated encryption and one-time recovery codes."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config.settings import get_settings


def _key() -> bytes:
    settings = get_settings()
    master = settings.session_secret or settings.dashboard_api_key
    return derive_encryption_key(master)


def derive_encryption_key(master: str) -> bytes:
    if len(master) < 32:
        raise RuntimeError("A stable secret of at least 32 characters is required for encrypted credentials")
    return hashlib.sha256(master.encode("utf-8")).digest()


def encrypt_secret(secret: str, username: str) -> str:
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(_key()).encrypt(nonce, secret.encode("ascii"), username.encode("utf-8"))
    return base64.urlsafe_b64encode(nonce + cipher).decode("ascii")


def decrypt_secret(value: str, username: str) -> str:
    raw = base64.urlsafe_b64decode(value.encode("ascii"))
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], username.encode("utf-8")).decode("ascii")


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, username: str) -> str:
    label = quote(f"HEX ALERT:{username}", safe="")
    return f"otpauth://totp/{label}?{urlencode({'secret': secret, 'issuer': 'HEX ALERT', 'algorithm': 'SHA1', 'digits': 6, 'period': 30})}"


def totp_at(secret: str, timestamp: int | None = None) -> str:
    counter = int(timestamp if timestamp is not None else time.time()) // 30
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str, timestamp: int | None = None) -> bool:
    if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
        return False
    now = int(timestamp if timestamp is not None else time.time())
    return any(hmac.compare_digest(totp_at(secret, now + offset * 30), code) for offset in (-1, 0, 1))


def new_recovery_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(8).upper() for _ in range(count)]


def hash_recovery_code(code: str, username: str) -> str:
    return hmac.new(_key(), (username + ":" + code.strip().upper()).encode("utf-8"), hashlib.sha256).hexdigest()
