"""Shared password and one-time recovery-token primitives."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    result = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${result.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, salt, expected = encoded.split("$", 2)
        actual = hash_password(password, bytes.fromhex(salt)).split("$")[-1]
        return algo == "scrypt" and hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, AttributeError):
        return False


def reset_token_digest(raw_token: str) -> str:
    """Hash the exact UTF-8 token value. Never trim or case-normalize credentials."""
    if not isinstance(raw_token, str):
        raise TypeError("Reset token must be text")
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_reset_token(*, now: datetime | None = None, lifetime: timedelta = timedelta(minutes=15)) -> tuple[str, str, datetime]:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Reset-token creation time must be timezone-aware")
    raw = secrets.token_urlsafe(32)
    return raw, reset_token_digest(raw), now.astimezone(timezone.utc) + lifetime


def utc_aware(value: datetime | None) -> datetime | None:
    """Treat legacy naive database values as UTC; normalize aware values to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
