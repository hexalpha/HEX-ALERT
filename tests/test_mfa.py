import base64

from config.settings import get_settings
from services.mfa import (decrypt_secret, encrypt_secret, generate_secret, hash_recovery_code,
                          new_recovery_codes, totp_at, verify_totp)


def test_rfc6238_totp_vector_and_time_window():
    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert totp_at(secret, 59) == "287082"
    assert verify_totp(secret, "287082", 59)
    assert not verify_totp(secret, "000000", 59)


def test_totp_secret_encryption_and_recovery_codes(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "test-session-master-secret-that-is-long-enough")
    get_settings.cache_clear()
    try:
        secret = generate_secret()
        encrypted = encrypt_secret(secret, "admin")
        assert secret not in encrypted
        assert decrypt_secret(encrypted, "admin") == secret
        codes = new_recovery_codes()
        assert len(codes) == 10 and len(set(codes)) == 10
        hashes = {hash_recovery_code(code, "admin") for code in codes}
        assert hash_recovery_code(codes[0], "admin") in hashes
        assert codes[0] not in hashes
    finally:
        get_settings.cache_clear()
