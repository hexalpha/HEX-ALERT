"""Persistent, atomic runtime configuration with encrypted secret values."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any
import base64
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from services.mfa import derive_encryption_key


SECRET_KEYS = {"DISCORD_TOKEN", "OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "CUSTOM_API_KEY", "GOOGLE_SEARCH_API_KEY", "GOOGLE_SEARCH_ENGINE_ID", "TAVILY_API_KEY", "SERPER_API_KEY", "BRAVE_SEARCH_API_KEY", "BING_SEARCH_API_KEY", "CUSTOM_SEARCH_API_KEY"}


class RuntimeConfigError(RuntimeError):
    """Raised when the persistent runtime configuration cannot be read or written."""


class RuntimeConfigStore:
    def __init__(self, directory: str | Path | None = None, master_secret: str = ""):
        configured = directory or os.environ.get("HEX_ALERT_CONFIG_DIR")
        self.directory = Path(configured) if configured else Path.cwd() / "config" / "runtime"
        self.path = self.directory / "runtime.json"
        self.master_secret = master_secret

    def _ensure_dir(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            self.directory.chmod(0o700)
        except OSError:
            pass  # Windows ACLs govern access there; Docker uses POSIX ownership.

    def _key(self) -> bytes:
        try:
            return derive_encryption_key(self.master_secret)
        except RuntimeError as exc:
            raise RuntimeConfigError("A stable SESSION_SECRET of at least 32 characters is required to encrypt runtime credentials") from exc

    def read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            stored = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(stored, dict):
                raise ValueError("configuration root must be an object")
            result: dict[str, Any] = {}
            for name, value in stored.items():
                if name in SECRET_KEYS and isinstance(value, dict) and set(value) == {"aes_gcm"}:
                    ciphertext=base64.urlsafe_b64decode(value["aes_gcm"].encode())
                    result[name]=AESGCM(self._key()).decrypt(ciphertext[:12],ciphertext[12:],f"hex-alert-runtime:{name}".encode()).decode()
                else:
                    result[name] = value
            return result
        except (OSError, ValueError, TypeError, InvalidTag, json.JSONDecodeError) as exc:
            raise RuntimeConfigError("Runtime configuration could not be read") from exc

    def write(self, changes: dict[str, Any]) -> None:
        self._ensure_dir()
        current = self.read()
        current.update(changes)
        stored: dict[str, Any] = {}
        for name, value in current.items():
            if name in SECRET_KEYS:
                nonce=secrets.token_bytes(12)
                encrypted=AESGCM(self._key()).encrypt(nonce,str(value).encode(),f"hex-alert-runtime:{name}".encode())
                stored[name] = {"aes_gcm": base64.urlsafe_b64encode(nonce+encrypted).decode()}
            else:
                stored[name] = value
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.directory, prefix=".runtime-", suffix=".tmp", delete=False) as temp:
                temp_name = temp.name
                os.chmod(temp_name, 0o600)
                json.dump(stored, temp, separators=(",", ":"), sort_keys=True)
                temp.flush()
                os.fsync(temp.fileno())
            os.replace(temp_name, self.path)
            os.chmod(self.path, 0o600)
        except OSError as exc:
            if temp_name:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
            raise RuntimeConfigError("Runtime configuration could not be saved") from exc


def _bootstrap_master_secret() -> str:
    # Importing Settings directly avoids recursion through cached get_settings().
    from config.settings import Settings
    settings=Settings()
    return settings.session_secret or settings.dashboard_api_key


def get_runtime_config(master_secret: str | None = None) -> dict[str, Any]:
    return RuntimeConfigStore(master_secret=master_secret if master_secret is not None else _bootstrap_master_secret()).read()


def update_runtime_config(changes: dict[str, Any], master_secret: str | None = None) -> None:
    RuntimeConfigStore(master_secret=master_secret if master_secret is not None else _bootstrap_master_secret()).write(changes)
