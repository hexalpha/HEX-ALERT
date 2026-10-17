import os
import stat

import pytest

from config.runtime_config import RuntimeConfigStore

TEST_MASTER_SECRET = "test-master-secret-hex-alert-0123456789"


def test_encrypted_secret_survives_store_reopen_replace_and_clear(tmp_path):
    first = RuntimeConfigStore(tmp_path, TEST_MASTER_SECRET)
    token_one = "unit-test-token-alpha-do-not-use-for-discord"
    token_two = "unit-test-token-beta-do-not-use-for-discord"

    first.write({"DISCORD_TOKEN": token_one, "TEST_MODE": True})
    raw = (tmp_path / "runtime.json").read_text(encoding="utf-8")
    assert token_one not in raw
    assert "DISCORD_TOKEN" in raw and "aes_gcm" in raw

    # A new store instance represents a process/container restart reading the same volume.
    restarted = RuntimeConfigStore(tmp_path, TEST_MASTER_SECRET)
    assert restarted.read()["DISCORD_TOKEN"] == token_one
    assert restarted.read()["TEST_MODE"] is True

    restarted.write({"DISCORD_TOKEN": token_two})
    assert RuntimeConfigStore(tmp_path, TEST_MASTER_SECRET).read()["DISCORD_TOKEN"] == token_two
    assert token_one not in (tmp_path / "runtime.json").read_text(encoding="utf-8")
    assert token_two not in (tmp_path / "runtime.json").read_text(encoding="utf-8")

    restarted.write({"DISCORD_TOKEN": ""})
    assert RuntimeConfigStore(tmp_path, TEST_MASTER_SECRET).read()["DISCORD_TOKEN"] == ""


def test_runtime_config_is_private_and_writable_by_non_root_container_user(tmp_path):
    if hasattr(os, "geteuid"):
        assert os.geteuid() != 0, "Docker application container must run as a non-root user"
    store = RuntimeConfigStore(tmp_path / "persistent-config", TEST_MASTER_SECRET)
    store.write({"DISCORD_TOKEN": "unit-test-token-for-permission-check"})
    assert store.read()["DISCORD_TOKEN"]
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "persistent-config" / "runtime.json").stat().st_mode) == 0o600
