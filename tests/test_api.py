from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from fastapi.testclient import TestClient
from api import app as api_module
from api.app import app, DiscordSetupPayload
from database.models import Base, Alert, SentMessage, ChannelConfig
from config.runtime_config import RuntimeConfigError, RuntimeConfigStore


def test_json_source_testing_counts_cve_and_kev_list_fields():
    from api.app import _json_list_items, _source_test_params, _json_source_preview
    from api.app import SourcePayload
    assert len(_json_list_items({"vulnerabilities": [{"cveID": f"CVE-2026-{i}"} for i in range(3)]})) == 3
    assert len(_json_list_items({"vulnerabilities": []})) == 0
    assert len(_json_list_items({"items": [1], "data": [1, 2]})) == 1
    assert len(_json_list_items([1, 2])) == 2
    nvd = SourcePayload(name="NVD CVE API", url="https://services.nvd.nist.gov/rest/json/cves/2.0", source_type="json_api")
    kev = SourcePayload(name="CISA KEV", url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", source_type="json_api")
    assert _source_test_params(nvd) == {"resultsPerPage": 50}
    assert _source_test_params(kev) is None
    sample = _json_source_preview({"cveID": "CVE-2026-12345", "dateAdded": "2026-10-01", "dueDate": "2026-10-04", "notes": "https://example.com/advisory", "vulnerabilityName": "Sample advisory"})
    assert sample["cve_id"] == "CVE-2026-12345"
    assert sample["kev_added_at"] == "2026-10-01"
    assert sample["published_at"] is None
    assert sample["modified_at"] is None
    assert sample["due_date"] == "2026-10-04"
    assert sample["references"] == ["https://example.com/advisory"]


def test_health_endpoint_has_required_service_fields():
    result = TestClient(app).get("/health").json()
    assert {"bot", "database", "redis", "scheduler", "sources_active", "discord", "test_mode", "production_mode"} <= result.keys()
    assert isinstance(result["test_mode"], bool)
    assert result["production_mode"] is (not result["test_mode"])


def test_dashboard_is_served():
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "HEX ALERT" in response.text


def test_timezone_preferences_validate_and_persist(monkeypatch, tmp_path):
    monkeypatch.setenv("HEX_ALERT_CONFIG_DIR", str(tmp_path / "timezone-runtime"))
    monkeypatch.setenv("SESSION_SECRET", "timezone-test-session-secret-hex-alert-0123456789")
    api_module.get_settings.cache_clear()
    app.dependency_overrides[api_module.require_admin] = lambda: True
    try:
        client = TestClient(app)
        saved = client.post("/api/settings/time", json={"timezone": "Asia/Kolkata", "time_format": "12h"})
        assert saved.status_code == 200
        assert saved.json()["timezone"] == "Asia/Kolkata"
        assert saved.json()["time_format"] == "12h"
        again = client.get("/api/settings/time")
        assert again.json()["timezone"] == "Asia/Kolkata"
        assert again.json()["daily_digest_display"] == "Every day at 8:00 AM IST"
        invalid = client.post("/api/settings/time", json={"timezone": "Mars/Olympus", "time_format": "12h"})
        assert invalid.status_code == 422
    finally:
        app.dependency_overrides.pop(api_module.require_admin, None)
        api_module.get_settings.cache_clear()


def test_discord_token_validation_does_not_echo_credentials():
    secret = "DO_NOT_ECHO_THIS_DISCORD_TOKEN_" + "x" * 250
    app.dependency_overrides[api_module.require_admin] = lambda: True
    try:
        response = TestClient(app).post("/api/discord/test", json={"token": secret})
        assert response.status_code == 422
        assert secret not in response.text
        assert "Invalid Discord credential request" in response.text
    finally:
        app.dependency_overrides.pop(api_module.require_admin, None)


@pytest.mark.asyncio
async def test_discord_test_uses_protected_saved_token_when_field_is_blank(monkeypatch):
    monkeypatch.setattr(api_module, "get_settings", lambda: SimpleNamespace(discord_token="protected-server-token"))

    async def verify(token):
        assert token == "protected-server-token"
        return {"username": "HexBot", "id": "123", "bot": True}

    monkeypatch.setattr(api_module, "_verify_discord_token", verify)
    monkeypatch.setitem(api_module.runtime, "bot", None)
    result = await api_module.test_discord(DiscordSetupPayload())
    assert result == {"username": "HexBot", "id": "123", "bot": True, "connected": False, "guilds": []}


@pytest.mark.asyncio
async def test_discord_test_starts_gateway_and_returns_guilds_for_first_run(monkeypatch):
    monkeypatch.setattr(api_module, "get_settings", lambda: SimpleNamespace(discord_token=""))
    guild = SimpleNamespace(id=77, name="Hex Lab", member_count=12)

    class Bot:
        user = SimpleNamespace(id=123)
        guilds = [guild]
        latency = 0.03

        def is_ready(self): return True
        async def wait_until_ready(self): return None

    class Controller:
        async def start_bot(self, token):
            assert token == "test-only-token-for-gateway-flow"
            api_module.runtime["bot"] = Bot()

    async def verify(token):
        assert token == "test-only-token-for-gateway-flow"
        return {"username": "HexBot", "id": "123", "bot": True}

    monkeypatch.setattr(api_module, "_verify_discord_token", verify)
    monkeypatch.setitem(api_module.runtime, "bot", None)
    monkeypatch.setitem(api_module.runtime, "controller", Controller())
    result = await api_module.test_discord(DiscordSetupPayload(token="test-only-token-for-gateway-flow"))

    assert result["connected"] is True
    assert result["guilds"] == [{"id": "77", "name": "Hex Lab", "member_count": 12}]
    assert "token" not in result and "test-only-token-for-gateway-flow" not in repr(result)


@pytest.mark.asyncio
async def test_dashboard_discord_save_replace_and_clear_never_echo_or_log_token(monkeypatch, tmp_path, caplog):
    caplog.set_level("INFO", logger="hexalert.api")
    monkeypatch.setenv("HEX_ALERT_CONFIG_DIR", str(tmp_path / "runtime-config"))
    monkeypatch.setenv("DISCORD_TOKEN", "")
    monkeypatch.setenv("SESSION_SECRET", "api-test-session-secret-hex-alert-0123456789")
    api_module.get_settings.cache_clear()
    token_one = "unit-test-token-one-never-a-real-credential"
    token_two = "unit-test-token-two-never-a-real-credential"
    verified = []

    async def verify(token):
        verified.append(token)
        return {"username": "HexBot", "id": "1001", "bot": True}

    class Controller:
        started = []
        stopped = 0
        ready_waits = 0

        async def start_bot(self, token):
            self.started.append(token)
            controller = self
            class Bot:
                user = SimpleNamespace(id=1001)
                guilds = []
                def is_ready(self): return True
                async def wait_until_ready(self): controller.ready_waits += 1
            api_module.runtime["bot"] = Bot()

        async def stop_bot(self):
            self.stopped += 1
            api_module.runtime["bot"] = None

    controller = Controller()
    monkeypatch.setattr(api_module, "_verify_discord_token", verify)
    monkeypatch.setitem(api_module.runtime, "controller", controller)
    monkeypatch.setitem(api_module.runtime, "bot", None)
    try:
        settings=api_module.get_settings()
        master=settings.session_secret or settings.dashboard_api_key
        assert len(master) >= 32
        saved = await api_module.save_discord_config(DiscordSetupPayload(token=token_one))
        assert saved == {"success": True, "token_configured": True, "connected": True}
        assert token_one not in repr(saved)
        assert token_one not in caplog.text
        assert RuntimeConfigStore(tmp_path / "runtime-config", master).read()["DISCORD_TOKEN"] == token_one
        assert controller.ready_waits == 1

        saved = await api_module.save_discord_config(DiscordSetupPayload(token=token_two))
        assert saved["token_configured"] is True
        assert RuntimeConfigStore(tmp_path / "runtime-config", master).read()["DISCORD_TOKEN"] == token_two
        assert controller.started == [token_one, token_two]
        assert controller.ready_waits == 2

        # A mapping-only save submits a blank token and must preserve the saved credential.
        saved = await api_module.save_discord_config(DiscordSetupPayload(token=""))
        assert saved["token_configured"] is True
        assert RuntimeConfigStore(tmp_path / "runtime-config", master).read()["DISCORD_TOKEN"] == token_two
        assert controller.started == [token_one, token_two, token_two]
        assert verified == [token_one, token_two, token_two]

        cleared = await api_module.clear_discord_token()
        assert cleared == {"token_configured": False, "connected": False}
        assert RuntimeConfigStore(tmp_path / "runtime-config", master).read()["DISCORD_TOKEN"] == ""
        assert controller.stopped == 1
        assert "Discord token validation successful" in caplog.text
        assert "Discord token persisted" in caplog.text
        assert "Guild discovery complete count=0" in caplog.text
        assert token_one not in caplog.text and token_two not in caplog.text
    finally:
        api_module.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_discord_config_write_failure_returns_safe_message_and_does_not_log_token(monkeypatch, caplog):
    token = "unit-test-token-write-failure-not-a-real-credential"
    monkeypatch.setattr(api_module, "get_settings", lambda: SimpleNamespace(
        discord_token="", session_secret="test-session-secret-that-is-long-enough", dashboard_api_key=""
    ))

    async def verify(_token):
        return {"username": "HexBot", "id": "1001", "bot": True}

    def fail_write(*_args, **_kwargs):
        raise RuntimeConfigError("private filesystem detail")

    monkeypatch.setattr(api_module, "_verify_discord_token", verify)
    monkeypatch.setattr(api_module, "update_runtime_config", fail_write)
    with pytest.raises(api_module.HTTPException) as error:
        await api_module.save_discord_config(DiscordSetupPayload(token=token))

    assert error.value.status_code == 500
    assert error.value.detail == "Unable to save Discord configuration."
    assert token not in caplog.text
    assert "private filesystem detail" not in caplog.text


@pytest.mark.asyncio
async def test_discord_channel_listing_includes_send_and_embed_permissions(monkeypatch):
    permissions = SimpleNamespace(view_channel=True, send_messages=True, embed_links=False, read_message_history=True)
    channel = SimpleNamespace(id=42, name="cyber-test", type="text", permissions_for=lambda member: permissions)
    guild = SimpleNamespace(me=object(), text_channels=[channel])
    bot = SimpleNamespace(get_guild=lambda guild_id: guild if guild_id == 123 else None)
    monkeypatch.setitem(api_module.runtime, "bot", bot)

    result = await api_module.discord_channels("123")

    assert result == [{"id": "42", "name": "cyber-test", "type": "text", "can_view_channel": True, "can_send_messages": True, "can_embed_links": False, "can_read_message_history": True}]


@pytest.mark.asyncio
async def test_discord_test_alert_is_test_mode_only_and_persists_delivery(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(api_module, "SessionLocal", sessions)
    monkeypatch.setattr(api_module, "get_settings", lambda: SimpleNamespace(test_mode=True, test_channel_id=42))
    async with sessions() as session:
        session.add(ChannelConfig(guild_id="7", name="TEST_CHANNEL_ID", channel_id="42"))
        await session.commit()
    perms = SimpleNamespace(view_channel=True, send_messages=True, embed_links=True, read_message_history=True)
    member = object()
    guild = SimpleNamespace(id=7, me=member)

    class Channel:
        def __init__(self):
            self.id = 42
            self.guild = guild

        def permissions_for(self, _member):
            return perms

        async def send(self, **_kwargs):
            return SimpleNamespace(id=999)

    monkeypatch.setitem(api_module.runtime, "bot", SimpleNamespace(get_channel=lambda channel_id: Channel() if channel_id == 42 else None))
    try:
        result = await api_module.send_test_alert("cve")
        assert result["status"] == "SENT"
        assert result["message_id"] == "999"
        assert result["guild_id"] == "7" and result["channel_id"] == "42"
        async with sessions() as session:
            alert = await session.scalar(select(Alert).where(Alert.id == result["alert_id"]))
            message = await session.scalar(select(SentMessage).where(SentMessage.message_id == "999"))
            assert alert and alert.status == "sent" and alert.message_id == "999"
            assert message and message.guild_id == "7" and message.channel_id == "42"
    finally:
        await engine.dispose()
