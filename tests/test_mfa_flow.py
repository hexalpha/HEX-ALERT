"""End-to-end HTTP flow for admin MFA using an isolated disposable SQLite DB."""
import asyncio
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api import app as api_module
from database.models import Base
from services.mfa import totp_at


def test_admin_totp_login_recovery_and_disable_flow(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "isolated-test-session-secret-with-more-than-32-characters")
    monkeypatch.setenv("DASHBOARD_API_KEY", "isolated-test-dashboard-api-key")
    api_module.get_settings.cache_clear()

    database_path = Path(__file__).with_name(".mfa-flow-test.db")
    engine = create_async_engine(URL.create("sqlite+aiosqlite", database=str(database_path.resolve())))
    original_factory = api_module.SessionLocal
    try:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        api_module.SessionLocal = factory
        async def create_schema():
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

        asyncio.run(create_schema())
        client = TestClient(api_module.app)
        origin = {"Origin": "http://testserver"}
        credentials = {"username": "flow-admin", "password": "a-very-long-test-admin-password"}

        setup = client.post("/api/auth/setup", json=credentials, headers=origin)
        assert setup.status_code == 200
        assert setup.json()["authenticated"] is True

        enrollment = client.post("/api/mfa/setup", headers=origin)
        assert enrollment.status_code == 200
        setup_data = enrollment.json()
        assert setup_data["qr_data_url"].startswith("data:image/png;base64,")
        secret = setup_data["secret"]

        bad_enrollment = client.post("/api/mfa/confirm", json={"code": "invalid"}, headers=origin)
        assert bad_enrollment.status_code == 422
        enabled = client.post("/api/mfa/confirm", json={"code": totp_at(secret)}, headers=origin)
        assert enabled.status_code == 200
        recovery_code = enabled.json()["recovery_codes"][0]
        assert len(enabled.json()["recovery_codes"]) == 10

        client.post("/api/auth/logout")
        password_login = client.post("/api/auth/login", json=credentials)
        assert password_login.status_code == 200
        assert password_login.json() == {"mfa_required": True}
        assert client.get("/api/auth/me").status_code == 401
        assert client.post("/api/auth/mfa-verify", json={"code": "invalid"}, headers=origin).status_code == 401

        recovery_login = client.post("/api/auth/mfa-verify", json={"code": recovery_code}, headers=origin)
        assert recovery_login.status_code == 200
        assert recovery_login.json()["authenticated"] is True
        assert client.get("/api/auth/me").status_code == 200

        client.post("/api/auth/logout")
        assert client.post("/api/auth/login", json=credentials).json() == {"mfa_required": True}
        assert client.post("/api/auth/mfa-verify", json={"code": recovery_code}, headers=origin).status_code == 401
        totp_login = client.post("/api/auth/mfa-verify", json={"code": totp_at(secret)}, headers=origin)
        assert totp_login.status_code == 200
        assert client.get("/api/auth/me").status_code == 200

        bad_disable = client.post(
            "/api/mfa/disable", json={"password": credentials["password"], "code": "invalid"}, headers=origin
        )
        assert bad_disable.status_code == 422
        disabled = client.post(
            "/api/mfa/disable", json={"password": credentials["password"], "code": totp_at(secret)}, headers=origin
        )
        assert disabled.status_code == 200
        assert disabled.json()["enabled"] is False
        assert client.get("/api/mfa/status").json()["enabled"] is False
    finally:
        api_module.SessionLocal = original_factory
        api_module.get_settings.cache_clear()
        asyncio.run(engine.dispose())
        database_path.unlink(missing_ok=True)
