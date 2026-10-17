import asyncio
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import time
import zipfile
import base64
import binascii
from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Literal

import discord
from fastapi import FastAPI, HTTPException, Header, Depends, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select, func, desc, text, DateTime
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from config.settings import get_settings
from config.runtime_config import RuntimeConfigError, update_runtime_config, get_runtime_config
from database.db import SessionLocal
from services.admin_passwords import hash_password, reset_token_digest, utc_aware, verify_password
from database.models import (Base, Job, NewsArticle, CVE, Threat, SecurityTool, Source, SystemLog, SentMessage, Guild,
    CrawlerJob, CrawlerRun, CrawlerPage, AdminUser, AdminSession, Alert, SchedulerConfig, ChannelConfig,
    AutomationRule, CustomDiscordRoute, CustomCommand, EmbedTemplate, AIConfig, utcnow)
from collectors.base import Collector, validate_public_url
from collectors.crawler import public_addresses
from services.discord_routing import (ROUTE_CHANNEL_KEYS, RoutingError, normalize_category,
                                      resolve_discord_channel, resolve_explicit_channel, route_storage_names)
from services.time_utils import DEFAULT_TIMEZONE, format_local_datetime, get_timezone, iso_utc, utc_now

log = logging.getLogger("hexalert.api")
app = FastAPI(title="Hex Alert Admin", version="2.0.0", docs_url="/docs")
app.mount("/static",StaticFiles(directory=os.path.join(os.path.dirname(__file__),"static")),name="static")
bot_state = {"online": False, "scheduler": False, "started_at": time.monotonic()}
runtime = {"scheduler": None, "bot": None}
_login_failures: dict[str, tuple[int, float]] = {}
BACKUP_DIR = Path(os.environ.get("HEX_ALERT_DATA_DIR", Path.cwd())) / "backups"
BACKUP_MAX_BYTES = 50 * 1024 * 1024
BACKUP_MAX_EXPANDED_BYTES = 100 * 1024 * 1024


@app.exception_handler(RequestValidationError)
async def safe_validation_error(request: Request, exc: RequestValidationError):
    # Pydantic's default 422 body includes the rejected input value; never echo credentials.
    sanitized=[]
    for error in exc.errors():
        location=error.get("loc",())
        is_discord_token=request.url.path.startswith("/api/discord/") and "token" in location
        sanitized.append({"loc":list(location),"msg":"Invalid Discord credential request" if is_discord_token else str(error.get("msg","Invalid request")),"type":str(error.get("type","value_error"))})
    return JSONResponse(status_code=422,content={"detail":sanitized})


def _serializer():
    settings = get_settings()
    key = settings.session_secret or settings.dashboard_api_key
    if not key: raise HTTPException(503, "Set SESSION_SECRET or DASHBOARD_API_KEY before creating the admin account")
    return URLSafeTimedSerializer(key, salt="hex-alert-admin")


def _mfa_challenge_serializer():
    settings = get_settings()
    key = settings.session_secret or settings.dashboard_api_key
    if not key: raise HTTPException(503, "Set SESSION_SECRET before using MFA")
    return URLSafeTimedSerializer(key, salt="hex-alert-mfa-login")


def _username_from_request(request: Request) -> str:
    token = request.cookies.get("hex_session", "")
    try: return _serializer().loads(token, max_age=60 * 60 * 12).get("sub", "")
    except Exception: raise HTTPException(401, "Sign in to manage MFA")


def _hash_password(password: str, salt: bytes | None = None) -> str:
    return hash_password(password, salt)


def _verify_password(password: str, encoded: str) -> bool:
    return verify_password(password, encoded)


async def _set_session(response: Response, username: str, request: Request, *, mfa_verified: bool = False,
                       session_version: int = 0):
    session_id=secrets.token_urlsafe(32)
    async with SessionLocal() as session:
        user=await session.scalar(select(AdminUser).where(AdminUser.username==username))
        if not user: raise HTTPException(401,"Admin account no longer exists")
        version=user.session_version
        session.add(AdminSession(admin_user_id=user.id,session_id=session_id,session_version=version,
                                 expires_at=utcnow()+timedelta(hours=12)))
        await session.commit()
    token = _serializer().dumps({"sub": username, "mfa_verified": mfa_verified, "sv": version, "sid": session_id})
    response.set_cookie("hex_session", token, httponly=True, secure=request.url.scheme == "https", samesite="strict", max_age=60 * 60 * 12, path="/")


async def require_admin(request: Request, x_admin_key: str = Header(default="")):
    configured = get_settings().dashboard_api_key
    if configured and x_admin_key and secrets.compare_digest(x_admin_key, configured):
        async with SessionLocal() as session:
            mfa_active = await session.scalar(select(func.count()).select_from(AdminUser).where(AdminUser.mfa_enabled.is_(True)))
        if mfa_active: raise HTTPException(401, "Use a verified MFA session; API-key access is disabled while MFA is enabled")
        return True
    token = request.cookies.get("hex_session", "")
    if not token: raise HTTPException(401, "Sign in to manage Hex Alert")
    try: identity = _serializer().loads(token, max_age=60 * 60 * 12)
    except (BadSignature, SignatureExpired): raise HTTPException(401, "Admin session expired; sign in again")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin", "")
        if not origin or origin.rstrip("/") != str(request.base_url).rstrip("/"):
            raise HTTPException(403, "Cross-origin admin request rejected")
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == identity.get("sub")))
        session_record = None
        if identity.get("sid"):
            session_record = await session.scalar(select(AdminSession).where(
                AdminSession.session_id == identity.get("sid"),
                AdminSession.admin_user_id == user.id if user else False,
                AdminSession.session_version == (user.session_version if user else -1),
                AdminSession.revoked_at.is_(None), AdminSession.expires_at > utcnow()))
    if not user: raise HTTPException(401, "Admin account no longer exists")
    if identity.get("sv", 0) != user.session_version: raise HTTPException(401, "Admin session was revoked; sign in again")
    if identity.get("sid") and not session_record: raise HTTPException(401,"Admin session expired or was revoked")
    if user.mfa_enabled and not identity.get("mfa_verified"):
        raise HTTPException(401, "MFA was enabled; sign in again with an authenticator code")
    return True


class LoginPayload(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    method: Literal["password", "pin"] = "password"
    password: str | None = Field(default=None, min_length=12, max_length=256)
    pin: str | None = Field(default=None, min_length=6, max_length=6, pattern=r"^\d{6}$")

    @field_validator("username", mode="before")
    @classmethod
    def normalize_username(cls, value):
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_credential(self):
        if self.method == "password" and not self.password:
            raise ValueError("Password is required")
        if self.method == "pin" and not self.pin:
            raise ValueError("Enter your six-digit PIN")
        return self


class AdminAccountCreatePayload(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)
    pin: str | None = Field(default=None, min_length=6, max_length=6, pattern=r"^\d{6}$")

    @field_validator("username", mode="before")
    @classmethod
    def normalize_username(cls, value):
        return value.strip() if isinstance(value, str) else value


class PinSettingsPayload(BaseModel):
    current_password: str = Field(min_length=12, max_length=256)
    pin: str | None = Field(default=None, min_length=6, max_length=6, pattern=r"^\d{6}$")
    clear: bool = False
    code: str = Field(default="", max_length=32)

    @model_validator(mode="after")
    def validate_action(self):
        if not self.clear and not self.pin:
            raise ValueError("Enter a six-digit PIN or choose clear")
        if self.clear and self.pin:
            raise ValueError("Choose either a PIN or clear the existing PIN")
        return self


class MfaVerifyPayload(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class MfaDisablePayload(MfaVerifyPayload):
    password: str = Field(min_length=12, max_length=256)


class PasswordResetPayload(BaseModel):
    token: str = Field(min_length=30, max_length=128)
    new_password: str = Field(min_length=12, max_length=256)


class PasswordChangePayload(BaseModel):
    current_password: str = Field(min_length=12, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)
    code: str = Field(default="", max_length=32)


class RecoveryCodesPayload(BaseModel):
    password: str = Field(min_length=12, max_length=256)
    code: str = Field(default="", max_length=32)


class CustomRoutePayload(BaseModel):
    route_name: str = Field(min_length=2, max_length=100)
    route_key: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    description: str = Field(default="", max_length=1000)
    guild_id: str = Field(min_length=1, max_length=32)
    channel_id: str = Field(min_length=1, max_length=32)
    category: str = Field(default="custom", min_length=1, max_length=50)
    keywords: list[str] = Field(default_factory=list, max_length=30)
    priority: int = Field(default=3, ge=1, le=5)
    enabled: bool = False


class DiscordCreateChannelPayload(BaseModel):
    guild_id: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9_-]+$")
    topic: str = Field(default="", max_length=1024)
    category_id: str = Field(default="", max_length=32)
    nsfw: bool = False
    position: int | None = Field(default=None, ge=0, le=500)


class SourcePayload(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    url: str = Field(min_length=8, max_length=2000)
    source_type: Literal["rss", "atom", "website", "json_api", "github", "job_feed", "rss_job_feed", "lever", "greenhouse", "ashby", "remote_ok", "public_job_api", "public_career_page", "company_careers", "linkedin_reference", "wellfound_reference", "naukri_reference", "reference", "news", "security_advisory", "threat_intelligence", "custom"] = "rss"
    category: Literal["jobs", "news", "cve", "technology", "threat", "custom"] = "news"
    description: str = Field(default="", max_length=2000)
    interval_minutes: int = Field(default=30, ge=5, le=1440)
    enabled: bool = False
    company_name: str = Field(default="", max_length=200)
    parser_config: dict[str, str] = Field(default_factory=dict)
    priority: int = Field(default=3, ge=1, le=5)
    tags: list[str] = Field(default_factory=list, max_length=30)
    parser_type: Literal["feed", "html", "json", "github"] = "feed"
    auth_mode: Literal["none", "api_key", "bearer"] = "none"
    auth_env_var: str = Field(default="", max_length=100)
    timeout_seconds: int = Field(default=20, ge=3, le=60)
    max_response_bytes: int = Field(default=2000000, ge=1024, le=10000000)
    requests_per_minute: int = Field(default=6, ge=1, le=60)
    test_metrics: dict = Field(default_factory=dict)


class JobReferencePayload(BaseModel):
    source: Literal["linkedin", "wellfound", "naukri", "manual"] = "manual"
    apply_url: str = Field(min_length=8, max_length=2000)
    title: str = Field(min_length=2, max_length=300)
    company: str = Field(default="", max_length=200)
    location: str = Field(default="", max_length=200)
    experience: str = Field(default="", max_length=200)
    employment_type: str = Field(default="", max_length=100)
    posted_at: str = Field(default="", max_length=80)
    description: str = Field(default="", max_length=12000)
    skills: list[str] = Field(default_factory=list, max_length=30)


class ATSDiscoveryPayload(BaseModel):
    company_domain: str = Field(min_length=8, max_length=2000)


class JobIntelligencePreferences(BaseModel):
    location_priorities: list[str] = Field(min_length=1, max_length=30)
    fresh_hours: int = Field(default=24, ge=1, le=168)
    acceptable_days: int = Field(default=7, ge=1, le=60)
    high_fit_threshold: int = Field(default=75, ge=0, le=100)


class CrawlerPayload(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    start_url: str = Field(min_length=8, max_length=2000)
    allowed_domain: str = Field(default="", max_length=255)
    allowed_paths: list[str] = Field(default_factory=list, max_length=30)
    blocked_paths: list[str] = Field(default_factory=list, max_length=30)
    max_depth: int = Field(default=1, ge=0, le=5)
    max_pages: int = Field(default=10, ge=1, le=100)
    request_delay_ms: int = Field(default=1500, ge=1000, le=60000)
    interval_minutes: int = Field(default=120, ge=5, le=10080)
    user_agent: str = Field(default="HexAlertCrawler/1.0 (respectful public monitor)", min_length=8, max_length=200)
    follow_links: bool = False
    mode: Literal["single_page", "multi_page", "article_discovery", "change_monitor", "job_listing", "documentation", "security_advisory"] = "single_page"
    selectors: dict[str, str] = Field(default_factory=dict)
    enabled: bool = False
    channel_id: str = Field(default="",max_length=32)


class ChannelPayload(BaseModel):
    guild_id: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=50)
    channel_id: str = Field(min_length=1, max_length=32)


class DiscordSetupPayload(BaseModel):
    token: str = Field(default="", max_length=200)
    channels: dict[str, str] = Field(default_factory=dict)
    guild_id: str = Field(default="", max_length=32)


class AISettingsPayload(BaseModel):
    provider: Literal["disabled","local_gguf","openai","gemini","groq","ollama","custom"]
    api_key: str = Field(default="",max_length=500)
    model: str = Field(default="",max_length=100)
    base_url: str = Field(default="http://localhost:11434",max_length=500)


class RulePayload(BaseModel):
    name: str = Field(min_length=2,max_length=150)
    keywords: list[str] = Field(default_factory=list,max_length=50)
    category: str = Field(default="General",max_length=80)
    severity: str = Field(default="Informational",max_length=30)
    channel_id: str = Field(default="",max_length=32)
    enabled: bool = True
    rule_type: Literal["route","filter"] = "route"
    logic: Literal["AND","OR"] = "AND"
    conditions: dict = Field(default_factory=dict)
    route_key: str = Field(default="", max_length=64, pattern=r"^([a-z][a-z0-9_]*|)$")


class TestModePayload(BaseModel):
    enabled: bool
    channel_id: str = ""


class TimeSettingsPayload(BaseModel):
    timezone: str = Field(default=DEFAULT_TIMEZONE, min_length=1, max_length=100)
    time_format: Literal["12h", "24h"] = "12h"

    @field_validator("timezone")
    @classmethod
    def validate_iana_timezone(cls, value: str) -> str:
        try:
            get_timezone(value)
        except ValueError as exc:
            raise ValueError("Choose a valid IANA timezone") from exc
        return value


async def _verify_discord_token(token: str):
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response=await client.get("https://discord.com/api/v10/users/@me",headers={"Authorization":f"Bot {token}"})
    except httpx.TimeoutException:
        raise HTTPException(504,"Discord API request timed out") from None
    except httpx.HTTPError:
        raise HTTPException(503,"Unable to reach Discord API") from None
    if response.status_code != 200: raise HTTPException(422,"Discord rejected that bot token")
    data=response.json()
    if not data.get("bot"):raise HTTPException(422,"Token belongs to a user account; a Discord bot token is required")
    return {"username":data.get("username",""),"id":data.get("id",""),"bot":data.get("bot",False)}


def _store_runtime_values(values:dict[str,object], *, message="Unable to save configuration."):
    try:
        settings=get_settings()
        update_runtime_config(values, settings.session_secret or settings.dashboard_api_key)
    except RuntimeConfigError as exc:
        log.error("Runtime configuration save failed (%s)", type(exc).__name__)
        raise HTTPException(500, message) from None
    get_settings.cache_clear()


@app.get("/api/auth/setup-needed")
async def setup_needed():
    async with SessionLocal() as session: count = await session.scalar(select(func.count()).select_from(AdminUser))
    return {"setup_needed": count == 0}


async def _auth_audit(event: str, level: str = "INFO"):
    async with SessionLocal() as session:
        session.add(SystemLog(level=level, component="auth", message=event))
        await session.commit()


def _login_limit_key(request: Request) -> str:
    # Trust the socket peer only; forwarded headers are not trusted by this local service.
    return request.client.host if request.client else "unknown"


def _check_login_limit(key: str):
    failures, started = _login_failures.get(key, (0, time.monotonic()))
    if time.monotonic() - started >= 900:
        _login_failures.pop(key, None)
        return
    if failures >= 5:
        raise HTTPException(429, "Too many sign-in attempts. Wait 15 minutes and try again.")


def _record_login_failure(key: str):
    failures, started = _login_failures.get(key, (0, time.monotonic()))
    if time.monotonic() - started >= 900:
        failures, started = 0, time.monotonic()
    _login_failures[key] = (failures + 1, started)


@app.post("/api/auth/setup")
async def create_admin(payload: LoginPayload, request: Request, response: Response):
    origin=request.headers.get("origin")
    if not origin or origin.rstrip("/")!=str(request.base_url).rstrip("/"): raise HTTPException(403,"Initial setup is local-only and requires a same-origin browser request")
    async with SessionLocal() as session:
        if await session.scalar(select(func.count()).select_from(AdminUser)):
            raise HTTPException(409, "Initial admin account already exists")
        username = payload.username.strip()
        user = AdminUser(username=username, password_hash=_hash_password(payload.password), password_changed_at=utcnow())
        session.add(user)
        try: await session.commit()
        except Exception: await session.rollback(); raise HTTPException(409, "Could not create initial admin account")
    await _auth_audit("LOGIN_SUCCESS")
    await _set_session(response, username, request, session_version=user.session_version)
    return {"authenticated": True, "username": username}


@app.post("/api/auth/login")
async def login(payload: LoginPayload, request: Request, response: Response):
    rate_key = _login_limit_key(request)
    _check_login_limit(rate_key)
    submitted_username = payload.username.strip().casefold()
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(func.lower(AdminUser.username) == submitted_username))
    valid = False
    if user and payload.method == "password" and payload.password:
        valid = _verify_password(payload.password, user.password_hash)
    elif user and payload.method == "pin" and payload.pin and user.pin_hash:
        valid = _verify_password(payload.pin, user.pin_hash)
    if not valid:
        _record_login_failure(rate_key)
        await _auth_audit("LOGIN_FAILED", "WARNING")
        raise HTTPException(401, "Invalid username or password")
    _login_failures.pop(rate_key, None)
    if user.mfa_enabled:
        challenge = _mfa_challenge_serializer().dumps({"sub": user.username, "purpose": "mfa-login", "sv": user.session_version})
        response.set_cookie("hex_mfa_challenge", challenge, httponly=True, secure=request.url.scheme == "https", samesite="strict", max_age=300, path="/")
        return {"mfa_required": True}
    await _auth_audit("LOGIN_SUCCESS")
    await _set_session(response, user.username, request, session_version=user.session_version)
    return {"authenticated": True, "username": user.username}


@app.get("/api/auth/accounts", dependencies=[Depends(require_admin)])
async def list_admin_accounts(request: Request):
    current = _username_from_request(request)
    async with SessionLocal() as session:
        users = (await session.scalars(select(AdminUser).order_by(func.lower(AdminUser.username)))).all()
        return {"accounts": [{"username": user.username, "pin_configured": bool(user.pin_hash),
                               "current": user.username.casefold() == current.casefold()} for user in users]}


@app.post("/api/auth/accounts", dependencies=[Depends(require_admin)])
async def create_admin_account(payload: AdminAccountCreatePayload, request: Request):
    current = _username_from_request(request)
    async with SessionLocal() as session:
        existing = await session.scalar(select(AdminUser.id).where(func.lower(AdminUser.username) == payload.username.casefold()))
        if existing:
            raise HTTPException(409, "An account with that username already exists")
        user = AdminUser(username=payload.username, password_hash=_hash_password(payload.password),
                         pin_hash=_hash_password(payload.pin) if payload.pin else None,
                         password_changed_at=utcnow())
        session.add(user)
        try:
            await session.commit()
        except Exception:
            await session.rollback()
            raise HTTPException(409, "Could not create the administrator account") from None
    await _auth_audit("ADMIN_ACCOUNT_CREATED")
    return {"created": True, "username": payload.username, "pin_configured": bool(payload.pin),
            "created_by": current}


@app.post("/api/auth/pin", dependencies=[Depends(require_admin)])
async def update_admin_pin(payload: PinSettingsPayload, request: Request):
    username = _username_from_request(request)
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == username))
        if not user or not _verify_password(payload.current_password, user.password_hash):
            raise HTTPException(401, "Current password is incorrect")
        if user.mfa_enabled:
            from services.mfa import decrypt_secret, verify_totp
            try:
                valid = verify_totp(decrypt_secret(user.totp_secret_encrypted, username), payload.code)
            except Exception:
                valid = False
            if not valid:
                raise HTTPException(422, "Enter a valid authenticator code")
        user.pin_hash = None if payload.clear else _hash_password(payload.pin)
        await session.commit()
    await _auth_audit("LOGIN_PIN_CLEARED" if payload.clear else "LOGIN_PIN_UPDATED")
    return {"pin_configured": not payload.clear}


@app.post("/api/auth/mfa-verify")
async def finish_mfa_login(payload: MfaVerifyPayload, request: Request, response: Response):
    rate_key=_login_limit_key(request)
    _check_login_limit(rate_key)
    origin = request.headers.get("origin", "")
    if not origin or origin.rstrip("/") != str(request.base_url).rstrip("/"):
        raise HTTPException(403, "Cross-origin login verification rejected")
    token = request.cookies.get("hex_mfa_challenge", "")
    try: identity = _mfa_challenge_serializer().loads(token, max_age=300)
    except (BadSignature, SignatureExpired): raise HTTPException(401, "MFA login challenge expired; sign in again")
    if identity.get("purpose") != "mfa-login": raise HTTPException(401, "Invalid MFA login challenge")
    username = identity.get("sub", "")
    from services.mfa import decrypt_secret, hash_recovery_code, verify_totp
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == username))
        if not user or not user.mfa_enabled: raise HTTPException(401, "MFA login is no longer available")
        if identity.get("sv", 0) != user.session_version: raise HTTPException(401, "Admin session was revoked; sign in again")
        valid = False
        try: valid = verify_totp(decrypt_secret(user.totp_secret_encrypted, username), payload.code)
        except Exception: valid = False
        if not valid:
            digest = hash_recovery_code(payload.code, username)
            codes = list(user.recovery_code_hashes or [])
            index = next((i for i, stored in enumerate(codes) if hmac.compare_digest(stored, digest)), None)
            if index is not None:
                codes.pop(index); user.recovery_code_hashes = codes; valid = True
                await session.commit()
        if not valid:
            _record_login_failure(rate_key)
            await _auth_audit("LOGIN_FAILED", "WARNING")
            raise HTTPException(401, "Invalid authenticator or recovery code")
    _login_failures.pop(rate_key,None)
    await _auth_audit("LOGIN_SUCCESS")
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == username))
        session_version = user.session_version if user else 0
    await _set_session(response, username, request, mfa_verified=True, session_version=session_version)
    response.delete_cookie("hex_mfa_challenge", path="/")
    return {"authenticated": True, "username": username}


@app.post("/api/auth/password-reset")
async def reset_admin_password(payload: PasswordResetPayload, request: Request, response: Response):
    rate_key=_login_limit_key(request)
    _check_login_limit(rate_key)
    origin = request.headers.get("origin", "")
    if not origin or origin.rstrip("/") != str(request.base_url).rstrip("/"):
        raise HTTPException(403, "Password recovery must be submitted from this dashboard")
    # Hash the exact field value submitted by the browser. In particular, do not
    # trim or otherwise normalize token_urlsafe characters.
    digest = reset_token_digest(payload.token)
    now = utcnow()
    async with SessionLocal() as session:
        # Lock candidate rows so concurrent requests cannot both consume one token.
        users = (await session.scalars(select(AdminUser).where(
            AdminUser.reset_token_hash != "").with_for_update())).all()
        user = next((u for u in users if u.reset_token_hash and hmac.compare_digest(u.reset_token_hash, digest)), None)
        expires = utc_aware(user.reset_token_expires_at) if user else None
        if (not user or user.reset_token_used_at is not None or not expires or
                expires <= now.astimezone(timezone.utc)):
            _record_login_failure(rate_key)
            raise HTTPException(401, "Reset token is invalid, expired, or already used")
        user.password_hash = _hash_password(payload.new_password)
        user.password_changed_at = now
        user.session_version += 1
        user.reset_token_used_at = now
        user.reset_token_hash = ""
        user.reset_token_expires_at = None
        session.add(SystemLog(level="WARNING", component="auth", message="PASSWORD_RESET"))
        await session.commit()
    _login_failures.pop(rate_key,None)
    response.delete_cookie("hex_session", path="/")
    response.delete_cookie("hex_mfa_challenge", path="/")
    return {"reset": True, "message": "Password reset. Sign in using your new password."}


@app.post("/api/auth/change-password", dependencies=[Depends(require_admin)])
async def change_admin_password(payload: PasswordChangePayload, request: Request):
    username = _username_from_request(request)
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == username))
        if not user or not _verify_password(payload.current_password, user.password_hash):
            raise HTTPException(401, "Current password is incorrect")
        if user.mfa_enabled:
            from services.mfa import decrypt_secret, verify_totp
            try: valid = verify_totp(decrypt_secret(user.totp_secret_encrypted, username), payload.code)
            except Exception: valid = False
            if not valid: raise HTTPException(422, "Enter a valid authenticator code")
        user.password_hash = _hash_password(payload.new_password)
        user.password_changed_at = utcnow()
        user.session_version += 1
        session.add(SystemLog(level="INFO", component="auth", message="PASSWORD_CHANGED"))
        await session.commit()
    return {"changed": True, "message": "Password changed. Sign in again."}


@app.get("/api/security/admin-status", dependencies=[Depends(require_admin)])
async def admin_status():
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).order_by(AdminUser.id))
        if not user:
            return {"admin_exists": False, "mfa_enabled": False, "last_successful_login": None,
                    "failed_login_attempts": 0, "session_count": 0, "password_changed_at": None}
        success = await session.scalar(select(SystemLog.created_at).where(
            SystemLog.component == "auth", SystemLog.message == "LOGIN_SUCCESS").order_by(SystemLog.created_at.desc()).limit(1))
        failures = await session.scalar(select(func.count()).select_from(SystemLog).where(
            SystemLog.component == "auth", SystemLog.message == "LOGIN_FAILED")) or 0
        sessions=await session.scalar(select(func.count()).select_from(AdminSession).where(
            AdminSession.admin_user_id==user.id,AdminSession.session_version==user.session_version,
            AdminSession.revoked_at.is_(None),AdminSession.expires_at>utcnow())) or 0
        return {"admin_exists": True, "mfa_enabled": user.mfa_enabled,
                "last_successful_login": iso_utc(success),
                "failed_login_attempts": failures, "session_count": sessions,
                "password_changed_at": iso_utc(user.password_changed_at)}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    token=request.cookies.get("hex_session","")
    if token:
        try:
            identity=_serializer().loads(token,max_age=60*60*12)
            if identity.get("sid"):
                async with SessionLocal() as session:
                    record=await session.scalar(select(AdminSession).where(AdminSession.session_id==identity["sid"]))
                    if record and record.revoked_at is None:
                        record.revoked_at=utcnow(); await session.commit()
        except Exception:
            pass
    response.delete_cookie("hex_session", path="/")
    response.delete_cookie("hex_mfa_challenge", path="/")
    return {"authenticated": False}


@app.get("/api/auth/me")
async def auth_me(request: Request, _=Depends(require_admin)):
    if request and request.cookies.get("hex_session"):
        try: return {"authenticated": True, "username": _serializer().loads(request.cookies["hex_session"], max_age=60 * 60 * 12).get("sub")}
        except Exception: pass
    return {"authenticated": True, "username": "admin"}


@app.get("/api/mfa/status", dependencies=[Depends(require_admin)])
async def mfa_status(request: Request):
    username = _username_from_request(request)
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == username))
        if not user: raise HTTPException(401, "Admin account no longer exists")
        return {"enabled": user.mfa_enabled, "recovery_codes_remaining": len(user.recovery_code_hashes or [])}


@app.post("/api/mfa/setup", dependencies=[Depends(require_admin)])
async def mfa_setup(request: Request, response: Response):
    username = _username_from_request(request)
    from services.mfa import encrypt_secret, generate_secret, provisioning_uri
    try:
        import qrcode
        from services.mfa import _key
        _key()
    except Exception as exc: raise HTTPException(503, "MFA dependencies or persistent SESSION_SECRET are unavailable") from exc
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == username))
        if not user: raise HTTPException(401, "Admin account no longer exists")
        if user.mfa_enabled: raise HTTPException(409, "MFA is already enabled")
        secret = generate_secret()
        user.totp_pending_encrypted = encrypt_secret(secret, username)
        await session.commit()
    image = qrcode.make(provisioning_uri(secret, username))
    output = BytesIO(); image.save(output, format="PNG")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {"secret": secret, "qr_data_url": "data:image/png;base64," + base64.b64encode(output.getvalue()).decode("ascii")}


@app.post("/api/mfa/confirm", dependencies=[Depends(require_admin)])
async def mfa_confirm(payload: MfaVerifyPayload, request: Request):
    username = _username_from_request(request)
    from services.mfa import decrypt_secret, hash_recovery_code, new_recovery_codes, verify_totp
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == username))
        if not user or not user.totp_pending_encrypted: raise HTTPException(409, "Start MFA setup first")
        try: secret = decrypt_secret(user.totp_pending_encrypted, username)
        except Exception: raise HTTPException(503, "Could not decrypt the pending MFA setup; start again")
        if not verify_totp(secret, payload.code): raise HTTPException(422, "Authenticator code did not verify")
        codes = new_recovery_codes()
        user.totp_secret_encrypted = user.totp_pending_encrypted
        user.totp_pending_encrypted = ""
        user.mfa_enabled = True
        user.recovery_code_hashes = [hash_recovery_code(code, username) for code in codes]
        session.add(SystemLog(level="INFO", component="admin-mfa", message="MFA_ENABLED"))
        await session.commit()
    return {"enabled": True, "recovery_codes": codes}


@app.post("/api/mfa/disable", dependencies=[Depends(require_admin)])
async def mfa_disable(payload: MfaDisablePayload, request: Request):
    username = _username_from_request(request)
    from services.mfa import decrypt_secret, verify_totp
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(AdminUser.username == username))
        if not user or not _verify_password(payload.password, user.password_hash): raise HTTPException(401, "Invalid password")
        if not user.mfa_enabled: raise HTTPException(409, "MFA is already disabled")
        try: valid = verify_totp(decrypt_secret(user.totp_secret_encrypted, username), payload.code)
        except Exception: valid = False
        if not valid: raise HTTPException(422, "Current authenticator code is invalid")
        user.mfa_enabled = False; user.totp_secret_encrypted = ""; user.totp_pending_encrypted = ""; user.recovery_code_hashes = []
        session.add(SystemLog(level="INFO", component="admin-mfa", message="MFA_DISABLED"))
        await session.commit()
    return {"enabled": False}


@app.post("/api/mfa/recovery-codes", dependencies=[Depends(require_admin)])
async def regenerate_recovery_codes(payload: RecoveryCodesPayload, request: Request):
    username=_username_from_request(request)
    from services.mfa import decrypt_secret, hash_recovery_code, new_recovery_codes, verify_totp
    async with SessionLocal() as session:
        user=await session.scalar(select(AdminUser).where(AdminUser.username==username))
        if not user or not _verify_password(payload.password,user.password_hash):
            raise HTTPException(401,"Current password is incorrect")
        if not user.mfa_enabled:
            raise HTTPException(409,"Enable MFA before generating recovery codes")
        try: valid=verify_totp(decrypt_secret(user.totp_secret_encrypted,username),payload.code)
        except Exception: valid=False
        if not valid: raise HTTPException(422,"Enter a valid authenticator code")
        codes=new_recovery_codes()
        user.recovery_code_hashes=[hash_recovery_code(code,username) for code in codes]
        session.add(SystemLog(level="INFO",component="auth",message="RECOVERY_CODES_REGENERATED"))
        await session.commit()
    return {"recovery_codes":codes}


@app.get("/health")
@app.get("/api/health")
async def health():
    database = "online"; active = failed = 0
    try:
        async with SessionLocal() as session:
            await session.execute(select(func.count()).select_from(Source))
            active = await session.scalar(select(func.count()).select_from(Source).where(Source.enabled.is_(True))) or 0
            failed = await session.scalar(select(func.count()).select_from(Source).where(Source.enabled.is_(True), Source.healthy.is_(False))) or 0
    except Exception: database = "offline"
    manager=runtime.get("scheduler").crawlers if runtime.get("scheduler") else None
    redis = "not_configured"
    if get_settings().redis_url:
        try:
            from redis.asyncio import from_url
            client = from_url(get_settings().redis_url, socket_connect_timeout=2, socket_timeout=2)
            await client.ping(); await client.aclose(); redis = "online"
        except Exception: redis = "offline"
    bot = runtime.get("bot")
    settings = get_settings()
    directory_summary={"status":"unavailable","total":0,"humans":0,"eligible":0,"last_sync":None}
    try:
        from services.member_directory import directory_status
        states=[await directory_status(guild.id) for guild in (bot.guilds if bot else [])]
        intent=bool(bot and getattr(getattr(bot,"intents",None),"members",False))
        directory_summary={"status":"ready" if intent and states and all(x["status"]=="ready" for x in states) else ("limited" if states or not intent else "unavailable"),
            "total":sum(x["total"] for x in states),"humans":sum(x["humans"] for x in states),
            "eligible":sum(x["eligible"] for x in states),"last_sync":max((x["last_sync_at"] for x in states if x["last_sync_at"]),default=None)}
    except Exception:
        pass
    return {"status": "healthy" if database == "online" else "degraded", "backend": "online", "frontend": "online", "bot": "online" if bot_state["online"] else "offline", "database": database, "redis": redis, "scheduler": "running" if bot_state["scheduler"] else "stopped", "discord": "connected" if bot and bot.is_ready() else "disconnected", "test_mode": settings.test_mode, "production_mode": not settings.test_mode, "active_sources": active, "sources_active": active, "failed_sources": failed, "active_crawlers": sum(not task.done() for task in manager.tasks.values()) if manager else 0, "uptime_seconds": int(time.monotonic()-bot_state["started_at"]), "ai": await _ai_health(), "internet_search": __import__("services.internet_search", fromlist=["internet_search"]).internet_search.status(),"discord_members":directory_summary}


@app.get("/api/dashboard", dependencies=[Depends(require_admin)])
async def dashboard_data():
    from datetime import timedelta
    now=utc_now();start=now-timedelta(days=6);days=[(start.date()+timedelta(days=i)).isoformat() for i in range(7)]
    async with SessionLocal() as session:
        counts = {}
        for name, model in [("jobs",Job),("news",NewsArticle),("cves",CVE),("threats",Threat),("tools",SecurityTool),("messages",SentMessage),("sources",Source),("crawlers",CrawlerJob)]:
            counts[name] = await session.scalar(select(func.count()).select_from(model)) or 0
        counts["active_sources"] = await session.scalar(select(func.count()).select_from(Source).where(Source.enabled.is_(True))) or 0
        counts["healthy_sources"] = await session.scalar(select(func.count()).select_from(Source).where(Source.enabled.is_(True),Source.healthy.is_(True))) or 0
        counts["failed_sources"] = counts["active_sources"]-counts["healthy_sources"]
        counts["critical_cves"] = await session.scalar(select(func.count()).select_from(CVE).where((CVE.cvss>=8)|(CVE.exploited=="YES"))) or 0
        latest_jobs=(await session.scalars(select(Job).order_by(Job.created_at.desc()).limit(5))).all()
        latest_news=(await session.scalars(select(NewsArticle).order_by(NewsArticle.created_at.desc()).limit(5))).all()
        latest_cves=(await session.scalars(select(CVE).order_by(CVE.created_at.desc()).limit(5))).all()
        latest_logs=(await session.scalars(select(SystemLog).order_by(SystemLog.created_at.desc()).limit(8))).all()
        trends={name:{day:0 for day in days} for name in ["jobs","news","cves","messages"]}
        for name,model in [("jobs",Job),("news",NewsArticle),("cves",CVE),("messages",SentMessage)]:
            stamps=(await session.scalars(select(model.created_at).where(model.created_at>=start))).all()
            for stamp in stamps:
                if stamp: trends[name].setdefault(stamp.date().isoformat(),0);trends[name][stamp.date().isoformat()]+=1
        severity_rows=(await session.scalars(select(CVE.severity))).all();severity={}
        for value in severity_rows:severity[value or "Unknown"]=severity.get(value or "Unknown",0)+1
        crawler_runs=(await session.scalars(select(CrawlerRun.status).where(CrawlerRun.started_at>=start))).all();crawl_results={}
        for value in crawler_runs:crawl_results[value]=crawl_results.get(value,0)+1
    def record(row, title): return {"title":getattr(row,title),"source":getattr(row,"source",""),"url":getattr(row,"source_url",""),"created_at":iso_utc(row.created_at)}
    return {"health":await health(),"counts":counts,"trends":trends,"cve_severity":severity,"crawler_results":crawl_results,"latest_jobs":[record(x,"title") for x in latest_jobs],"latest_news":[record(x,"title") for x in latest_news],"latest_cves":[record(x,"cve_id") for x in latest_cves],"recent_logs":[{"level":x.level,"component":x.component,"message":x.message,"created_at":iso_utc(x.created_at)} for x in latest_logs]}


@app.get("/api/stats", dependencies=[Depends(require_admin)])
async def stats(): return (await dashboard_data())["counts"]


def _safe_source(source: Source):
    from config.secrets import secret_value
    configured = bool(source.auth_mode != "none" and source.auth_env_var and secret_value(source.auth_env_var))
    return {"id":source.id,"name":source.name,"url":source.url,"category":source.category,"source_type":source.source_type,"company_name":source.company_name,"description":source.description,"interval_minutes":source.interval_minutes,"enabled":source.enabled,"priority":source.priority,"tags":source.tags,"parser_type":source.parser_type,"parser_config":source.parser_config,"auth_mode":source.auth_mode,"credential_status":"Configured" if configured else "Not Configured","healthy":source.healthy,"failure_count":source.failure_count,"last_fetch":iso_utc(source.last_fetch),"last_success":iso_utc(source.last_success),"last_failure":iso_utc(source.last_failure),"last_error":source.last_error,"http_status":source.http_status,"rate_limit_status":source.rate_limit_status,"response_time_ms":source.response_time_ms,"items_found":source.items_found,"relevant_items":source.relevant_items,"entry_level_items":source.entry_level_items,"fresh_items":source.fresh_items,"new_items":source.new_items,"duplicate_items":source.duplicate_items,"closed_items":source.closed_items,"baseline_items":source.baseline_items,"parser_status":source.parser_status,"baseline_complete":source.baseline_complete,"last_test_at":iso_utc(source.last_test_at),"last_test_metrics":source.last_test_metrics or {},"last_new_job":iso_utc(source.last_new_job),"last_item_date":iso_utc(source.last_item_date),"timeout_seconds":source.timeout_seconds,"max_response_bytes":source.max_response_bytes,"requests_per_minute":source.requests_per_minute}


@app.get("/api/sources", dependencies=[Depends(require_admin)])
async def sources():
    async with SessionLocal() as session: rows=(await session.scalars(select(Source).order_by(Source.category,Source.name))).all()
    return [_safe_source(row) for row in rows]


async def _source_auth_headers(payload):
    from config.secrets import secret_value
    if payload.auth_mode == "none": return {}
    if not payload.auth_env_var or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,99}",payload.auth_env_var): raise HTTPException(422,"Provide an environment variable name for the source credential; secrets are never stored in the database")
    value=secret_value(payload.auth_env_var)
    if not value: raise HTTPException(422,"Configured credential environment variable is not available")
    return {"Authorization": f"Bearer {value}"} if payload.auth_mode=="bearer" else {"X-API-Key":value}


def _json_list_items(payload):
    if isinstance(payload, list): return payload
    if isinstance(payload, dict):
        return next((payload[key] for key in ("items", "data", "vulnerabilities", "results", "cves") if isinstance(payload.get(key), list)), [])
    return []


def _json_source_preview(item):
    if not isinstance(item, dict): return {"title": str(item)[:300]}
    cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
    metrics = cve.get("metrics", {}) if isinstance(cve, dict) else {}
    metric = next((group[0] for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2") if isinstance((group := metrics.get(key)), list) and group), {})
    cvss = metric.get("cvssData", {}) if isinstance(metric, dict) else {}
    references = [ref.get("url", "") for ref in cve.get("references", [])[:3] if isinstance(ref, dict)] if isinstance(cve.get("references", []), list) else []
    if not references and isinstance(item.get("notes"), str) and item["notes"].strip(): references = [item["notes"].strip()]
    cve_id = cve.get("id") or item.get("cveID") or item.get("id") or ""
    return {"title": str(item.get("vulnerabilityName") or item.get("title") or cve_id or item.get("name") or "CVE record")[:300], "cve_id": cve_id, "cvss": cvss.get("baseScore"), "severity": cvss.get("baseSeverity") or item.get("severity", ""), "published_at": cve.get("published") or item.get("datePublished"), "modified_at": cve.get("lastModified") or item.get("dateModified"), "kev_added_at": item.get("dateAdded"), "due_date": item.get("dueDate"), "source_url": references[0] if references else item.get("url", ""), "references": references, "description": str(item.get("shortDescription") or item.get("description") or item.get("requiredAction") or "")[:1000], "kev": bool(item.get("cveID"))}


def _source_test_params(payload):
    from urllib.parse import urlsplit
    parts = urlsplit(payload.url)
    if (payload.source_type == "json_api" and parts.hostname == "services.nvd.nist.gov"
            and parts.path == "/rest/json/cves/2.0"):
        # The NVD endpoint defaults to a very large response that exceeds our
        # bounded source-test download size. A small page is enough to validate
        # HTTP, JSON parsing, and CVE preview extraction without changing the
        # production collector's date-bounded query.
        return {"resultsPerPage": 50}
    return None


@app.get("/api/jobs/source-matrix", dependencies=[Depends(require_admin)])
async def job_source_matrix():
    """Return safe setup guidance for automated and reference-only sources."""
    from collectors.jobs.source_catalog import source_catalog
    return source_catalog()


@app.get("/api/jobs/preferences", dependencies=[Depends(require_admin)])
async def job_intelligence_preferences():
    settings = get_settings()
    return {"location_priorities": settings.job_location_priority_list,
            "fresh_hours": settings.job_fresh_hours,
            "acceptable_days": settings.job_acceptable_days,
            "high_fit_threshold": settings.high_fit_job_threshold}


@app.post("/api/jobs/preferences", dependencies=[Depends(require_admin)])
async def save_job_intelligence_preferences(payload: JobIntelligencePreferences):
    priorities = [" ".join(item.split())[:80] for item in payload.location_priorities if item.strip()]
    if not priorities:
        raise HTTPException(422, "Provide at least one preferred job location")
    _store_runtime_values({"JOB_LOCATION_PRIORITIES": ",".join(priorities),
                           "JOB_FRESH_HOURS": payload.fresh_hours,
                           "JOB_ACCEPTABLE_DAYS": payload.acceptable_days,
                           "HIGH_FIT_JOB_THRESHOLD": payload.high_fit_threshold},
                          message="Unable to save Jobs Intelligence preferences.")
    return {"saved": True, "location_priorities": priorities, "fresh_hours": payload.fresh_hours,
            "acceptable_days": payload.acceptable_days, "high_fit_threshold": payload.high_fit_threshold}


@app.post("/api/jobs/discover-ats", dependencies=[Depends(require_admin)])
async def discover_company_ats(payload: ATSDiscoveryPayload):
    from urllib.parse import urlsplit
    from collectors.jobs.discovery import discover_ats_links
    validate_public_url(payload.company_domain)
    try:
        await public_addresses(urlsplit(payload.company_domain).hostname)
    except Exception:
        raise HTTPException(422, "Company hostname did not resolve to a public IP") from None
    collector = Collector()
    try:
        response = await collector.get(payload.company_domain, max_bytes=1_000_000, allow_error_status=True,
                                       headers={"Accept": "text/html"})
        if not response.is_success:
            return {"http_status": response.status_code, "candidates": [], "warning": f"Company page returned HTTP {response.status_code}"}
        candidates = discover_ats_links(response.text, payload.company_domain)
        return {"http_status": response.status_code, "candidates": candidates,
                "warning": "Review and test a detected board before saving it disabled." if candidates else "No supported ATS link was found on this one public page."}
    finally:
        await collector.close()

@app.post("/api/sources/test", dependencies=[Depends(require_admin)])
async def test_source_payload(payload: SourcePayload):
    from urllib.parse import urlsplit
    if payload.category=="jobs" and payload.source_type in {"lever","greenhouse","ashby"} and not payload.company_name.strip():
        raise HTTPException(422,"Enter the company name so job previews do not infer it from the source label")
    if payload.category == "jobs" and payload.auth_mode != "none":
        raise HTTPException(422,"Public job board adapters do not accept credentials")
    from collectors.jobs.source_catalog import reference_source_type
    if payload.category == "jobs" and reference_source_type(payload.source_type):
        validate_public_url(payload.url)
        return {"http_status": None, "response_time_ms": 0, "content_type": "reference", "title": payload.name,
                "items_discovered": 0, "relevant_items": 0, "fresh_relevant_items": 0,
                "parser_result": "REFERENCE_ONLY", "parse_errors": 0, "previews": [],
                "preview_quality": {"status": "REFERENCE_ONLY", "fields_per_item": "manual", "fields_checked": 0, "items_checked": 0},
                "error": "Automated collection is disabled for this source; save public listings manually.",
                "saved": False, "enabled": False}
    validate_public_url(payload.url)
    try:await public_addresses(urlsplit(payload.url).hostname)
    except Exception:raise HTTPException(422,"Source hostname did not resolve to a public IP")
    if payload.category == "jobs":
        from types import SimpleNamespace
        from collectors.jobs.adapters import JobSourceAdapter
        from collectors.jobs.normalize import is_cyber_job
        collector=Collector(); collector.client.timeout=__import__("httpx").Timeout(payload.timeout_seconds)
        try:
            result=await JobSourceAdapter().fetch(collector,SimpleNamespace(**payload.model_dump()))
            previews=[]
            # Put cyber-relevant results first so an administrator can assess fit,
            # then fill the preview with other normalized entries when available.
            from collectors.jobs.normalize import is_cyber_job
            freshness_order = {"FRESH": 3, "ACCEPTABLE": 2, "UNKNOWN": 1, "OLD": 0}
            relevant = [item for item in result.jobs if is_cyber_job(item)]
            relevant.sort(key=lambda item: (item.get("match_score", 0), freshness_order.get(item.get("freshness_status"), 0)), reverse=True)
            preview_items = relevant
            preview_items.extend(item for item in result.jobs if not is_cyber_job(item))
            for item in preview_items[:3]:
                preview = {key:(iso_utc(value) if isinstance(value,datetime) else value)
                           for key,value in item.items() if key in {"title","company","location","experience","employment_type","work_mode","salary","published_at","published_at_date_only","apply_url","source","freshness_status","listing_status","match_score","score_breakdown","skills"}}
                if item.get("published_at_date_only") and isinstance(item.get("published_at"),datetime):
                    preview["published_at"] = item["published_at"].date().isoformat()
                previews.append(preview)
            quality_fields = ("title", "company", "location", "experience", "employment_type", "published_at", "apply_url")
            quality_values = [sum(bool(item.get(field)) and item.get(field) != "Not publicly available" for field in quality_fields) for item in previews]
            quality_average = (sum(quality_values) / len(quality_values)) if quality_values else 0
            quality = {"status": "GOOD" if quality_average >= 6 else "PARTIAL" if quality_average >= 4 else "LOW" if previews else "UNKNOWN",
                       "fields_per_item": f"{quality_average:.1f}/{len(quality_fields)}", "fields_checked": len(quality_fields),
                       "items_checked": len(previews)}
            return {"http_status":result.http_status or None,"response_time_ms":result.response_time_ms,
                    "content_type":"application/json" if payload.source_type in {"lever","greenhouse","ashby","remote_ok","public_job_api"} else "text/html / feed",
                    "title":payload.name,"items_discovered":len(result.jobs),"relevant_items":sum(is_cyber_job(x) for x in result.jobs),
                    "entry_level_items":sum(is_cyber_job(x) and x.get("is_entry_level") for x in result.jobs),
                    "fresh_relevant_items":sum(is_cyber_job(x) and x.get("freshness_status")=="FRESH" for x in result.jobs),
                    "acceptable_relevant_items":sum(is_cyber_job(x) and x.get("freshness_status")=="ACCEPTABLE" for x in result.jobs),
                    "old_relevant_items":sum(is_cyber_job(x) and x.get("freshness_status")=="OLD" for x in result.jobs),
                    "parser_result":result.parser,"parse_errors":result.parse_errors,"rate_limit":result.rate_limit,"previews":previews,"preview_quality":quality,
                    "error":result.error or None,"saved":False,"enabled":False}
        finally:
            await collector.close()
    headers=await _source_auth_headers(payload); start=time.monotonic(); collector=Collector();collector.client.timeout=__import__("httpx").Timeout(payload.timeout_seconds)
    try:
        response=await collector.get(payload.url,max_bytes=payload.max_response_bytes,allow_error_status=True,headers=headers,params=_source_test_params(payload))
        content_type=response.headers.get("content-type",""); title=""; item_count=0; result="Fetched"
        if not response.is_success:
            return {"http_status":response.status_code,"response_time_ms":int((time.monotonic()-start)*1000),"content_type":content_type,"title":"","items_discovered":0,"parser_result":"HTTP error response","last_updated":response.headers.get("last-modified"),"error":f"HTTP {response.status_code}"}
        if "xml" in content_type or payload.parser_type=="feed":
            import feedparser
            parsed=feedparser.parse(response.content); title=parsed.feed.get("title",""); item_count=len(parsed.entries); result="RSS/Atom parsed" if not parsed.bozo else "Feed fetched with parse warnings"
            previews=[]
            for entry in parsed.entries[:3]:
                published = entry.get("published") or entry.get("updated") or ""
                if entry.get("published_parsed"):
                    try:
                        published = iso_utc(datetime(*entry.published_parsed[:6], tzinfo=timezone.utc))
                    except (TypeError, ValueError):
                        pass
                previews.append({"title": str(entry.get("title") or "")[:300],
                                 "source": title or payload.name,
                                 "source_url": str(entry.get("link") or ""),
                                 "published_at": published})
            quality_values=[sum(bool(item.get(field)) for field in ("title","source_url","source","published_at")) for item in previews]
            quality_average=(sum(quality_values)/len(quality_values)) if quality_values else 0
            preview_quality={"status":"GOOD" if quality_average >= 3 else "PARTIAL" if quality_average >= 2 else "LOW" if previews else "UNKNOWN",
                             "fields_per_item":f"{quality_average:.1f}/4" if previews else "—","fields_checked":4,"items_checked":len(previews)}
        elif "html" in content_type:
            from bs4 import BeautifulSoup
            soup=BeautifulSoup(response.text,"html.parser"); title=soup.title.get_text(" ",strip=True) if soup.title else ""; item_count=len(soup.select("a[href]")); result="HTML parsed"
        elif "json" in content_type:
            parsed=response.json(); json_items=_json_list_items(parsed); item_count=len(json_items); previews=[_json_source_preview(item) for item in json_items[:3]]; preview_quality={"status":"GOOD" if previews else "UNKNOWN","fields_per_item":"JSON records" if previews else "—","fields_checked":0,"items_checked":len(previews)}; result="JSON parsed"
        return {"http_status":response.status_code,"response_time_ms":int((time.monotonic()-start)*1000),"content_type":content_type,"title":title,"items_discovered":item_count,"parser_result":result,"previews":locals().get("previews",[]),"preview_quality":locals().get("preview_quality",{"status":"UNKNOWN","fields_per_item":"—","fields_checked":0,"items_checked":0}),"last_updated":response.headers.get("last-modified"),"error":None}
    except Exception as exc: return {"http_status":None,"response_time_ms":int((time.monotonic()-start)*1000),"content_type":"","title":"","items_discovered":0,"parser_result":"Failed","error":type(exc).__name__}
    finally: await collector.close()


@app.post("/api/sources", dependencies=[Depends(require_admin)])
async def add_source(payload: SourcePayload):
    if payload.category=="jobs" and payload.source_type in {"lever","greenhouse","ashby"} and not payload.company_name.strip():
        raise HTTPException(422,"Company name is required for this public job board type")
    if payload.category == "jobs" and payload.auth_mode != "none":
        raise HTTPException(422,"Public job board adapters do not accept credentials")
    validate_public_url(payload.url)
    if payload.auth_mode!="none": await _source_auth_headers(payload)
    name=payload.name.strip()
    async with SessionLocal() as session:
        if await session.scalar(select(Source).where(func.lower(Source.name)==name.lower())): raise HTTPException(409,"Source name already exists")
        metrics = payload.test_metrics or {}
        row=Source(name=name,url=payload.url,category=payload.category,source_type=payload.source_type,company_name=payload.company_name,parser_config=payload.parser_config,description=payload.description,interval_minutes=payload.interval_minutes,enabled=False,priority=payload.priority,tags=payload.tags,parser_type=payload.parser_type,auth_mode=payload.auth_mode,auth_env_var=payload.auth_env_var,timeout_seconds=payload.timeout_seconds,max_response_bytes=payload.max_response_bytes,requests_per_minute=payload.requests_per_minute)
        if metrics:
            row.last_test_at=utcnow(); row.last_test_metrics=metrics; row.parser_status=str(metrics.get("parser_result") or "UNKNOWN")[:40]
        session.add(row); await session.commit(); await session.refresh(row)
        return _safe_source(row)


@app.put("/api/sources/{source_id}", dependencies=[Depends(require_admin)])
async def edit_source(source_id:int,payload:SourcePayload):
    validate_public_url(payload.url)
    async with SessionLocal() as session:
        row=await session.get(Source,source_id)
        if not row: raise HTTPException(404,"Source not found")
        for key,value in payload.model_dump().items():
            if key != "enabled":
                setattr(row,key,value)
        await session.commit(); await session.refresh(row); return _safe_source(row)


@app.delete("/api/sources/{source_id}", dependencies=[Depends(require_admin)])
async def delete_source(source_id:int):
    async with SessionLocal() as session:
        row=await session.get(Source,source_id)
        if not row: raise HTTPException(404,"Source not found")
        await session.delete(row); await session.commit()
    return {"deleted":True}


@app.post("/api/sources/{source_id}/enabled", dependencies=[Depends(require_admin)])
async def set_source_enabled(source_id:int,enabled:bool):
    async with SessionLocal() as session:
        row=await session.get(Source,source_id)
        if not row: raise HTTPException(404,"Source not found")
        from collectors.jobs.source_catalog import reference_source_type
        if enabled and row.category == "jobs" and reference_source_type(row.source_type):
            raise HTTPException(409,"Reference-only sources cannot be enabled for automated collection")
        if enabled and row.category == "jobs" and (not row.last_test_at or (row.last_test_metrics or {}).get("error")):
            raise HTTPException(409,"Test this source successfully before enabling it")
        row.enabled=enabled; await session.commit(); return {"name":row.name,"enabled":row.enabled}


@app.post("/api/sources/{source_id}/interval", dependencies=[Depends(require_admin)])
async def set_source_interval(source_id:int,minutes:int):
    if not 5<=minutes<=1440: raise HTTPException(422,"Interval must be between 5 and 1440 minutes")
    async with SessionLocal() as session:
        row=await session.get(Source,source_id)
        if not row: raise HTTPException(404,"Source not found")
        row.interval_minutes=minutes; category=row.category; await session.commit()
    scheduler=runtime.get("scheduler")
    if scheduler:
        try: scheduler.scheduler.reschedule_job(category,trigger="interval",minutes=minutes)
        except Exception: pass
    return {"interval_minutes":minutes}


@app.post("/api/refresh/{category}", dependencies=[Depends(require_admin)])
async def refresh(category:str):
    scheduler=runtime.get("scheduler")
    if not scheduler: raise HTTPException(503,"Scheduler is not ready")
    if category not in {"jobs","news","cve","technology","threat","custom"}: raise HTTPException(422,"Unknown category")
    await scheduler.run(category); return {"status":"completed","category":category}


@app.post("/api/sources/{source_id}/test", dependencies=[Depends(require_admin)])
async def test_source_saved(source_id:int):
    async with SessionLocal() as session: source=await session.get(Source,source_id)
    if not source: raise HTTPException(404,"Source not found")
    payload=SourcePayload(name=source.name,url=source.url,source_type=source.source_type,category=source.category,description=source.description,interval_minutes=source.interval_minutes,enabled=source.enabled,company_name=source.company_name,parser_config=source.parser_config or {},priority=source.priority,tags=source.tags,parser_type=source.parser_type,auth_mode=source.auth_mode,auth_env_var=source.auth_env_var,timeout_seconds=source.timeout_seconds,max_response_bytes=source.max_response_bytes,requests_per_minute=source.requests_per_minute)
    result = await test_source_payload(payload)
    metrics = {k: result.get(k) for k in ("http_status","response_time_ms","items_discovered","relevant_items","entry_level_items","fresh_relevant_items","acceptable_relevant_items","old_relevant_items","rate_limit","parser_result","parse_errors","previews","preview_quality","error")}
    async with SessionLocal() as session:
        source=await session.get(Source,source_id)
        source.last_test_at=utcnow(); source.last_test_metrics=metrics
        source.parser_status=str(result.get("parser_result") or "UNKNOWN")[:40]
        if not source.enabled:
            source.http_status=result.get("http_status")
            source.response_time_ms=result.get("response_time_ms")
            source.items_found=result.get("items_discovered") or 0
            source.relevant_items=result.get("relevant_items") or 0
            source.entry_level_items=result.get("entry_level_items") or 0
            source.fresh_items=result.get("fresh_relevant_items") or 0
            source.rate_limit_status=str(result.get("rate_limit") or "UNKNOWN")[:80]
        await session.commit()
    return result


def _crawler_json(row):
    return {k:getattr(row,k) for k in ("id","name","start_url","allowed_domain","allowed_paths","blocked_paths","max_depth","max_pages","request_delay_ms","interval_minutes","user_agent","follow_links","mode","selectors","enabled","status","next_run","channel_id","created_at") if hasattr(row,k)}


@app.get("/api/crawlers", dependencies=[Depends(require_admin)])
async def crawlers():
    async with SessionLocal() as session: rows=(await session.scalars(select(CrawlerJob).order_by(CrawlerJob.name))).all()
    result=[]
    async with SessionLocal() as session:
        for row in rows:
            run=await session.scalar(select(CrawlerRun).where(CrawlerRun.crawler_id==row.id).order_by(CrawlerRun.started_at.desc()).limit(1))
            item=_crawler_json(row); item["latest_run"]={k:getattr(run,k) for k in ("id","status","current_url","pages_processed","pages_remaining","new_items","duplicate_items","errors","started_at","finished_at","last_error")} if run else None; result.append(item)
    return result


@app.post("/api/crawlers", dependencies=[Depends(require_admin)])
async def create_crawler(payload:CrawlerPayload):
    from urllib.parse import urlsplit
    validate_public_url(payload.start_url); host=urlsplit(payload.start_url).hostname
    await public_addresses(host)
    allowed=payload.allowed_domain.strip().lower() or host
    if allowed!=host and not host.endswith("."+allowed): raise HTTPException(422,"Allowed domain must include the starting host")
    if payload.channel_id and not payload.channel_id.isdigit():raise HTTPException(422,"Discord channel ID must be numeric")
    for path in payload.allowed_paths+payload.blocked_paths:
        if not path.startswith("/") or len(path)>300: raise HTTPException(422,"Crawler paths must be absolute URL paths")
    async with SessionLocal() as session:
        row=CrawlerJob(**payload.model_dump(exclude={"allowed_domain"}),allowed_domain=allowed)
        session.add(row); await session.commit(); await session.refresh(row); return _crawler_json(row)


@app.put("/api/crawlers/{crawler_id}", dependencies=[Depends(require_admin)])
async def update_crawler(crawler_id:int,payload:CrawlerPayload):
    from urllib.parse import urlsplit
    validate_public_url(payload.start_url); host=urlsplit(payload.start_url).hostname; await public_addresses(host)
    allowed=payload.allowed_domain.strip().lower() or host
    if allowed!=host and not host.endswith("."+allowed): raise HTTPException(422,"Allowed domain must include the starting host")
    if payload.channel_id and not payload.channel_id.isdigit():raise HTTPException(422,"Discord channel ID must be numeric")
    async with SessionLocal() as session:
        row=await session.get(CrawlerJob,crawler_id)
        if not row: raise HTTPException(404,"Crawler not found")
        for key,value in payload.model_dump(exclude={"allowed_domain"}).items(): setattr(row,key,value)
        row.allowed_domain=allowed; await session.commit(); return _crawler_json(row)


@app.delete("/api/crawlers/{crawler_id}", dependencies=[Depends(require_admin)])
async def delete_crawler(crawler_id:int):
    manager=runtime.get("scheduler").crawlers if runtime.get("scheduler") else None
    if manager: await manager.stop(crawler_id)
    async with SessionLocal() as session:
        row=await session.get(CrawlerJob,crawler_id)
        if not row: raise HTTPException(404,"Crawler not found")
        await session.delete(row); await session.commit()
    return {"deleted":True}


@app.post("/api/crawlers/{crawler_id}/start", dependencies=[Depends(require_admin)])
@app.post("/api/crawlers/{crawler_id}/run", dependencies=[Depends(require_admin)])
async def start_crawler(crawler_id:int):
    async with SessionLocal() as session:
        row=await session.get(CrawlerJob,crawler_id)
        if not row: raise HTTPException(404,"Crawler not found")
        row.status="running"; await session.commit()
    manager=runtime.get("scheduler").crawlers if runtime.get("scheduler") else None
    if not manager: raise HTTPException(503,"Scheduler is not ready")
    if not await manager.start(crawler_id): raise HTTPException(409,"Crawler is already running")
    return {"status":"running","crawler_id":crawler_id}


@app.post("/api/crawlers/{crawler_id}/stop", dependencies=[Depends(require_admin)])
async def stop_crawler(crawler_id:int):
    manager=runtime.get("scheduler").crawlers if runtime.get("scheduler") else None
    if manager: await manager.stop(crawler_id)
    async with SessionLocal() as session:
        row=await session.get(CrawlerJob,crawler_id)
        if row:row.status="stopped";await session.commit()
    return {"status":"stopped"}


@app.post("/api/crawlers/{crawler_id}/pause", dependencies=[Depends(require_admin)])
async def pause_crawler(crawler_id:int):
    manager=runtime.get("scheduler").crawlers if runtime.get("scheduler") else None
    if manager: manager.pause(crawler_id)
    async with SessionLocal() as session:
        row=await session.get(CrawlerJob,crawler_id)
        if row: row.status="paused"; await session.commit()
    return {"status":"paused"}


@app.post("/api/crawlers/{crawler_id}/resume", dependencies=[Depends(require_admin)])
async def resume_crawler(crawler_id:int):
    manager=runtime.get("scheduler").crawlers if runtime.get("scheduler") else None
    if manager: manager.resume(crawler_id)
    async with SessionLocal() as session:
        row=await session.get(CrawlerJob,crawler_id)
        if row: row.status="running"; await session.commit()
    return {"status":"running"}


@app.get("/api/crawlers/{crawler_id}/events", dependencies=[Depends(require_admin)])
async def crawler_events(crawler_id:int):
    async def event_stream():
        last=None
        while True:
            async with SessionLocal() as session:
                run=await session.scalar(select(CrawlerRun).where(CrawlerRun.crawler_id==crawler_id).order_by(CrawlerRun.started_at.desc()).limit(1))
                if not run: yield "event: status\ndata: {}\n\n"; return
                obj={"status":run.status,"current_url":run.current_url,"pages_processed":run.pages_processed,"pages_remaining":run.pages_remaining,"new_items":run.new_items,"duplicate_items":run.duplicate_items,"errors":run.errors,"updated_at":iso_utc(run.updated_at)}
            serialized=json.dumps(obj)
            if serialized!=last: yield f"event: status\ndata: {serialized}\n\n"; last=serialized
            if obj["status"] not in {"running","paused"}: return
            await asyncio.sleep(1)
    return StreamingResponse(event_stream(),media_type="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


@app.get("/api/crawlers/{crawler_id}/pages", dependencies=[Depends(require_admin)])
async def crawler_pages(crawler_id:int):
    async with SessionLocal() as session: rows=(await session.scalars(select(CrawlerPage).where(CrawlerPage.crawler_id==crawler_id).order_by(CrawlerPage.fetched_at.desc()).limit(100))).all()
    return [{"url":x.url,"title":x.title,"summary":x.summary,"content_hash":x.content_hash,"fetched_at":iso_utc(x.fetched_at)} for x in rows]


@app.get("/api/scheduler", dependencies=[Depends(require_admin)])
async def scheduler_jobs():
    scheduler=runtime.get("scheduler")
    if not scheduler: return []
    async with SessionLocal() as session: saved={x.task:x for x in (await session.scalars(select(SchedulerConfig))).all()}
    return [{"id":job.id,"task":job.name or job.id,"next_run":iso_utc(job.next_run_time),"trigger":str(job.trigger),"enabled":job.next_run_time is not None,"last_run":iso_utc(saved[job.id].last_run) if job.id in saved else None,"last_result":saved[job.id].last_result if job.id in saved else "unknown","interval_minutes":saved[job.id].interval_minutes if job.id in saved else None} for job in scheduler.scheduler.get_jobs()]


@app.post("/api/scheduler/{task_id}/run",dependencies=[Depends(require_admin)])
async def scheduler_run_now(task_id:str):
    scheduler=runtime.get("scheduler")
    if not scheduler: raise HTTPException(503,"Scheduler is not ready")
    if task_id in {"news","cve","jobs","technology","threat","custom"}: asyncio.create_task(scheduler.run(task_id)); return {"started":True}
    try:scheduler.scheduler.modify_job(task_id,next_run_time=utc_now());return {"started":True}
    except Exception:raise HTTPException(404,"Scheduled task not found")


@app.post("/api/scheduler/{task_id}/enabled",dependencies=[Depends(require_admin)])
async def scheduler_enabled(task_id:str,enabled:bool):
    scheduler=runtime.get("scheduler")
    if not scheduler: raise HTTPException(503,"Scheduler is not ready")
    job=scheduler.scheduler.get_job(task_id)
    if not job: raise HTTPException(404,"Scheduled task not found")
    try:scheduler.scheduler.resume_job(task_id) if enabled else scheduler.scheduler.pause_job(task_id)
    except Exception as exc:raise HTTPException(422,type(exc).__name__)
    async with SessionLocal() as session:
        row=await session.scalar(select(SchedulerConfig).where(SchedulerConfig.task==task_id))
        if not row:row=SchedulerConfig(task=task_id,interval_minutes=30,enabled=enabled);session.add(row)
        row.enabled=enabled;await session.commit()
    return {"task":task_id,"enabled":enabled}


@app.post("/api/scheduler/{task_id}/interval",dependencies=[Depends(require_admin)])
async def scheduler_interval(task_id:str,minutes:int):
    if not 5<=minutes<=10080:raise HTTPException(422,"Interval must be between 5 and 10080 minutes")
    scheduler=runtime.get("scheduler")
    if not scheduler:raise HTTPException(503,"Scheduler is not ready")
    try:scheduler.scheduler.reschedule_job(task_id,trigger="interval",minutes=minutes)
    except Exception:raise HTTPException(404,"Task does not support an interval")
    async with SessionLocal() as session:
        row=await session.scalar(select(SchedulerConfig).where(SchedulerConfig.task==task_id))
        if not row:row=SchedulerConfig(task=task_id,interval_minutes=minutes);session.add(row)
        row.interval_minutes=minutes;await session.commit()
    return {"task":task_id,"interval_minutes":minutes}


@app.get("/api/alerts", dependencies=[Depends(require_admin)])
async def alerts(limit:int=50):
    async with SessionLocal() as session: rows=(await session.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(min(200,max(1,limit))))).all()
    return [{"id":x.id,"category":x.category,"title":x.title,"source":x.source,"source_url":x.source_url,"channel_id":x.channel_id,"channel_name":x.channel_name,"message_id":x.message_id,"guild_id":(await session.scalar(select(SentMessage.guild_id).where(SentMessage.item_type=="jobs",SentMessage.item_id==str(x.id)).order_by(SentMessage.created_at.desc()).limit(1))) or "","status":x.status,"error":x.error,"created_at":iso_utc(x.created_at)} for x in rows]


@app.get("/api/logs", dependencies=[Depends(require_admin)])
async def logs(level:str="",search:str="",limit:int=100):
    query=select(SystemLog).order_by(SystemLog.created_at.desc()).limit(min(500,max(1,limit)))
    if level: query=query.where(SystemLog.level==level.upper())
    if search: query=query.where(SystemLog.message.ilike(f"%{search[:100]}%"))
    async with SessionLocal() as session: rows=(await session.scalars(query)).all()
    return [{"level":x.level,"component":x.component,"message":x.message,"status":x.status,"created_at":iso_utc(x.created_at)} for x in rows]


@app.get("/api/discord/status", dependencies=[Depends(require_admin)])
async def discord_status():
    bot=runtime.get("bot")
    settings=get_settings()
    async with SessionLocal() as session:
        mappings=(await session.scalars(select(ChannelConfig))).all()
        latest_alert=await session.scalar(select(Alert).order_by(Alert.created_at.desc()).limit(1))
    missing_permissions=0
    if bot and bot.is_ready():
        for mapping in mappings:
            channel=bot.get_channel(int(mapping.channel_id)) if mapping.channel_id.isdigit() else None
            guild=getattr(channel,"guild",None); member=getattr(guild,"me",None)
            if not channel or not member:
                missing_permissions+=1
                continue
            perms=channel.permissions_for(member)
            if not all((perms.view_channel,perms.send_messages,perms.embed_links,perms.read_message_history)):
                missing_permissions+=1
    from config.ai import options
    ai=options()
    intents=getattr(bot,"intents",None)
    content_enabled=bool(intents and getattr(intents,"message_content",False))
    mention_intent="ENABLED" if content_enabled else "DISABLED"
    guilds_enabled=bool(intents and getattr(intents,"guilds",False))
    messages_enabled=bool(intents and getattr(intents,"messages",False))
    mention_ready=bool(bot_state.get("mention_chat_verified",False))
    from services.member_directory import directory_status
    directory_rows=[]
    if bot:
        for guild in bot.guilds:
            directory_rows.append({"guild_id":str(guild.id),"guild_name":str(guild.name),**(await directory_status(guild.id))})
    member_intent_enabled=bool(intents and getattr(intents,"members",False))
    return {"connected":bool(bot and bot.is_ready()),"status":"CONNECTED" if bot and bot.is_ready() else ("DISCONNECTED" if not bot else "DEGRADED"),"token_configured":bool(settings.discord_token),"username":str(bot.user) if bot and bot.user else None,"bot_id":str(bot.user.id) if bot and bot.user else None,"guild_count":len(bot.guilds) if bot else 0,"latency_ms":round(bot.latency*1000,1) if bot and bot.is_ready() else None,"guilds":[{"id":str(g.id),"name":g.name,"member_count":g.member_count} for g in bot.guilds] if bot else [],"mapped_channels":len(mappings),"missing_permissions":missing_permissions,"test_mode":settings.test_mode,"mention_chat_enabled":ai.mention_chat,"mention_chat_ready":"READY" if mention_ready else "NOT VERIFIED","mention_listener_registered":bool(bot_state.get("mention_listener_registered",False)),"guilds_intent_enabled":guilds_enabled,"messages_intent_enabled":messages_enabled,"message_content_intent_enabled":content_enabled,"message_content_intent_status":mention_intent,"message_content_intent_required":False,"guild_members_intent_enabled":member_intent_enabled,"member_directory_status":"ready" if member_intent_enabled and directory_rows and all(x["status"]=="ready" for x in directory_rows) else ("limited" if any(x["status"]=="limited" for x in directory_rows) or not member_intent_enabled else "unavailable"),"member_directories":directory_rows,"last_message":iso_utc(latest_alert.created_at) if latest_alert else None,"last_error":(latest_alert.error or None) if latest_alert and latest_alert.status=="failed" else None}


@app.post("/api/discord/test", dependencies=[Depends(require_admin)])
async def test_discord(payload:DiscordSetupPayload):
    token=payload.token or get_settings().discord_token
    if not token: raise HTTPException(422,"Paste the Discord bot token first")
    identity=await _verify_discord_token(token)
    log.info("Discord token validation successful")
    bot=runtime.get("bot")
    connected=bool(bot and bot.is_ready() and bot.user and str(bot.user.id)==identity["id"])
    if not connected:
        controller=runtime.get("controller")
        if controller:
            await controller.start_bot(token)
            bot=runtime.get("bot")
            if bot:
                try:
                    await asyncio.wait_for(bot.wait_until_ready(),timeout=20)
                except asyncio.TimeoutError:
                    raise HTTPException(504,"Discord gateway connection timed out while loading servers") from None
                connected=bool(bot.is_ready() and bot.user and str(bot.user.id)==identity["id"])
                if connected:
                    log.info("Discord gateway connected")
                    log.info("Guild discovery complete count=%d",len(bot.guilds))
    return {**identity,"connected":connected,"guilds":[{"id":str(g.id),"name":g.name,"member_count":g.member_count} for g in bot.guilds] if connected else []}


@app.post("/api/discord/config", dependencies=[Depends(require_admin)])
async def save_discord_config(payload:DiscordSetupPayload):
    previous_settings=get_settings()
    token=payload.token or previous_settings.discord_token
    if not token: raise HTTPException(422,"Paste and test the Discord bot token first")
    bot_info=await _verify_discord_token(token)
    log.info("Discord token validation successful")
    allowed={"JOB_CHANNEL_ID","NEWS_CHANNEL_ID","CVE_CHANNEL_ID","ZERO_DAY_CHANNEL_ID","TECH_CHANNEL_ID","THREAT_CHANNEL_ID","GITHUB_TOOLS_CHANNEL_ID","RESEARCH_CHANNEL_ID","DIGEST_CHANNEL_ID","STATUS_CHANNEL_ID","TEST_CHANNEL_ID"}
    unknown=set(payload.channels)-allowed
    if unknown: raise HTTPException(422,"Unsupported channel mapping")
    for channel_id in payload.channels.values():
        if channel_id and not channel_id.isdigit(): raise HTTPException(422,"Discord channel IDs must be numeric")
    if payload.guild_id and not payload.guild_id.isdigit(): raise HTTPException(422,"Discord server IDs must be numeric")
    bot=runtime.get("bot")
    selected_guild=bot.get_guild(int(payload.guild_id)) if bot and payload.guild_id else None
    if payload.guild_id and not selected_guild: raise HTTPException(422,"Selected server is not available to the connected bot")
    if selected_guild:
        for key,channel_id in payload.channels.items():
            if channel_id:
                channel=selected_guild.get_channel(int(channel_id))
                if not channel: raise HTTPException(422,f"Selected channel for {key} is not in the selected server")
                perms=channel.permissions_for(selected_guild.me) if selected_guild.me else None
                if not perms or not (perms.view_channel and perms.send_messages and perms.embed_links and perms.read_message_history):
                    raise HTTPException(422,f"Selected channel for {key} must grant View Channel, Send Messages, Embed Links and Read Message History")
    values={"DISCORD_TOKEN":token}
    if not previous_settings.discord_token:
        values["TEST_MODE"]="true"
    _store_runtime_values(values, message="Unable to save Discord configuration.")
    log.info("Discord token persisted")
    if payload.guild_id:
        try:
            async with SessionLocal() as session:
                guild=await session.scalar(select(Guild).where(Guild.discord_id==payload.guild_id))
                if not guild: session.add(Guild(discord_id=payload.guild_id,name=selected_guild.name))
                else: guild.name=selected_guild.name
                for key, channel_id in payload.channels.items():
                    row=await session.scalar(select(ChannelConfig).where(ChannelConfig.guild_id==payload.guild_id,ChannelConfig.name==key))
                    if not channel_id:
                        if row: await session.delete(row)
                    elif row:
                        row.channel_id=channel_id
                    else:
                        session.add(ChannelConfig(guild_id=payload.guild_id,name=key,channel_id=channel_id))
                await session.commit()
        except Exception as exc:
            log.error("Discord channel configuration save failed (%s)", type(exc).__name__)
            raise HTTPException(500,"Unable to save Discord configuration.") from None
    controller=runtime.get("controller")
    connected=False
    if controller:
        await controller.start_bot(token)
        bot=runtime.get("bot")
        if bot:
            try:
                await asyncio.wait_for(bot.wait_until_ready(),timeout=20)
            except asyncio.TimeoutError:
                log.warning("Discord gateway readiness timed out after credential save")
            else:
                connected=bool(bot.is_ready() and bot.user and str(bot.user.id)==bot_info["id"])
                if connected:
                    log.info("Discord gateway connected")
                    log.info("Guild discovery complete count=%d",len(bot.guilds))
    return {"success":True,"token_configured":True,"connected":connected}


@app.delete("/api/discord/token", dependencies=[Depends(require_admin)])
async def clear_discord_token():
    _store_runtime_values({"DISCORD_TOKEN":""}, message="Unable to save Discord configuration.")
    controller=runtime.get("controller")
    if controller:
        try:
            await controller.stop_bot()
        except Exception as exc:
            log.error("Discord service stop failed while clearing credentials (%s)", type(exc).__name__)
            raise HTTPException(500,"Unable to save Discord configuration.") from None
    return {"token_configured":False,"connected":False}


@app.post("/api/ai/config",dependencies=[Depends(require_admin)])
async def save_ai_config(payload:AISettingsPayload):
    from config.ai import options, KEYS
    cfg=options(); cfg.provider=payload.provider
    if payload.provider!='disabled':
        entry=cfg.providers[payload.provider]; entry.enabled=True
        if payload.model: entry.model=payload.model
        if payload.provider in ('ollama','custom'): entry.base_url=payload.base_url
    values={'AI_OPTIONS':cfg.model_dump(),'AI_PROVIDER':payload.provider,'AI_MODEL':payload.model}
    if payload.api_key and payload.provider in KEYS: values[KEYS[payload.provider]]=payload.api_key
    _store_runtime_values(values,message='Unable to save AI configuration.')
    from services.ai_chat import chat_service
    chat_service.memory.clear()
    return {'saved':True,'provider':payload.provider,'key_configured':bool(payload.api_key)}


@app.get("/api/export/config",dependencies=[Depends(require_admin)])
async def export_config():
    from fastapi.responses import JSONResponse
    async with SessionLocal() as session:
        sources=(await session.scalars(select(Source))).all(); crawlers=(await session.scalars(select(CrawlerJob))).all()
        rules=(await session.scalars(select(AutomationRule))).all(); commands=(await session.scalars(select(CustomCommand))).all()
        custom_routes=(await session.scalars(select(CustomDiscordRoute))).all()
        embeds=(await session.scalars(select(EmbedTemplate))).all(); schedules=(await session.scalars(select(SchedulerConfig))).all()
    def model_values(row,keys): return {key:getattr(row,key) for key in keys}
    payload={"version":1,"exported_at":iso_utc(utcnow()),"sources":[model_values(x,["name","url","category","source_type","description","interval_minutes","enabled","priority","tags","parser_type","auth_mode","auth_env_var","timeout_seconds","max_response_bytes","requests_per_minute"]) for x in sources],"crawlers":[model_values(x,["name","start_url","allowed_domain","allowed_paths","blocked_paths","max_depth","max_pages","request_delay_ms","interval_minutes","user_agent","follow_links","mode","selectors","enabled"]) for x in crawlers],"rules":[model_values(x,["name","keywords","category","severity","channel_id","route_key","enabled","rule_type","logic","conditions"]) for x in rules],"custom_routes":[model_values(x,["route_name","route_key","description","guild_id","channel_id","category","keywords","priority","enabled"]) for x in custom_routes],"commands":[model_values(x,["name","response","enabled"]) for x in commands],"embeds":[model_values(x,["name","title","description","color"]) for x in embeds],"scheduler":[model_values(x,["task","interval_minutes","enabled"]) for x in schedules]}
    return JSONResponse(payload,headers={"Content-Disposition":"attachment; filename=hex-alert-config.json"})


def _backup_tables():
    # Admin credentials, reset hashes, and live session identifiers stay local.
    return [table for table in Base.metadata.sorted_tables if table.name not in {"admin_users", "admin_sessions"}]


def _backup_json_value(value):
    return iso_utc(value) if isinstance(value, datetime) else value


async def _make_backup() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    database = {}
    async with SessionLocal() as session:
        for table in _backup_tables():
            rows = (await session.execute(select(table))).mappings().all()
            database[table.name] = [{key: _backup_json_value(value) for key, value in row.items()} for row in rows]
    manifest = {"version": 1, "created_at": iso_utc(utc_now()),
                "database_schema_version": "alembic-head", "application_version": app.version,
                "included_tables": list(database), "excluded_tables": ["admin_users"],
                "secrets": "Environment credentials and admin authentication data are excluded."}
    stamp = utc_now().strftime("%Y%m%d-%H%M%S")
    path = BACKUP_DIR / f"hex-alert-backup-{stamp}.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, separators=(",", ":")))
        archive.writestr("database.json", json.dumps(database, default=_backup_json_value, separators=(",", ":")))
    return path


@app.post("/api/backups", dependencies=[Depends(require_admin)])
async def create_backup():
    try:
        path = await _make_backup()
        return {"name": path.name, "created_at": iso_utc(utc_now()), "size_bytes": path.stat().st_size}
    except Exception as exc:
        log.exception("Backup creation failed (%s)", type(exc).__name__)
        raise HTTPException(500, "Backup could not be created")


@app.get("/api/backups", dependencies=[Depends(require_admin)])
async def backup_history():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return [{"name": p.name, "size_bytes": p.stat().st_size,
             "modified_at": iso_utc(datetime.fromtimestamp(p.stat().st_mtime, timezone.utc))}
            for p in sorted(BACKUP_DIR.glob("hex-alert-backup-*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)]


@app.get("/api/backups/{name}", dependencies=[Depends(require_admin)])
async def download_backup(name: str):
    if not re.fullmatch(r"hex-alert-backup-[0-9]{8}-[0-9]{6}\.zip", name): raise HTTPException(400, "Invalid backup name")
    path = BACKUP_DIR / name
    if not path.is_file(): raise HTTPException(404, "Backup not found")
    return FileResponse(path, media_type="application/zip", filename=name)


async def _read_limited_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > BACKUP_MAX_BYTES: raise HTTPException(413, "Backup archive exceeds the 50 MB limit")
    return bytes(body)


@app.post("/api/backups/restore", dependencies=[Depends(require_admin)])
async def restore_backup(request: Request):
    raw = await _read_limited_body(request)
    if not raw: raise HTTPException(400, "Upload a backup ZIP archive")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if {item.filename for item in infos} != {"manifest.json", "database.json"} or len(infos) != 2:
                raise ValueError("Archive must contain only manifest.json and database.json")
            for item in infos:
                if item.filename.startswith(("/", "\\")) or ".." in item.filename.replace("\\", "/").split("/"):
                    raise ValueError("Unsafe archive path")
                if (item.external_attr >> 16) & 0o170000 == 0o120000: raise ValueError("Symbolic links are not allowed")
            if sum(item.file_size for item in infos) > BACKUP_MAX_EXPANDED_BYTES:
                raise ValueError("Expanded archive exceeds the 100 MB limit")
            manifest = json.loads(archive.read("manifest.json"))
            payload = json.loads(archive.read("database.json"))
        if not isinstance(manifest, dict) or not isinstance(manifest.get("application_version"), str):
            raise ValueError("Invalid backup manifest")
        if manifest.get("version") != 1 or manifest.get("application_version", "").split(".", 1)[0] != app.version.split(".", 1)[0]:
            raise ValueError("Backup version is incompatible with this application")
        if not isinstance(payload, dict): raise ValueError("Invalid database payload")
        tables = {table.name: table for table in _backup_tables()}
        if set(payload) != set(tables) or set(manifest.get("included_tables", [])) != set(tables):
            raise ValueError("Backup database schema does not match this application")
        for name, rows in payload.items():
            if not isinstance(rows, list): raise ValueError(f"Invalid rows for {name}")
            allowed = {column.name: column for column in tables[name].columns}
            for row in rows:
                if not isinstance(row, dict) or set(row) - set(allowed): raise ValueError(f"Invalid columns for {name}")
                for key, value in row.items():
                    if value is not None and isinstance(allowed[key].type, DateTime):
                        row[key] = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError, TypeError, ValueError, OSError, RuntimeError) as exc:
        raise HTTPException(400, f"Backup validation failed: {str(exc)[:200]}")

    # Keep an automatic recovery point before the single transactional replacement.
    try:
        before = await _make_backup()
        async with SessionLocal() as session:
            async with session.begin():
                for table in reversed(_backup_tables()): await session.execute(table.delete())
                for table in _backup_tables():
                    if payload[table.name]: await session.execute(table.insert(), payload[table.name])
                if session.bind and session.bind.dialect.name == "postgresql":
                    for table in _backup_tables():
                        if "id" in table.c and table.c.id.primary_key:
                            quoted = '"' + table.name.replace('"', '""') + '"'
                            query = f"SELECT setval(pg_get_serial_sequence(:table_name, 'id'), GREATEST(COALESCE((SELECT MAX(id) FROM {quoted}), 1), 1), EXISTS (SELECT 1 FROM {quoted}))"
                            await session.execute(text(query), {"table_name": table.name})
        return {"restored": True, "pre_restore_backup": before.name}
    except Exception as exc:
        log.exception("Restore failed (%s)", type(exc).__name__)
        raise HTTPException(500, "Restore failed; the database transaction was rolled back")


@app.get("/api/rules",dependencies=[Depends(require_admin)])
async def rules():
    async with SessionLocal() as session: rows=(await session.scalars(select(AutomationRule).order_by(AutomationRule.name))).all()
    return [{"id":x.id,"name":x.name,"keywords":x.keywords,"category":x.category,"severity":x.severity,"channel_id":x.channel_id,"route_key":x.route_key,"enabled":x.enabled,"rule_type":x.rule_type,"logic":x.logic,"conditions":x.conditions} for x in rows]


@app.post("/api/rules",dependencies=[Depends(require_admin)])
async def create_rule(payload:RulePayload):
    bot=runtime.get("bot")
    if not payload.keywords and not payload.conditions: raise HTTPException(422,"Add at least one keyword or condition")
    channel_id=payload.channel_id
    if payload.rule_type == "route" and payload.route_key:
        async with SessionLocal() as session:
            custom = await session.scalar(select(CustomDiscordRoute).where(
                CustomDiscordRoute.route_key == payload.route_key, CustomDiscordRoute.enabled.is_(True)))
        if not custom: raise HTTPException(422,"Choose an enabled custom route")
    if payload.rule_type=="filter" and normalize_category(payload.category)=="jobs":
        if not channel_id:
            async with SessionLocal() as session:
                channel_id=await session.scalar(select(ChannelConfig.channel_id).where(ChannelConfig.name=="JOB_CHANNEL_ID").order_by(ChannelConfig.id.desc())) or ""
    if channel_id and (not channel_id.isdigit() or not bot or not bot.get_channel(int(channel_id))): raise HTTPException(422,"Target channel must be available to the bot")
    async with SessionLocal() as session:
        row=AutomationRule(**{**payload.model_dump(),"channel_id":channel_id}); session.add(row); await session.commit(); await session.refresh(row)
        return {"id":row.id,"name":row.name,"enabled":row.enabled}


@app.post("/api/rules/job-fresher-preset",dependencies=[Depends(require_admin)])
async def create_job_fresher_preset():
    from services.job_rules import DEFAULT_FRESHER_CYBER_RULE
    async with SessionLocal() as session:
        channel_id=await session.scalar(select(ChannelConfig.channel_id).where(ChannelConfig.name=="JOB_CHANNEL_ID").order_by(ChannelConfig.id.desc()))
        if not channel_id: raise HTTPException(409,"Configure the cyber-jobs channel before creating the preset")
        row=await session.scalar(select(AutomationRule).where(AutomationRule.name=="Cybersecurity Fresher Jobs"))
        if row is None:
            row=AutomationRule(name="Cybersecurity Fresher Jobs",keywords=[],category="jobs",severity="Informational",
                               channel_id=channel_id,enabled=True,rule_type="filter",logic="AND",conditions=DEFAULT_FRESHER_CYBER_RULE)
            session.add(row)
        else:
            row.category="jobs"; row.channel_id=channel_id; row.enabled=True; row.rule_type="filter"; row.logic="AND"; row.conditions=DEFAULT_FRESHER_CYBER_RULE
        await session.commit(); await session.refresh(row)
        return {"id":row.id,"name":row.name,"enabled":row.enabled,"rule_type":row.rule_type,"channel_id":row.channel_id}


@app.delete("/api/rules/{rule_id}",dependencies=[Depends(require_admin)])
async def delete_rule(rule_id:int):
    async with SessionLocal() as session:
        row=await session.get(AutomationRule,rule_id)
        if not row: raise HTTPException(404,"Rule not found")
        await session.delete(row); await session.commit()
    return {"deleted":True}


@app.get("/api/commands",dependencies=[Depends(require_admin)])
async def custom_commands():
    async with SessionLocal() as session: rows=(await session.scalars(select(CustomCommand).order_by(CustomCommand.name))).all()
    return [{"id":x.id,"name":x.name,"response":x.response,"enabled":x.enabled} for x in rows]


@app.post("/api/commands",dependencies=[Depends(require_admin)])
async def add_custom_command(payload:dict):
    name=str(payload.get("name","" )).lower(); text=str(payload.get("response",""))
    if not re.fullmatch(r"[a-z0-9_-]{1,32}",name): raise HTTPException(422,"Command name must use lowercase letters, numbers, hyphens or underscores")
    if not text or len(text)>1800: raise HTTPException(422,"Response must contain 1–1800 characters")
    if name in {"help","status","hexstatus","jobs","news","cve","latest-cve","critical-cve","tools","latest-tools","threats","sources","job-profile","admin-status","admin-refresh","admin-source-enable","admin-source-disable","ask","ai-status","model","reset-chat"}:
        raise HTTPException(409,"That command name is reserved by HEX ALERT")
    async with SessionLocal() as session:
        existing=await session.scalar(select(CustomCommand).where(CustomCommand.name==name))
        if existing: raise HTTPException(409,"Command already exists")
        row=CustomCommand(name=name,response=text); session.add(row); await session.commit(); await session.refresh(row)
    await _register_custom_command(name,text)
    return {"id":row.id,"name":name,"enabled":True}


async def _register_custom_command(name,text):
    bot=runtime.get("bot")
    if not bot: return
    def make_callback(response_text):
        async def callback(interaction:discord.Interaction): await interaction.response.send_message(response_text,ephemeral=True,allowed_mentions=discord.AllowedMentions.none())
        return callback
    command_obj=discord.app_commands.Command(name=name,description=f"Hex Alert custom command: {name}",callback=make_callback(text))
    try:
        bot.tree.add_command(command_obj,override=True)
        await bot.tree.sync()
    except Exception as exc: log.warning("Custom command sync failed (%s)",type(exc).__name__)


@app.delete("/api/commands/{command_id}",dependencies=[Depends(require_admin)])
async def delete_custom_command(command_id:int):
    async with SessionLocal() as session:
        row=await session.get(CustomCommand,command_id)
        if not row: raise HTTPException(404,"Command not found")
        name=row.name; await session.delete(row); await session.commit()
    bot=runtime.get("bot")
    if bot:
        try: bot.tree.remove_command(name); await bot.tree.sync()
        except Exception as exc: log.warning("Could not remove command (%s)",type(exc).__name__)
    return {"deleted":True}


@app.get("/api/embeds",dependencies=[Depends(require_admin)])
async def embed_templates():
    async with SessionLocal() as session: rows=(await session.scalars(select(EmbedTemplate).order_by(EmbedTemplate.name))).all()
    return [{"id":x.id,"name":x.name,"title":x.title,"description":x.description,"color":x.color} for x in rows]


@app.post("/api/embeds",dependencies=[Depends(require_admin)])
async def save_embed(payload:dict):
    name=str(payload.get("name",""))[:100]; title=str(payload.get("title",""))[:256]; description=str(payload.get("description",""))[:3500]; color=str(payload.get("color","#14B8A6"))
    if not name or not re.fullmatch(r"#[0-9A-Fa-f]{6}",color): raise HTTPException(422,"Provide a name and six-digit hex color")
    async with SessionLocal() as session:
        row=await session.scalar(select(EmbedTemplate).where(EmbedTemplate.name==name))
        if not row: row=EmbedTemplate(name=name); session.add(row)
        row.title=title; row.description=description; row.color=color; await session.commit(); await session.refresh(row)
        return {"id":row.id,"name":row.name}


@app.get("/api/ai/config",dependencies=[Depends(require_admin)])
async def ai_config():
    from config.ai import options, KEYS
    cfg=options(); entry=cfg.providers.get(cfg.provider)
    stored=get_runtime_config()
    return {'provider':cfg.provider,'model':entry.model if entry else '', 'base_url':entry.base_url if entry else '',
            'key_configured':bool(stored.get(KEYS.get(cfg.provider,''),'') or getattr(get_settings(),KEYS.get(cfg.provider,'').lower(),''))}


@app.post('/api/ai/test',dependencies=[Depends(require_admin)])
async def ai_test():
    from services.ai_chat import chat_service
    from services.ai_providers import AIUnavailable
    try:
        result=await chat_service.ask(('legacy-admin-test',), 'Say HEX ALERT AI is ready.', remember=False)
        return {'provider':result['provider'],'result':result['answer'],'connected':True}
    except AIUnavailable as exc: raise HTTPException(503,str(exc)) from None


@app.get("/api/settings/test-mode",dependencies=[Depends(require_admin)])
async def test_mode_status():
    settings=get_settings()
    async with SessionLocal() as session:
        mapping=await session.scalar(select(ChannelConfig).where(ChannelConfig.name=="TEST_CHANNEL_ID").order_by(ChannelConfig.id.desc()))
    return {"enabled":settings.test_mode,"channel_id":mapping.channel_id if mapping else ""}


@app.get("/api/settings/time", dependencies=[Depends(require_admin)])
async def time_settings():
    settings = get_settings()
    try:
        zone = get_timezone(settings.app_timezone)
    except ValueError:
        zone = get_timezone(DEFAULT_TIMEZONE)
    local_now = utc_now().astimezone(zone)
    try:
        digest_zone = get_timezone(settings.daily_digest_timezone)
    except ValueError:
        digest_zone = get_timezone(DEFAULT_TIMEZONE)
    digest_now = utc_now().astimezone(digest_zone)
    hour = max(0, min(23, settings.daily_digest_hour))
    digest_label = datetime(2000, 1, 1, hour).strftime("%I:%M %p").lstrip("0")
    return {
        "timezone": zone.key,
        "timezone_abbr": local_now.tzname() or zone.key,
        "time_format": settings.time_format if settings.time_format in {"12h", "24h"} else "12h",
        "daily_digest_hour": hour,
        "daily_digest_timezone": digest_zone.key,
        "daily_digest_timezone_abbr": digest_now.tzname() or digest_zone.key,
        "daily_digest_display": f"Every day at {digest_label} {digest_now.tzname() or digest_zone.key}",
    }


@app.post("/api/settings/time", dependencies=[Depends(require_admin)])
async def update_time_settings(payload: TimeSettingsPayload):
    _store_runtime_values({"APP_TIMEZONE": payload.timezone, "TIME_FORMAT": payload.time_format},
                          message="Unable to save time display settings.")
    return await time_settings()


@app.post("/api/settings/test-mode",dependencies=[Depends(require_admin)])
async def set_test_mode(payload:TestModePayload):
    if payload.enabled and not payload.channel_id.isdigit(): raise HTTPException(422,"Choose a numeric test channel ID before enabling Test Mode")
    if payload.channel_id:
        bot=runtime.get("bot")
        if not bot or not bot.get_channel(int(payload.channel_id)): raise HTTPException(422,"Test channel is not available to the bot")
        channel=bot.get_channel(int(payload.channel_id)); guild=getattr(channel,"guild",None); me=getattr(guild,"me",None)
        if not me: raise HTTPException(422,"The bot is not a member of the test channel's server")
        perms=channel.permissions_for(me)
        missing=[name for name,ok in (("View Channel",perms.view_channel),("Send Messages",perms.send_messages),("Embed Links",perms.embed_links),("Read Message History",perms.read_message_history)) if not ok]
        if missing: raise HTTPException(422,"Test channel missing required permissions: "+", ".join(missing))
        async with SessionLocal() as session:
            row=await session.scalar(select(ChannelConfig).where(ChannelConfig.guild_id==str(guild.id),ChannelConfig.name=="TEST_CHANNEL_ID"))
            if row: row.channel_id=payload.channel_id
            else: session.add(ChannelConfig(guild_id=str(guild.id),name="TEST_CHANNEL_ID",channel_id=payload.channel_id))
            await session.commit()
    _store_runtime_values({"TEST_MODE":payload.enabled}, message="Unable to save Discord configuration.")
    return {"test_mode":payload.enabled,"channel_id":payload.channel_id}


@app.post("/api/discord/test-alert/{kind}",dependencies=[Depends(require_admin)])
async def send_test_alert(kind:str):
    if kind not in {"job","news","cve","zero-day","threat","tool","github-tool","daily-digest"}:raise HTTPException(422,"Unknown alert type")
    bot=runtime.get("bot");settings=get_settings()
    async with SessionLocal() as session:
        test_mappings=(await session.scalars(select(ChannelConfig).where(ChannelConfig.name=="TEST_CHANNEL_ID").order_by(ChannelConfig.id.desc()))).all()
    channel=next((bot.get_channel(int(row.channel_id)) for row in test_mappings if bot and row.channel_id.isdigit() and bot.get_channel(int(row.channel_id))),None)
    if not settings.test_mode: raise HTTPException(409,"Enable Test Mode before sending test alerts")
    if not channel:raise HTTPException(422,"Select a test channel before sending test alerts.")
    guild=getattr(channel,"guild",None); me=getattr(guild,"me",None)
    if not me: raise HTTPException(422,"The bot is not a member of the test channel's server")
    perms=channel.permissions_for(me)
    missing=[label for label,allowed in (("View Channel",perms.view_channel),("Send Messages",perms.send_messages),("Embed Links",perms.embed_links),("Read Message History",perms.read_message_history)) if not allowed]
    title_map={"job":"🚨 HEX ALERT — CYBERSECURITY JOB TEST","news":"📰 HEX ALERT — CYBERSECURITY NEWS TEST","cve":"🚨 HEX ALERT — CRITICAL CVE TEST","zero-day":"🚨 HEX ALERT — ZERO-DAY TEST","threat":"🛡️ HEX ALERT — THREAT INTELLIGENCE TEST","tool":"🛠️ HEX ALERT — CYBER TECHNOLOGY TEST","github-tool":"🛠️ HEX ALERT — GITHUB SECURITY TOOL TEST","daily-digest":"🌐 HEX ALERT — DAILY CYBER BRIEF TEST"}
    embed=discord.Embed(title=title_map[kind],description="This is a HEX ALERT Discord integration test. It is not a production intelligence alert.",color=0x14B8A6)
    if kind in {"cve","zero-day"}:
        for name,value in (("CVE","CVE-TEST-2026-0001"),("Severity","CRITICAL"),("CVSS","9.8"),("Status","TEST ALERT")):
            embed.add_field(name=name,value=value,inline=True)
    embed.set_footer(text="HEX ALERT • TEST MODE")
    title=title_map[kind]
    async with SessionLocal() as session:
        alert=Alert(category=kind,title=title,source="HEX ALERT test",source_url="",channel_id=str(channel.id),channel_name=str(getattr(channel,"name",channel.id)),status="pending")
        session.add(alert); await session.flush()
        if missing:
            alert.status="failed"; alert.error="Missing permissions: "+", ".join(missing)
            await session.commit()
            raise HTTPException(403,alert.error)
        try:
            message=await channel.send(embed=embed,allowed_mentions=discord.AllowedMentions.none())
            alert.status="sent"; alert.message_id=str(message.id)
            session.add(SentMessage(item_type=kind,item_id=str(alert.id),guild_id=str(guild.id),channel_id=str(channel.id),message_id=str(message.id)))
            await session.commit()
            return {"sent":True,"status":"SENT","message_id":str(message.id),"guild_id":str(guild.id),"channel_id":str(channel.id),"alert_id":alert.id}
        except discord.HTTPException as exc:
            alert.status="failed"; alert.error=f"Discord HTTP {exc.status}: {type(exc).__name__}"
            await session.commit()
            raise HTTPException(502,"Discord rejected the test alert; delivery failure was recorded")


@app.get("/api/discord/channels", dependencies=[Depends(require_admin)])
async def discord_channels(guild_id:str):
    bot=runtime.get("bot"); guild=bot.get_guild(int(guild_id)) if bot and guild_id.isdigit() else None
    if not guild: raise HTTPException(404,"Connected Discord server not found")
    return [{"id":str(c.id),"name":c.name,"type":str(c.type),"can_view_channel":bool(guild.me and c.permissions_for(guild.me).view_channel),"can_send_messages":bool(guild.me and c.permissions_for(guild.me).send_messages),"can_embed_links":bool(guild.me and c.permissions_for(guild.me).embed_links),"can_read_message_history":bool(guild.me and c.permissions_for(guild.me).read_message_history)} for c in guild.text_channels]


@app.post("/api/discord/channels", dependencies=[Depends(require_admin)])
async def save_channel(payload:ChannelPayload):
    if not payload.guild_id.isdigit() or not payload.channel_id.isdigit():raise HTTPException(422,"Discord IDs must be numeric")
    bot=runtime.get("bot"); guild=bot.get_guild(int(payload.guild_id)) if bot and payload.guild_id.isdigit() else None
    if not guild or not guild.get_channel(int(payload.channel_id)): raise HTTPException(422,"Channel is not in a connected server")
    async with SessionLocal() as session:
        row=await session.scalar(select(ChannelConfig).where(ChannelConfig.guild_id==payload.guild_id,ChannelConfig.name==payload.name))
        if not row: row=ChannelConfig(guild_id=payload.guild_id,name=payload.name,channel_id=payload.channel_id); session.add(row)
        else: row.channel_id=payload.channel_id
        await session.commit()
    return {"saved":True}


@app.get("/api/discord/mappings", dependencies=[Depends(require_admin)])
async def channel_mappings():
    async with SessionLocal() as session: rows=(await session.scalars(select(ChannelConfig))).all()
    return [{"guild_id":x.guild_id,"name":x.name,"channel_id":x.channel_id} for x in rows]


@app.get("/api/discord/routing", dependencies=[Depends(require_admin)])
async def discord_routing_matrix():
    bot = runtime.get("bot")
    route_labels = {
        "jobs": "Jobs", "news": "News", "critical_cve": "Critical CVE",
        "zero_day": "Zero-Day", "threat_intel": "Threat", "technology": "Technology",
        "github_tools": "GitHub", "security_research": "Research",
        "daily_digest": "Daily Digest", "bot_status": "Bot Status", "test_alerts": "Test Alerts",
    }
    async with SessionLocal() as session:
        mapping_rows = (await session.scalars(select(ChannelConfig).order_by(ChannelConfig.id.desc()))).all()
        alerts_rows = (await session.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(500))).all()
        jobs_run = await session.scalar(select(SchedulerConfig).where(SchedulerConfig.task == "jobs"))
        jobs_error = await session.scalar(select(SystemLog).where(SystemLog.component == "jobs", SystemLog.level == "ERROR").order_by(SystemLog.created_at.desc()).limit(1))
    result = []
    for category, label in route_labels.items():
        names = route_storage_names(category)
        configured = next((row for row in mapping_rows if row.name in names), None)
        try:
            resolved = await resolve_discord_channel(category, configured.guild_id if configured else None, bot=bot)
            channel_name = resolved.channel_name
            channel_id = resolved.channel_id
            permission = "READY"
        except RoutingError as exc:
            channel_name = ""
            channel_id = configured.channel_id if configured else ""
            permission = f"FAILED: {str(exc)}"
        last = next((row for row in alerts_rows if normalize_category(row.category) == category), None)
        result.append({
            "category": category, "label": label, "channel_name": channel_name,
            "channel_id": channel_id, "permission": permission,
            "last_alert": last.title if last else "Never routed",
            "last_status": last.status.upper() if last else "NEVER",
            "last_error": last.error if last and last.status == "failed" else "",
            "last_routed_at": iso_utc(last.created_at) if last else None,
        })
    if jobs_run and jobs_run.last_result == "failed":
        job_route = next(row for row in result if row["category"] == "jobs")
        job_route["last_status"] = "COLLECTOR FAILED"
        if jobs_error:
            job_route["last_error"] = jobs_error.message[:300]
    return {"test_mode": get_settings().test_mode, "routes": result}


def _custom_route_view(route: CustomDiscordRoute, channel_name="", permission="UNKNOWN"):
    return {"id": route.id, "route_name": route.route_name, "route_key": route.route_key,
            "description": route.description, "guild_id": route.guild_id, "channel_id": route.channel_id,
            "category": route.category, "keywords": route.keywords or [], "priority": route.priority,
            "enabled": route.enabled, "last_used": iso_utc(route.last_used),
            "status": permission if permission != "UNKNOWN" else route.status,
            "channel_name": channel_name}


@app.get("/api/discord/custom-routes", dependencies=[Depends(require_admin)])
async def list_custom_routes():
    async with SessionLocal() as session:
        rows = (await session.scalars(select(CustomDiscordRoute).order_by(CustomDiscordRoute.priority, CustomDiscordRoute.route_name))).all()
    result=[]
    for route in rows:
        try:
            resolution=await resolve_explicit_channel(route.channel_id, bot=runtime.get("bot"))
            if resolution.guild_id != route.guild_id: raise RoutingError("Channel belongs to a different server")
            result.append(_custom_route_view(route, resolution.channel_name, "READY"))
        except RoutingError as exc:
            result.append(_custom_route_view(route, "", f"FAILED: {str(exc)}"))
    return result


async def _validate_custom_route_target(guild_id: str, channel_id: str):
    if not guild_id.isdigit() or not channel_id.isdigit():
        raise HTTPException(422, "Select a valid Discord server and channel")
    try:
        resolution=await resolve_explicit_channel(channel_id, bot=runtime.get("bot"))
    except RoutingError as exc:
        raise HTTPException(422, str(exc)) from None
    if resolution.guild_id != guild_id:
        raise HTTPException(422, "Selected channel does not belong to the selected server")
    return resolution


@app.post("/api/discord/custom-routes", dependencies=[Depends(require_admin)])
async def create_custom_route(payload: CustomRoutePayload):
    resolution=await _validate_custom_route_target(payload.guild_id, payload.channel_id)
    async with SessionLocal() as session:
        if await session.scalar(select(CustomDiscordRoute.id).where(CustomDiscordRoute.route_key == payload.route_key)):
            raise HTTPException(409, "That custom route key already exists")
        route=CustomDiscordRoute(**payload.model_dump(), status="READY")
        session.add(route)
        session.add(SystemLog(level="INFO", component="discord-routing", message="CUSTOM_ROUTE_CREATED"))
        try: await session.commit()
        except Exception:
            await session.rollback()
            raise HTTPException(409, "Could not create custom route") from None
        await session.refresh(route)
        return _custom_route_view(route, resolution.channel_name, "READY")


@app.put("/api/discord/custom-routes/{route_id}", dependencies=[Depends(require_admin)])
async def update_custom_route(route_id: int, payload: CustomRoutePayload):
    resolution=await _validate_custom_route_target(payload.guild_id, payload.channel_id)
    async with SessionLocal() as session:
        route=await session.get(CustomDiscordRoute, route_id)
        if not route: raise HTTPException(404,"Custom route not found")
        duplicate=await session.scalar(select(CustomDiscordRoute.id).where(
            CustomDiscordRoute.route_key==payload.route_key, CustomDiscordRoute.id!=route_id))
        if duplicate: raise HTTPException(409,"That custom route key already exists")
        for key,value in payload.model_dump().items(): setattr(route,key,value)
        route.status="READY"
        session.add(SystemLog(level="INFO", component="discord-routing", message="CUSTOM_ROUTE_CHANGED"))
        await session.commit(); await session.refresh(route)
        return _custom_route_view(route,resolution.channel_name,"READY")


@app.delete("/api/discord/custom-routes/{route_id}", dependencies=[Depends(require_admin)])
async def delete_custom_route(route_id: int):
    async with SessionLocal() as session:
        route=await session.get(CustomDiscordRoute,route_id)
        if not route: raise HTTPException(404,"Custom route not found")
        await session.delete(route)
        session.add(SystemLog(level="INFO", component="discord-routing", message="CUSTOM_ROUTE_DELETED"))
        await session.commit()
    return {"deleted":True}


@app.post("/api/discord/custom-routes/{route_key}/test", dependencies=[Depends(require_admin)])
async def test_custom_route(route_key: str):
    if not get_settings().test_mode:
        raise HTTPException(409,"Custom route tests are allowed only while TEST_MODE is enabled")
    bot=runtime.get("bot")
    async with SessionLocal() as session:
        route=await session.scalar(select(CustomDiscordRoute).where(CustomDiscordRoute.route_key==route_key.lower()))
        if not route: raise HTTPException(404,"Custom route not found")
        route_id=route.id; guild_id=route.guild_id; channel_id=route.channel_id; category=route.category
        title=f"🧪 HEX ALERT — CUSTOM ROUTE TEST: {route.route_name}"[:256]
        route_name=route.route_name
        alert=Alert(category=f"custom:{route_key}"[:40], title=title, source="HEX ALERT test",
                    channel_id=channel_id, status="pending")
        session.add(alert); await session.flush()
        alert_id=alert.id
        await session.commit()
    try:
        resolution=await resolve_explicit_channel(channel_id,bot=bot)
        if resolution.guild_id!=guild_id: raise RoutingError("Mapped channel belongs to a different server")
        embed=discord.Embed(title=title,description=f"CUSTOM ROUTE TEST · key `{route_key}` · category `{category}`. This controlled message is not a production alert.",color=0x14B8A6)
        embed.set_footer(text="HEX ALERT • TEST MODE")
        message=await resolution.channel.send(embed=embed,allowed_mentions=discord.AllowedMentions.none())
        async with SessionLocal() as session:
            alert=await session.get(Alert,alert_id); route=await session.get(CustomDiscordRoute,route_id)
            alert.channel_id=channel_id; alert.channel_name=resolution.channel_name
            alert.message_id=str(message.id); alert.status="sent"; alert.error=""
            route.status="SENT"; route.last_used=utcnow()
            session.add(SentMessage(item_type=f"custom:{route_key}"[:30],item_id=str(alert_id),guild_id=guild_id,
                                    channel_id=channel_id,message_id=str(message.id)))
            session.add(SystemLog(level="INFO",component="discord-routing",message="CUSTOM_ROUTE_TEST_SENT"))
            await session.commit()
        return {"sent":True,"route_name":route_name,"route_key":route_key,"channel_name":resolution.channel_name,
                "guild_id":guild_id,"channel_id":channel_id,"message_id":str(message.id),"alert_id":alert_id}
    except Exception as exc:
        reason=str(exc)[:500] if isinstance(exc,RoutingError) else f"Discord send failed ({type(exc).__name__})"
        async with SessionLocal() as session:
            alert=await session.get(Alert,alert_id); route=await session.get(CustomDiscordRoute,route_id)
            if alert: alert.status="failed"; alert.error=reason
            if route: route.status="FAILED"
            await session.commit()
        log.warning("[DISCORD] Custom route test failed route=%s reason=%s",route_key,reason)
        raise HTTPException(502,"Custom route test failed; the attempt was recorded") from None


@app.get("/api/discord/categories", dependencies=[Depends(require_admin)])
async def discord_categories(guild_id: str):
    bot=runtime.get("bot"); guild=bot.get_guild(int(guild_id)) if bot and guild_id.isdigit() else None
    if not guild: raise HTTPException(404,"Connected Discord server not found")
    return [{"id":str(c.id),"name":c.name} for c in guild.categories]


@app.post("/api/discord/create-channel", dependencies=[Depends(require_admin)])
async def create_discord_channel(payload: DiscordCreateChannelPayload):
    bot=runtime.get("bot"); guild=bot.get_guild(int(payload.guild_id)) if bot and payload.guild_id.isdigit() else None
    if not guild: raise HTTPException(404,"Connected Discord server not found")
    me=getattr(guild,"me",None)
    if not me or not me.guild_permissions.manage_channels:
        raise HTTPException(403,"Bot does not have Manage Channels permission.")
    category=None
    if payload.category_id:
        if not payload.category_id.isdigit(): raise HTTPException(422,"Invalid Discord category ID")
        category=guild.get_channel(int(payload.category_id))
        if not isinstance(category,discord.CategoryChannel): raise HTTPException(422,"Selected category is unavailable in this server")
    try:
        channel=await guild.create_text_channel(name=payload.name,topic=payload.topic or None,
                                                category=category,nsfw=payload.nsfw,
                                                position=payload.position,reason="Created from HEX ALERT admin UI")
    except discord.Forbidden:
        raise HTTPException(403,"Bot does not have Manage Channels permission.") from None
    except discord.HTTPException as exc:
        raise HTTPException(502,f"Discord could not create the channel (HTTP {exc.status}).") from None
    async with SessionLocal() as session:
        session.add(SystemLog(level="INFO",component="discord-routing",message="DISCORD_CHANNEL_CREATED"))
        await session.commit()
    return {"id":str(channel.id),"name":channel.name,"guild_id":str(guild.id)}


@app.post("/api/discord/test-route/{category}", dependencies=[Depends(require_admin)])
async def test_mapped_discord_route(category: str):
    canonical = normalize_category(category)
    if canonical not in ROUTE_CHANNEL_KEYS:
        raise HTTPException(422, "Unknown Discord routing category")
    if not get_settings().test_mode:
        raise HTTPException(409, "Mapped-channel route tests are allowed only while TEST_MODE is enabled")
    bot = runtime.get("bot")
    title = f"TEST ROUTE • {canonical.replace('_', ' ').title()}"
    try:
        resolution = await resolve_discord_channel(canonical, bot=bot)
    except RoutingError as exc:
        async with SessionLocal() as session:
            alert = Alert(category=canonical, title=title, source="HEX ALERT routing test",
                          status="failed", error=str(exc)[:1000])
            session.add(alert)
            await session.commit()
        raise HTTPException(422, str(exc)) from None
    embed = discord.Embed(
        title=f"🧪 HEX ALERT — TEST ROUTE: {canonical.replace('_', ' ').upper()}",
        description="Controlled routing verification. This confirms the PostgreSQL channel mapping, bot access, and Discord message delivery. No production intelligence alert was generated.",
        color=0x14B8A6, timestamp=utcnow())
    embed.add_field(name="Route", value=f"{canonical} → #{resolution.channel_name}", inline=False)
    embed.add_field(name="Mode", value="TEST_MODE enabled", inline=True)
    embed.set_footer(text="HEX ALERT • TEST ROUTE • No production alert")
    async with SessionLocal() as session:
        alert = Alert(category=canonical, title=title, source="HEX ALERT routing test",
                      channel_id=resolution.channel_id, channel_name=resolution.channel_name,
                      status="pending")
        session.add(alert)
        await session.flush()
        alert_id = alert.id
        try:
            message = await resolution.channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
            alert.message_id = str(message.id)
            alert.status = "sent"
            session.add(SentMessage(item_type=canonical, item_id=str(alert_id),
                                    guild_id=resolution.guild_id, channel_id=resolution.channel_id,
                                    message_id=str(message.id)))
            await session.commit()
            log.info("[DISCORD] Test route sent category=%s channel=%s message=%s",
                     canonical, resolution.channel_id, message.id)
            return {"sent": True, "status": "SENT", "category": canonical,
                    "channel_name": resolution.channel_name, "channel_id": resolution.channel_id,
                    "guild_id": resolution.guild_id, "message_id": str(message.id), "alert_id": alert_id}
        except discord.HTTPException as exc:
            alert.status = "failed"
            alert.error = f"Discord HTTP {exc.status}: {type(exc).__name__}"
            await session.commit()
            raise HTTPException(502, "Discord rejected the mapped-channel test route; failure was recorded") from None


@app.get("/api/data/{kind}", dependencies=[Depends(require_admin)])
async def content_data(kind:str,limit:int=50):
    models={"jobs":Job,"news":NewsArticle,"cves":CVE,"threats":Threat,"tools":SecurityTool}; model=models.get(kind)
    if not model: raise HTTPException(404,"Unknown content category")
    async with SessionLocal() as session: rows=(await session.scalars(select(model).order_by(model.created_at.desc()).limit(min(200,max(1,limit))))).all()
    def get(obj,key,default=""):
        value=getattr(obj,key,default)
        return iso_utc(value) if isinstance(value,datetime) else value
    result=[]
    for row in rows:
        published = row.published_at.date().isoformat() if getattr(row,"published_at_date_only",False) and row.published_at else get(row,"published_at")
        data={"id":row.id,"title":get(row,"title",get(row,"cve_id","")),"source":get(row,"source"),"url":get(row,"source_url"),"apply_url":get(row,"apply_url",get(row,"source_url")),"published_at":published,"created_at":get(row,"created_at")}
        if hasattr(row,"published_at_date_only"): data["published_at_date_only"]=row.published_at_date_only
        for key in ("company","location","experience","salary","severity","cvss","exploited","summary","description","product","vendor","name","category","actor","malware","posted_to_discord"):
            if hasattr(row,key): data[key]=get(row,key)
        if isinstance(row, Job):
            for key in ("employment_type","work_mode","remote_status","freshness_status","listing_status","match_score","score_breakdown","first_seen_at","last_seen_at","discovered_at","alert_eligible","source_id","posting_id","external_id","experience_min","experience_max","salary_min","salary_max","currency","canonical_job_key","source_provenance","is_cybersecurity","is_entry_level","match_category","suppressed"):
                data[key]=get(row,key)
        result.append(data)
    return result


@app.post("/api/jobs/reference", dependencies=[Depends(require_admin)])
async def save_job_reference(payload: JobReferencePayload):
    """Store a manually supplied public listing without automated platform scraping."""
    validate_public_url(payload.apply_url)
    from types import SimpleNamespace
    from collectors.jobs.normalize import normalize_job
    from database.repository import save_job
    source_name = {"linkedin": "LinkedIn Reference", "wellfound": "Wellfound Reference",
                   "naukri": "Naukri Reference"}.get(payload.source, "Manual Job Reference")
    async with SessionLocal() as session:
        source = await session.scalar(select(Source).where(Source.name == source_name))
        if source is None:
            source = Source(name=source_name, url=payload.apply_url, category="jobs",
                            source_type=f"{payload.source}_reference", enabled=False,
                            parser_status="REFERENCE_ONLY", description="Manual public listing references; no automated scraping.")
            session.add(source)
            await session.flush()
        item = normalize_job({"title": payload.title, "company": payload.company, "location": payload.location,
                              "experience": payload.experience, "employment_type": payload.employment_type,
                              "description": payload.description, "skills": payload.skills,
                              "published_at": payload.posted_at, "apply_url": payload.apply_url,
                              "posting_id": payload.apply_url, "listing_status": "OPEN"},
                             SimpleNamespace(name=source_name, company_name=payload.company, url=payload.apply_url))
        values = {"title": item["title"], "company": item["company"], "location": item["location"],
                  "experience": item["experience"], "employment_type": item["employment_type"],
                  "work_mode": item["work_mode"], "remote_status": item["remote_status"], "salary": item["salary"],
                  "salary_min": item["salary_min"], "salary_max": item["salary_max"], "currency": item["currency"],
                  "experience_min": item["experience_min"], "experience_max": item["experience_max"], "skills": item["skills"],
                  "description": item["description"], "source": source_name, "source_url": item["apply_url"],
                  "apply_url": item["apply_url"], "published_at": item["published_at"],
                  "published_at_date_only": item["published_at_date_only"], "match_category": item["match_category"],
                  "freshness_status": item["freshness_status"], "listing_status": item["listing_status"],
                  "match_score": item["match_score"], "score_breakdown": item["score_breakdown"],
                  "source_type": source.source_type, "source_id": source.id, "posting_id": item["posting_id"],
                  "external_id": item["external_id"], "discovered_at": item["discovered_at"],
                  "is_cybersecurity": item["is_cybersecurity"], "is_entry_level": item["is_entry_level"],
                  "alert_eligible": False}
        job, created = await save_job(session, values)
        await session.commit()
        return {"id": job.id, "created": created, "source": source_name, "status": "REFERENCE_ONLY",
                "title": job.title, "apply_url": job.source_url, "freshness_status": job.freshness_status,
                "match_score": job.match_score}


@app.post("/api/jobs/{job_id}/test-route", dependencies=[Depends(require_admin)])
async def test_job_route(job_id: int):
    if not get_settings().test_mode:
        raise HTTPException(409, "Job route tests are allowed only while TEST_MODE is enabled")
    async with SessionLocal() as session:
        job=await session.get(Job,job_id)
        if not job: raise HTTPException(404,"Job not found")
        alert=Alert(category="jobs",title=f"TEST JOB ROUTE • {job.title[:450]}",source=job.source or "Stored job listing",
                    source_url=job.source_url,status="pending")
        session.add(alert); await session.flush(); alert_id=alert.id
        try:
            resolution=await resolve_discord_channel("jobs",bot=runtime.get("bot"))
            from bot.embeds.factory import job_embed
            embed=job_embed(job)
            embed.title="🧪 TEST ROUTE • CYBERSECURITY JOB"
            embed.description=("TEST JOB ROUTE\nNOT A NEW JOB ALERT\n\nControlled test using this stored job record.\n\n" + (embed.description or ""))[:4096]
            embed.set_footer(text="HEX ALERT • TEST ROUTE • No production alert")
            message=await resolution.channel.send(embed=embed,allowed_mentions=discord.AllowedMentions.none())
            alert.channel_id=resolution.channel_id; alert.channel_name=resolution.channel_name
            alert.message_id=str(message.id); alert.status="sent"
            session.add(SentMessage(item_type="jobs",item_id=str(alert_id),guild_id=resolution.guild_id,
                                    channel_id=resolution.channel_id,message_id=str(message.id)))
            await session.commit()
            return {"sent":True,"category":"jobs","channel_name":resolution.channel_name,"channel_id":resolution.channel_id,"message_id":str(message.id)}
        except RoutingError as exc:
            alert.status="failed"; alert.error=str(exc)[:1000]; await session.commit()
            raise HTTPException(422,"Job route failed; the attempt was recorded") from None
        except discord.HTTPException as exc:
            alert.status="failed"; alert.error=f"Discord HTTP {exc.status}: {type(exc).__name__}"; await session.commit()
            raise HTTPException(502,"Discord rejected the job route test; the attempt was recorded") from None


@app.post("/api/jobs/{job_id}/{action}", dependencies=[Depends(require_admin)])
async def job_action(job_id: int, action: Literal["suppress","closed"]):
    async with SessionLocal() as session:
        job=await session.get(Job,job_id)
        if not job: raise HTTPException(404,"Job not found")
        job.alert_eligible=False
        if action=="suppress": job.suppressed=True
        if action=="closed": job.listing_status="CLOSED"
        await session.commit()
    return {"updated":True,"id":job_id,"action":action}


@app.get("/", include_in_schema=False)
async def dashboard_page():
    html=Path(os.path.join(os.path.dirname(__file__),"static","index.html")).read_text(encoding="utf-8")
    html=re.sub(r'(/static/app\.js\?v=)[^" ]+',r'\g<1>20261008-rollout2',html)
    return HTMLResponse(html,headers={"Cache-Control":"no-store"})


from api.ai_routes import router as ai_router
app.include_router(ai_router(require_admin))
from api.community_routes import router as community_router
app.include_router(community_router(require_admin))

async def _ai_health():
    from services.ai_chat import chat_service
    try:
        state = await chat_service.health()
        return {key:state.get(key) for key in ("provider","model","status","backend")}
    except Exception:
        return {"provider":"unknown","model":"","status":"offline","backend":""}
