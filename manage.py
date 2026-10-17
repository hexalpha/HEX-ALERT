"""Trusted local administration commands for a self-hosted HEX ALERT instance."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import hmac
import sys
from datetime import datetime, timezone

from sqlalchemy import delete, func, select

from database.db import SessionLocal
from database.models import AdminSession, AdminUser, SystemLog
from services.admin_passwords import create_reset_token, hash_password, utc_aware


async def admin_reset(username: str | None = None) -> int:
    """Rotate a user's single-use recovery token; only its raw value is printed."""
    async with SessionLocal() as session:
        query = select(AdminUser).order_by(AdminUser.id).with_for_update()
        users = (await session.scalars(query)).all()
        if username:
            normalized = username.strip().casefold()
            user = next((item for item in users if item.username.casefold() == normalized), None)
        else:
            user = users[0] if len(users) == 1 else None
        if not user:
            print("Select an existing administrator with --username; no reset token was created.", file=sys.stderr)
            return 2
        raw, digest, expires = create_reset_token()
        now = datetime.now(timezone.utc)
        # Keep one outstanding recovery credential across accounts, not one per account.
        for existing in users:
            existing.reset_token_hash = ""
            existing.reset_token_expires_at = None
            existing.reset_token_used_at = now
        user.reset_token_hash = digest
        user.reset_token_expires_at = expires
        user.reset_token_used_at = None
        await session.commit()
    print("One-time admin password reset token (expires in 15 minutes):")
    print(raw)
    print("Enter it only in the local HEX ALERT recovery page. It will not be shown again.")
    return 0


async def set_admin_password(username: str, password: str, confirmation: str) -> int:
    """Apply the trusted-local password reset flow; deliberately not an API route."""
    if len(password) < 12:
        print("Password must contain at least 12 characters.", file=sys.stderr)
        return 2
    if not hmac.compare_digest(password, confirmation):
        print("Passwords do not match.", file=sys.stderr)
        return 2
    normalized = username.strip().casefold()
    async with SessionLocal() as session:
        user = await session.scalar(select(AdminUser).where(func.lower(AdminUser.username) == normalized).with_for_update())
        if not user:
            print("Administrator account not found.", file=sys.stderr)
            return 2
        now = datetime.now(timezone.utc)
        user.password_hash = hash_password(password)
        user.password_changed_at = now
        user.session_version += 1
        user.reset_token_hash = ""
        user.reset_token_expires_at = None
        user.reset_token_used_at = now
        await session.execute(delete(AdminSession).where(AdminSession.admin_user_id == user.id))
        session.add(SystemLog(level="WARNING", component="auth", message="ADMIN_PASSWORD_SET_LOCAL"))
        await session.commit()
    print("Administrator password updated. Existing sessions and reset tokens were invalidated.")
    return 0


async def status() -> int:
    async with SessionLocal() as session:
        users = (await session.scalars(select(AdminUser).order_by(AdminUser.id))).all()
        print(f"Admin exists: {'Yes' if users else 'No'}")
        for user in users:
            now = datetime.now(timezone.utc)
            expires = utc_aware(user.reset_token_expires_at)
            active_token = bool(user.reset_token_hash and user.reset_token_used_at is None and expires and expires > now)
            remaining = max(0, (expires - now).total_seconds() / 60) if active_token and expires else 0
            active_sessions = await session.scalar(select(func.count()).select_from(AdminSession).where(
                AdminSession.admin_user_id == user.id,
                AdminSession.session_version == user.session_version,
                AdminSession.revoked_at.is_(None),
                AdminSession.expires_at > now,
            )) or 0
            print(f"Username: {user.username}")
            print(f"Password configured: {'Yes' if user.password_hash else 'No'}")
            print(f"MFA enabled: {'Yes' if user.mfa_enabled else 'No'}")
            print(f"Active reset token: {'Yes' if active_token else 'No'}")
            print(f"Minutes remaining: {remaining:.1f}")
            print(f"Active sessions: {active_sessions}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trusted local HEX ALERT admin recovery")
    sub = parser.add_subparsers(dest="command", required=True)
    reset = sub.add_parser("admin-reset", help="Create/rotate a one-time recovery token")
    reset.add_argument("--username", help="Administrator username (required when multiple accounts exist)")
    set_password = sub.add_parser("admin-set-password", help="Set a password locally without a recovery token")
    set_password.add_argument("--username", help="Administrator username (required when multiple accounts exist)")
    sub.add_parser("admin-status", help="Show safe administrator recovery status")
    args = parser.parse_args(argv)
    if args.command == "admin-status":
        return asyncio.run(status())
    if args.command == "admin-reset":
        return asyncio.run(admin_reset(args.username))
    if args.command == "admin-set-password":
        async def prompt_and_set() -> int:
            async with SessionLocal() as session:
                users = (await session.scalars(select(AdminUser).order_by(AdminUser.id))).all()
            target = args.username or (users[0].username if len(users) == 1 else None)
            if not target:
                print("Use --username when multiple administrator accounts exist.", file=sys.stderr)
                return 2
            password = getpass.getpass("New administrator password (input hidden): ")
            confirmation = getpass.getpass("Confirm new password (input hidden): ")
            return await set_admin_password(target, password, confirmation)
        return asyncio.run(prompt_and_set())
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
