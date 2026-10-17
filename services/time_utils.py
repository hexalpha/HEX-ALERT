"""Shared timezone policy: timestamps are stored/serialized as UTC and formatted locally."""
from __future__ import annotations

from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_TIMEZONE = "Asia/Kolkata"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_timezone(name: str | None = None) -> ZoneInfo:
    try:
        return ZoneInfo(name or DEFAULT_TIMEZONE)
    except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
        raise ValueError("Timezone must be a valid IANA timezone") from exc


def parse_datetime(value: datetime | date | str | None) -> datetime | date | None:
    """Parse timestamps; naive historical/database datetimes are interpreted as UTC."""
    if value is None or isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if len(raw) == 10:
            try:
                return date.fromisoformat(raw)
            except ValueError:
                pass
        try:
            value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def to_utc(value: datetime | str) -> datetime:
    parsed = parse_datetime(value)
    if not isinstance(parsed, datetime):
        raise ValueError("A valid datetime is required")
    return parsed.astimezone(timezone.utc)


def to_local_time(value: datetime | str, timezone_name: str | None = None) -> datetime:
    return to_utc(value).astimezone(get_timezone(timezone_name))


def iso_utc(value: datetime | date | str | None) -> str | None:
    """Canonical ISO output for API timestamps; date-only values remain date-only."""
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    if isinstance(parsed, date) and not isinstance(parsed, datetime):
        return parsed.isoformat()
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def format_local_datetime(value: datetime | date | str | None, timezone_name: str | None = None,
                          time_format: str = "12h") -> str:
    parsed = parse_datetime(value)
    if parsed is None:
        return "Not available"
    if isinstance(parsed, date) and not isinstance(parsed, datetime):
        return parsed.strftime("%d %b %Y")
    local = parsed.astimezone(get_timezone(timezone_name))
    if time_format == "24h":
        return local.strftime("%d %b %Y, %H:%M %Z")
    return local.strftime("%d %b %Y, %I:%M %p %Z").replace(", 0", ", ")
