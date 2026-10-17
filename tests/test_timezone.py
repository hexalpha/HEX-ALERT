from datetime import date, datetime, timezone

from apscheduler.triggers.cron import CronTrigger

from collectors.cve.collector import CVECollector
from collectors.feeds import _coerce_date, is_date_only
from database.models import Base, utcnow
from services.time_utils import format_local_datetime, iso_utc, parse_datetime, to_local_time


def test_utc_converts_to_kolkata_with_zoneinfo():
    source = datetime.fromisoformat("2026-10-01T12:30:00+00:00")
    assert format_local_datetime(source, "Asia/Kolkata") == "01 Oct 2026, 6:00 PM IST"
    assert to_local_time("2026-10-01T12:30:00Z", "Asia/Kolkata").isoformat() == "2026-10-01T18:00:00+05:30"


def test_postgres_style_aware_timestamp_and_offset_are_converted_once():
    source = datetime.fromisoformat("2026-10-01T08:00:00-04:00")
    assert iso_utc(source) == "2026-10-01T12:00:00Z"
    assert format_local_datetime(source, "Asia/Kolkata") == "01 Oct 2026, 5:30 PM IST"


def test_24_hour_display_uses_the_configured_timezone():
    source = datetime.fromisoformat("2026-10-01T12:30:00+00:00")
    assert format_local_datetime(source, "Asia/Kolkata", "24h") == "01 Oct 2026, 18:00 IST"


def test_current_utc_clock_is_aware_and_timestamp_columns_are_timezone_aware():
    assert utcnow().tzinfo is not None and utcnow().utcoffset().total_seconds() == 0
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if column.name.endswith(("_at", "_run", "_fetch", "_success", "_failure", "_seen", "_used")):
                if getattr(column.type, "timezone", None) is not None:
                    assert column.type.timezone, f"{table.name}.{column.name} must be timezone-aware"


def test_local_conversion_crosses_calendar_midnight_correctly():
    assert format_local_datetime("2026-10-01T20:00:00Z", "Asia/Kolkata") == "02 Oct 2026, 1:30 AM IST"


def test_naive_legacy_datetime_is_normalized_as_utc():
    parsed = parse_datetime("2026-10-01T12:30:00")
    assert parsed == datetime(2026, 10, 1, 12, 30, tzinfo=timezone.utc)
    assert iso_utc(datetime(2026, 10, 1, 12, 30)) == "2026-10-01T12:30:00Z"


def test_date_only_value_keeps_its_calendar_date():
    assert parse_datetime("2026-10-01") == date(2026, 10, 1)
    assert format_local_datetime("2026-10-01", "America/New_York") == "01 Oct 2026"
    assert iso_utc("2026-10-01") == "2026-10-01"


def test_publication_date_only_markers_keep_calendar_dates_without_localizing_midnight():
    assert is_date_only("2026-10-01")
    assert not is_date_only("2026-10-01T00:00:00Z")
    assert _coerce_date("2026-10-01") == datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert CVECollector._date_only("2026-10-01")
    assert not CVECollector._date_only("2026-10-01T00:00:00Z")
    assert CVECollector._date("2026-10-01").tzinfo is not None


def test_india_has_no_dst_offset_change():
    zone_winter = to_local_time("2026-01-01T00:00:00Z", "Asia/Kolkata").utcoffset()
    zone_summer = to_local_time("2026-07-01T00:00:00Z", "Asia/Kolkata").utcoffset()
    assert zone_winter == zone_summer
    assert zone_winter.total_seconds() == 5.5 * 60 * 60


def test_daily_digest_cron_is_eight_am_ist_not_eight_am_utc():
    trigger = CronTrigger(hour=8, minute=0, timezone="Asia/Kolkata")
    next_run = trigger.get_next_fire_time(None, datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc))
    assert next_run.isoformat() == "2026-10-01T08:00:00+05:30"
    assert next_run.astimezone(timezone.utc).hour == 2
    assert next_run.astimezone(timezone.utc).minute == 30
