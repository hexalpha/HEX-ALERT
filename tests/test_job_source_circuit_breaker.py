from datetime import datetime, timedelta, timezone

from collectors.jobs.collector import source_retry_delay, source_retry_due


def test_source_backoff_starts_at_threshold_and_grows_exponentially():
    assert source_retry_delay(4) == timedelta(0)
    assert source_retry_delay(5) == timedelta(minutes=5)
    assert source_retry_delay(6) == timedelta(minutes=10)
    assert source_retry_delay(7) == timedelta(minutes=20)


def test_source_backoff_is_bounded_to_one_day():
    assert source_retry_delay(30) == timedelta(hours=24)


def test_unhealthy_source_waits_until_persisted_retry_window():
    now = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
    last_failure = now - timedelta(minutes=4)

    assert not source_retry_due(5, last_failure, now)
    assert source_retry_due(5, last_failure, now + timedelta(minutes=1))


def test_naive_failure_timestamp_is_interpreted_as_utc():
    now = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
    last_failure = datetime(2026, 10, 8, 11, 50)

    assert source_retry_due(6, last_failure, now)
