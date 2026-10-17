from datetime import datetime, timedelta, timezone

from services.scheduler import CollectionScheduler


class FixedRandom:
    def __init__(self, result):
        self.result = result
        self.bounds = None

    def randint(self, low, high):
        self.bounds = (low, high)
        assert low <= self.result <= high
        return self.result


def test_startup_preserves_a_future_collection_due_time():
    now = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
    last_run = now - timedelta(minutes=10)

    result = CollectionScheduler.startup_run_at(last_run, 30, now=now)

    assert result == now + timedelta(minutes=20)


def test_startup_delays_missed_runs_by_ten_to_thirty_minutes():
    now = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
    rng = FixedRandom(17)

    result = CollectionScheduler.startup_run_at(
        now - timedelta(hours=3), 30, now=now, rng=rng
    )

    assert rng.bounds == (10, 30)
    assert result == now + timedelta(minutes=17)


def test_first_run_is_staggered_instead_of_firing_at_startup():
    now = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
    rng = FixedRandom(8)

    result = CollectionScheduler.startup_run_at(None, 30, now=now, rng=rng)

    assert rng.bounds == (1, 15)
    assert result == now + timedelta(minutes=8)


def test_naive_persisted_run_time_is_treated_as_utc():
    now = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
    last_run = datetime(2026, 10, 8, 11, 50)

    result = CollectionScheduler.startup_run_at(last_run, 30, now=now)

    assert result == now + timedelta(minutes=20)
