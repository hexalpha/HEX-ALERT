from database.repository import digest, normalize_url


def test_normalize_url_removes_tracking_and_fragment():
    assert normalize_url("HTTPS://Example.com/jobs/123/?utm_source=x&ref=mail#apply") == "https://example.com/jobs/123"


def test_digest_ignores_case_and_whitespace():
    assert digest(" Acme  Corp ", "SOC Analyst") == digest("acme corp", "soc analyst")


def test_different_job_sources_have_distinct_fingerprint():
    assert digest("Acme", "SOC Analyst", "Remote", "https://example.com/1") != digest("Acme", "SOC Analyst", "Remote", "https://example.com/2")
