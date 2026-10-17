import gzip
import httpx
import pytest

from collectors.base import Collector
from collectors.news.collector import SECURITY_TERMS
from collectors.jobs.collector import ROLE, FRESHER
from collectors.threat_intel.collector import THREAT


def test_news_quality_filter():
    assert SECURITY_TERMS.search("CISA publishes vulnerability advisory")
    assert not SECURITY_TERMS.search("New quarterly earnings report")


def test_job_role_and_fresher_classification():
    description = "SOC Analyst Intern - entry level security operations"
    assert ROLE.search(description)
    assert FRESHER.search(description)


def test_threat_intel_filter():
    assert THREAT.search("Ransomware campaign targets government systems")
    assert not THREAT.search("New laptop review")


@pytest.mark.asyncio
async def test_collector_decompresses_body_once():
    payload = b'{"ok":true}'
    encoded = gzip.compress(payload)
    collector = Collector()
    await collector.client.aclose()
    collector.client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, headers={"content-encoding": "gzip", "content-length": str(len(encoded))}, content=encoded)
    ))
    try:
        response = await collector._request("https://example.org/data.json", max_bytes=1024)
        assert response.json() == {"ok": True}
        assert "content-encoding" not in response.headers
        assert response.headers["content-length"] == str(len(payload))
    finally:
        await collector.close()
