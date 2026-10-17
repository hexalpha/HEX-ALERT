import pytest
import asyncio
import socket
from collectors.base import validate_public_url, PinnedAsyncHTTPTransport, _is_non_public_address


@pytest.mark.parametrize("url", ["https://example.org/feed.xml", "http://cisa.gov/feed"])
def test_public_urls_are_allowed(url): assert validate_public_url(url) == url


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://localhost/a", "http://127.0.0.1/", "http://10.0.0.1/feed", "http://user:pass@example.org/", "https://example.org/feed?api_key=do-not-allow"])
def test_private_and_non_http_urls_are_rejected(url):
    with pytest.raises(ValueError): validate_public_url(url)


@pytest.mark.parametrize("url", [
    "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/",
    "http://0/", "http://[::ffff:127.0.0.1]/", "http://[fc00::1]/",
    "http://[fe80::1]/", "http://224.0.0.1/", "http://169.254.169.254/",
])
def test_reject_legacy_and_reserved_address_spellings(url):
    with pytest.raises(ValueError): validate_public_url(url)


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254",
    "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:192.168.1.1",
])
def test_non_public_ip_filter(address):
    assert _is_non_public_address(address)


@pytest.mark.asyncio
async def test_transport_connects_to_validated_pin(monkeypatch):
    async def resolver(self, host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", resolver)
    transport = PinnedAsyncHTTPTransport()
    calls = []

    class FakeBackend:
        async def connect_tcp(self, host, port, **kwargs):
            calls.append((host, port))
            return object()
        async def sleep(self, seconds): pass

    transport._pinned_backend._backend = FakeBackend()
    try:
        await transport.pin("example.test")
        await transport._pinned_backend.connect_tcp("example.test", 443)
        assert calls == [("93.184.216.34", 443)]
    finally:
        await transport.aclose()
