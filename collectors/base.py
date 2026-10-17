import asyncio
import ipaddress
import logging
import random
import re
import socket
from urllib.parse import urlsplit, urljoin, parse_qsl
import httpx
import httpcore
from config.settings import get_settings

log = logging.getLogger("hexalert.collectors")


def _normal_host(host: str) -> str:
    return host.rstrip(".").lower()


def _is_non_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("224.0.0.0/4"):
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip in ipaddress.ip_network("ff00::/8"):
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_non_public_address(str(ip.ipv4_mapped))
    # is_global is deliberately used as the allow-list: it excludes private,
    # loopback, link-local, multicast, reserved, unspecified and mapped private IPs.
    return not ip.is_global


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Connect to prevalidated IPs while httpcore retains the original TLS name."""

    def __init__(self):
        from httpcore._backends.auto import AutoBackend
        self._backend = AutoBackend()
        self._pins: dict[str, str] = {}

    async def pin(self, hostname: str) -> str:
        host = _normal_host(hostname)
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".internal")):
            raise ValueError("Local network hosts are not allowed")
        try:
            # inet_aton accepts legacy decimal, octal and hex IPv4 spellings.
            # Reject them unless they are the canonical ipaddress representation.
            legacy_ip = socket.inet_aton(host)
        except OSError:
            legacy_ip = None
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if legacy_ip is not None:
            parsed = ipaddress.IPv4Address(legacy_ip)
            if literal is None or parsed != literal:
                if not parsed.is_global:
                    raise ValueError("Non-public IP URLs are not allowed")
                raise ValueError("Non-canonical numeric IP URLs are not allowed")
        if literal is not None:
            if _is_non_public_address(str(literal)):
                raise ValueError("Non-public IP URLs are not allowed")
            address = str(literal)
        else:
            try:
                records = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            except (OSError, UnicodeError) as exc:
                raise ValueError("Source hostname could not be resolved") from exc
            addresses = {record[4][0].split("%", 1)[0] for record in records}
            if not addresses or any(_is_non_public_address(item) for item in addresses):
                raise ValueError("Source host resolves to a non-public address")
            # Pin one validated result; no second DNS query occurs during connect.
            address = sorted(addresses)[0]
        self._pins[host] = address
        return address

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                          local_address: str | None = None, socket_options=None):
        original = _normal_host(host.decode("ascii") if isinstance(host, bytes) else host)
        address = self._pins.get(original)
        if not address:
            # Fail closed if a request reaches the transport without preflight.
            address = await self.pin(original)
        return await self._backend.connect_tcp(address, port, timeout=timeout,
                                               local_address=local_address, socket_options=socket_options)

    async def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options=None):
        raise ValueError("Unix sockets are not allowed for public source requests")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport whose TCP connections use the exact validated DNS pin."""

    def __init__(self, **kwargs):
        # Proxies are intentionally not accepted: a proxy would perform its own DNS lookup.
        if kwargs.get("proxy"):
            raise ValueError("Proxies are not permitted for public source fetching")
        kwargs["trust_env"] = False
        super().__init__(**kwargs)
        self._pinned_backend = _PinnedBackend()
        self._pool._network_backend = self._pinned_backend

    async def pin(self, hostname: str) -> str:
        return await self._pinned_backend.pin(hostname)


def validate_public_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise ValueError("Only credential-free HTTP(S) URLs are allowed")
    credential_names={"token","access_token","refresh_token","api_key","apikey","key","secret","password","credential","authorization","client_secret"}
    if any(name.lower() in credential_names or name.lower().endswith(("_token","_key","_secret","_password")) for name,_ in parse_qsl(parts.query)):
        raise ValueError("Do not place credentials in source URL query parameters; use an environment variable reference")
    host = _normal_host(parts.hostname)
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal", ".localhost")):
        raise ValueError("Local network URLs are not allowed")
    try:
        legacy_ip = socket.inet_aton(host)
    except OSError:
        legacy_ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if legacy_ip is not None:
        parsed = ipaddress.IPv4Address(legacy_ip)
        if ip is None or parsed != ip:
            if not parsed.is_global: raise ValueError("Non-public IP URLs are not allowed")
            raise ValueError("Non-canonical numeric IP URLs are not allowed")
    if ip is not None and _is_non_public_address(str(ip)):
        raise ValueError("Non-public IP URLs are not allowed")
    return url


class Collector:
    def __init__(self):
        self.settings = get_settings()
        self.transport = PinnedAsyncHTTPTransport()
        self.client = httpx.AsyncClient(timeout=self.settings.request_timeout_seconds, follow_redirects=False, headers={"User-Agent": "HexAlert/1.0 (+public security information aggregator)"}, transport=self.transport)
        self._failures = 0
        self._open_until = 0.0

    async def close(self): await self.client.aclose()

    async def get(self, url: str, *, max_bytes: int = 2_000_000, allow_error_status: bool = False, **kwargs) -> httpx.Response:
        validate_public_url(url)
        if asyncio.get_running_loop().time() < self._open_until: raise RuntimeError("Source circuit breaker is open")
        try:
            max_bytes=max(1024,min(10_000_000,int(max_bytes)))
            response = None
            for attempt in range(3):
                response = await self._safe_request(url, max_bytes=max_bytes, **kwargs)
                if response.status_code not in {429,500,502,503,504} or attempt==2: break
                retry_after=response.headers.get("Retry-After","")
                delay=min(30,int(retry_after)) if retry_after.isdigit() else min(8,2**attempt+random.random())
                await asyncio.sleep(delay)
            if not allow_error_status: response.raise_for_status()
            self._failures = 0
            return response
        except Exception:
            self._failures += 1
            if self._failures >= 5:
                self._open_until = asyncio.get_running_loop().time() + min(900, 30 * 2 ** min(self._failures - 5, 4))
            raise

    async def _safe_request(self, url: str, *, max_bytes: int, **kwargs):
        # Resolve and reject private destinations, then revalidate each redirect target.
        current = url
        request_kwargs=dict(kwargs)
        for _ in range(4):
            validate_public_url(current)
            host = urlsplit(current).hostname
            loop = asyncio.get_running_loop()
            await self.transport.pin(host)
            for attempt in range(3):
                try:
                    response = await self._request(current, max_bytes=max_bytes, **request_kwargs)
                    break
                except (httpx.TimeoutException, httpx.NetworkError):
                    if attempt == 2: raise
                    await asyncio.sleep(min(8, 2 ** attempt + random.random()))
            if response.status_code not in {301, 302, 303, 307, 308}: return response
            target = response.headers.get("location")
            if not target: return response
            destination=urljoin(current,target)
            old=urlsplit(current);new=urlsplit(destination)
            if (old.scheme.lower(),old.hostname,old.port)!=(new.scheme.lower(),new.hostname,new.port):
                headers=dict(request_kwargs.get("headers",{}))
                request_kwargs["headers"]={key:value for key,value in headers.items() if key.lower() not in {"authorization","proxy-authorization","cookie","x-api-key"}}
            current = destination
        raise ValueError("Too many redirects")

    async def _request(self, url: str, *, max_bytes: int, **kwargs):
        async with self.client.stream("GET",url,**kwargs) as response:
            body=bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body)>max_bytes: raise ValueError(f"Source response exceeded its {max_bytes} byte limit")
            # aiter_bytes() already decoded gzip/deflate/br; do not retain headers
            # that would make downstream parsers attempt a second decompression.
            headers={key:value for key,value in response.headers.items() if key.lower() not in {"content-encoding","content-length","transfer-encoding"}}
            return httpx.Response(response.status_code,headers=headers,content=bytes(body),request=response.request)
