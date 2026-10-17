"""Bounded ATS discovery from public company pages; discoveries are never enabled."""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup


ATS_HOSTS = {
    "boards.greenhouse.io": "greenhouse",
    "job-boards.greenhouse.io": "greenhouse",
    "jobs.lever.co": "lever",
    "jobs.ashbyhq.com": "ashby",
}


def ats_type(url: str) -> str | None:
    host = (urlsplit(url).hostname or "").casefold()
    return next((kind for suffix, kind in ATS_HOSTS.items() if host == suffix or host.endswith("." + suffix)), None)


def discover_ats_links(html: str, base_url: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    direct = ats_type(base_url)
    if direct:
        seen.add((direct, base_url))
        candidates.append({"source_type": direct, "url": base_url, "evidence": "Provided domain is a public ATS board"})
    soup = BeautifulSoup(html or "", "html.parser")
    for link in soup.select("a[href]")[:500]:
        absolute = urljoin(base_url, str(link.get("href") or "").strip())
        kind = ats_type(absolute)
        if not kind:
            continue
        parts = urlsplit(absolute)
        board_url = f"{parts.scheme}://{parts.netloc}/{parts.path.strip('/').split('/')[0]}"
        key = (kind, board_url)
        if key in seen:
            continue
        seen.add(key)
        candidates.append({"source_type": kind, "url": board_url,
                           "evidence": "Linked from the supplied public company page"})
    return candidates[:10]
