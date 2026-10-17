"""Safe, bounded checks for the local HEX ALERT health endpoint."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


HEALTH_URL = "http://127.0.0.1:8080/health"


def read_health(timeout: float = 2.5) -> dict:
    try:
        request = urllib.request.Request(HEALTH_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return {}
            data = json.loads(response.read().decode("utf-8"))
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError, urllib.error.URLError):
        return {}
