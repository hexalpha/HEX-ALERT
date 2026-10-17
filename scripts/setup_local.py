"""Create a fresh local .env without overwriting or displaying credentials."""
from __future__ import annotations

import os
from pathlib import Path
import secrets


def create_environment(root: Path) -> bool:
    destination = root / ".env"
    if destination.exists():
        return False
    template = (root / ".env.example").read_text(encoding="utf-8")
    password = secrets.token_urlsafe(32)
    replacements = {
        "POSTGRES_PASSWORD=change-me": f"POSTGRES_PASSWORD={password}",
        "hexalert:change-me@db": f"hexalert:{password}@db",
        "DASHBOARD_API_KEY=replace-with-a-long-random-value": f"DASHBOARD_API_KEY={secrets.token_urlsafe(48)}",
        "SESSION_SECRET=replace-with-a-different-long-random-value": f"SESSION_SECRET={secrets.token_urlsafe(48)}",
    }
    for marker, replacement in replacements.items():
        if marker not in template:
            raise ValueError("Unexpected configuration template; existing configuration was not changed.")
        template = template.replace(marker, replacement)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(template)
    return True


if __name__ == "__main__":
    project = Path(__file__).resolve().parents[1]
    created = create_environment(project)
    print("Local configuration created. Secrets were generated and are not displayed." if created
          else "Existing .env preserved. No configuration was changed.")
    print("Keep TEST_MODE enabled. Open the dashboard after starting Docker Compose.")
