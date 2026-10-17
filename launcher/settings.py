"""Non-secret, per-user launcher preferences."""
from __future__ import annotations

import json
import os
from pathlib import Path


def settings_path() -> Path:
    base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    return base / "HexAlert" / "launcher.json"


def defaults(project_root: Path) -> dict:
    return {
        "project_root": str(project_root),
        "open_dashboard_after_start": True,
        "close_to_tray": True,
        "start_with_windows": False,
        "auto_start_services": False,
        "health_poll_seconds": 7,
    }


def load(project_root: Path) -> dict:
    values = defaults(project_root)
    try:
        saved = json.loads(settings_path().read_text(encoding="utf-8"))
        if isinstance(saved, dict):
            values.update(saved)
    except (OSError, ValueError, TypeError):
        pass
    values["health_poll_seconds"] = min(10, max(5, int(values.get("health_poll_seconds", 7))))
    values["project_root"] = str(Path(values["project_root"]).expanduser().resolve())
    return values


def save(values: dict) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(values, indent=2), encoding="utf-8")
    os.replace(temporary, path)
