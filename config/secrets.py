import os
from pathlib import Path
from dotenv import dotenv_values


def secret_value(name: str) -> str | None:
    """Read credentials from the process environment first, then the protected env file."""
    if not name or not name.replace("_", "").isalnum(): return None
    value=os.getenv(name)
    if value:return value
    path=Path(os.getenv("HEX_ALERT_ENV_FILE",".env"))
    try:return dotenv_values(path).get(name)
    except OSError:return None
