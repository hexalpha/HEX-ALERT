"""Docker Desktop and Compose operations for the HEX ALERT launcher."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0) | CREATE_NO_WINDOW


def docker_cli() -> str | None:
    found = shutil.which("docker")
    if found:
        return found
    candidates = (
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
        Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Docker" / "resources" / "bin" / "docker.exe",
    )
    return str(next((p for p in candidates if p.is_file()), "")) or None


def desktop_executable() -> Path | None:
    candidates = (
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "Docker Desktop.exe",
        Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "Docker" / "Docker" / "Docker Desktop.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Docker" / "Docker" / "Docker Desktop.exe",
    )
    return next((p for p in candidates if p.is_file()), None)


class DockerManager:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.cli = docker_cli()

    def set_root(self, root: Path) -> None:
        self.root = root.resolve()

    def _run(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        self.cli = self.cli or docker_cli()
        if not self.cli:
            raise RuntimeError("Docker Desktop is required. Install Docker Desktop, then retry.")
        try:
            return subprocess.run([self.cli, *args], cwd=self.root, capture_output=True,
                                  text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"Docker operation timed out after {timeout} seconds.") from exc

    def engine_ready(self) -> bool:
        result = self._run(["info", "--format", "{{.ServerVersion}}"], timeout=8)
        return result.returncode == 0 and bool(result.stdout.strip())

    def ensure_engine(self, progress=lambda _message: None, timeout: int = 120) -> None:
        if self.engine_ready():
            progress("Docker engine ready.")
            return
        desktop = desktop_executable()
        if not desktop:
            if not self.cli:
                raise RuntimeError("Docker Desktop not found. Docker Desktop is required to run HEX ALERT.")
            raise RuntimeError("Docker Desktop not found or its engine is stopped. Start Docker Desktop, then retry.")
        progress("Starting Docker Desktop…")
        subprocess.Popen([str(desktop)], cwd=str(desktop.parent), creationflags=DETACHED,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(3)
            try:
                if self.engine_ready():
                    progress("Docker engine ready.")
                    return
            except (RuntimeError, TimeoutError):
                pass
        raise TimeoutError("Docker engine is still starting. Open Docker Desktop and wait until it reports Running.")

    def compose(self, args: list[str], timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess:
        if not (self.root / "docker-compose.yml").is_file() and not (self.root / "compose.yml").is_file():
            raise RuntimeError(f"Compose file not found in the selected project folder: {self.root}")
        result = self._run(["compose", *args], timeout=timeout)
        if check and result.returncode:
            detail = (result.stderr or result.stdout or "Docker Compose operation failed.").strip()[-1800:]
            raise RuntimeError(redact(detail))
        return result

    def compose_rows(self) -> list[dict]:
        result = self.compose(["ps", "--all", "--format", "json"], timeout=15, check=False)
        if result.returncode:
            return []
        output = result.stdout.strip()
        if not output:
            return []
        try:
            parsed = json.loads(output)
            return parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            rows = []
            for line in output.splitlines():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return rows

    def start(self, progress=lambda _message: None) -> None:
        self.validate_files()
        model = self.root / "CyberSecurity.gguf"
        services = [] if model.is_file() else ["db", "config-init", "bot"]
        self.compose(["config", "--quiet", *services], timeout=45)
        self.compose(["up", "-d", "--build", *services], timeout=900)
        progress("Docker Compose services started.")

    def stop(self) -> None:
        self.compose(["stop"], timeout=180)

    def restart(self) -> None:
        self.compose(["restart"], timeout=300)

    def logs(self, service: str = "") -> str:
        args = ["logs", "--tail=200", "--no-color"]
        if service in {"bot", "llm", "db"}:
            args.append(service)
        result = self.compose(args, timeout=30, check=False)
        return redact(result.stdout + ("\n" + result.stderr if result.stderr else ""))[-160_000:]

    def validate_files(self) -> None:
        compose_file = self.root / "docker-compose.yml"
        if not compose_file.is_file() and not (self.root / "compose.yml").is_file():
            raise RuntimeError("docker-compose.yml was not found in the configured project folder.")
        if not (self.root / ".env").is_file():
            raise RuntimeError("Application configuration is missing. Use the launcher Settings to initialize configuration.")
        if not (self.root / "CyberSecurity.gguf").is_file():
            # Model absence does not prevent database, bot, dashboard, or scheduler operation.
            return


def redact(text: str) -> str:
    import re
    patterns = (
        (r"(?im)^(\s*(?:DISCORD_TOKEN|OPENAI_API_KEY|GEMINI_API_KEY|GROQ_API_KEY|GITHUB_TOKEN|NVD_API_KEY|SESSION_SECRET|DASHBOARD_API_KEY|POSTGRES_PASSWORD|DATABASE_URL|AI_ENCRYPTION_KEY)\s*[=:]\s*).+$", r"\1[REDACTED]"),
        (r"(?i)(\b(?:token|api[_ -]?key|secret|password)\b\s*[=:]\s*)([^\s,;]+)", r"\1[REDACTED]"),
        (r"(?i)(Bot\s+)[A-Za-z0-9._-]{20,}", r"\1[REDACTED]"),
        (r"(?i)(sk-[A-Za-z0-9_-]{16,})", "[REDACTED_KEY]"),
        (r"(?i)(gh[pousr]_[A-Za-z0-9]{20,})", "[REDACTED_TOKEN]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text
