"""Create a source-plus-launcher Windows package without secrets or the GGUF model."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "release" / "HEX-ALERT-Windows"
EXE = ROOT / "dist" / "HEX-ALERT.exe"
SKIP_DIRS = {
    ".git", ".venv", ".venv313", ".venv314", "__pycache__", ".pytest_cache",
    ".builddeps", ".pyinstaller-cache", "archive", "node_modules", "build", "dist",
    "release", "backups", "tests", "artifacts", "runtime-config", "runtime_config",
}
SKIP_FILES = {".env", "CyberSecurity.gguf"}
SKIP_SUFFIXES = {".pyc", ".log", ".db", ".sqlite", ".sqlite3", ".dump", ".zip", ".bak", ".gguf"}


def package() -> Path:
    if not EXE.is_file():
        raise SystemExit(f"Build the standalone launcher first: {EXE}")
    if DEST.exists() and any(DEST.iterdir()):
        raise SystemExit(f"Release destination already contains files; review it before packaging: {DEST}")
    DEST.mkdir(parents=True, exist_ok=True)
    for current, directories, files in os.walk(ROOT):
        current_path = Path(current)
        directories[:] = [name for name in directories if name not in SKIP_DIRS and not name.startswith(".venv")]
        for filename in files:
            source = current_path / filename
            if filename in SKIP_FILES or source.suffix.lower() in SKIP_SUFFIXES:
                continue
            target = DEST / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    shutil.copy2(EXE, DEST / EXE.name)
    runtime_assets = ROOT / "dist" / "_internal"
    if runtime_assets.is_dir():
        shutil.copytree(runtime_assets, DEST / "_internal", dirs_exist_ok=True)
    (DEST / "README-FIRST-RUN.txt").write_text(
        "HEX ALERT — WINDOWS FIRST RUN\n\n"
        "Requirements: Windows x64 and Docker Desktop. The launcher does not install Docker.\n"
        "1. For an existing HEX ALERT installation, open Settings and select its original project folder "
        "(for this installation: D:\\CyArt\\Discord Bot). This preserves its Compose project and volumes.\n"
        "2. Double-click HEX-ALERT.exe and choose Start HEX ALERT.\n"
        "3. Wait for dashboard/database/bot health. Local AI may take about two minutes to load.\n"
        "4. Finish first-run setup in http://127.0.0.1:8080 and configure Discord in the dashboard.\n\n"
        "This package includes the Windows runtime files in _internal. It excludes .env, backups, runtime secrets, databases, and CyberSecurity.gguf. "
        "The local AI model remains outside the executable; configure the project folder that contains it.\n"
        "Start, Stop and Restart preserve Docker volumes. Never use `docker compose down -v` for normal operation.\n",
        encoding="utf-8",
    )
    return DEST


if __name__ == "__main__":
    destination = package()
    print(f"Windows release created: {destination}")
    print(f"Executable size: {(destination / EXE.name).stat().st_size:,} bytes")
