# HEX ALERT Windows Launcher Guide

## Requirements

- Windows 10/11 x64 with the Windows .NET Framework 4.x runtime (already present on supported Windows 10/11 installations).
- Docker Desktop, installed for the same Windows user who runs the launcher.
- The existing HEX ALERT project folder containing `docker-compose.yml` and `.env.example`.
- `CyberSecurity.gguf` in the project folder for Local AI. If the model is missing, the launcher starts PostgreSQL, the dashboard, bot, and scheduler without Local AI.
- Network access is needed to pull/build images on the first start. Discord is optional for local dashboard and database use.

Python is not required. The launcher is a native Windows Forms executable and runs from `dist\HEX-ALERT.exe` without an adjacent runtime folder. The model and Docker images are never bundled.

## First launch

1. Double-click `dist\HEX-ALERT.exe`.
2. Click **START HEX ALERT**. The launcher checks Docker Desktop, creates a private `.env` with random local secrets if this is the first run, and starts the existing Compose services. It never prints these secrets.
3. Wait for Database, Dashboard, Bot, and Scheduler to become healthy. Local AI can show **Loading** for up to about two minutes after a cold start while the rest of HEX ALERT remains usable.
4. The browser opens when the dashboard is reachable (enabled by default). Complete first-run admin setup there.
5. Configure Discord under **Dashboard → Discord → Connection**. The launcher displays only connected/disconnected status.

The launcher discovers the project in its parent folders, which covers `dist\HEX-ALERT.exe` and `release\HEX-ALERT-Windows\HEX-ALERT.exe`. Choose **Settings → Project folder** to select a different location.

## Daily use

- **Start HEX ALERT** launches Docker Desktop if installed but stopped, runs `docker compose up -d --build`, and waits for database/backend/dashboard/scheduler health. Local AI and Discord report their own states and do not block startup.
- **Stop HEX ALERT** performs a graceful `docker compose stop`. Containers, volumes, PostgreSQL data, runtime configuration, secrets, and model files are preserved.
- **Restart HEX ALERT** restarts the existing services and waits for health.
- **Open Dashboard** is enabled only when the dashboard health endpoint responds.
- **Open Logs** can show all services, bot/backend, Local AI, or PostgreSQL. Common credential formats are redacted.
- **AI Status**, **Discord Status**, and **Refresh Status** display safe metadata only.
- **Exit** asks whether to leave services running or stop them first.

The **TEST_MODE** and **Production** badges are read from the live health endpoint. The launcher does not offer a Production Mode switch.

## Tray and Windows startup

Closing the main window minimizes it to the notification area by default. The tray menu can reopen the control center or dashboard, start/stop/restart HEX ALERT, show status, toggle per-user Windows startup, and exit.

Use **Settings → Start HEX ALERT with Windows** to register the launcher for the current user only. **Auto-start services when launcher opens** is separate and defaults off. Startup and engine waits are bounded.

## Settings and security

Non-secret settings are stored under `%APPDATA%\HexAlert\launcher.ini`. Application secrets remain in the existing protected project configuration and persistent runtime configuration. Settings never open or display `.env`.

The optional Desktop Shortcut action creates `HEX ALERT.lnk` pointing at the current executable. No administrator permission is requested.

## Troubleshooting

- **Docker Desktop is required:** install Docker Desktop and retry. The launcher never installs Docker or requests administrator rights.
- **Docker engine is still starting:** open Docker Desktop and wait until its engine reports Running, then use **Refresh Status**.
- **Port 8080 is already in use:** close the application using it or resolve its port conflict. HEX ALERT does not terminate unrelated processes.
- **PostgreSQL unhealthy:** open Logs and inspect PostgreSQL output. Never delete Docker volumes as a troubleshooting step.
- **Dashboard/backend offline:** inspect bot/backend logs and refresh status. Health waits are bounded.
- **Local AI loading/offline:** verify the model is present at the configured project root. AI may load independently from the other services.
- **Discord disconnected:** configure and test the bot in Dashboard → Discord → Connection. Do not paste credentials into the launcher or chat.

## Developer build

Run `launcher\build.ps1` to compile `dist\HEX-ALERT.exe`. Use `launcher\build.ps1 -DebugBuild` to build a console-enabled diagnostic executable. The launcher uses the installed Windows .NET Framework compiler; Python and PyInstaller are not required.
