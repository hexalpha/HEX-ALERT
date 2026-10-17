# Install and operate HEX ALERT

## Requirements

- Docker Engine/Desktop with Compose v2; Linux containers on Windows.
- Git to clone this repository.
- Python 3.12+ for the optional first-run setup helper and development.
- Your own Discord bot application for Discord delivery.
- A compatible GGUF model and sufficient available RAM if using Local AI. Weights are not provided.

## Fresh installation

```powershell
git clone https://github.com/hexalpha/HEX-ALERT.git
cd HEX-ALERT
python scripts/setup_local.py
docker compose build bot
docker compose up -d db config-init bot
```

The setup helper creates `.env` with independent random secrets and matching database credentials. It preserves an existing `.env` and never displays the generated values. On Windows, `py -3` can replace `python`; on Linux/macOS use `python3` if needed. Keep the file private and back up its encryption secret securely.

Alternatively copy `.env.example` to `.env`, replace all three secret placeholders, and use the same database password in `POSTGRES_PASSWORD` and `DATABASE_URL`. URL-encode special characters in the database URL password. The template is not a production credential set.

Open **http://127.0.0.1:8080** and create the first admin account. Use the dashboard to configure Discord, sources, routing and AI. First-run collection may take a polling cycle to populate records.

## Optional Local AI

Place your own compatible model at `CyberSecurity.gguf` in the project root, then run:

```powershell
docker compose up -d --build llm
```

The file is mounted read-only at `/models/CyberSecurity.gguf`. It stays outside Docker images, Git and release assets. Cold loading may take several minutes on CPU. The dashboard/database can operate while AI is loading or unavailable. Choose Local GGUF in **AI Settings**; external fallback is off by default. See [the local AI guide](../LOCAL%20AI%20GUIDE.md).

## Discord configuration

1. Create a bot in the Discord Developer Portal and invite it with `bot` and `applications.commands` scopes.
2. Grant View Channel, Send Messages, Embed Links and Read Message History for its target channels. Administrator is unnecessary.
3. Open **Discord → Connection**, enter the token, test the connection, select the server and save.
4. Open **Channel Routing** and map categories, including a dedicated test channel.
5. Keep **TEST_MODE enabled** and validate individual routes with clearly labeled tests.

The token is encrypted in the runtime volume. Channel mappings live in PostgreSQL. `/ask` and outgoing alerts do not require Message Content intent. Member join/leave automation needs the Members intent; review the dashboard's intent status before enabling it. Optional mention chat has its own setting.

## Daily operation

```powershell
docker compose ps
docker compose logs --tail=100 bot
docker compose stop
docker compose up -d db config-init bot
```

Start `llm` separately when its model is installed, or use `docker compose up -d` for the full configured stack. No normal shutdown should remove named volumes. Never use `down -v` to troubleshoot a live installation.

## Windows control center

Build the native launcher from the source checkout:

```powershell
.\launcher\build.ps1
```

Then double-click `dist\HEX-ALERT.exe`. It discovers the source folder from its parents and can also use a configured project folder. Docker Desktop remains required. Python, GGUF weights, secrets and Docker images are not bundled in the executable. See [Launcher Guide](../LAUNCHER%20GUIDE.md).

## Persistent data and recovery

| Data | Location |
| --- | --- |
| Database records | `postgres_data` named volume |
| Encrypted credentials and runtime settings | `hex_runtime_config` named volume |
| Backup archives | `hex_backups` named volume |
| LLM service state | `llm_state` named volume |
| Bootstrap encryption secret and DB credentials | Local `.env` |
| Model | Host `CyberSecurity.gguf` file |

Compose prefixes volume names with the project name. Keep the same project directory/name when restarting an existing installation; changing it can select different volumes. Preserve the original `.env` and encryption secret. A database backup alone does not replace secure backup of the runtime secret store and its key.

Use **Settings → Backup** for configured data backups and review the restore confirmation carefully. For local account recovery, see `python manage.py --help` and run the supported admin command inside the bot container. Do not share reset tokens or use them in public issues.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Dashboard does not open | Docker engine, `docker compose ps`, port 8080 and bot logs |
| Fresh install cannot find config-init image | Run `docker compose build bot`; both services use `hex-alert-bot:local` |
| Database login fails | `POSTGRES_PASSWORD` and URL password match; existing volume credentials are preserved |
| AI is offline | External model file exists, sufficient memory, LLM health/logs |
| Discord is offline | Token configuration, server membership, permissions and network access |
| No scheduled messages | Test mode deliberately suppresses production delivery; also inspect source/rule status |
| Source fails | Check permitted access, current feed URL, parser preview and rate limits |

Health and screenshots describe one point in time. This source preview is not a production security certification.
