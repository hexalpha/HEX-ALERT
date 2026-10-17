# Publication verification

This page records checks for the source snapshot published on October 17, 2026. It distinguishes automated validation from deployment-specific integrations.

## Source publication checks

| Check | Result |
| --- | --- |
| Curated source inventory | PASS — secrets, runtime data, backups, binaries and model weights excluded |
| High-confidence credential scan | PASS |
| Python compilation | PASS |
| Dashboard JavaScript syntax | PASS |
| Docker Compose configuration | PASS |
| Isolated Docker regression suite | PASS — 253 passed, 0 failed, 5 dependency/deprecation warnings |

The publication run used Python 3.12 in a disposable Docker container with a temporary SQLite database and a private temporary runtime configuration directory. The repository workflow repeats the same type of isolated validation. This does not contact a real Discord server or load local GGUF weights.

## Running development installation

At the screenshot capture point, the existing local installation reported:

- application health: healthy;
- bot: online;
- PostgreSQL: online;
- scheduler: running;
- Local GGUF: ready through llama.cpp;
- test mode: enabled;
- production mode: disabled.

These checks were read from the local health endpoint and running Compose services. They describe that installation at that time and are not portable proof for another deployment.

## Deployment-specific checks

Each operator must validate the following in their own environment:

- Discord token, guild membership, intents, channel permissions and every saved route;
- PostgreSQL persistence, backup/restore and migration procedure;
- permitted source availability, parser previews, schedules and rate limits;
- model compatibility, memory requirements, response quality and model licensing;
- dashboard network exposure, TLS/reverse proxy and access policy;
- production alert rules and volume.

Keep test mode enabled until these checks are complete. A successful CI run does not authorize or enable production alerts.

## Exclusions

The public repository contains no `.env`, runtime configuration, database dump, backup archive, operational log, built executable, Docker image, Discord token, external API key, TOTP secret, reset token or GGUF model weight.
