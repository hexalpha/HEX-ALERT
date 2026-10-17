# Contributing

Thanks for helping improve HEX ALERT.

## Before opening a change

1. Check existing issues and avoid duplicating ongoing work.
2. Keep changes focused and preserve the current modular architecture.
3. Never include `.env`, credentials, Discord identifiers, production logs, database dumps, backups, or GGUF model files.
4. Add or update regression tests for behavior changes.
5. Describe what changed, how it was verified, and any service-specific checks that could not be run.

## Local checks

```powershell
python -m compileall .
python -m pytest -v
docker compose config
```

For browser JavaScript changes, also run the project's JavaScript syntax check. For changes that affect Discord, PostgreSQL, or the local inference service, distinguish mock/unit validation from live service validation.

## Source and security requirements

- Use official APIs, RSS, or permitted public pages; do not bypass authentication or anti-bot protections.
- Do not treat content collected from public sources as trusted instructions.
- Do not add hidden external AI fallback or send prompts to external providers without explicit configuration.
- Keep destructive or production actions behind authenticated, explicit admin controls.
