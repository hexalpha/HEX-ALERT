from pathlib import Path

from launcher.docker_manager import DockerManager, redact
from launcher.settings import defaults, load, save, settings_path


def test_launcher_redacts_environment_secrets_and_provider_tokens():
    message = "DISCORD_TOKEN=do-not-show\npassword: hunter2\nBot abcdefghijklmnopqrstuvwxyz0123456789\nsk-abcdefghijklmnop1234"
    cleaned = redact(message)
    assert "do-not-show" not in cleaned
    assert "hunter2" not in cleaned
    assert "abcdefghijklmnopqrstuvwxyz0123456789" not in cleaned
    assert "sk-abcdefghijklmnop1234" not in cleaned


def test_launcher_prefs_are_nonsecret_and_persist_under_appdata(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    root = tmp_path / "project"
    values = defaults(root)
    values["auto_start_services"] = True
    save(values)
    loaded = load(root)
    assert loaded["auto_start_services"] is True
    assert loaded["health_poll_seconds"] == 7
    content = settings_path().read_text(encoding="utf-8")
    assert "DISCORD_TOKEN" not in content
    assert "SESSION_SECRET" not in content


def test_launcher_start_excludes_local_ai_when_model_is_missing(monkeypatch, tmp_path):
    root = tmp_path
    (root / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    (root / ".env").write_text("TEST_MODE=true", encoding="utf-8")
    manager = DockerManager(root)
    commands = []
    monkeypatch.setattr(manager, "validate_files", lambda: None)
    monkeypatch.setattr(manager, "compose", lambda args, **kwargs: commands.append(args))
    manager.start()
    assert commands == [
        ["config", "--quiet", "db", "config-init", "bot"],
        ["up", "-d", "--build", "db", "config-init", "bot"],
    ]


def test_launcher_start_includes_model_service_when_gguf_exists(monkeypatch, tmp_path):
    root = tmp_path
    (root / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    (root / ".env").write_text("TEST_MODE=true", encoding="utf-8")
    (root / "CyberSecurity.gguf").write_bytes(b"existing-model")
    manager = DockerManager(root)
    commands = []
    monkeypatch.setattr(manager, "validate_files", lambda: None)
    monkeypatch.setattr(manager, "compose", lambda args, **kwargs: commands.append(args))
    manager.start()
    assert commands == [["config", "--quiet"], ["up", "-d", "--build"]]
