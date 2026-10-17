from pathlib import Path

from scripts.setup_local import create_environment


def test_fresh_setup_generates_matching_database_credentials_and_keeps_test_mode(tmp_path):
    template = Path(__file__).parents[1] / ".env.example"
    (tmp_path / ".env.example").write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    assert create_environment(tmp_path) is True
    values = dict(line.split("=", 1) for line in (tmp_path / ".env").read_text().splitlines()
                  if line and not line.startswith("#") and "=" in line)
    assert len(values["POSTGRES_PASSWORD"]) >= 32
    assert f':{values["POSTGRES_PASSWORD"]}@db' in values["DATABASE_URL"]
    assert len(values["SESSION_SECRET"]) >= 48
    assert values["SESSION_SECRET"] != values["DASHBOARD_API_KEY"]
    assert values["TEST_MODE"] == "true"
    assert "change-me" not in values["DATABASE_URL"]


def test_setup_never_replaces_existing_configuration(tmp_path):
    path = tmp_path / ".env"
    path.write_text("existing configuration", encoding="utf-8")
    assert create_environment(tmp_path) is False
    assert path.read_text() == "existing configuration"
