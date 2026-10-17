from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", env_ignore_empty=True, extra="ignore")

    discord_token: str = ""
    database_url: str = "postgresql+asyncpg://localhost/hexalert"
    redis_url: str = ""
    ai_provider: str = "local_gguf"
    openai_api_key: str = ""
    gemini_api_key: str = ""
    groq_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"
    ai_model: str = ""
    job_channel_id: int | None = None
    news_channel_id: int | None = None
    cve_channel_id: int | None = None
    zero_day_channel_id: int | None = None
    tech_channel_id: int | None = None
    threat_channel_id: int | None = None
    github_tools_channel_id: int | None = None
    research_channel_id: int | None = None
    digest_channel_id: int | None = None
    status_channel_id: int | None = None
    nvd_api_key: str = ""
    github_token: str = ""
    poll_jobs_minutes: int = 45
    poll_news_minutes: int = 20
    poll_cve_minutes: int = 12
    poll_tech_minutes: int = 120
    poll_threats_minutes: int = 30
    daily_digest_hour: int = 8
    daily_digest_timezone: str = "Asia/Kolkata"
    app_timezone: str = "Asia/Kolkata"
    time_format: str = "12h"
    auto_backup_daily: bool = True
    backup_hour_utc: int = 3
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    admin_user_ids: str = ""
    dashboard_api_key: str = ""
    session_secret: str = ""
    # Test routing is the safe first-run default; production requires an explicit admin switch.
    test_mode: bool = True
    test_channel_id: int | None = None
    critical_cve_threshold: float = 8.0
    max_job_alerts_per_run: int = 5
    high_fit_job_threshold: int = 75
    job_fresh_hours: int = 24
    job_acceptable_days: int = 7
    job_location_priorities: str = "Remote,Remote India,India,Rajasthan,Jaipur,Delhi,Delhi NCR,Gurugram,Gurgaon,Noida"
    log_level: str = "INFO"
    request_timeout_seconds: int = 20
    news_feeds: str = "https://feeds.feedburner.com/TheHackersNews,https://www.bleepingcomputer.com/feed/,https://www.cisa.gov/cybersecurity-advisories/all.xml"
    threat_feeds: str = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    job_feeds: str = ""
    tech_feeds: str = "https://github.blog/category/security/feed/,https://hnrss.org/newest?q=cybersecurity"

    @staticmethod
    def _list(raw: str) -> list[str]:
        return [item.strip() for item in raw.split(",") if item.strip()]

    @property
    def news_feed_urls(self) -> list[str]: return self._list(self.news_feeds)
    @property
    def threat_feed_urls(self) -> list[str]: return self._list(self.threat_feeds)
    @property
    def job_feed_urls(self) -> list[str]: return self._list(self.job_feeds)
    @property
    def tech_feed_urls(self) -> list[str]: return self._list(self.tech_feeds)
    @property
    def job_location_priority_list(self) -> list[str]: return self._list(self.job_location_priorities)
    @property
    def admin_ids(self) -> set[int]:
        return {int(v) for v in self._list(self.admin_user_ids) if v.isdigit()}


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    from config.runtime_config import get_runtime_config

    runtime = get_runtime_config(settings.session_secret or settings.dashboard_api_key)
    fields = {
        "DISCORD_TOKEN": "discord_token",
        "AI_PROVIDER": "ai_provider",
        "AI_MODEL": "ai_model",
        "OLLAMA_BASE_URL": "ollama_base_url",
        "OPENAI_API_KEY": "openai_api_key",
        "GEMINI_API_KEY": "gemini_api_key",
        "GROQ_API_KEY": "groq_api_key",
        "TEST_MODE": "test_mode",
        "APP_TIMEZONE": "app_timezone",
        "TIME_FORMAT": "time_format",
        "HIGH_FIT_JOB_THRESHOLD": "high_fit_job_threshold",
        "JOB_FRESH_HOURS": "job_fresh_hours",
        "JOB_ACCEPTABLE_DAYS": "job_acceptable_days",
        "JOB_LOCATION_PRIORITIES": "job_location_priorities",
    }
    overrides = {field: runtime[key] for key, field in fields.items() if key in runtime}
    # Discord credentials are dashboard-managed only; never consume a bootstrap .env token.
    overrides["discord_token"] = runtime.get("DISCORD_TOKEN", "")
    return Settings(**{**settings.model_dump(), **overrides}) if overrides else settings
