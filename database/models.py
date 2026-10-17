from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from services.time_utils import utc_now


def utcnow() -> datetime: return utc_now()


class Base(DeclarativeBase): pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    discord_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), default="")


class Guild(TimestampMixin, Base):
    __tablename__ = "guilds"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    discord_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(150), default="")


class ChannelConfig(TimestampMixin, Base):
    __tablename__ = "channel_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guild_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(50))
    channel_id: Mapped[str] = mapped_column(String(32))
    __table_args__ = (UniqueConstraint("guild_id", "name"),)


class CustomDiscordRoute(TimestampMixin, Base):
    __tablename__ = "custom_discord_routes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    route_name: Mapped[str] = mapped_column(String(100))
    route_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    guild_id: Mapped[str] = mapped_column(String(32), index=True)
    channel_id: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(50), default="custom")
    keywords: Mapped[list] = mapped_column(JSON, default=list)
    priority: Mapped[int] = mapped_column(Integer, default=3)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="UNKNOWN")


class JobPreference(TimestampMixin, Base):
    __tablename__ = "job_preferences"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    roles: Mapped[list] = mapped_column(JSON, default=list)
    skills: Mapped[list] = mapped_column(JSON, default=list)
    locations: Mapped[list] = mapped_column(JSON, default=list)
    experience: Mapped[list] = mapped_column(JSON, default=list)
    remote_only: Mapped[bool] = mapped_column(Boolean, default=False)


class Job(TimestampMixin, Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300), index=True)
    company: Mapped[str] = mapped_column(String(200), default="Not publicly available")
    location: Mapped[str] = mapped_column(String(200), default="Not publicly available")
    experience: Mapped[str] = mapped_column(String(200), default="Not publicly available")
    employment_type: Mapped[str] = mapped_column(String(100), default="Not publicly available")
    work_mode: Mapped[str] = mapped_column(String(100), default="Not publicly available")
    salary: Mapped[str] = mapped_column(String(200), default="Not publicly available")
    skills: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(100), default="")
    source_url: Mapped[str] = mapped_column(Text)
    apply_url: Mapped[str] = mapped_column(Text, default="")
    external_id: Mapped[str] = mapped_column(String(150), default="", index=True)
    remote_status: Mapped[str] = mapped_column(String(100), default="Not publicly available")
    experience_min: Mapped[int | None] = mapped_column(Integer, nullable=True)
    experience_max: Mapped[int | None] = mapped_column(Integer, nullable=True)
    salary_min: Mapped[float | None] = mapped_column(Float, nullable=True)
    salary_max: Mapped[float | None] = mapped_column(Float, nullable=True)
    currency: Mapped[str] = mapped_column(String(12), default="")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    canonical_job_key: Mapped[str] = mapped_column(String(64), default="", index=True)
    source_provenance: Mapped[list] = mapped_column(JSON, default=list)
    is_cybersecurity: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_entry_level: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    published_at_date_only: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    freshness_status: Mapped[str] = mapped_column(String(20), default="UNKNOWN", index=True)
    listing_status: Mapped[str] = mapped_column(String(20), default="UNKNOWN", index=True)
    match_score: Mapped[float] = mapped_column(Float, default=0, index=True)
    score_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    alert_eligible: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"), nullable=True, index=True)
    posting_id: Mapped[str] = mapped_column(String(150), default="", index=True)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    posted_to_discord: Mapped[bool] = mapped_column(Boolean, default=False)
    match_category: Mapped[str] = mapped_column(String(50), default="Not publicly available")


class NewsArticle(TimestampMixin, Base):
    __tablename__ = "news_articles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(500), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(100), default="Security News")
    source: Mapped[str] = mapped_column(String(100), default="")
    source_url: Mapped[str] = mapped_column(Text, unique=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    published_at_date_only: Mapped[bool] = mapped_column(Boolean, default=False)
    posted_to_discord: Mapped[bool] = mapped_column(Boolean, default=False)


class CVE(TimestampMixin, Base):
    __tablename__ = "cves"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    vendor: Mapped[str] = mapped_column(String(200), default="Not publicly available")
    product: Mapped[str] = mapped_column(String(300), default="Not publicly available")
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(30), default="Unknown")
    attack_vector: Mapped[str] = mapped_column(String(60), default="Not publicly available")
    affected_versions: Mapped[str] = mapped_column(Text, default="Not publicly available")
    exploited: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    verified_zero_day: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_available: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    mitigation: Mapped[str] = mapped_column(Text, default="Not publicly available")
    source_url: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    published_at_date_only: Mapped[bool] = mapped_column(Boolean, default=False)
    posted_to_discord: Mapped[bool] = mapped_column(Boolean, default=False)


class Threat(TimestampMixin, Base):
    __tablename__ = "threats"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    summary: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(200), default="Not publicly available")
    malware: Mapped[str] = mapped_column(String(200), default="Not publicly available")
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    indicators: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(100), default="")
    source_url: Mapped[str] = mapped_column(Text, unique=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    published_at_date_only: Mapped[bool] = mapped_column(Boolean, default=False)
    posted_to_discord: Mapped[bool] = mapped_column(Boolean, default=False)


class SecurityTool(TimestampMixin, Base):
    __tablename__ = "tools"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(100), default="Security Tool")
    developer: Mapped[str] = mapped_column(String(200), default="Not publicly available")
    source: Mapped[str] = mapped_column(String(100), default="")
    source_url: Mapped[str] = mapped_column(Text, unique=True)
    github_url: Mapped[str] = mapped_column(Text, default="")
    documentation_url: Mapped[str] = mapped_column(Text, default="")
    open_source: Mapped[str] = mapped_column(String(10), default="UNKNOWN")
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    published_at_date_only: Mapped[bool] = mapped_column(Boolean, default=False)
    posted_to_discord: Mapped[bool] = mapped_column(Boolean, default=False)


class Source(TimestampMixin, Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    url: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(50))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    healthy: Mapped[bool] = mapped_column(Boolean, default=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    last_fetch: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    interval_minutes: Mapped[int] = mapped_column(Integer, default=30)
    source_type: Mapped[str] = mapped_column(String(40), default="rss")
    company_name: Mapped[str] = mapped_column(String(200), default="")
    parser_config: Mapped[dict] = mapped_column(JSON, default=dict)
    baseline_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    baseline_items: Mapped[int] = mapped_column(Integer, default=0)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    description: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[int] = mapped_column(Integer, default=3)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    parser_type: Mapped[str] = mapped_column(String(40), default="feed")
    auth_mode: Mapped[str] = mapped_column(String(20), default="none")
    auth_env_var: Mapped[str] = mapped_column(String(100), default="")
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=20)
    max_response_bytes: Mapped[int] = mapped_column(Integer, default=2000000)
    requests_per_minute: Mapped[int] = mapped_column(Integer, default=6)
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failure: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    items_found: Mapped[int] = mapped_column(Integer, default=0)
    relevant_items: Mapped[int] = mapped_column(Integer, default=0)
    entry_level_items: Mapped[int] = mapped_column(Integer, default=0)
    fresh_items: Mapped[int] = mapped_column(Integer, default=0)
    new_items: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_items: Mapped[int] = mapped_column(Integer, default=0)
    closed_items: Mapped[int] = mapped_column(Integer, default=0)
    parser_status: Mapped[str] = mapped_column(String(40), default="UNKNOWN")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rate_limit_status: Mapped[str] = mapped_column(String(80), default="UNKNOWN")
    last_new_job: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_item_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CrawlerJob(TimestampMixin, Base):
    __tablename__ = "crawler_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    start_url: Mapped[str] = mapped_column(Text)
    allowed_domain: Mapped[str] = mapped_column(String(255))
    allowed_paths: Mapped[list] = mapped_column(JSON, default=list)
    blocked_paths: Mapped[list] = mapped_column(JSON, default=list)
    max_depth: Mapped[int] = mapped_column(Integer, default=1)
    max_pages: Mapped[int] = mapped_column(Integer, default=10)
    request_delay_ms: Mapped[int] = mapped_column(Integer, default=1500)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=120)
    user_agent: Mapped[str] = mapped_column(String(200), default="HexAlertCrawler/1.0 (respectful public monitor)")
    follow_links: Mapped[bool] = mapped_column(Boolean, default=False)
    mode: Mapped[str] = mapped_column(String(40), default="single_page")
    selectors: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="idle")
    next_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    channel_id: Mapped[str] = mapped_column(String(32), default="")


class CrawlerRun(TimestampMixin, Base):
    __tablename__ = "crawler_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    crawler_id: Mapped[int] = mapped_column(ForeignKey("crawler_jobs.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    current_url: Mapped[str] = mapped_column(Text, default="")
    pages_processed: Mapped[int] = mapped_column(Integer, default=0)
    pages_remaining: Mapped[int] = mapped_column(Integer, default=0)
    new_items: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_items: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")


class CrawlerPage(Base):
    __tablename__ = "crawler_pages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    crawler_id: Mapped[int] = mapped_column(ForeignKey("crawler_jobs.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(String(500), default="")
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("crawler_id", "url", name="uq_crawler_page_url"),)


class AdminUser(TimestampMixin, Base):
    __tablename__ = "admin_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    pin_hash: Mapped[str | None] = mapped_column(String(300), nullable=True)
    totp_secret_encrypted: Mapped[str] = mapped_column(Text, default="")
    totp_pending_encrypted: Mapped[str] = mapped_column(Text, default="")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    recovery_code_hashes: Mapped[list] = mapped_column(JSON, default=list)
    session_version: Mapped[int] = mapped_column(Integer, default=0)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reset_token_hash: Mapped[str] = mapped_column(String(64), default="")
    reset_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reset_token_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    admin_user_id: Mapped[int] = mapped_column(ForeignKey("admin_users.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    session_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Alert(TimestampMixin, Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    title: Mapped[str] = mapped_column(String(500))
    source: Mapped[str] = mapped_column(String(200), default="")
    source_url: Mapped[str] = mapped_column(Text, default="")
    channel_id: Mapped[str] = mapped_column(String(32), default="")
    channel_name: Mapped[str] = mapped_column(String(150), default="")
    message_id: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(30), default="pending")
    error: Mapped[str] = mapped_column(Text, default="")


class SchedulerConfig(TimestampMixin, Base):
    __tablename__ = "scheduler_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task: Mapped[str] = mapped_column(String(80), unique=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=30)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_result: Mapped[str] = mapped_column(String(30), default="unknown")


class AutomationRule(TimestampMixin, Base):
    __tablename__ = "automation_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150))
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"), nullable=True)
    keywords: Mapped[list] = mapped_column(JSON, default=list)
    category: Mapped[str] = mapped_column(String(80), default="General")
    severity: Mapped[str] = mapped_column(String(30), default="Informational")
    channel_id: Mapped[str] = mapped_column(String(32), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_type: Mapped[str] = mapped_column(String(20), default="route")
    logic: Mapped[str] = mapped_column(String(8), default="AND")
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    route_key: Mapped[str] = mapped_column(String(64), default="")


class CustomCommand(TimestampMixin, Base):
    __tablename__ = "custom_commands"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True)
    response: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class EmbedTemplate(TimestampMixin, Base):
    __tablename__ = "embed_templates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    title: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    color: Mapped[str] = mapped_column(String(10), default="#14B8A6")


class AIConfig(TimestampMixin, Base):
    __tablename__ = "ai_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(30), default="disabled")
    model: Mapped[str] = mapped_column(String(100), default="")
    base_url: Mapped[str] = mapped_column(Text, default="")
    api_key_env_var: Mapped[str] = mapped_column(String(100), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class CommunityConfig(TimestampMixin, Base):
    """Per-guild, opt-in community automation configuration."""
    __tablename__ = "community_configs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guild_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)


class CommunityPost(Base):
    """Delivery/deduplication record for welcome, farewell and Channel Pulse posts."""
    __tablename__ = "community_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guild_id: Mapped[str] = mapped_column(String(32), index=True)
    channel_id: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    message_id: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(20), default="sent")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class PulseDeliveryEvent(Base):
    """Content-free Pulse observability; records outcomes without post text."""
    __tablename__ = "pulse_delivery_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guild_id: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    channel_id: Mapped[str] = mapped_column(String(32), default="")
    content_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    reason: Mapped[str] = mapped_column(String(180), default="")
    message_id: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class SentMessage(TimestampMixin, Base):
    __tablename__ = "sent_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_type: Mapped[str] = mapped_column(String(30), index=True)
    item_id: Mapped[str] = mapped_column(String(100), index=True)
    guild_id: Mapped[str] = mapped_column(String(32), default="")
    channel_id: Mapped[str] = mapped_column(String(32), default="")
    message_id: Mapped[str] = mapped_column(String(32), default="")
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SystemLog(Base):
    __tablename__ = "system_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    level: Mapped[str] = mapped_column(String(20), index=True)
    component: Mapped[str] = mapped_column(String(100))
    message: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="CURRENT", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CommunityEngagementMember(Base):
    """Persistent, minimal Discord member directory and engagement metadata."""
    __tablename__ = "community_engagement_members"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guild_id: Mapped[str] = mapped_column(String(32), index=True)
    user_id: Mapped[str] = mapped_column(String(32), index=True)
    username: Mapped[str] = mapped_column(String(80), default="")
    display_name: Mapped[str] = mapped_column(String(80), default="")
    is_bot: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    joined_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_interaction_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_engagement_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    role_ids: Mapped[list] = mapped_column(JSON, default=list)
    opted_out: Mapped[bool] = mapped_column(Boolean, default=False)
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_nudged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_nudged_date: Mapped[str] = mapped_column(String(10), default="")
    last_response_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    __table_args__ = (UniqueConstraint("guild_id", "user_id"),)


class CommunityEngagementEvent(Base):
    """Delivery audit with message hash and routing metadata, never message content."""
    __tablename__ = "community_engagement_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guild_id: Mapped[str] = mapped_column(String(32), index=True)
    channel_id: Mapped[str] = mapped_column(String(32), index=True)
    target_user_id: Mapped[str] = mapped_column(String(32), default="")
    message_id: Mapped[str] = mapped_column(String(32), default="")
    event_type: Mapped[str] = mapped_column(String(20), index=True)
    style: Mapped[str] = mapped_column(String(32), default="")
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(20), default="sent")
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    test_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action_type: Mapped[str] = mapped_column(String(32), default="")
    __table_args__ = (UniqueConstraint("test_run_id", "action_type", name="uq_engagement_test_action"),)


class DiscordMemberSyncState(Base):
    """Per-guild directory sync state and aggregate counts; never a member list."""
    __tablename__ = "discord_member_sync_state"
    guild_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(20), default="unavailable")
    total_members: Mapped[int] = mapped_column(Integer, default=0)
    human_members: Mapped[int] = mapped_column(Integer, default=0)
    bots_excluded: Mapped[int] = mapped_column(Integer, default=0)
    opted_out: Mapped[int] = mapped_column(Integer, default=0)
    eligible_members: Mapped[int] = mapped_column(Integer, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class SocialInteractionMember(Base):
    """Per-member social opt-out and rate-limit metadata; never stores messages."""
    __tablename__ = "social_interaction_members"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guild_id: Mapped[str] = mapped_column(String(32), index=True)
    user_id: Mapped[str] = mapped_column(String(32), index=True)
    opted_out: Mapped[bool] = mapped_column(Boolean, default=False)
    last_reaction_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_social_reply_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reaction_count: Mapped[int] = mapped_column(Integer, default=0)
    reply_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    __table_args__ = (UniqueConstraint("guild_id", "user_id"),)


class SocialInteractionEvent(Base):
    """Content-free reaction/reply delivery history and persisted rate-limit ledger."""
    __tablename__ = "social_interaction_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    guild_id: Mapped[str] = mapped_column(String(32), index=True)
    channel_id: Mapped[str] = mapped_column(String(32), index=True)
    user_id: Mapped[str] = mapped_column(String(32), index=True)
    source_message_id: Mapped[str] = mapped_column(String(32), default="")
    delivery_message_id: Mapped[str] = mapped_column(String(32), default="")
    event_kind: Mapped[str] = mapped_column(String(24), index=True)
    reaction: Mapped[str] = mapped_column(String(16), default="")
    status: Mapped[str] = mapped_column(String(16), default="sent", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

