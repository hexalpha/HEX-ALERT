import logging
import random
from datetime import timedelta, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from database.db import SessionLocal
from config.settings import get_settings
from collectors.news.collector import NewsCollector
from collectors.cve.collector import CVECollector
from collectors.jobs.collector import JobCollector
from collectors.github.collector import TechnologyCollector
from collectors.threat_intel.collector import ThreatCollector
from services.dispatcher import DiscordDispatcher
from database.models import Source, SchedulerConfig
from sqlalchemy import select
from database.repository import log_system_event
from database.models import CrawlerJob, SystemLog, utcnow
from collectors.crawler import CrawlerManager
from services.community import community_automation

log = logging.getLogger("hexalert.scheduler")


class CollectionScheduler:
    def __init__(self, bot):
        self.bot = bot; self.settings = get_settings(); self.scheduler = AsyncIOScheduler(timezone="UTC"); self.dispatch = DiscordDispatcher(bot); self.crawlers=CrawlerManager(bot)
        self.collectors = {"news": NewsCollector(), "cve": CVECollector(), "jobs": JobCollector(), "technology": TechnologyCollector(), "threat": ThreatCollector()}

    async def start(self):
        async with SessionLocal() as session:
            sources = (await session.scalars(select(Source).where(Source.enabled.is_(True)))).all()
            intervals = {}
            for source in sources:
                intervals[source.category] = min(intervals.get(source.category, source.interval_minutes), source.interval_minutes)
            saved=(await session.scalars(select(SchedulerConfig))).all()
            saved_by_task={row.task:row for row in saved}
            saved_intervals={row.task:row.interval_minutes for row in saved if row.interval_minutes>=5}
            disabled={row.task for row in saved if not row.enabled}
        for key, interval in [("news", self.settings.poll_news_minutes), ("custom", self.settings.poll_news_minutes), ("cve", self.settings.poll_cve_minutes), ("jobs", self.settings.poll_jobs_minutes), ("technology", self.settings.poll_tech_minutes), ("threat", self.settings.poll_threats_minutes)]:
            task_interval=max(5, saved_intervals.get(key,intervals.get(key, interval)))
            prior=saved_by_task.get(key)
            self.scheduler.add_job(self.run, "interval", args=[key], minutes=task_interval, jitter=300, id=key, max_instances=1, coalesce=True, misfire_grace_time=120, next_run_time=self.startup_run_at(prior.last_run if prior else None,task_interval))
        self.scheduler.add_job(self.dispatch.digest, CronTrigger(hour=self.settings.daily_digest_hour, minute=0, timezone=self.settings.daily_digest_timezone), id="daily_digest", max_instances=1, coalesce=True)
        if self.settings.auto_backup_daily:
            self.scheduler.add_job(self.backup_daily, CronTrigger(hour=max(0, min(23, self.settings.backup_hour_utc)), minute=0, timezone="UTC"), id="daily_backup", max_instances=1, coalesce=True)
        self.scheduler.add_job(self.crawl_due,"interval",minutes=1,id="crawler_fetch",max_instances=1,coalesce=True)
        # One lightweight due-check; individual Pulse channels retain their own
        # interval and are disabled until explicitly enabled in the dashboard.
        self.scheduler.add_job(self.community_pulse,"interval",minutes=5,id="community_pulse",max_instances=1,coalesce=True,misfire_grace_time=60)
        from services.member_engagement import member_engagement
        await member_engagement.startup_recover(self.bot)
        self.scheduler.add_job(self.member_engagement_cycle,"interval",minutes=1,id="member_engagement_cycle",max_instances=1,coalesce=True,misfire_grace_time=60)
        self.scheduler.add_job(self.member_directory_cycle,"interval",hours=6,id="member_directory_reconcile",max_instances=1,coalesce=True,misfire_grace_time=600)
        self.scheduler.start()
        for task_id in disabled:
            try:self.scheduler.pause_job(task_id)
            except Exception:pass

    @staticmethod
    def startup_run_at(last_run, interval_minutes, now=None, rng=random):
        """Resume collection cadence without a burst after a bot restart."""
        now=now or utcnow()
        if now.tzinfo is None: now=now.replace(tzinfo=timezone.utc)
        if last_run is not None:
            if last_run.tzinfo is None: last_run=last_run.replace(tzinfo=timezone.utc)
            due=last_run+timedelta(minutes=max(5,int(interval_minutes)))
            if due>now: return due
            # The previous run was missed while offline; wait before resuming.
            delay_minutes=rng.randint(10,30)
        else:
            # Stagger first-ever runs across categories instead of firing all at startup.
            delay_minutes=rng.randint(1,15)
        return now+timedelta(minutes=delay_minutes)

    async def member_engagement_cycle(self):
        try:
            from services.member_engagement import member_engagement
            await member_engagement.run_due(self.bot)
        except Exception as exc:
            log.warning("[COMMUNITY] Member Engagement cycle failed (%s)",type(exc).__name__)

    async def member_directory_cycle(self):
        try:
            from services.member_directory import reconcile_all
            await reconcile_all(self.bot,force_fetch=True)
        except Exception as exc:
            log.warning("[DISCORD] Member directory reconciliation failed (%s)",type(exc).__name__)

    async def community_pulse(self):
        try:
            sent=await community_automation.run_due(self.bot)
            if sent: log.info('[COMMUNITY] Channel Pulse sent %d scheduled message(s)',sent)
        except Exception as exc:
            log.warning('[COMMUNITY] Channel Pulse cycle failed (%s)',type(exc).__name__)

    @staticmethod
    async def backup_daily():
        try:
            from api.app import _make_backup
            path = await _make_backup()
            log.info("[BACKUP] Daily backup created: %s", path.name)
        except Exception as exc:
            log.exception("[BACKUP] Daily backup failed (%s)", type(exc).__name__)

    async def crawl_due(self):
        async with SessionLocal() as session:
            rows=(await session.scalars(select(CrawlerJob).where(CrawlerJob.enabled.is_(True)))).all()
            due=[row.id for row in rows if row.status not in {"running","paused"} and (row.next_run is None or row.next_run<=utcnow())]
            for row in rows:
                if row.id in due: row.next_run=utcnow()+__import__("datetime").timedelta(minutes=row.interval_minutes)
            await session.commit()
        for crawler_id in due: await self.crawlers.start(crawler_id)

    async def run(self, category):
        started=__import__("time").monotonic(); success=False
        try:
            async with SessionLocal() as session:
                cfg = self.settings
                advisory_items=[]
                if category in {"news","custom"}: urls=await self._urls(session,category,cfg.news_feed_urls); items = await self.collectors["news"].collect(session, urls)
                elif category == "cve":
                    items = await self.collectors[category].collect(session)
                    advisory_urls=await self._urls(session,"cve",[])
                    if advisory_urls: advisory_items=await self.collectors["news"].collect(session,advisory_urls)
                elif category == "jobs":
                    sources = list((await session.scalars(select(Source).where(
                        Source.enabled.is_(True), Source.category == "jobs").order_by(Source.priority, Source.id))).all())
                    await self.collectors[category].collect(session, sources)
                    items = await self.collectors[category].pending_alerts(session, cfg.max_job_alerts_per_run)
                elif category == "technology": urls=await self._urls(session,category,cfg.tech_feed_urls); items = await self.collectors[category].collect(session, urls)
                else: urls=await self._urls(session,category,cfg.threat_feed_urls); items = await self.collectors[category].collect(session, urls)
            # The embed factory uses the singular content kind; ``jobs`` here was
            # previously passed through and raised KeyError before any job could route.
            kind = {"jobs": "job", "technology": "tool", "threat": "threat", "custom":"news"}.get(category, category)
            await self.dispatch.deliver(kind, items)
            if advisory_items:await self.dispatch.deliver("news",advisory_items)
            success=True
            async with SessionLocal() as session:
                old_errors=(await session.scalars(select(SystemLog).where(SystemLog.status=="CURRENT",SystemLog.level=="ERROR",SystemLog.component==category))).all()
                for event in old_errors: event.status="RESOLVED"
                if old_errors: await session.commit()
            log.info("[%s] collection completed; %d new records", category.upper(), len(items))
        except Exception as exc:
            log.exception("[%s] collection cycle failed", category.upper())
            try:
                async with SessionLocal() as session:
                    await log_system_event(session, "ERROR", category, f"Collection cycle failed ({type(exc).__name__})")
                    await session.commit()
            except Exception: log.error("Could not persist collection error record")
        finally:
            try:
                async with SessionLocal() as session:
                    row=await session.scalar(select(SchedulerConfig).where(SchedulerConfig.task==category))
                    if not row:row=SchedulerConfig(task=category,interval_minutes=getattr(self.settings,f"poll_{category}_minutes",30));session.add(row)
                    row.last_run=utcnow();row.last_result="success" if success else "failed";await session.commit()
            except Exception:log.warning("Could not persist scheduler run status")

    @staticmethod
    async def _urls(session,category,configured):
        sources=(await session.scalars(select(Source).where(Source.enabled.is_(True),Source.category==category))).all()
        return list(dict.fromkeys([*configured,*[source.url for source in sources if source.source_type in {"rss","atom","website","json_api","job_feed","news","security_advisory","threat_intelligence","github","custom"}]]))

    async def close(self):
        if self.scheduler.running: self.scheduler.shutdown(wait=False)
        await __import__("asyncio").gather(*(self.crawlers.stop(cid) for cid,task in list(self.crawlers.tasks.items()) if not task.done()),return_exceptions=True)
        await __import__("asyncio").gather(*(c.close() for c in self.collectors.values()), return_exceptions=True)
