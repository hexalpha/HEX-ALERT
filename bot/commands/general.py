import discord
from discord import app_commands
from discord.ext import commands
from sqlalchemy import select, func
from config.settings import get_settings
from database.db import SessionLocal
from database.models import Job, NewsArticle, CVE, SecurityTool, Threat, Source, User, JobPreference
from database.repository import latest
from bot.embeds.factory import job_embed, news_embed, cve_embed, tool_embed, threat_embed


class General(commands.Cog):
    def __init__(self, bot): self.bot = bot; self.settings = get_settings()

    @app_commands.command(name="jobs", description="Browse recent cybersecurity jobs")
    @app_commands.describe(role="Role keyword", location="Location keyword", fresher="Show fresher and internship roles")
    async def jobs(self, interaction: discord.Interaction, role: str = "", location: str = "", fresher: bool = False):
        async with SessionLocal() as s:
            q = select(Job).order_by(Job.published_at.desc().nullslast()).limit(10)
            rows = (await s.scalars(q)).all()
            user = await s.scalar(select(User).where(User.discord_id == str(interaction.user.id)))
            prefs = await s.scalar(select(JobPreference).where(JobPreference.user_id == user.id)) if user else None
        rows = [x for x in rows if (not role or role.lower() in x.title.lower()) and (not location or location.lower() in x.location.lower()) and (not fresher or x.match_category.lower() in {"fresher", "internship"})]
        embeds = []
        for row in rows[:5]:
            embed = job_embed(row)
            if prefs:
                score, matched, missing = score_job(row, prefs)
                if matched or missing: embed.add_field(name=f"🎯 Job Match: {score}%", value=("**Matched:**\n" + ("\n".join(f"✓ {x}" for x in matched) or "None") + "\n\n**Not shown in listing:**\n" + ("\n".join(f"✗ {x}" for x in missing) or "None"))[:1000], inline=False)
            embeds.append(embed)
        await interaction.response.send_message(embeds=embeds if rows else [], content="Recent matching cybersecurity jobs:" if rows else "No matching jobs are stored yet.", ephemeral=True)

    @app_commands.command(name="cve", description="Look up a CVE ID")
    async def cve(self, interaction: discord.Interaction, cve_id: str):
        cve_id = cve_id.strip().upper()
        if not __import__("re").fullmatch(r"CVE-\d{4}-\d{4,8}", cve_id): return await interaction.response.send_message("Use a CVE identifier such as CVE-2024-12345.", ephemeral=True)
        async with SessionLocal() as s: item = await s.scalar(select(CVE).where(CVE.cve_id == cve_id))
        await interaction.response.send_message(embed=cve_embed(item), ephemeral=True) if item else await interaction.response.send_message("That CVE is not in the local database yet.", ephemeral=True)

    @app_commands.command(name="latest-cve", description="Show the latest collected CVEs")
    async def latest_cve(self, interaction: discord.Interaction): await self._latest(interaction, CVE, cve_embed)

    @app_commands.command(name="critical-cve", description="Show critical and known exploited CVEs")
    async def critical_cve(self, interaction: discord.Interaction):
        async with SessionLocal() as s: rows = list((await s.scalars(select(CVE).where((CVE.cvss >= 8) | (CVE.exploited == "YES")).order_by(CVE.published_at.desc().nullslast()).limit(5))).all())
        await interaction.response.send_message(embeds=[cve_embed(x) for x in rows] or None, content=None if rows else "No critical or exploited CVEs are stored yet.", ephemeral=True)

    @app_commands.command(name="news", description="Browse collected cybersecurity news")
    async def news(self, interaction: discord.Interaction, query: str = ""):
        async with SessionLocal() as s: rows = await latest(s, NewsArticle, 20)
        rows = [x for x in rows if not query or query.lower() in (x.title + " " + x.summary).lower()]
        await interaction.response.send_message(embeds=[news_embed(x) for x in rows[:5]] or None, content=None if rows else "No matching news is stored.", ephemeral=True)

    @app_commands.command(name="tools", description="Browse recently collected security tools")
    async def tools(self, interaction: discord.Interaction): await self._latest(interaction, SecurityTool, tool_embed)
    @app_commands.command(name="latest-tools", description="Show the latest security tools")
    async def latest_tools(self, interaction: discord.Interaction): await self._latest(interaction, SecurityTool, tool_embed)
    @app_commands.command(name="threats", description="Browse public threat intelligence reports")
    async def threats(self, interaction: discord.Interaction): await self._latest(interaction, Threat, threat_embed)

    @app_commands.command(name="status", description="Show Hex Alert service status")
    async def status(self, interaction: discord.Interaction):
        async with SessionLocal() as s:
            counts = [await s.scalar(select(func.count()).select_from(m)) for m in (Job, NewsArticle, CVE, SecurityTool, Threat)]
            source_count = await s.scalar(select(func.count()).select_from(Source).where(Source.enabled.is_(True)))
        await interaction.response.send_message(f"🛡️ **HEX ALERT online**\nJobs: {counts[0]} • News: {counts[1]} • CVEs: {counts[2]} • Tools: {counts[3]} • Threat reports: {counts[4]}\nActive sources: {source_count or 0}", ephemeral=True)

    @app_commands.command(name="hexstatus", description="Show HEX ALERT connection and collection health")
    async def hexstatus(self, interaction: discord.Interaction):
        async with SessionLocal() as s:
            source_count = await s.scalar(select(func.count()).select_from(Source).where(Source.enabled.is_(True)))
            unhealthy = await s.scalar(select(func.count()).select_from(Source).where(Source.enabled.is_(True), Source.healthy.is_(False)))
        scheduler = self.bot.scheduler
        mode = "TEST" if get_settings().test_mode else "PRODUCTION"
        await interaction.response.send_message(
            f"🛡️ **HEX ALERT Status**\nBot: Online\nDatabase: Healthy\nScheduler: {'Running' if scheduler and scheduler.scheduler.running else 'Stopped'}\nSources: {source_count or 0} active · {unhealthy or 0} unhealthy\nMode: {mode}",
            ephemeral=True,
        )

    @app_commands.command(name="sources", description="List configured collection sources")
    async def sources(self, interaction: discord.Interaction):
        async with SessionLocal() as s: rows = (await s.scalars(select(Source).order_by(Source.category, Source.name))).all()
        text = "\n".join(f"{'✅' if x.enabled else '⏸️'} {x.name} · {'healthy' if x.healthy else 'unhealthy'}" for x in rows) or "Sources will appear after the first scheduler run."
        await interaction.response.send_message(text[:1900], ephemeral=True)

    @app_commands.command(name="help", description="Show Hex Alert command help")
    async def help_command(self, interaction: discord.Interaction):
        await interaction.response.send_message("**🛡️ HEX ALERT**\n/jobs [role] [location] [fresher] · /cve · /latest-cve · /critical-cve · /news [query] · /tools · /latest-tools · /threats · /job-profile · /status · /sources\nAdmins: /admin-status · /admin-refresh · /admin-source-enable · /admin-source-disable", ephemeral=True)

    @app_commands.command(name="job-profile", description="Set a transparent personal job filter")
    @app_commands.describe(roles="Comma-separated roles", skills="Comma-separated skills", locations="Comma-separated locations", experience="Comma-separated experience types", remote_only="Only show remote roles")
    async def job_profile(self, interaction: discord.Interaction, roles: str = "", skills: str = "", locations: str = "", experience: str = "", remote_only: bool = False):
        async with SessionLocal() as s:
            user = await s.scalar(select(User).where(User.discord_id == str(interaction.user.id)))
            if not user: user = User(discord_id=str(interaction.user.id), username=str(interaction.user)); s.add(user); await s.flush()
            pref = await s.scalar(select(JobPreference).where(JobPreference.user_id == user.id))
            if not pref: pref = JobPreference(user_id=user.id); s.add(pref)
            split = lambda x: [v.strip()[:80] for v in x.split(",") if v.strip()][:20]
            pref.roles=split(roles); pref.skills=split(skills); pref.locations=split(locations); pref.experience=split(experience); pref.remote_only=remote_only
            await s.commit()
        await interaction.response.send_message("Job preferences saved. Matches are based only on fields present in each listing.", ephemeral=True)

    async def _latest(self, interaction, model, embed_factory):
        async with SessionLocal() as s: rows = await latest(s, model, 5)
        await interaction.response.send_message(embeds=[embed_factory(x) for x in rows] or None, content=None if rows else "No records are stored yet.", ephemeral=True)


def admin_check(interaction: discord.Interaction) -> bool:
    if interaction.user.id in get_settings().admin_ids: return True
    return bool(interaction.guild and interaction.user.guild_permissions.manage_guild)


def score_job(job, pref):
    """Equal-weight category score; only fields explicitly present in the listing count."""
    haystack = " ".join([job.title or "", job.company or "", job.location or "", job.experience or "", job.employment_type or "", job.description or "", " ".join(job.skills or [])]).lower()
    checks = []
    for label, values, text in [("Role", pref.roles or [], (job.title or "").lower()), ("Skill", pref.skills or [], haystack), ("Location", pref.locations or [], (job.location or "").lower()), ("Experience", pref.experience or [], ((job.experience or "") + " " + (job.employment_type or "")).lower())]:
        checks.extend((f"{label}: {value}", value.lower() in text) for value in values)
    if pref.remote_only: checks.append(("Remote", "remote" in (job.location or "").lower()))
    if not checks: return 0, [], []
    matched = [label for label, ok in checks if ok]
    missing = [label for label, ok in checks if not ok]
    return round(len(matched) * 100 / len(checks)), matched, missing


class Admin(commands.Cog):
    def __init__(self, bot): self.bot = bot

    @app_commands.command(name="admin-status", description="Admin: show source and scheduler status")
    @app_commands.check(admin_check)
    async def admin_status(self, interaction: discord.Interaction):
        async with SessionLocal() as s: rows = (await s.scalars(select(Source))).all()
        await interaction.response.send_message(f"Scheduler: {'running' if self.bot.scheduler.scheduler.running else 'stopped'}\nSources: {len(rows)} · unhealthy: {sum(not x.healthy for x in rows)}", ephemeral=True)

    @app_commands.command(name="admin-refresh", description="Admin: run a collector now")
    @app_commands.describe(category="Collector to run: jobs, news, cve, technology, threat")
    @app_commands.check(admin_check)
    async def admin_refresh(self, interaction: discord.Interaction, category: str):
        if category not in {"jobs", "news", "cve", "technology", "threat"}: return await interaction.response.send_message("Unknown collector category.", ephemeral=True)
        await interaction.response.defer(ephemeral=True, thinking=True)
        await self.bot.scheduler.run(category)
        await interaction.followup.send(f"Refresh finished for {category}.", ephemeral=True)

    @app_commands.command(name="admin-source-enable", description="Admin: enable a source by name")
    @app_commands.check(admin_check)
    async def source_enable(self, interaction: discord.Interaction, name: str): await self._source(interaction, name, True)

    @app_commands.command(name="admin-source-disable", description="Admin: disable a source by name")
    @app_commands.check(admin_check)
    async def source_disable(self, interaction: discord.Interaction, name: str): await self._source(interaction, name, False)

    async def _source(self, interaction, name, enabled):
        async with SessionLocal() as s:
            row = await s.scalar(select(Source).where(func.lower(Source.name) == name.strip().lower()))
            if row: row.enabled = enabled; await s.commit()
        await interaction.response.send_message(f"Source {'enabled' if enabled else 'disabled'}." if row else "Source not found. Names are listed by /sources.", ephemeral=True)
