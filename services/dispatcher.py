from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from types import SimpleNamespace

import discord
from sqlalchemy import select

from config.settings import get_settings
from database.db import SessionLocal
from database.models import (Alert, AutomationRule, CustomDiscordRoute, CVE, Job, NewsArticle, SecurityTool,
                             SentMessage, Threat)
from database.repository import latest
from bot.embeds.factory import job_embed, news_embed, cve_embed, tool_embed, threat_embed, BRAND
from services.ai_service import AIService
from services.discord_routing import (RoutingError, category_for_item, normalize_category,
                                      resolve_custom_route, resolve_discord_channel, resolve_explicit_channel)

log = logging.getLogger("hexalert.discord")
CONTENT_MODELS = (Job, NewsArticle, CVE, SecurityTool, Threat)
EMBED_FACTORIES = {"job": job_embed, "news": news_embed, "cve": cve_embed,
                   "tool": tool_embed, "threat": threat_embed}
KIND_ALIASES = {"jobs": "job", "job": "job", "cve": "cve", "critical_cve": "cve",
                "zero_day": "cve", "zero-day": "cve", "news": "news", "custom": "news",
                "tool": "tool", "technology": "tool", "github": "tool", "github_tools": "tool",
                "research": "tool", "security_research": "tool", "threat": "threat",
                "threat_intel": "threat"}


class DiscordDispatcher:
    def __init__(self, bot):
        self.bot = bot
        self.settings = get_settings()
        self.ai = AIService()

    async def resolve_discord_channel(self, category, guild_id=None):
        return await resolve_discord_channel(category, guild_id, bot=self.bot)

    @staticmethod
    def _item_title(item):
        return str(getattr(item, "title", getattr(item, "cve_id", "Alert")) or "Alert")[:500]

    async def _record_suppressed(self, item, category, title, source, source_url):
        async with SessionLocal() as session:
            previous = await session.scalar(select(Alert).where(
                Alert.category == category, Alert.title == title, Alert.source_url == source_url,
                Alert.status == "suppressed").order_by(Alert.id.desc()))
            if previous:
                return
            session.add(Alert(category=category, title=title, source=source,
                              source_url=source_url, status="suppressed",
                              error="TEST_MODE: scheduled production alert suppressed"))
            await session.commit()

    async def post(self, item, kind: str, embed, override_channel=None):
        """Send one alert through a canonical route and persist every outcome."""
        self.settings = get_settings()
        category = category_for_item(kind, item)
        title = self._item_title(item)
        source = str(getattr(item, "source", "") or "")[:200]
        source_url = str(getattr(item, "source_url", "") or "")

        # Scheduled collection is observation-only while TEST_MODE is enabled.
        # The only mapped-channel sends in TEST_MODE use the explicit test-route API.
        if self.settings.test_mode:
            await self._record_suppressed(item, category, title, source, source_url)
            log.info("[DISCORD] Suppressed scheduled %s alert in TEST_MODE", category)
            return False

        async with SessionLocal() as session:
            alert = Alert(category=category, title=title, source=source, source_url=source_url,
                          status="pending")
            session.add(alert)
            await session.commit()
            alert_id = alert.id

        try:
            if override_channel is not None:
                resolution = await resolve_explicit_channel(override_channel, bot=self.bot)
            else:
                resolution = await self.resolve_discord_channel(category)
        except RoutingError as exc:
            async with SessionLocal() as session:
                alert = await session.get(Alert, alert_id)
                if alert:
                    alert.status = "failed"
                    alert.error = str(exc)[:1000]
                    await session.commit()
            log.warning("[DISCORD] Route failed category=%s reason=%s", category, str(exc))
            return False
        except Exception as exc:
            async with SessionLocal() as session:
                alert = await session.get(Alert, alert_id)
                if alert:
                    alert.status = "failed"
                    alert.error = f"Channel resolution failed ({type(exc).__name__})"
                    await session.commit()
            log.exception("[DISCORD] Channel resolution failed category=%s", category)
            return False

        try:
            message = await resolution.channel.send(
                embed=embed, allowed_mentions=discord.AllowedMentions.none())
            async with SessionLocal() as session:
                alert = await session.get(Alert, alert_id)
                if alert:
                    alert.channel_id = resolution.channel_id
                    alert.channel_name = resolution.channel_name
                    alert.message_id = str(message.id)
                    alert.status = "sent"
                    alert.error = ""
                session.add(SentMessage(item_type=category, item_id=str(alert_id),
                                        guild_id=resolution.guild_id,
                                        channel_id=resolution.channel_id,
                                        message_id=str(message.id)))
                if isinstance(item, CONTENT_MODELS):
                    persisted = await session.get(type(item), item.id)
                    if persisted:
                        persisted.posted_to_discord = True
                await session.commit()
            if isinstance(item, CONTENT_MODELS):
                item.posted_to_discord = True
            log.info("[DISCORD] Posted category=%s channel=%s message=%s",
                     category, resolution.channel_id, message.id)
            return True
        except discord.HTTPException as exc:
            failure = f"Discord HTTP {exc.status}: {type(exc).__name__}"
        except Exception as exc:
            failure = f"Discord send failed ({type(exc).__name__})"
        async with SessionLocal() as session:
            alert = await session.get(Alert, alert_id)
            if alert:
                alert.channel_id = resolution.channel_id
                alert.channel_name = resolution.channel_name
                alert.status = "failed"
                alert.error = failure
                await session.commit()
        log.error("[DISCORD] Send failed category=%s channel=%s reason=%s",
                  category, resolution.channel_id, failure)
        return False

    async def deliver(self, kind, items):
        embed_kind = KIND_ALIASES.get(str(kind).lower())
        factory = EMBED_FACTORIES.get(embed_kind)
        if not factory:
            log.error("[DISCORD] Unsupported collector item kind=%s", str(kind))
            return
        from services.community import CommunityAutomation
        module='jobs' if embed_kind=='job' else 'urgent_alerts' if embed_kind=='cve' else 'pulse'
        if CommunityAutomation._automation_paused(module):
            log.info('[DISCORD] Autonomous delivery held; module=%s',module)
            return
        self.settings = get_settings()
        for item in items:
            if item.posted_to_discord:
                continue
            if embed_kind == "cve":
                threshold = self.settings.critical_cve_threshold
                if not (getattr(item, "verified_zero_day", False) is True or
                        item.exploited == "YES" or (item.cvss is not None and item.cvss >= threshold)):
                    continue
            if embed_kind == "news":
                embed = factory(item, summary=await self.ai.summarize(item.summary, 700))
            elif embed_kind == "cve":
                embed = factory(item, summary=await self.ai.summarize(item.description, 700))
            elif embed_kind == "threat":
                embed = factory(item, summary=await self.ai.summarize(item.summary, 700))
            else:
                embed = factory(item)
            route = category_for_item(kind, item)
            await self.post(item, route, embed)

            # Explicit automation-rule destinations remain separate destinations,
            # but TEST_MODE suppresses all collector-driven sends above and below.
            if self.settings.test_mode:
                continue
            content = " ".join(str(getattr(item, key, "")) for key in
                               ("title", "description", "summary", "location")).lower()
            async with SessionLocal() as session:
                rules = (await session.scalars(select(AutomationRule).where(
                    AutomationRule.enabled.is_(True)))).all()
            for rule in rules:
                if getattr(rule, "rule_type", "route") == "filter":
                    continue
                rule_category = normalize_category(rule.category)
                if rule_category not in {route, "general", "all"}:
                    continue
                if rule.conditions:
                    from services.job_rules import evaluate_condition
                    fields={key:getattr(item,key,None) for key in ("title","experience","location","freshness_status","match_score","published_at","cvss","exploited","verified_zero_day","severity","cve_id")}
                    fields["category"] = route
                    fields["title_experience"] = f"{fields.get('title') or ''} {fields.get('experience') or ''}"
                    fields["content"] = content
                    matches=evaluate_condition(fields,rule.conditions)
                else:
                    matches=any(str(word).lower() in content for word in (rule.keywords or []))
                if matches:
                    base_channel_id = None
                    try:
                        base_channel_id = (await resolve_discord_channel(route, bot=self.bot)).channel_id
                    except RoutingError:
                        pass
                    if rule.route_key:
                        try:
                            custom, _resolution = await resolve_custom_route(rule.route_key, bot=self.bot)
                        except RoutingError as exc:
                            async with SessionLocal() as session:
                                session.add(Alert(category=f"custom:{rule.route_key}"[:40],
                                                  title=self._item_title(item),
                                                  source=str(getattr(item, "source", "") or "")[:200],
                                                  source_url=str(getattr(item, "source_url", "") or ""),
                                                  status="failed", error=str(exc)[:1000]))
                                await session.commit()
                            log.warning("[DISCORD] Custom route failed route=%s reason=%s", rule.route_key, str(exc))
                            continue
                        route_category=normalize_category(custom.category)
                        if route_category not in {"custom","general","all",route}:
                            continue
                        if custom.keywords and not any(str(word).lower() in content for word in custom.keywords):
                            continue
                        if str(custom.channel_id) == str(base_channel_id):
                            continue
                        sent = await self.post(item, route, embed, override_channel=int(custom.channel_id))
                        async with SessionLocal() as session:
                            stored = await session.scalar(select(CustomDiscordRoute).where(
                                CustomDiscordRoute.route_key == rule.route_key))
                            if stored:
                                stored.status = "SENT" if sent else "FAILED"
                                if sent:
                                    stored.last_used = datetime.now(timezone.utc)
                                await session.commit()
                    else:
                        if not rule.channel_id or not rule.channel_id.isdigit():
                            # The category channel already received the normal alert.
                            continue
                        if str(rule.channel_id) == str(base_channel_id):
                            continue
                        await self.post(item, route, embed, override_channel=int(rule.channel_id))

    async def digest(self):
        from services.community import CommunityAutomation
        if CommunityAutomation._automation_paused('daily_digest'):
            log.info('[DISCORD] Daily digest held; Autopilot delivery is paused or disabled')
            return
        self.settings = get_settings()
        async with SessionLocal() as session:
            from services.daily_digest import recent_digest_sections, digest_fields
            data = await recent_digest_sections(session)

        embed = discord.Embed(title="🌐 HEX ALERT — DAILY CYBER BRIEF",
                              color=0x14B8A6, timestamp=datetime.now(timezone.utc))
        fields=digest_fields(data)
        if fields:
            for field in fields:
                embed.add_field(name=field["name"],value=field["value"],inline=False)
        else:
            embed.description="ℹ️ No new verified updates were found in the collection window."
        embed.set_footer(text=BRAND)
        digest_item = SimpleNamespace(id=f"daily-{datetime.now(timezone.utc):%Y%m%d}",
                                      title="HEX ALERT Daily Cyber Brief", source="HEX ALERT scheduler",
                                      source_url="", posted_to_discord=False)
        await self.post(digest_item, "daily_digest", embed)
