import discord
from datetime import datetime, timezone

BRAND = "🛡️ HEX ALERT • Cybersecurity Intelligence"
MISSING = "Not publicly available"


def stamp(value, *, date_only=False):
    if not value:
        return MISSING
    from config.settings import get_settings
    from services.time_utils import format_local_datetime
    rendered = value.date().isoformat() if date_only and isinstance(value, datetime) else value
    return format_local_datetime(rendered, get_settings().app_timezone, get_settings().time_format)


def job_embed(job):
    from config.settings import get_settings
    threshold = get_settings().high_fit_job_threshold
    score = int(getattr(job, "match_score", 0) or 0)
    high_fit = score >= threshold
    breakdown = getattr(job, "score_breakdown", {}) or {}
    evidence = [f"{name.replace('_', ' ').title()}: {value.get('evidence')}" for name, value in breakdown.items()
                if isinstance(value, dict) and value.get("evidence") and "penalty" not in name][:5]
    why = "\n".join(f"• {line}" for line in evidence) or "• Based on the publicly listed role details"
    apply_url = getattr(job, "apply_url", "") or getattr(job, "source_url", "")
    if not apply_url.startswith(("https://", "http://")):
        apply = MISSING
    else:
        apply = f"[Apply]({apply_url})"
    def known(value):
        return "Unknown" if not value or value == MISSING else value
    posted = stamp(getattr(job, 'published_at', None), date_only=getattr(job, 'published_at_date_only', False))
    description = ("🔥 **HIGH-FIT FRESHER OPPORTUNITY**\n\n" if high_fit else "") + (
        f"**Role:** {known(getattr(job, 'title', None))}\n"
        f"**Company:** {known(getattr(job, 'company', None))}\n"
        f"**Location:** {known(getattr(job, 'location', None))}\n"
        f"**Experience:** {known(getattr(job, 'experience', None))}\n"
        f"**Employment Type:** {known(getattr(job, 'employment_type', None))}\n"
        f"**Remote:** {known(getattr(job, 'remote_status', None) or getattr(job, 'work_mode', None))}\n"
        f"**Posted:** {known(posted)}\n"
        f"**Freshness:** {getattr(job, 'freshness_status', 'UNKNOWN') or 'UNKNOWN'}\n"
        f"**Source:** {known(getattr(job, 'source', None))}\n"
        f"**🎯 Match Score:** {score}%\n\n**Why it matches:**\n{why}\n\n{apply}"
    )
    e = discord.Embed(title="🚨 NEW CYBERSECURITY JOB", description=description[:4096], color=0x22C55E)
    e.set_footer(text=BRAND); return e


def news_embed(article, summary=None):
    text = summary or article.summary or MISSING
    e = discord.Embed(title="📰 CYBERSECURITY NEWS", description=f"**{article.title}**\n\n**Category:** {article.category}\n**Source:** {article.source}\n**Published:** {stamp(article.published_at)}\n\n**Summary:**\n{text[:900]}\n\n**Why it matters:** Review the linked report for affected systems and recommended actions.\n**Affected Technology:** {MISSING}\n**Severity:** {MISSING}\n\n[🔗 Read More]({article.source_url})", color=0x3B82F6)
    e.set_footer(text=BRAND); return e


def cve_embed(cve, summary=None):
    from config.settings import get_settings
    zero_day = getattr(cve, "verified_zero_day", False) is True
    critical = (cve.cvss or 0) >= get_settings().critical_cve_threshold or cve.exploited == "YES" or zero_day
    title = "🚨 VERIFIED ZERO-DAY ALERT" if zero_day else "🚨 CRITICAL CVE ALERT" if critical else "🛡️ CVE ALERT"
    e = discord.Embed(title=title, description=f"**CVE:** {cve.cve_id}\n**Product:** {cve.product}\n**Vendor:** {cve.vendor}\n**CVSS:** {cve.cvss if cve.cvss is not None else MISSING}\n**Severity:** {cve.severity}\n**Published:** {stamp(cve.published_at)}\n**Attack Vector:** {cve.attack_vector}\n**Affected Versions:** {cve.affected_versions}\n\n**Description:**\n{(summary or cve.description)[:900] or MISSING}\n\n**Impact:** {cve.severity}; consult the official advisory for affected deployment scope.\n**Known Exploitation:** {cve.exploited}\n**Patch Available:** {cve.patch_available}\n**Mitigation:** {cve.mitigation}\n\n**Official Advisory:** {cve.source_url}\n**References:** {' • '.join(cve.references[:3]) or MISSING}", color=0xDC2626 if critical else 0xF59E0B)
    e.set_footer(text=BRAND); return e


def tool_embed(tool):
    links = [f"[Source]({tool.source_url})"]
    if tool.github_url: links.append(f"[GitHub]({tool.github_url})")
    e = discord.Embed(title="🛠️ NEW CYBERSECURITY TECHNOLOGY", description=f"**Name:** {tool.name}\n**Type:** {tool.category}\n**Developer:** {tool.developer}\n**Released/Updated:** {stamp(tool.published_at)}\n\n**Description:** {tool.description[:900] or MISSING}\n\n**Interesting Features:**\n• {tool.description[:250] or MISSING}\n\n**Possible Uses:** Security research and operations (based on source title/category)\n**Open Source:** {tool.open_source}\n\n{' • '.join(links)}", color=0x8B5CF6)
    e.set_footer(text=BRAND); return e


def threat_embed(threat, summary=None):
    e = discord.Embed(title="🚨 THREAT INTELLIGENCE", description=f"**{threat.title}**\n\n**Summary:** {(summary or threat.summary)[:1100] or MISSING}\n**Source:** {threat.source}\n**Published:** {stamp(threat.published_at)}\n**MITRE ATT&CK Technique:** {MISSING}\n**Tactic:** {MISSING}\n**Threat Actor:** {threat.actor}\n**Malware:** {threat.malware}\n**Public Indicators:** {', '.join(threat.indicators) if threat.indicators else MISSING}\n\n[Read report]({threat.source_url})", color=0xEF4444)
    e.set_footer(text=BRAND); return e
