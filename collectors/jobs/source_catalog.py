"""Compliance metadata for job-source setup and reference-only platforms.

This catalog is deliberately descriptive.  It does not claim access to partner
APIs and it keeps restricted platforms out of automated collection unless an
approved public integration is configured.
"""
from __future__ import annotations


JOB_SOURCE_CATALOG = [
    {
        "source": "Remote OK",
        "source_type": "remote_ok",
        "integration_type": "Public JSON/RSS",
        "account_required": False,
        "api_key_required": False,
        "login_required": False,
        "status": "READY",
        "recommended": True,
        "setup_action": "Use https://remoteok.com/api (JSON) or https://remoteok.com/remote-jobs.rss (RSS). Save disabled, test, then enable manually.",
        "automated": True,
    },
    {
        "source": "LinkedIn",
        "source_type": "linkedin_reference",
        "integration_type": "Restricted official API / reference",
        "account_required": True,
        "api_key_required": True,
        "login_required": False,
        "status": "REFERENCE_ONLY",
        "recommended": False,
        "setup_action": "Official developer app and approved partner/product access are required. HEX ALERT never uses private login, cookies, or authenticated scraping.",
        "automated": False,
    },
    {
        "source": "Wellfound",
        "source_type": "wellfound_reference",
        "integration_type": "Reference only unless an official feed is supplied",
        "account_required": False,
        "api_key_required": False,
        "login_required": False,
        "status": "REFERENCE_ONLY",
        "recommended": False,
        "setup_action": "Save a public listing URL manually; no authenticated or anti-bot scraping is used.",
        "automated": False,
    },
    {
        "source": "Naukri",
        "source_type": "naukri_reference",
        "integration_type": "Reference only unless an approved partner feed is supplied",
        "account_required": False,
        "api_key_required": False,
        "login_required": False,
        "status": "REFERENCE_ONLY",
        "recommended": False,
        "setup_action": "Save a public listing URL manually; recruiter/private APIs are not assumed or fabricated.",
        "automated": False,
    },
    {
        "source": "Greenhouse",
        "source_type": "greenhouse",
        "integration_type": "Public ATS JSON",
        "account_required": False,
        "api_key_required": False,
        "login_required": False,
        "status": "READY",
        "recommended": True,
        "setup_action": "Enter a public boards.greenhouse.io board URL and company name.",
        "automated": True,
    },
    {
        "source": "Lever",
        "source_type": "lever",
        "integration_type": "Public ATS JSON",
        "account_required": False,
        "api_key_required": False,
        "login_required": False,
        "status": "READY",
        "recommended": True,
        "setup_action": "Enter a public jobs.lever.co board URL and company name.",
        "automated": True,
    },
    {
        "source": "Ashby",
        "source_type": "ashby",
        "integration_type": "Public ATS JSON",
        "account_required": False,
        "api_key_required": False,
        "login_required": False,
        "status": "READY",
        "recommended": True,
        "setup_action": "Enter a public jobs.ashbyhq.com board URL and company name.",
        "automated": True,
    },
    {
        "source": "Direct company careers",
        "source_type": "company_careers",
        "integration_type": "Public page / JSON-LD",
        "account_required": False,
        "api_key_required": False,
        "login_required": False,
        "status": "CONDITIONAL",
        "recommended": True,
        "setup_action": "Use only permitted public pages with bounded requests and robots/policy compliance.",
        "automated": True,
    },
    {
        "source": "Indeed",
        "source_type": "reference",
        "integration_type": "Partner products / reference",
        "account_required": False,
        "api_key_required": False,
        "login_required": False,
        "status": "REFERENCE_ONLY",
        "recommended": False,
        "setup_action": "No general public job-search feed is configured. Save the public job URL manually and prefer the employer apply URL.",
        "automated": False,
    },
    *[
        {"source": name, "source_type": "reference", "integration_type": "Reference only",
         "account_required": False, "api_key_required": False, "login_required": False,
         "status": "REFERENCE_ONLY", "recommended": False,
         "setup_action": "No verified public collection feed is configured. Save a public listing reference manually and prefer the employer/ATS apply URL.",
         "automated": False}
        for name in ("Glassdoor", "Foundit / Monster", "Instahyre", "Cutshort", "Hirist", "Internshala", "Startup boards", "Google Jobs references")
    ],
]


SOURCE_CAPABILITIES = {
    "Remote OK": ("YES", "YES", "NO", "NO"),
    "LinkedIn": ("PARTNER_ONLY", "NO", "YES", "YES"),
    "Wellfound": ("NO_PUBLIC_JOBS_API", "NO", "NO", "NO"),
    "Naukri": ("NO_PUBLIC_API", "NO", "UNKNOWN", "NO"),
    "Greenhouse": ("YES", "NO", "NO", "NO"),
    "Lever": ("YES", "NO", "NO", "NO"),
    "Ashby": ("YES", "NO", "NO", "NO"),
    "Direct company careers": ("NO", "PAGE_IF_ALLOWED", "NO", "NO"),
}


def source_catalog() -> list[dict]:
    """Return copies so API callers cannot mutate the process-wide catalog."""
    result = []
    for entry in JOB_SOURCE_CATALOG:
        item = dict(entry)
        official_api, public_feed, partner, auth = SOURCE_CAPABILITIES.get(item["source"], ("NO_VERIFIED_PUBLIC_API", "NO_VERIFIED_PUBLIC_FEED", "UNKNOWN", "NO"))
        item.update({"official_api": official_api, "public_feed": public_feed,
                     "partner_approval": partner, "authentication_required": auth,
                     "automation_available": "YES" if item["automated"] else "NO",
                     "recommended_mode": "AUTOMATED" if item["automated"] else "REFERENCE"})
        result.append(item)
    return result


def reference_source_type(source_type: str) -> bool:
    return source_type.lower() in {"reference", "linkedin_reference", "wellfound_reference", "naukri_reference"}
