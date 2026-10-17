from datetime import date, datetime, time, timezone, timedelta
from sqlalchemy import select
from database.models import CVE, Source, utcnow
from database.repository import save_cve, upsert_source
from collectors.base import Collector
from services.time_utils import parse_datetime

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CVECollector(Collector):
    async def collect(self, session):
        cisa_source = await upsert_source(session, name="CISA KEV", url=KEV, category="cve", interval=self.settings.poll_cve_minutes)
        kev_ids = set()
        try:
            if cisa_source.enabled:
                data = (await self.get(KEV)).json()
                kev_ids = {x.get("cveID") for x in data.get("vulnerabilities", [])}
                for item in data.get("vulnerabilities", []):
                    existing = await session.scalar(select(CVE).where(CVE.cve_id == item.get("cveID")))
                    if existing:
                        existing.exploited = "YES"
                        existing.mitigation = item.get("requiredAction") or existing.mitigation
                    else:
                        await save_cve(session, {"cve_id": item.get("cveID"), "description": item.get("shortDescription", ""), "vendor": item.get("vendorProject", "Not publicly available"), "product": item.get("product", "Not publicly available"), "severity": "Known Exploited", "exploited": "YES", "patch_available": "UNKNOWN", "mitigation": item.get("requiredAction") or "Not publicly available", "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "references": [item.get("notes", "")], "published_at": self._date(item.get("dateAdded")), "published_at_date_only": self._date_only(item.get("dateAdded"))})
                cisa_source.healthy = True; cisa_source.failure_count = 0; cisa_source.last_error = ""
        except Exception as exc:
            cisa_source.failure_count += 1; cisa_source.healthy = cisa_source.failure_count < 5; cisa_source.last_error = type(exc).__name__
        cisa_source.last_fetch = utcnow()
        nvd_source = await upsert_source(session, name="NVD CVE API", url=NVD, category="cve", interval=self.settings.poll_cve_minutes)
        added = []
        if nvd_source.enabled:
            try:
                params = {"pubStartDate": (datetime.now(timezone.utc)-timedelta(days=2)).isoformat(timespec="milliseconds"), "pubEndDate": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "resultsPerPage": 100}
                headers = {"apiKey": self.settings.nvd_api_key} if self.settings.nvd_api_key else {}
                payload = (await self.get(NVD, params=params, headers=headers)).json()
                for record in payload.get("vulnerabilities", []):
                    cve = record.get("cve", {}); metrics = cve.get("metrics", {})
                    metric = next((m[0] for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2") if (m := metrics.get(key))), {})
                    cvss_data = metric.get("cvssData", {})
                    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
                    refs = [r.get("url", "") for r in cve.get("references", [])[:8]]
                    vendor, product, affected = self._affected(cve.get("configurations", []))
                    value = {"cve_id": cve.get("id"), "description": desc[:8000], "vendor": vendor, "product": product, "cvss": cvss_data.get("baseScore"), "severity": cvss_data.get("baseSeverity", "Unknown"), "attack_vector": cvss_data.get("attackVector", "Not publicly available"), "affected_versions": affected, "exploited": "YES" if cve.get("id") in kev_ids else "UNKNOWN", "patch_available": "UNKNOWN", "mitigation": "Not publicly available", "source_url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}", "references": refs, "published_at": self._date(cve.get("published")), "published_at_date_only": self._date_only(cve.get("published"))}
                    row, fresh = await save_cve(session, value)
                    if fresh: added.append(row)
                    elif cve.get("id") in kev_ids: row.exploited = "YES"
                nvd_source.healthy = True; nvd_source.failure_count = 0; nvd_source.last_error = ""
            except Exception as exc:
                nvd_source.failure_count += 1; nvd_source.healthy = nvd_source.failure_count < 5; nvd_source.last_error = type(exc).__name__
            nvd_source.last_fetch = utcnow()
        # Newly marked exploited rows are returned so Discord can deliver KEV updates once.
        for cve_id in kev_ids:
            row = await session.scalar(select(CVE).where(CVE.cve_id == cve_id, CVE.posted_to_discord.is_(False)))
            if row and row not in added: added.append(row)
        await session.commit()
        return added

    @staticmethod
    def _date(value):
        if not value: return None
        parsed = parse_datetime(value)
        if isinstance(parsed, datetime): return parsed.astimezone(timezone.utc)
        if isinstance(parsed, date): return datetime.combine(parsed, time.min, tzinfo=timezone.utc)
        return None

    @staticmethod
    def _date_only(value):
        if not isinstance(value, str) or len(value.strip()) != 10: return False
        parsed = parse_datetime(value)
        return isinstance(parsed, date) and not isinstance(parsed, datetime)

    @staticmethod
    def _affected(configurations):
        import re
        found = []
        def visit(node):
            if isinstance(node, dict):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 6:
                        vendor = parts[3].replace("_", " ")
                        product = parts[4].replace("_", " ")
                        version = parts[5]
                        span = version
                        if match.get("versionStartIncluding"): span = f"{match['versionStartIncluding']} to …"
                        if match.get("versionEndExcluding"): span = f"{match.get('versionStartIncluding', '…')} to < {match['versionEndExcluding']}"
                        if match.get("versionEndIncluding"): span = f"{match.get('versionStartIncluding', '…')} to <= {match['versionEndIncluding']}"
                        found.append((vendor, product, span))
                for value in node.values():
                    if isinstance(value, (dict, list)): visit(value)
            elif isinstance(node, list):
                for value in node: visit(value)
        visit(configurations)
        if not found: return "Not publicly available", "Not publicly available", "Not publicly available"
        vendors = ", ".join(dict.fromkeys(x[0] for x in found[:4]))
        products = ", ".join(dict.fromkeys(x[1] for x in found[:4]))
        versions = "; ".join(dict.fromkeys(f"{x[1]} {x[2]}" for x in found[:8]))
        return vendors[:200], products[:300], versions[:1000]
