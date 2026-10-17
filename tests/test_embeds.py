from types import SimpleNamespace
from datetime import datetime, timezone
from bot.embeds.factory import job_embed, cve_embed, BRAND


def test_fresher_job_embed_labels_unknown_data_without_invention():
    row = SimpleNamespace(title="SOC Analyst Intern", company="Example", location="Remote", experience="Fresher", employment_type="Internship", salary="Not publicly available", skills=[], description="", source="Example RSS", source_url="https://example.org/job/1", published_at=None, match_category="Fresher", freshness_status="UNKNOWN", match_score=87, score_breakdown={"role": {"evidence": "SOC Analyst"}, "experience": {"evidence": "intern"}})
    embed = job_embed(row)
    assert "HIGH-FIT FRESHER" in embed.description
    assert "Unknown" in embed.description
    assert embed.footer.text == BRAND


def test_cve_embed_marks_only_verified_kev_as_exploited():
    row = SimpleNamespace(cve_id="CVE-2026-12345", product="Not publicly available", vendor="Not publicly available", cvss=9.1, severity="Critical", published_at=datetime.now(timezone.utc), attack_vector="NETWORK", affected_versions="Not publicly available", description="Example flaw", exploited="NO", patch_available="UNKNOWN", mitigation="Not publicly available", source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-12345", references=[])
    assert "Known Exploitation:** NO" in cve_embed(row).description
