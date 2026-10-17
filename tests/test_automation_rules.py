from services.job_rules import evaluate_condition


CRITICAL_CVE = {
    "all": [
        {"field": "category", "op": "eq", "value": "critical_cve"},
        {"any": [
            {"field": "cvss", "op": "gte", "value": 8.0},
            {"field": "exploited", "op": "eq", "value": "YES"},
        ]},
    ]
}


def test_critical_cve_rule_matches_cvss_or_kev_only():
    assert evaluate_condition({"category": "critical_cve", "cvss": 8.0, "exploited": "UNKNOWN"}, CRITICAL_CVE)
    assert evaluate_condition({"category": "critical_cve", "cvss": 4.0, "exploited": "YES"}, CRITICAL_CVE)
    assert not evaluate_condition({"category": "critical_cve", "cvss": 7.9, "exploited": "UNKNOWN"}, CRITICAL_CVE)
    assert not evaluate_condition({"category": "news", "cvss": 10.0, "exploited": "YES"}, CRITICAL_CVE)


def test_zero_day_requires_explicit_verified_flag():
    zero_day = {"all": [
        {"field": "category", "op": "eq", "value": "zero_day"},
        {"field": "verified_zero_day", "op": "eq", "value": True},
    ]}
    assert evaluate_condition({"category": "zero_day", "verified_zero_day": True}, zero_day)
    assert not evaluate_condition({"category": "zero_day", "verified_zero_day": False, "exploited": "YES"}, zero_day)
