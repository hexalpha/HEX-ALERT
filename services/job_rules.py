"""Transparent, data-only matcher for job automation conditions."""
from __future__ import annotations

from datetime import datetime, timezone

from collectors.jobs.normalize import CYBER_TERMS, ENTRY_TERMS, SENIOR_TERMS, minimum_experience_years


DEFAULT_FRESHER_CYBER_RULE = {
    "all": [
        {"field": "category", "op": "eq", "value": "jobs"},
        {"any": [{"field": "title_experience", "op": "contains", "value": term} for term in ENTRY_TERMS]},
        {"any": [{"field": "title", "op": "contains", "value": term} for term in CYBER_TERMS]},
        {"not": {"field": "title", "op": "contains_any", "values": list(SENIOR_TERMS)}},
        {"not": {"field": "experience", "op": "contains", "value": "3+ years"}},
        {"not": {"field": "experience", "op": "min_years_gte", "value": 3}},
        {"field": "published_at", "op": "days_lte", "value": 14},
        {"field": "match_score", "op": "gte", "value": 55},
    ]
}


def _value(job, field):
    if field == "title_experience":
        return f"{job.get('title') or ''} {job.get('experience') or ''}".lower()
    if field == "category":
        return job.get("category", "jobs")
    return job.get(field)


def evaluate_condition(job: dict, node: dict) -> bool:
    if not isinstance(node, dict):
        return False
    if "all" in node:
        terms = node["all"]
        return isinstance(terms, list) and all(evaluate_condition(job, item) for item in terms)
    if "any" in node:
        terms = node["any"]
        return isinstance(terms, list) and any(evaluate_condition(job, item) for item in terms)
    if "not" in node:
        return not evaluate_condition(job, node["not"])
    field, op, expected = node.get("field"), node.get("op"), node.get("value")
    actual = _value(job, str(field or ""))
    if op == "contains":
        return str(expected or "").casefold() in str(actual or "").casefold()
    if op == "contains_any":
        return any(str(value).casefold() in str(actual or "").casefold() for value in node.get("values", []) if value)
    if op == "in":
        return str(actual).casefold() in {str(value).casefold() for value in node.get("values", [])}
    if op == "eq":
        return str(actual).casefold() == str(expected).casefold()
    if op in {"gte", "lte"}:
        try:
            return float(actual) >= float(expected) if op == "gte" else float(actual) <= float(expected)
        except (TypeError, ValueError):
            return False
    if op == "days_lte":
        value = actual
        if not value:
            return False
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return False
        if not isinstance(value, datetime):
            return False
        value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        age = max(0, (datetime.now(timezone.utc) - value).total_seconds() / 86400)
        return age <= float(expected)
    if op == "min_years_gte":
        minimum = minimum_experience_years(actual)
        return minimum is not None and minimum >= float(expected)
    if op == "seniority_excluded":
        text = str(actual or "").casefold()
        return not any(str(value).casefold() in text for value in node.get("values", []))
    return False


def matches_fresher_cyber_rule(job: dict, conditions: dict | None = None) -> bool:
    return evaluate_condition(job, conditions or DEFAULT_FRESHER_CYBER_RULE)
