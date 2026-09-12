def search_approved_evidence(query: str) -> str:
    allowed_topics = {
        "refund": "Refund requests are reviewed within 14 days and depend on account eligibility.",
        "escalation": "Escalate account changes, identity checks, and exceptions to a human reviewer.",
    }
    return allowed_topics.get(query.lower(), "No approved evidence found. Escalate to support.")
