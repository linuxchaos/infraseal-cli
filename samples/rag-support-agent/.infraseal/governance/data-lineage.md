# Data Lineage

Inputs include the system prompt in `prompts/system.md`, approved policy evidence in `.infraseal/evidence/knowledge-base.md`, exported chatbot responses in `exports/chatbot-responses.jsonl`, and agent skill manifests under `.infraseal/agent-skills/`. Evaluation outputs are stored under `.infraseal/reports/`.

Customer identifiers must be redacted before inclusion in test cases or reports. Production exports should contain question, answer, evidence, evidence file, support status, and severity. Secrets must not be embedded in prompts, Terraform plans, or scan artifacts.
