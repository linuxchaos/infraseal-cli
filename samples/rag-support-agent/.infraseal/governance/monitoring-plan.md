# Monitoring Plan

The team samples production chatbot exports weekly and runs a focused hallucination scan against those outputs. A full InfraSeal scan runs before production release and after prompt, retrieval, dependency, agent skill, model, or Terraform changes.

Metrics include unsupported-answer rate, prompt-injection refusal rate, PII leakage findings, high/critical source findings, dependency vulnerabilities, and infrastructure plan exposure. Alert thresholds and investigation notes are tracked in GitHub issues with report links.
