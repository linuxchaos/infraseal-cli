# CLI Reference

## Configuration

InfraSeal reads `.infraseal/infraseal.yaml` by default. Use another path with `--config`.

```yaml
project:
  name: customer-support-agent
  type: rag-agent
  purpose: Answer support questions from approved policy.
  owner: ""
runtime:
  preferred: local
  fallback: local
inputs:
  prompts:
    - prompts/system.md
  evidence:
    - .infraseal/evidence/knowledge-base.md
  test_cases:
    - .infraseal/test-cases/*.yaml
  agent_skills:
    - .infraseal/agent-skills/
  targets:
    - exports/chatbot-responses.jsonl
    - infra/tfplan.json
  include:
    - prompts/
    - src/
    - app/
    - exports/
    - infra/
    - .infraseal/agent-skills/
  exclude:
    - .git/**
    - node_modules/**
    - .infraseal/reports/**
    - '**/*.pdf'
  terraform_plan_json:
    - infra/tfplan.json
output:
  formats: [json, markdown, html, csv]
settings:
  show_tool_details: false
  block_on_critical: true
  minimum_readiness_score: 80
governance:
  data_owner: support-data-owner
  approval_workflow: Security and data owner approve the full scan report before release.
  human_review_required: true
  evaluation_cadence: Weekly output sampling and full scan before release.
  reevaluate_on_change: true
  policy_path: .infraseal/governance/ai-policy.md
  risk_register: .infraseal/governance/risk-register.md
  impact_assessment: .infraseal/governance/impact-assessment.md
  model_card: .infraseal/governance/model-card.md
  data_lineage: .infraseal/governance/data-lineage.md
  human_oversight_plan: .infraseal/governance/human-oversight-plan.md
  monitoring_plan: .infraseal/governance/monitoring-plan.md
  change_management: .infraseal/governance/change-management.md
  incident_response_runbook: .infraseal/governance/incident-response.md
  vendor_review: .infraseal/governance/vendor-review.md
  training_records: .infraseal/governance/training-records.md
  user_disclosure: .infraseal/governance/user-disclosure.md
  audit_log: .infraseal/governance/audit-log.md
  remediation_tracking: GitHub issues with owner, due date, and closure evidence.
```

`targets` is the default scan surface. `include` can be used as the cleaner repo-wide scope for normal scans. `exclude` removes folders/files from target expansion and native file walking. CLI flags can override per run:

```bash
infraseal scan --profile full --target src/ --target infra/tfplan.json --exclude vendor/** --format html --format csv
```

## `infraseal init`

Creates `.infraseal/infraseal.yaml`, a reports directory, starter knowledge evidence, five evaluation cases, an agent skill manifest, a starter Terraform plan JSON evidence file, governance evidence templates, and a starter system prompt. It does not upload data, call a model API, install dependencies, or start a background service. Existing starters are preserved unless `--force` is used.

The generated files are intentionally editable. Governance templates contain `TODO` markers and are reported as incomplete until replaced with real content.

## `infraseal scan`

```bash
infraseal scan --profile quick
infraseal scan --profile rag --include-tool-details
infraseal scan --profile full --fail-on-gate
infraseal scan --check hallucination --target exports/chatbot-responses.jsonl
infraseal scan --check prompt-injection --target prompts/
infraseal scan --check pii --target exports/
infraseal scan --check agent-safety --target agents/
infraseal scan --check runtime-security --target infra/tfplan.json
infraseal scan --check dependency-risk --target app/
```

`--fail-on-gate` is intended for CI. Local scans report the decision without forcing a non-zero exit by default.

## `infraseal compliance iso42001`

Runs the readiness pack and generates local reports. Compliance commands inspect governance evidence and the latest technical scan evidence; they do not execute scanner adapters. Use `--fail-on-readiness` for a CI gate against `minimum_readiness_score`.

InfraSeal also includes:

```bash
infraseal compliance nist-ai-rmf
infraseal compliance aiuc1
```

Each pack uses the same repository evidence and maps gaps to concrete files or YAML fields, including policy, risk register, impact assessment, oversight plan, monitoring plan, change management, training records, user disclosure, vendor review, and audit log.

## `infraseal doctor`

Checks configuration, evidence, test cases, recommended governance inputs, evaluator availability, and local/Taubyte runtime state.

## `infraseal scanners`

Shows InfraSeal evaluation capabilities and whether enhanced, native, missing, disabled, or errored coverage is present. Backend implementation names and install commands are kept in `docs/scanner-integrations.md`.

## `infraseal report`

Regenerates a report from `.infraseal/reports/latest.json`.

```bash
infraseal report --format json
infraseal report --format markdown
infraseal report --format html
infraseal report --format csv
infraseal report --format pdf
```
