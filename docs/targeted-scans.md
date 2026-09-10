# Targeted Scans

Use `--check` when a full profile is unnecessary and `--target` when the assessment should focus on specific files, directories, or globs.

```bash
infraseal scan --check hallucination --target exports/chatbot-responses.jsonl
infraseal scan --check pii --target responses/
infraseal scan --check prompt-injection --target prompts/
infraseal scan --check agent-safety --target .infraseal/agent-skills/
infraseal scan --check code-security --target app/
infraseal scan --check runtime-security --target infra/tfplan.json
infraseal scan --profile full --target src/ --exclude vendor/** --exclude node_modules/**
```

Supported check names:

- `prompt-injection`
- `pii`
- `output-safety`
- `hallucination`
- `grounding`
- `rag-quality`
- `agent-safety`
- `code-security`
- `dependency-risk`
- `runtime-security`
- `governance`

Aliases such as `privacy`, `rag`, `agent`, `code`, `dependencies`, `terraform`, and `infra` are normalized. Flags may be repeated or comma-separated.

## YAML Targeting

The most common setup is to put stable defaults in `.infraseal/infraseal.yaml`:

```yaml
inputs:
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
    - vendor/**
    - .infraseal/reports/**
    - '**/*.pdf'
  terraform_plan_json:
    - infra/tfplan.json
output:
  formats: [json, markdown, html, csv]
```

Use CLI flags for one-off reviews. CLI targets override YAML targets for that run, while `--exclude` adds to YAML exclusions.

## Terraform Plan JSON

InfraSeal can scan Terraform output generated from a real plan:

```bash
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > infra/tfplan.json
infraseal scan --check runtime-security --target infra/tfplan.json
```

The native Terraform reader looks for public ingress, sensitive public ports, public object storage, public or unencrypted databases, wildcard IAM policies, and secret-like literal values in plan output. Keep plan files out of public artifacts when they may contain sensitive values.

## Production Chatbot Exports

Yes, the deterministic grounding backend can scan real samples exported from a production chatbot. Keep secrets and unnecessary personal data out of the export.

JSONL example:

```json
{"id":"prod-001","question":"What is the refund policy?","answer":"Refunds are reviewed within 14 days.","evidence":"Refund requests are reviewed within 14 days.","supported":true}
{"id":"prod-002","question":"Do I always get 90 days?","answer":"Yes, every customer gets a 90-day unconditional refund.","evidence_file":"policies/refunds.md","unsupported_claim":"90-day unconditional refund","supported":false,"severity":"high"}
```

The same fields can be supplied as a JSON array, `{ "cases": [...] }`, a YAML array, or `cases:` YAML envelope.

Fields:

- `id`: stable case identifier
- `question`: optional originating user question
- `answer`: required chatbot output
- `evidence`: inline approved evidence
- `evidence_file`: evidence path relative to the repository or export file
- `supported`: explicit production review label
- `unsupported_claim`: a claim expected to be absent from evidence
- `severity`: optional severity override

The offline backend performs deterministic evidence resolution and declared-claim comparison. It does not infer semantic entailment when neither `supported` nor `unsupported_claim` is supplied. Configure the semantic grounding integration for that deeper judgment.
