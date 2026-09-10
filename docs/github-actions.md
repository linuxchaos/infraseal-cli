# GitHub Actions

InfraSeal can run as a pull request gate in a repository that contains AI workload evidence, prompts, source code, agent definitions, exported model responses, and optional Terraform plan JSON.

## Repository Setup

Run this once from the repository root:

```bash
infraseal init
infraseal doctor
```

Then edit `.infraseal/infraseal.yaml` so `inputs.include`, `inputs.exclude`, `inputs.prompts`, `inputs.evidence`, `inputs.test_cases`, `inputs.agent_skills`, and `inputs.terraform_plan_json` point to real files in that repository.

If the repository uses Terraform, generate a plan JSON during the workflow before running InfraSeal:

```bash
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > infra/tfplan.json
```

## Pull Request Workflow

Create `.github/workflows/infraseal.yml` in the target repository:

```yaml
name: InfraSeal

on:
  pull_request:
    paths:
      - ".infraseal/**"
      - "prompts/**"
      - "agents/**"
      - "app/**"
      - "src/**"
      - "infra/**"
      - "**/*.go"
  workflow_dispatch:

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.24.x"

      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Install InfraSeal
        run: go install github.com/linuxchaos/infraseal-cli/cmd/infraseal@latest

      - name: Generate Terraform plan evidence
        if: hashFiles('infra/**/*.tf') != ''
        run: |
          cd infra
          terraform init -input=false
          terraform plan -out=tfplan.bin
          terraform show -json tfplan.bin > tfplan.json
          cd ..

      - name: Run AI assurance scan
        run: infraseal scan --profile full --fail-on-gate --format json --format markdown --format html --format csv

      - name: Run readiness gate
        run: infraseal compliance nist-ai-rmf --fail-on-readiness --format json --format markdown

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infraseal-reports
          path: .infraseal/reports/
```

## Targeted PR Gate

For a narrower hallucination-only check over exported chatbot responses:

```yaml
- name: Run hallucination evidence check
  run: infraseal scan --check hallucination --target exports/chatbot-responses.jsonl --fail-on-gate --format markdown --format csv
```

For infrastructure evidence only:

```yaml
- name: Run runtime security check
  run: infraseal scan --check runtime-security --target infra/tfplan.json --fail-on-gate --format markdown --format csv
```

## Expected Failure Behavior

`--fail-on-gate` returns a non-zero exit code when the scan decision is `fail`. `--fail-on-readiness` returns a non-zero exit code when the selected readiness pack is below the configured threshold or blocked by high-severity unresolved evidence.

Reports are still uploaded with `if: always()`, so reviewers can inspect the findings even when the pull request check fails.
