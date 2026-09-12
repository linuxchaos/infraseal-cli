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
      - uses: actions/checkout@v7

      - uses: actions/setup-go@v7
        with:
          go-version: "1.26.x"

      - uses: actions/setup-node@v7
        with:
          node-version: "24"

      - name: Install evaluator CLIs
        run: |
          npm install -g promptfoo@latest
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          go install golang.org/x/vuln/cmd/govulncheck@latest

      - name: Install optional agent analyzer
        continue-on-error: true
        run: |
          python3 -m pip install --user git+https://github.com/NVIDIA/SkillSpector.git
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

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
        run: infraseal compliance iso42001 --fail-on-readiness --format json --format markdown

      - uses: actions/upload-artifact@v7
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

## Notes On Coverage

The workflow installs the common open-source evaluator CLIs that InfraSeal can orchestrate. The CLI module targets Go 1.24, but current source-security and dependency tooling may require Go 1.26 or newer to install. If a repository does not contain matching inputs, a capability may still be disabled for that run. For example, source-security checks require `go.mod`, infrastructure checks require Terraform plan JSON, and prompt red-team checks require either a Promptfoo configuration or InfraSeal YAML test cases that can be converted into an offline Promptfoo run.

Readiness commands do not launch scanner adapters. Run `infraseal scan` first, then run `infraseal compliance iso42001` so the readiness report can load the latest technical evidence.
