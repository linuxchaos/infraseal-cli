# Installation And First Run

InfraSeal is designed to be downloaded beside or inside an existing GitHub repository and run locally. Native evaluation, governance checks, ISO readiness mapping, and reports work without a cloud login.

## Build From Source

Requirements: Git and Go 1.24 or newer.

```bash
git clone https://github.com/linuxchaos/infraseal-cli.git
cd infraseal-cli
go test ./...
go build -o bin/infraseal ./cmd/infraseal
```

On macOS:

```bash
brew install go node python terraform
git clone https://github.com/linuxchaos/infraseal-cli.git
cd infraseal-cli
go test ./...
go build -o bin/infraseal ./cmd/infraseal
./bin/infraseal version
```

On Windows:

```powershell
go build -o bin/infraseal.exe ./cmd/infraseal
$env:PATH += ";$PWD\bin"
infraseal version
```

To install from source into your Go binary directory:

```bash
go install github.com/linuxchaos/infraseal-cli/cmd/infraseal@latest
```

If your shell cannot find `infraseal`, add the Go binary directory to `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

## Use It In Another Repository

```bash
cd path/to/customer-ai-repository
/path/to/infraseal init
/path/to/infraseal doctor
/path/to/infraseal scan --profile quick
/path/to/infraseal compliance iso42001
/path/to/infraseal compliance nist-ai-rmf
/path/to/infraseal compliance aiuc1
```

You do not copy or reference the sample YAML. `init` generates a configuration owned by the repository you are assessing. When `.infraseal/infraseal.yaml` is used, relative input and target paths resolve from that repository's root.

After initialization:

1. Set `project.name`, `project.type`, `project.purpose`, and `project.owner`.
2. Replace the starter evidence and test cases with real repository-specific material.
3. Set `inputs.prompts`, `inputs.evidence`, `inputs.test_cases`, `inputs.agent_skills`, `inputs.include`, `inputs.exclude`, and `inputs.targets` to files that actually exist in the repository.
4. Add governance evidence files under `.infraseal/governance/` or update the YAML paths to your existing policy/risk/approval documentation.
5. Set `output.formats` to any combination of `json`, `markdown`, `html`, `csv`, and `pdf`.
6. Run `infraseal doctor` before the first scan.

To avoid generating starter files, create a YAML configuration manually and pass it with `--config`. If the config is not inside a `.infraseal` directory, relative paths resolve from the directory containing that config.

## What `infraseal init` Does

It creates only local starter files:

```text
.infraseal/
  infraseal.yaml
  evidence/knowledge-base.md
  evidence/tfplan.json
  governance/*.md
  test-cases/*.yaml
  agent-skills/skill-manifest.yaml
  reports/
prompts/system.md
```

It does not install tools, upload source code, call a model provider, create an account, or run a scan. The generated YAML tells MCPvia where the repository's prompts, evidence, tests, skills, and optional target exports live.

## Immediate Zero-Configuration Path

1. Run `infraseal init`.
2. Replace starter evidence and test content with repository-specific files.
3. Update paths and project metadata in `.infraseal/infraseal.yaml`.
4. Run `infraseal doctor`.
5. Optional: generate Terraform plan evidence with `terraform plan -out=tfplan.bin && terraform show -json tfplan.bin > infra/tfplan.json`.
6. Run `infraseal scan --profile quick`.
7. Run `infraseal compliance iso42001`.
8. Run `infraseal compliance nist-ai-rmf` or `infraseal compliance aiuc1` when those views are useful to the team.

Optional backend integrations add depth. They are not required for MCPvia native checks or local reports. See `scanner-integrations.md` for those requirements.

## Optional Evaluator Setup

InfraSeal is useful without any optional evaluator CLI. A first run can still inspect configured test cases, exported chatbot responses, Terraform plan JSON, governance evidence, and native targeted patterns. Optional tools add deeper checks when the repository contains matching files.

Common local setup:

```bash
npm install -g promptfoo
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
python -m pip install git+https://github.com/NVIDIA/SkillSpector.git
```

InfraSeal targets Go 1.24 or newer. Some optional evaluator CLIs may raise their own toolchain requirements; for example, recent `gosec@latest` releases require Go 1.25 or newer to install.

The `g0` evaluator is invoked through `npx`, so Node.js and npm are enough:

```bash
npx @guard0/g0 scan . --help
```

After installing optional tools:

```bash
infraseal doctor
infraseal scanners
infraseal scan --profile full --include-tool-details
```

Missing optional tools do not produce findings. They are reported as unavailable so the operator knows which coverage was not present.

## Using InfraSeal Without The Sample YAML

In a normal repository, do this from the repository root:

```bash
infraseal init
```

Then edit `.infraseal/infraseal.yaml` to point at the repository's real files. At minimum, set:

- `project.name`, `project.type`, `project.purpose`, and `project.owner`
- `inputs.include` for folders to scan
- `inputs.exclude` for generated files, vendored code, reports, and large assets
- `inputs.prompts` for prompt templates or system prompts
- `inputs.evidence` for approved policy, knowledge, retrieval, or product evidence
- `inputs.test_cases` for YAML evaluation cases
- `inputs.agent_skills` for agent tools, manifests, or skill folders
- `inputs.terraform_plan_json` for Terraform plan output when infrastructure should be reviewed
- `output.formats` for `json`, `markdown`, `html`, `csv`, or `pdf`

Relative paths resolve from the repository root when the config is at `.infraseal/infraseal.yaml`. If you keep the YAML elsewhere and pass `--config`, relative paths resolve from the directory containing that YAML.

Run a focused check first:

```bash
infraseal scan --check hallucination --target exports/chatbot-responses.jsonl --format html --format csv
```

Then run the broader release check:

```bash
infraseal scan --profile full --format json --format markdown --format html --format csv
infraseal compliance iso42001 --format markdown --format html
```
