# InfraSeal CLI

InfraSeal is a local-first command-line tool for evaluating AI workloads, agentic code, repository evidence, and governance readiness before deployment.

It is built for developers and AI teams who need a practical way to answer a simple release question: what evidence do we have that this AI system is grounded, safe enough to ship, monitored, and reviewable?

InfraSeal can run directly against a target folder, or from inside a repository that has been initialized with `.infraseal/infraseal.yaml`. It normalizes findings from native checks and optional evaluation backends, calculates a trust score, maps evidence to AI governance benchmarks, and writes local reports in JSON, Markdown, HTML, CSV, and PDF.

The orchestration layer is MCPvia, which resolves inputs, chooses scan profiles, runs evaluators, normalizes findings, maps benchmark evidence, and generates reports.

## What It Checks

Technical checks:

- Prompt injection and jailbreak test failures
- Hallucination and grounding gaps against approved evidence
- PII, credential, and data leakage signals
- Unsafe output regression cases
- Agent skill permissions and risky workflow patterns
- Go source security and reachable dependency risk
- Terraform plan JSON for runtime, network, IAM, storage, database, and secret exposure

Governance and readiness checks:

- AI system owner and data owner
- AI policy, risk register, impact assessment, model card, and data lineage
- Human oversight plan, approval workflow, monitoring cadence, and change-management rules
- Incident response, vendor review, user disclosure, training records, audit log, and remediation tracking
- ISO/IEC 42001 Clause 4-10 readiness, plus separate NIST AI RMF and AIUC-1 views

## What It Does Not Do

InfraSeal is not a certification authority, legal opinion, penetration test replacement, or guarantee that an AI system is compliant or safe.

Some benchmark controls are organizational controls. A CLI can check whether evidence exists, whether technical findings contradict readiness, and whether reports give useful next steps. It cannot prove that leadership assigned accountability, employees completed training, a vendor contract is enforceable, a human review process is actually followed, or an incident response process works in practice. For those controls, InfraSeal reports the missing or weak evidence and recommends concrete documents, owners, review steps, and operating processes.

## Why This Exists

AI systems are hard to audit because the important evidence is scattered across prompts, retrieval sources, model outputs, agent tools, source code, infrastructure plans, policies, and release decisions. Research and standards work increasingly distinguish between technical evaluation and process-oriented auditability: both matter. InfraSeal focuses on making repository-level evidence easier to collect, scan, normalize, and review before a release.

Useful references:

- [ISO/IEC 42001](https://www.iso.org/standard/42001)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
- [NIST AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/)
- [AIUC-1 public principles](https://aiuc-1.com/)
- [Can AI be Auditable?](https://arxiv.org/abs/2509.00575)
- [Auditing of AI: Legal, Ethical and Technical Approaches](https://arxiv.org/abs/2407.06235)

## Install

Requirements:

- Git
- Go 1.24 or newer
- Optional: Node.js and npm for enhanced AI workload scanning
- Optional: Python 3.11+ for selected evaluator integrations
- Optional: Terraform when you want to generate plan JSON before scanning

Optional evaluator CLIs:

```bash
npm install -g promptfoo
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
python -m pip install git+https://github.com/NVIDIA/SkillSpector.git
```

InfraSeal does not require every optional tool before it can run. Missing evaluators are reported as unavailable and do not create findings. Native checks, deterministic grounding checks, Terraform plan review, compliance readiness, and report generation still work locally. When Promptfoo is installed but no Promptfoo config exists, InfraSeal can generate an offline Promptfoo config from `.infraseal/test-cases/*.yaml` and run those cases through Promptfoo.

### macOS

```bash
brew install go node python terraform
git clone https://github.com/linuxchaos/infraseal-cli.git
cd infraseal-cli
go test ./...
go build -o bin/infraseal ./cmd/infraseal
./bin/infraseal version
```

To make the binary available from any terminal:

```bash
go install ./cmd/infraseal
export PATH="$(go env GOPATH)/bin:$PATH"
```

### Linux

```bash
git clone https://github.com/linuxchaos/infraseal-cli.git
cd infraseal-cli
go test ./...
go build -o bin/infraseal ./cmd/infraseal
./bin/infraseal version
```

### Windows

```powershell
git clone https://github.com/linuxchaos/infraseal-cli.git
cd infraseal-cli
go test ./...
go build -o bin/infraseal.exe ./cmd/infraseal
.\bin\infraseal.exe version
```

## Try The Included Sample

The repository includes a realistic sample workload at `samples/rag-support-agent/`. It contains prompts, exported chatbot responses, approved policy evidence, governance documents, an agent skill manifest, Go code, and Terraform plan JSON.

Run:

```bash
go run ./cmd/infraseal scan --profile full --target samples/rag-support-agent --format json --format markdown --format html --format csv --format pdf --include-tool-details
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml doctor
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance iso42001
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance nist-ai-rmf
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance aiuc1
```

The first command can be run from the CLI repo root. InfraSeal sees that the target folder already contains `.infraseal/infraseal.yaml`, uses that config automatically, and scans the whole sample directory.

Additional pass/fail tool cases live under `samples/tool-cases/`. They are small by design and let you verify each scanner path against a clean input and an intentionally risky input.

See [examples/local-verification.md](examples/local-verification.md) for the scanner pass/fail matrix.

Example output:

```text
InfraSeal AI Assurance

Project:      rag-support-agent
Workload:     rag-agent
Profile:      full
Trust Score:  0/100
Decision:     FAIL

Findings:
- critical Security: Data access without tenant filter - cross-tenant access risk
- critical Code Security: Terraform plan exposes inbound access to the internet
- high Grounding: unsupported 90-day refund claim
- high Grounding: Unsupported production chatbot claim detected: 90-day unconditional refund
- high Security: prompt injection disclosure
- high Code Security: Terraform plan makes a database publicly accessible
- high Governance: Terraform plan disables database storage encryption
- high Security: Terraform plan contains a secret-like literal value
- high Code Security: Terraform plan includes wildcard IAM policy access
- medium Code Security: G304 Potential file inclusion via variable

Reports:
- .infraseal/reports/scan-<timestamp>.html
- .infraseal/reports/scan-<timestamp>.csv
- .infraseal/reports/scan-<timestamp>.json
- .infraseal/reports/scan-<timestamp>.md
- .infraseal/reports/scan-<timestamp>.pdf

Evaluation Coverage: MCPvia native active; 6 real, 1 native, 3 missing, 1 disabled, 0 errors
```

## Use It In Your Own Repository

From the root of the repository you want to assess:

```bash
infraseal scan --profile full --target .
infraseal init
infraseal doctor
infraseal scan --profile full
infraseal compliance iso42001
```

The first command is the fastest technical scan and works even before initialization. It uses an in-memory default config, scans the target folder, and writes reports to `.infraseal/reports/`.

`infraseal init` creates `.infraseal/infraseal.yaml` plus starter evidence, test cases, governance templates, an agent skill manifest, a reports folder, and a starter system prompt. It does not upload data, install third-party tools, call a model API, or start a service. After initialization, `infraseal scan --profile full` uses the repo-owned YAML and scans `.` with default excludes.

Replace the starter files with real repository evidence, then update the YAML:

```yaml
project:
  name: support-agent
  type: rag-agent
  purpose: Answer support questions using approved policy evidence.
  owner: ai-platform-team
inputs:
  prompts:
    - prompts/system.md
  evidence:
    - docs/policies/refunds.md
  test_cases:
    - .infraseal/test-cases/*.yaml
  agent_skills:
    - agents/
  include:
    - .
  exclude:
    - .git/**
    - .github/**
    - .infraseal/governance/**
    - node_modules/**
    - vendor/**
    - .infraseal/test-cases/**
    - .infraseal/reports/**
  terraform_plan_json:
    - infra/tfplan.json
output:
  formats: [json, markdown, html, csv, pdf]
settings:
  block_on_critical: true
  minimum_readiness_score: 80
governance:
  data_owner: support-data-owner
  approval_workflow: Security and data owner approve full scan before release.
  human_review_required: true
  evaluation_cadence: Full scan before release and weekly output sampling.
```

## Targeted Scans

```bash
infraseal scan --check hallucination --target exports/chatbot-responses.jsonl
infraseal scan --check pii --target responses/
infraseal scan --check prompt-injection --target prompts/
infraseal scan --check agent-safety --target agents/
infraseal scan --check code-security --target app/
infraseal scan --check dependency-risk --target app/
infraseal scan --check runtime-security --target infra/tfplan.json
infraseal scan --profile full --target src/ --exclude vendor/** --format html --format csv
```

Terraform plan workflow:

```bash
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > infra/tfplan.json
infraseal scan --check runtime-security --target infra/tfplan.json
```

## Pull Request Checks

The repository includes `.github/workflows/infraseal.yml` for validating this CLI project. For another repository, use the workflow template in [docs/github-actions.md](docs/github-actions.md) to run InfraSeal during pull requests.

Typical PR gate:

```bash
infraseal scan --profile full --fail-on-gate
infraseal compliance nist-ai-rmf --fail-on-readiness
```

## Commands

```text
infraseal init
infraseal doctor
infraseal scanners
infraseal scan --profile quick|rag|agent|governance|full
infraseal scan --check hallucination|grounding|pii|prompt-injection|agent-safety|code-security|dependency-risk|runtime-security
infraseal compliance iso42001|nist-ai-rmf|aiuc1
infraseal report --format json|markdown|html|csv|pdf
infraseal version
```

## Optional Integrations

InfraSeal works without cloud credentials. Optional backends can add deeper evaluation coverage when installed and configured. Backend names and setup steps are intentionally kept in [docs/scanner-integrations.md](docs/scanner-integrations.md) instead of primary scan output.

## Taubyte Runtime

The Taubyte runtime provider is scaffolded but not live. `--runtime taubyte` currently falls back to local execution when `runtime.fallback: local` is configured. The planned integration is a sandbox deployment flow that provisions an isolated Taubyte or cloud-native environment, runs the workload there, and returns scan evidence to InfraSeal. See [docs/taubyte-runtime.md](docs/taubyte-runtime.md).

## Future Compliance Workflow

The ISO readiness pack now reports per-clause control assessments with applicability, status, evidence checked, gaps, and next steps. A planned workflow will add a step-by-step questionnaire for non-technical controls, then optionally use a customer-controlled AI reviewer to extract evidence from policy documents and summarize whether processes appear complete. That future mode should keep source material local or inside customer-owned infrastructure and preserve reviewer prompts, excerpts, model settings, and decision traces.

## Documentation

- [Installation](docs/installation.md)
- [CLI Reference](docs/cli.md)
- [Targeted Scans](docs/targeted-scans.md)
- [Compliance Benchmarks](docs/compliance-benchmarks.md)
- [GitHub Actions](docs/github-actions.md)
- [Scanner Integrations](docs/scanner-integrations.md)
- [Taubyte Runtime](docs/taubyte-runtime.md)
- [MCPvia](docs/mcpvia.md)

## Development

```bash
go test ./...
go run ./cmd/infraseal version
```

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
