# Optional Backend Integrations

This is the only InfraSeal document that intentionally names backend tools. End-user CLI output and generated reports use InfraSeal capability labels instead.

None of these tools is required to run MCPvia native checks, targeted text checks, deterministic grounding checks, Terraform plan review, governance assessment, ISO readiness, or local reports. Install only the coverage relevant to the repository. Missing dependencies are reported as unavailable and do not create synthetic findings.

## Promptfoo

Purpose: prompt injection, jailbreak, red-team, and prompt regression evaluation.

```bash
npm install -g promptfoo
promptfoo --version
```

Add `promptfooconfig.yaml` or `.infraseal/promptfooconfig.yaml`. A provider or deterministic local provider must be configured according to Promptfoo documentation. Without that file, InfraSeal marks this capability disabled and records no findings from this adapter.

## Giskard

Purpose: privacy, bias, robustness, and model regression evaluation.

```bash
python -m pip install "giskard[llm]"
```

Giskard needs a model function or endpoint and a dataset. The current CLI detects the dependency and marks the capability disabled until a repository-specific model binding is supplied. No production endpoint is called implicitly.

## RAGAS

Purpose: faithfulness, context precision, context recall, and RAG quality.

```bash
python -m pip install ragas
```

RAGAS usually needs exported question/answer/context/reference rows and, depending on metrics, model or embedding credentials. InfraSeal marks this capability missing or disabled until that evaluation binding is configured.

## DeepEval

Purpose: answer relevance, faithfulness, hallucination, and agent evaluation.

```bash
python -m pip install deepeval
```

DeepEval requires a test dataset and evaluator model configuration for model-judged metrics. InfraSeal does not silently reuse unrelated credentials.

## Hallbayes / Berry

Purpose: evidence-grounding verification with evidence spans, token logprobs, and an auditable ledger.

Berry is an MCP server, not a normal recursive file scanner. The project documents these basic steps:

```bash
git clone https://github.com/leochlon/hallbayes.git
cd hallbayes
pipx install -e .
berry init
berry setup
berry setup status
```

For an OpenAI-compatible verifier, `berry setup` prompts for provider, model, and credential. The backend requires a model endpoint that supports token logprobs. Keep API keys in Berry's user-level configuration or environment, never in the repository.

Example environment-based setup:

```bash
export OPENAI_API_KEY="..."
export BERRY_VERIFIER_BACKEND="openai"
export BERRY_VERIFIER_MODEL="gpt-4.1-mini"
berry mcp --transport stdio --project-root /path/to/repository
```

The current InfraSeal CLI supports the deterministic local workflow and detects Berry availability, but it does not yet invoke `detect_hallucination` over MCP. Until that binding is completed, reports explicitly label Berry-backed semantic verification as disabled and local evidence checks as `native`.

The local workflow can use real production chatbot exports. It deterministically resolves evidence and applies explicit `supported` or `unsupported_claim` labels; it does not send data to OpenAI. This is not a semantic model judge. It proves whether declared claims are backed by the supplied evidence file and keeps the source evidence in the report artifact.

Official project: https://github.com/leochlon/hallbayes

## NVIDIA SkillSpector

Purpose: agent skill permissions, credential exposure, hidden instructions, and data exfiltration risk.

```bash
python -m pip install git+https://github.com/NVIDIA/SkillSpector.git
skillspector --help
```

## Microsoft Agent Governance Toolkit

Purpose: agent policy, approval gates, budget policy, and decision trails. It is a governance plugin, not a sandbox security boundary. The CLI currently detects this capability and records it as missing until a compatible policy bundle is configured.

## Guard0 g0

Purpose: AI workload, MCP, agent, RAG, and supply-chain security.

```bash
npx @guard0/g0 scan .
npx @guard0/g0 scan src --json --output g0.json --no-banner
```

InfraSeal invokes the JSON-output form when Node.js and `npx` are available. If `--target` is supplied, InfraSeal passes the selected target path to g0 instead of always scanning the repository root.

## Terraform plan JSON

Purpose: runtime, network, IAM, storage, database, and secret-exposure review from infrastructure-as-code plan output.

```bash
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > infra/tfplan.json
infraseal scan --check runtime-security --target infra/tfplan.json
```

This adapter is native to InfraSeal and does not require Terraform at scan time when the JSON plan file already exists. It is intended for CI pipelines where Terraform produces plan evidence and InfraSeal evaluates the output as part of the AI workload release gate.

## gosec

Purpose: Go source security.

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

The target repository must contain `go.mod`.

## govulncheck

Purpose: reachable Go dependency vulnerabilities.

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

The target repository must contain `go.mod`.

## Verify Coverage

```bash
infraseal doctor
infraseal scanners
infraseal scan --profile full --include-tool-details
```

The public commands report capability status without backend names. Use this document when operator-level dependency troubleshooting is required.

## Pass/Fail Samples

The `samples/tool-cases/` directory includes small passing and failing inputs for Promptfoo, Hallbayes/Berry local grounding, SkillSpector/g0 agent analysis, gosec, govulncheck, and Terraform plan JSON. Run those samples before wiring a new repository into CI.
