# Tool Case Samples

These samples are intentionally small. Each pair has a passing and failing input so operators can see how InfraSeal turns real files, exported responses, source code, and infrastructure evidence into results.

Run commands from this repository root after building the CLI:

```bash
go build -o bin/infraseal ./cmd/infraseal
```

Optional evaluator CLIs improve coverage for the matching samples:

```bash
npm install -g promptfoo
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
python -m pip install git+https://github.com/NVIDIA/SkillSpector.git
```

Expected outcomes:

- `pass` samples should produce a `PASS` decision.
- `fail` samples should produce a `FAIL` decision.
- Missing optional CLIs are reported as unavailable and do not create findings.
- The Hallbayes/Berry samples use the native deterministic evidence workflow unless a semantic Berry MCP binding is configured later.

## Prompt And Red-Team Evaluation

```bash
./bin/infraseal --config samples/tool-cases/promptfoo/pass/.infraseal/infraseal.yaml scan --check prompt-injection --target promptfooconfig.yaml
./bin/infraseal --config samples/tool-cases/promptfoo/fail/.infraseal/infraseal.yaml scan --check prompt-injection --target promptfooconfig.yaml
```

## Hallucination And Grounding

```bash
./bin/infraseal --config samples/tool-cases/hallbayes/pass/.infraseal/infraseal.yaml scan --check hallucination --target exports/chatbot-responses.jsonl
./bin/infraseal --config samples/tool-cases/hallbayes/fail/.infraseal/infraseal.yaml scan --check hallucination --target exports/chatbot-responses.jsonl
```

## Terraform Plan Evidence

```bash
./bin/infraseal --config samples/tool-cases/terraform/pass/.infraseal/infraseal.yaml scan --check runtime-security --target infra/tfplan.json
./bin/infraseal --config samples/tool-cases/terraform/fail/.infraseal/infraseal.yaml scan --check runtime-security --target infra/tfplan.json
```

## Go Source Security

```bash
./bin/infraseal --config samples/tool-cases/go/pass/.infraseal/infraseal.yaml scan --check code-security --target app
./bin/infraseal --config samples/tool-cases/go/fail/.infraseal/infraseal.yaml scan --check code-security --target app
```

## Go Dependency Risk

```bash
./bin/infraseal --config samples/tool-cases/govulncheck/pass/.infraseal/infraseal.yaml scan --check dependency-risk --target app
./bin/infraseal --config samples/tool-cases/govulncheck/fail/.infraseal/infraseal.yaml scan --check dependency-risk --target app
```

## Agent Skill Safety

```bash
./bin/infraseal --config samples/tool-cases/agent/pass/.infraseal/infraseal.yaml scan --check agent-safety --target .infraseal/agent-skills
./bin/infraseal --config samples/tool-cases/agent/fail/.infraseal/infraseal.yaml scan --check agent-safety --target .infraseal/agent-skills
```
