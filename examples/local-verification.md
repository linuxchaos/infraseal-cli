# Local Verification Matrix

This matrix shows the expected behavior of the bundled pass/fail samples after the optional local evaluator CLIs are installed.

Run from the repository root after `go build -o bin/infraseal ./cmd/infraseal`.

| Sample | Command focus | Expected decision | Verified behavior |
| --- | --- | --- | --- |
| `samples/tool-cases/promptfoo/pass` | prompt injection | `PASS` | Prompt evaluator ran and produced no open findings |
| `samples/tool-cases/promptfoo/fail` | prompt injection | `FAIL` | Prompt evaluator ran and reported a failing prompt assertion |
| `samples/tool-cases/hallbayes/pass` | hallucination | `PASS` | Grounding validator resolved evidence and found no unsupported claim |
| `samples/tool-cases/hallbayes/fail` | hallucination | `FAIL` | Grounding validator resolved evidence and reported the unsupported claim |
| `samples/tool-cases/terraform/pass` | runtime security | `PASS` | Terraform plan reader parsed plan JSON and found no public runtime exposure |
| `samples/tool-cases/terraform/fail` | runtime security | `FAIL` | Terraform plan reader found public ingress, broad IAM, and unsafe data-store settings |
| `samples/tool-cases/go/pass` | code security | `PASS` | Workload/code analyzers ran against a clean Go target |
| `samples/tool-cases/go/fail` | code security | `FAIL` | Source security analyzer reported a path traversal finding |
| `samples/tool-cases/govulncheck/pass` | dependency risk | `PASS` | Dependency analyzer ran and found no reachable vulnerability |
| `samples/tool-cases/govulncheck/fail` | dependency risk | `FAIL` | Dependency analyzer reported a reachable vulnerable call path |
| `samples/tool-cases/agent/pass` | agent safety | `PASS` | Agent analyzers ran against a restricted skill manifest |
| `samples/tool-cases/agent/fail` | agent safety | `FAIL` | Agent checks reported risky tool permissions |

Focused scan examples:

```bash
./bin/infraseal --config samples/tool-cases/promptfoo/fail/.infraseal/infraseal.yaml scan --check prompt-injection --target promptfooconfig.yaml --include-tool-details
./bin/infraseal --config samples/tool-cases/hallbayes/fail/.infraseal/infraseal.yaml scan --check hallucination --target exports/chatbot-responses.jsonl --include-tool-details
./bin/infraseal --config samples/tool-cases/terraform/fail/.infraseal/infraseal.yaml scan --check runtime-security --target infra/tfplan.json --include-tool-details
./bin/infraseal --config samples/tool-cases/go/fail/.infraseal/infraseal.yaml scan --check code-security --target app --include-tool-details
./bin/infraseal --config samples/tool-cases/govulncheck/fail/.infraseal/infraseal.yaml scan --check dependency-risk --target app --include-tool-details
./bin/infraseal --config samples/tool-cases/agent/fail/.infraseal/infraseal.yaml scan --check agent-safety --target .infraseal/agent-skills --include-tool-details
```

The pass samples use the same command shape with `/pass/` in the config path.
