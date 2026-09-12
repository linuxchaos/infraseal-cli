# RAG Support Agent Sample

This sample demonstrates a RAG support agent with realistic governance evidence and intentionally unsafe technical/runtime evidence.

Expected findings:

- Exported chatbot output contains an unsupported 90-day refund claim
- Prompt evaluation includes a system-prompt disclosure failure
- Terraform plan JSON exposes public SSH, a public/unencrypted database, wildcard IAM, and a secret-like value
- Go source/security tooling flags intentionally risky sample code
- Governance evidence is mostly complete, but readiness remains blocked by open high/critical technical findings

Run from the `infraseal-cli` directory:

```bash
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml scan --profile quick
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml scan --profile rag --include-tool-details
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance iso42001
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance nist-ai-rmf
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance aiuc1
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml scan --check hallucination --target exports/chatbot-responses.jsonl
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml scan --check runtime-security --target infra/tfplan.json
```

The sample includes `exports/chatbot-responses.jsonl`, representing responses exported from a production chatbot. The deterministic grounding backend resolves inline evidence or `evidence_file`, then flags cases marked unsupported or containing a declared unsupported claim absent from the evidence. This is a valid way to assess downloaded production samples without sending them to another service.

The sample also includes `.infraseal/promptfooconfig.yaml`, which lets Promptfoo run locally against exported answers without a hosted model key. The deterministic grounding backend is not a semantic model judge. For semantic information-budget verification, configure the optional Berry integration described in `docs/scanner-integrations.md`. Reports state whether a capability ran through a real external evaluator, a native InfraSeal check, a disabled integration, a missing dependency, or an execution error.

The governance documents under `.infraseal/governance/` are intentionally short but complete enough to show how non-technical benchmark evidence is represented. Starter templates from `infraseal init` contain TODO markers and are reported as incomplete until replaced with real content.
