# Examples

Start with the bundled RAG support agent sample:

```bash
go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml scan --profile full --format html --format csv
```

The sample is shaped like a small development team repository. It includes:

- `app/`: intentionally risky Go code
- `prompts/`: system prompt under evaluation
- `exports/`: exported chatbot responses with supported and unsupported claims
- `infra/`: Terraform plan JSON with runtime and IAM risks
- `.infraseal/governance/`: governance evidence files
- `.infraseal/test-cases/`: evaluation cases
- `.infraseal/agent-skills/`: agent skill evidence

See [sample-output.md](sample-output.md) for an abbreviated terminal result.
