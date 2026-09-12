.PHONY: build test vet sample tool-cases clean

build:
	go build -o bin/infraseal ./cmd/infraseal

test:
	go test ./...

vet:
	go vet ./...

sample:
	go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml scan --profile quick
	go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance iso42001
	go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance nist-ai-rmf
	go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance aiuc1

tool-cases: build
	./bin/infraseal --config samples/tool-cases/promptfoo/pass/.infraseal/infraseal.yaml scan --check prompt-injection --target promptfooconfig.yaml
	./bin/infraseal --config samples/tool-cases/promptfoo/fail/.infraseal/infraseal.yaml scan --check prompt-injection --target promptfooconfig.yaml
	./bin/infraseal --config samples/tool-cases/hallbayes/pass/.infraseal/infraseal.yaml scan --check hallucination --target exports/chatbot-responses.jsonl
	./bin/infraseal --config samples/tool-cases/hallbayes/fail/.infraseal/infraseal.yaml scan --check hallucination --target exports/chatbot-responses.jsonl
	./bin/infraseal --config samples/tool-cases/terraform/pass/.infraseal/infraseal.yaml scan --check runtime-security --target infra/tfplan.json
	./bin/infraseal --config samples/tool-cases/terraform/fail/.infraseal/infraseal.yaml scan --check runtime-security --target infra/tfplan.json
	./bin/infraseal --config samples/tool-cases/go/pass/.infraseal/infraseal.yaml scan --check code-security --target app
	./bin/infraseal --config samples/tool-cases/go/fail/.infraseal/infraseal.yaml scan --check code-security --target app
	./bin/infraseal --config samples/tool-cases/govulncheck/pass/.infraseal/infraseal.yaml scan --check dependency-risk --target app
	./bin/infraseal --config samples/tool-cases/govulncheck/fail/.infraseal/infraseal.yaml scan --check dependency-risk --target app
	./bin/infraseal --config samples/tool-cases/agent/pass/.infraseal/infraseal.yaml scan --check agent-safety --target .infraseal/agent-skills
	./bin/infraseal --config samples/tool-cases/agent/fail/.infraseal/infraseal.yaml scan --check agent-safety --target .infraseal/agent-skills

clean:
	go clean
