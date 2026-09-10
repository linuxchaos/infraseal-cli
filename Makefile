.PHONY: build test sample clean

build:
	go build -o bin/infraseal ./cmd/infraseal

test:
	go test ./...

sample:
	go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml scan --profile quick
	go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance iso42001
	go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance nist-ai-rmf
	go run ./cmd/infraseal --config samples/rag-support-agent/.infraseal/infraseal.yaml compliance aiuc1

clean:
	go clean
