package deepeval

import "github.com/linuxchaos/infraseal-cli/internal/scanners"

func New() scanners.PassivePython {
	return scanners.PassivePython{
		ID: "deepeval", Label: "DeepEval", Module: "deepeval", Install: "python -m pip install deepeval",
		UseProfiles: []string{"rag", "agent", "full"}, Categories: []string{"grounding", "hallucination", "answer-relevancy", "agent-safety"},
	}
}
