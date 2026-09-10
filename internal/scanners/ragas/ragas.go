package ragas

import "github.com/linuxchaos/infraseal-cli/internal/scanners"

func New() scanners.PassivePython {
	return scanners.PassivePython{
		ID: "ragas", Label: "RAGAS", Module: "ragas", Install: "python -m pip install ragas",
		UseProfiles: []string{"rag", "full"}, Categories: []string{"grounding", "faithfulness", "context-quality", "evidence-coverage"},
	}
}
