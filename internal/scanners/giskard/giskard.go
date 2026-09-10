package giskard

import "github.com/linuxchaos/infraseal-cli/internal/scanners"

func New() scanners.PassivePython {
	return scanners.PassivePython{
		ID: "giskard", Label: "Giskard", Module: "giskard", Install: `python -m pip install "giskard[llm]"`,
		UseProfiles: []string{"quick", "full"}, Categories: []string{"pii", "privacy", "bias", "regression"},
	}
}
