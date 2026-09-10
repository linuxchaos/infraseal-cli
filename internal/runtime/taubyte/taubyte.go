package taubyte

import (
	"context"
	"errors"

	"github.com/linuxchaos/infraseal-cli/internal/runtime"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Provider struct{}

func (Provider) Name() string        { return "taubyte" }
func (Provider) DisplayName() string { return "Taubyte Trusted Evaluation Environment" }
func (Provider) Status(context.Context) runtime.Status {
	return runtime.Status{
		Name: "taubyte", Available: false,
		Description: "Trusted Evaluation Environment for isolated customer-owned assessments.",
		Detail:      "stub: deployment and artifact transport are not implemented in the CLI MVP",
	}
}

func (Provider) Execute(context.Context, []scanners.Scanner, scanners.Input) ([]schema.ToolResult, error) {
	return nil, errors.New("Taubyte Trusted Evaluation Environment is not yet available; configure runtime.fallback: local")
}
