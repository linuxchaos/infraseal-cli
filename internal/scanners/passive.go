package scanners

import (
	"context"
	"fmt"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type PassivePython struct {
	ID          string
	Label       string
	Module      string
	Install     string
	UseProfiles []string
	Categories  []string
}

func (p PassivePython) Name() string        { return p.ID }
func (p PassivePython) DisplayName() string { return p.Label }
func (p PassivePython) Profiles() []string  { return p.UseProfiles }

func (p PassivePython) IsAvailable(ctx context.Context, cfg config.Config) schema.ScannerStatus {
	status := PythonModuleStatus(ctx, cfg, p.ID, p.Label, p.Module, p.Install, p.Categories)
	if status.Status == StatusAvailable {
		status.Status = StatusDisabled
		status.Detail = fmt.Sprintf("%s is installed, but no repository-specific evaluator binding is configured", p.Label)
	}
	return status
}

func (p PassivePython) Scan(ctx context.Context, input Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := p.IsAvailable(ctx, input.Config)
	mode := "missing dependency"
	resultStatus := status.Status
	detail := status.Detail
	if status.Status == StatusDisabled {
		mode = "disabled"
		resultStatus = StatusDisabled
	}
	result := NewResult(p, resultStatus, mode, detail, nil, started)
	result.RawPath = WriteJSONArtifact(input, p.ID, map[string]any{
		"scanner": p.ID, "status": resultStatus, "mode": mode, "detail": detail,
		"test_case_sources": input.TestSources, "findings": []schema.Finding{},
	})
	return result, nil
}
