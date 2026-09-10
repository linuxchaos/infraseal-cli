package agentgovernance

import (
	"context"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Scanner struct{}

func New() Scanner                  { return Scanner{} }
func (Scanner) Name() string        { return "agent-governance-toolkit" }
func (Scanner) DisplayName() string { return "Microsoft Agent Governance Toolkit" }
func (Scanner) Profiles() []string  { return []string{"agent", "governance", "full"} }

func (s Scanner) IsAvailable(_ context.Context, cfg config.Config) schema.ScannerStatus {
	if config.IsDisabled(cfg, s.Name()) {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusDisabled, Detail: "disabled in configuration", Categories: categories()}
	}
	for _, command := range []string{"agt", "agent-governance"} {
		if path, ok := scanners.CommandAvailable(command); ok {
			return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusAvailable, Detail: path, Categories: categories()}
		}
	}
	return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusMissingDependency, Detail: "Agent Governance Toolkit command was not found", InstallHint: "Install and configure the toolkit as a policy plugin; it is not a sandbox boundary", Categories: categories()}
}

func (s Scanner) Scan(ctx context.Context, input scanners.Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := s.IsAvailable(ctx, input.Config)
	if status.Status == scanners.StatusAvailable {
		return scanners.NewResult(s, scanners.StatusDisabled, "disabled", "toolkit detected; policy bundle invocation is not configured in this MVP", nil, started), nil
	}
	mode := "missing dependency"
	if input.Config.Settings.AllowMockedScanners {
		mode = "mocked"
		status.Status = scanners.StatusMocked
		status.Detail = "governance policy coverage is evaluated by MCPvia native controls; external toolkit invocation is mocked"
	}
	result := scanners.NewResult(s, status.Status, mode, status.Detail, nil, started)
	result.RawPath = scanners.WriteJSONArtifact(input, s.Name(), result)
	return result, nil
}

func categories() []string {
	return []string{"agent-policy", "human-approval", "tool-governance", "decision-trail"}
}
