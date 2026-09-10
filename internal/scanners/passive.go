package scanners

import (
	"context"
	"fmt"
	"strings"
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
	return PythonModuleStatus(ctx, cfg, p.ID, p.Label, p.Module, p.Install, p.Categories)
}

func (p PassivePython) Scan(ctx context.Context, input Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := p.IsAvailable(ctx, input.Config)
	if status.Status == StatusDisabled {
		return NewResult(p, StatusDisabled, "disabled", status.Detail, nil, started), nil
	}
	mode := "missing dependency"
	resultStatus := status.Status
	detail := status.Detail
	if input.Config.Settings.AllowMockedScanners && len(input.TestCases) > 0 {
		mode = "mocked"
		resultStatus = StatusMocked
		detail = fmt.Sprintf("%s coverage is represented by declared local test-case fixtures; no remote model endpoint was called", p.Label)
	} else if status.Status == StatusAvailable {
		mode = "disabled"
		resultStatus = StatusDisabled
		detail = fmt.Sprintf("%s is installed, but this MVP needs a workload endpoint or exported fixture before invoking it", p.Label)
	}
	findings := findingsForCategories(input, p.Categories, p.ID, mode)
	result := NewResult(p, resultStatus, mode, detail, findings, started)
	result.RawPath = WriteJSONArtifact(input, p.ID, map[string]any{
		"scanner": p.ID, "status": resultStatus, "mode": mode, "detail": detail,
		"test_case_sources": input.TestSources, "findings": findings,
	})
	return result, nil
}

func findingsForCategories(input Input, categories []string, tool, mode string) []schema.Finding {
	wanted := map[string]bool{}
	for _, category := range categories {
		wanted[strings.ToLower(category)] = true
	}
	var findings []schema.Finding
	for i, tc := range input.TestCases {
		if tc.Pass || !wanted[strings.ToLower(tc.Category)] || !caseMatchesChecks(tc.Category, input.Checks) {
			continue
		}
		source := ""
		if i < len(input.TestSources) {
			source = input.TestSources[i]
		}
		findings = append(findings, schema.Finding{
			Severity: NormalizeSeverity(tc.Severity), Category: tc.Category,
			Title: tc.Name + " failed", Description: tc.Description,
			Evidence: tc.ActualOutput, Recommendation: "Harden the workload and turn this case into a blocking regression test.",
			SourceTool: tool, FilePath: source, HiddenByDefault: true, ExecutionMode: mode,
		})
	}
	return findings
}

func caseMatchesChecks(category string, checks []string) bool {
	if len(checks) == 0 {
		return true
	}
	category = strings.ToLower(strings.TrimSpace(category))
	for _, check := range checks {
		switch check {
		case "hallucination", "grounding", "rag-quality":
			if strings.Contains(category, "halluc") || strings.Contains(category, "ground") || strings.Contains(category, "rag") || strings.Contains(category, "context") || strings.Contains(category, "evidence") {
				return true
			}
		case "agent-safety":
			if strings.Contains(category, "agent") || strings.Contains(category, "skill") || strings.Contains(category, "tool") || strings.Contains(category, "credential") || strings.Contains(category, "exfiltrat") {
				return true
			}
		case "code-security":
			if strings.Contains(category, "code") || strings.Contains(category, "supply") {
				return true
			}
		case "dependency-risk":
			if strings.Contains(category, "depend") || strings.Contains(category, "vulnerab") {
				return true
			}
		case "runtime-security":
			if strings.Contains(category, "runtime") || strings.Contains(category, "infra") || strings.Contains(category, "network") || strings.Contains(category, "iam") {
				return true
			}
		default:
			if category == check {
				return true
			}
		}
	}
	return false
}

func FixtureFindings(input Input, categories []string, tool, mode string) []schema.Finding {
	return findingsForCategories(input, categories, tool, mode)
}
