package gosec

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Scanner struct{}

func New() Scanner                  { return Scanner{} }
func (Scanner) Name() string        { return "gosec" }
func (Scanner) DisplayName() string { return "gosec" }
func (Scanner) Profiles() []string  { return []string{"full"} }

func (s Scanner) IsAvailable(_ context.Context, cfg config.Config) schema.ScannerStatus {
	if config.IsDisabled(cfg, s.Name()) {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusDisabled, Detail: "disabled in configuration", Categories: categories()}
	}
	if path, ok := scanners.CommandAvailable("gosec"); ok {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusAvailable, Detail: path, Categories: categories()}
	}
	return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusMissingDependency, Detail: "gosec was not found on PATH", InstallHint: "go install github.com/securego/gosec/v2/cmd/gosec@latest", Categories: categories()}
}

func (s Scanner) Scan(ctx context.Context, input scanners.Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := s.IsAvailable(ctx, input.Config)
	if status.Status != scanners.StatusAvailable {
		return scanners.NewResult(s, status.Status, "missing dependency", status.Detail, nil, started), nil
	}
	if _, err := os.Stat(filepath.Join(input.RootDir, "go.mod")); err != nil {
		return scanners.NewResult(s, scanners.StatusDisabled, "disabled", "no go.mod found in workload root", nil, started), nil
	}
	outfile := filepath.Join(input.ArtifactsDir, "gosec-output.json")
	args := []string{"-fmt=json", "-out", outfile}
	args = append(args, scanners.GoPackagePatterns(input.RootDir, input.Targets, input.Excludes)...)
	output, _, err := scanners.RunCommand(ctx, input.RootDir, "gosec", args...)
	stdout := scanners.WriteArtifact(input, s.Name(), "stdout.txt", output)
	data, readErr := os.ReadFile(outfile)
	if readErr != nil {
		detail := readErr.Error()
		if err != nil {
			detail = err.Error()
		}
		result := scanners.NewResult(s, scanners.StatusError, "real", detail, nil, started)
		result.RawPath = stdout
		return result, nil
	}
	findings := parse(data)
	result := scanners.NewResult(s, scanners.StatusAvailable, "real", "Go source security evaluation completed", findings, started)
	result.RawPath = outfile
	return result, nil
}

func parse(data []byte) []schema.Finding {
	doc, err := scanners.DecodeJSON(data)
	if err != nil {
		return nil
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	issues, _ := root["Issues"].([]any)
	var findings []schema.Finding
	for _, item := range issues {
		issue, ok := item.(map[string]any)
		if !ok {
			continue
		}
		findings = append(findings, schema.Finding{
			Severity: scanners.NormalizeSeverity(scanners.TextValue(issue, "severity")), Category: "code-security",
			Title: scanners.TextValue(issue, "rule_id") + " " + scanners.TextValue(issue, "details"), Description: scanners.TextValue(issue, "details"),
			Evidence: scanners.TextValue(issue, "code"), Recommendation: "Review the source-security rule guidance and patch the unsafe code path.",
			FilePath: scanners.TextValue(issue, "file"), Line: scanners.IntValue(issue, "line"),
		})
	}
	return findings
}

func categories() []string { return []string{"code-security"} }
