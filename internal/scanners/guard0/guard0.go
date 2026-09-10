package guard0

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Scanner struct{}

func New() Scanner                  { return Scanner{} }
func (Scanner) Name() string        { return "guard0" }
func (Scanner) DisplayName() string { return "Guard0 g0" }
func (Scanner) Profiles() []string  { return []string{"agent", "full"} }

func (s Scanner) IsAvailable(_ context.Context, cfg config.Config) schema.ScannerStatus {
	if config.IsDisabled(cfg, s.Name()) {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusDisabled, Detail: "disabled in configuration", Categories: categories()}
	}
	if path, ok := scanners.CommandAvailable("npx"); ok {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusAvailable, Detail: path + " (npx @guard0/g0 scan .)", Categories: categories()}
	}
	return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusMissingDependency, Detail: "npx was not found on PATH", InstallHint: "Install Node.js/npm; the adapter runs npx @guard0/g0 scan .", Categories: categories()}
}

func (s Scanner) Scan(ctx context.Context, input scanners.Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := s.IsAvailable(ctx, input.Config)
	if status.Status != scanners.StatusAvailable {
		return scanners.NewResult(s, status.Status, "missing dependency", status.Detail, nil, started), nil
	}
	scanTargets := input.Targets
	if len(scanTargets) == 0 {
		scanTargets = []string{input.RootDir}
	}
	var findings []schema.Finding
	var stdoutPaths []string
	var errors []string
	for index, target := range scanTargets {
		if shouldSkipTarget(input.RootDir, target, input.Excludes) {
			continue
		}
		scanPath := target
		if rel, err := filepath.Rel(input.RootDir, target); err == nil {
			scanPath = filepath.ToSlash(rel)
		}
		outfile := filepath.Join(input.ArtifactsDir, fmt.Sprintf("guard0-output-%d.json", index+1))
		output, _, err := scanners.RunCommand(ctx, input.RootDir, "npx", "--yes", "@guard0/g0", "scan", scanPath, "--json", "--output", outfile, "--no-banner")
		stdoutPaths = append(stdoutPaths, scanners.WriteArtifact(input, s.Name(), fmt.Sprintf("stdout-%d.txt", index+1), output))
		data, readErr := os.ReadFile(outfile)
		if readErr != nil {
			if err != nil {
				errors = append(errors, err.Error())
			} else {
				errors = append(errors, readErr.Error())
			}
			continue
		}
		findings = append(findings, parse(data)...)
	}
	if len(findings) == 0 && len(errors) > 0 {
		result := scanners.NewResult(s, scanners.StatusError, "real", strings.Join(errors, "; "), nil, started)
		result.RawPath = strings.Join(stdoutPaths, ",")
		return result, nil
	}
	result := scanners.NewResult(s, scanners.StatusAvailable, "real", fmt.Sprintf("AI workload security evaluation completed for %d target(s)", len(scanTargets)), findings, started)
	result.RawPath = strings.Join(stdoutPaths, ",")
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
	items, _ := root["findings"].([]any)
	var findings []schema.Finding
	for _, item := range items {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		findings = append(findings, schema.Finding{
			Severity: scanners.NormalizeSeverity(scanners.TextValue(finding, "severity")), Category: scanners.TextValue(finding, "domain", "category"),
			Title: scanners.TextValue(finding, "title", "ruleId", "id"), Description: scanners.TextValue(finding, "description", "message"),
			Evidence: scanners.TextValue(finding, "snippet", "evidence", "path"), Recommendation: scanners.TextValue(finding, "remediation", "recommendation"),
			FilePath: scanners.TextValue(finding, "file", "path"), Line: scanners.IntValue(finding, "line"),
		})
	}
	return findings
}

func categories() []string {
	return []string{"agent-security", "mcp-security", "rag-security", "supply-chain"}
}

func shouldSkipTarget(root, target string, excludes []string) bool {
	return config.ShouldExclude(root, target, excludes)
}
