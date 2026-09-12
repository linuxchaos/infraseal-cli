package skillspector

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
func (Scanner) Name() string        { return "skillspector" }
func (Scanner) DisplayName() string { return "NVIDIA SkillSpector" }
func (Scanner) Profiles() []string  { return []string{"agent", "full"} }

func (s Scanner) IsAvailable(_ context.Context, cfg config.Config) schema.ScannerStatus {
	if config.IsDisabled(cfg, s.Name()) {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusDisabled, Detail: "disabled in configuration", Categories: categories()}
	}
	if path, ok := scanners.CommandAvailable("skillspector"); ok {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusAvailable, Detail: path, Categories: categories()}
	}
	return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusMissingDependency, Detail: "skillspector was not found on PATH", InstallHint: "python -m pip install git+https://github.com/NVIDIA/SkillSpector.git", Categories: categories()}
}

func (s Scanner) Scan(ctx context.Context, input scanners.Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := s.IsAvailable(ctx, input.Config)
	if status.Status != scanners.StatusAvailable {
		result := scanners.NewResult(s, status.Status, "missing dependency", status.Detail, nil, started)
		result.RawPath = scanners.WriteJSONArtifact(input, s.Name(), result)
		return result, nil
	}
	skillPaths := input.AgentSkills
	if len(skillPaths) == 0 {
		skillPaths = []string{filepath.Join(input.RootDir, ".infraseal", "agent-skills")}
	}
	var findings []schema.Finding
	var rawPaths []string
	var errors []string
	for index, skillPath := range skillPaths {
		if config.ShouldExclude(input.RootDir, skillPath, input.Excludes) {
			continue
		}
		outfile := filepath.Join(input.ArtifactsDir, fmt.Sprintf("skillspector-output-%d.json", index+1))
		output, _, err := scanners.RunCommand(ctx, input.RootDir, "skillspector", "scan", skillPath, "--no-llm", "--format", "json", "--output", outfile)
		stdout := scanners.WriteArtifact(input, s.Name(), fmt.Sprintf("stdout-%d.txt", index+1), output)
		rawPaths = append(rawPaths, stdout)
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
		result.RawPath = strings.Join(rawPaths, ",")
		return result, nil
	}
	result := scanners.NewResult(s, scanners.StatusAvailable, "real", fmt.Sprintf("agent skill evaluation completed for %d target(s)", len(skillPaths)), findings, started)
	result.RawPath = strings.Join(rawPaths, ",")
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
	items, _ := root["issues"].([]any)
	var findings []schema.Finding
	for _, item := range items {
		issue, ok := item.(map[string]any)
		if !ok {
			continue
		}
		location, _ := issue["location"].(map[string]any)
		findings = append(findings, schema.Finding{
			Severity: scanners.NormalizeSeverity(scanners.TextValue(issue, "severity")), Category: "agent-safety",
			Title: scanners.TextValue(issue, "pattern", "id", "category"), Description: scanners.TextValue(issue, "explanation", "description"),
			Evidence: scanners.TextValue(issue, "finding", "code_snippet"), Recommendation: scanners.TextValue(issue, "remediation"),
			FilePath: scanners.TextValue(location, "file"), Line: scanners.IntValue(location, "start_line"),
		})
	}
	return findings
}

func categories() []string {
	return []string{"agent-safety", "credential-exposure", "data-exfiltration"}
}
