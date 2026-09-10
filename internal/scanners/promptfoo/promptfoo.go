package promptfoo

import (
	"context"
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
func (Scanner) Name() string        { return "promptfoo" }
func (Scanner) DisplayName() string { return "Promptfoo" }
func (Scanner) Profiles() []string  { return []string{"quick", "rag", "full"} }

func (s Scanner) IsAvailable(_ context.Context, cfg config.Config) schema.ScannerStatus {
	if config.IsDisabled(cfg, s.Name()) {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusDisabled, Detail: "disabled in configuration", Categories: categories()}
	}
	if path, ok := scanners.CommandAvailable("promptfoo"); ok {
		return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusAvailable, Detail: path, Categories: categories()}
	}
	return schema.ScannerStatus{Name: s.Name(), DisplayName: s.DisplayName(), Status: scanners.StatusMissingDependency, Detail: "promptfoo CLI was not found on PATH", InstallHint: "npm install -g promptfoo", Categories: categories()}
}

func (s Scanner) Scan(ctx context.Context, input scanners.Input) (schema.ToolResult, error) {
	started := time.Now().UTC()
	status := s.IsAvailable(ctx, input.Config)
	if status.Status != scanners.StatusAvailable {
		mode := "missing dependency"
		resultStatus := status.Status
		if status.Status == scanners.StatusMissingDependency && input.Config.Settings.AllowMockedScanners {
			mode = "mocked"
			resultStatus = scanners.StatusMocked
		}
		findings := scanners.FixtureFindings(input, categories(), s.Name(), mode)
		result := scanners.NewResult(s, resultStatus, mode, status.Detail, findings, started)
		result.RawPath = scanners.WriteJSONArtifact(input, s.Name(), result)
		return result, nil
	}

	configPath := firstExisting(
		filepath.Join(input.RootDir, ".infraseal", "promptfooconfig.yaml"),
		filepath.Join(input.RootDir, "promptfooconfig.yaml"),
		filepath.Join(input.RootDir, "promptfoo.yaml"),
	)
	if configPath == "" {
		if input.Config.Settings.AllowMockedScanners && len(input.TestCases) > 0 {
			findings := scanners.FixtureFindings(input, categories(), s.Name(), "mocked")
			result := scanners.NewResult(s, scanners.StatusMocked, "mocked", "prompt evaluation is represented by declared local test-case fixtures; no model endpoint was called", findings, started)
			result.RawPath = scanners.WriteJSONArtifact(input, s.Name(), result)
			return result, nil
		}
		return scanners.NewResult(s, scanners.StatusDisabled, "disabled", "prompt evaluator is installed, but no compatible configuration is present", nil, started), nil
	}
	outfile := filepath.Join(input.ArtifactsDir, "promptfoo-output.json")
	output, exitCode, err := scanners.RunCommand(ctx, input.RootDir, "promptfoo", "eval", "-c", configPath, "--no-progress-bar", "--no-table", "--output", outfile)
	stdout := scanners.WriteArtifact(input, s.Name(), "stdout.txt", output)
	data, readErr := os.ReadFile(outfile)
	if readErr != nil {
		detail := strings.TrimSpace(string(output))
		if err != nil {
			detail = err.Error() + ": " + detail
		}
		result := scanners.NewResult(s, scanners.StatusError, "real", detail, nil, started)
		result.RawPath = stdout
		return result, nil
	}
	findings := parse(data)
	if exitCode != 0 && len(findings) == 0 {
		findings = append(findings, schema.Finding{
			Severity: "medium", Domain: "Security", Category: "prompt-regression",
			Title: "Prompt safety regression detected", Description: "The configured prompt evaluation returned a failing status.",
			Evidence: strings.TrimSpace(string(output)), Recommendation: "Review the failing assertions and add them to the blocking regression suite.",
		})
	}
	result := scanners.NewResult(s, scanners.StatusAvailable, "real", "promptfoo evaluation completed", findings, started)
	result.RawPath = outfile
	return result, nil
}

func parse(data []byte) []schema.Finding {
	doc, err := scanners.DecodeJSON(data)
	if err != nil {
		return nil
	}
	if findings := parseV3(doc); len(findings) > 0 {
		return findings
	}
	var findings []schema.Finding
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			failed := false
			if pass, ok := typed["pass"].(bool); ok && !pass {
				failed = true
			}
			if success, ok := typed["success"].(bool); ok && !success {
				failed = true
			}
			if failed {
				title := scanners.TextValue(typed, "description", "reason", "message", "prompt", "test")
				if title == "" {
					title = "Prompt safety assertion failed"
				}
				evidence := scanners.TextValue(typed, "output", "actual", "failureReason", "reason")
				category := normalizeCategory(scanners.TextValue(typed, "category", "type", "pluginId", "assertion", "reason") + " " + title + " " + evidence)
				findings = append(findings, schema.Finding{
					Severity: severity(category), Category: category, Title: title,
					Description:    "An LLM safety or regression assertion failed.",
					Evidence:       evidence,
					Recommendation: "Harden the prompt, retrieval boundary, or guardrail and retain this as a regression test.",
				})
			}
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(doc)
	return findings
}

func parseV3(doc any) []schema.Finding {
	root, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	resultsDoc, _ := root["results"].(map[string]any)
	items, _ := resultsDoc["results"].([]any)
	var findings []schema.Finding
	for _, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		failed := false
		if success, ok := record["success"].(bool); ok && !success {
			failed = true
		}
		grading, _ := record["gradingResult"].(map[string]any)
		if pass, ok := grading["pass"].(bool); ok && !pass {
			failed = true
		}
		if !failed {
			continue
		}
		testCase, _ := record["testCase"].(map[string]any)
		reason := scanners.TextValue(grading, "reason", "message", "failureReason")
		output := scanners.TextValue(record, "response", "output")
		if output == "" {
			if response, ok := record["response"].(map[string]any); ok {
				output = scanners.TextValue(response, "output", "text")
			}
		}
		title := scanners.TextValue(testCase, "description")
		if title == "" {
			title = reason
		}
		if title == "" {
			title = "Prompt safety assertion failed"
		}
		evidence := reason
		if output != "" {
			evidence = strings.TrimSpace(reason + " | Output: " + output)
		}
		category := normalizeCategory(title + " " + reason + " " + output)
		findings = append(findings, schema.Finding{
			Severity: severity(category), Category: category, Title: title,
			Description:    "An LLM safety or regression assertion failed.",
			Evidence:       evidence,
			Recommendation: "Harden the prompt, retrieval boundary, or guardrail and retain this as a regression test.",
		})
	}
	return findings
}

func normalizeCategory(value string) string {
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "inject"), strings.Contains(value, "jailbreak"), strings.Contains(value, "system prompt"):
		return "prompt-injection"
	case strings.Contains(value, "pii"), strings.Contains(value, "privacy"):
		return "pii"
	case strings.Contains(value, "halluc"), strings.Contains(value, "ground"), strings.Contains(value, "claim is absent"), strings.Contains(value, "unsupported"), strings.Contains(value, "absent from evidence"):
		return "grounding"
	case strings.Contains(value, "unsafe"):
		return "output-safety"
	default:
		return "prompt-regression"
	}
}

func severity(category string) string {
	if category == "prompt-injection" || category == "grounding" {
		return "high"
	}
	return "medium"
}

func firstExisting(paths ...string) string {
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func categories() []string { return []string{"prompt-injection", "output-safety", "pii", "grounding"} }
