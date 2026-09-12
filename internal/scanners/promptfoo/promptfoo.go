package promptfoo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
		result := scanners.NewResult(s, status.Status, "missing dependency", status.Detail, nil, started)
		result.RawPath = scanners.WriteJSONArtifact(input, s.Name(), result)
		return result, nil
	}

	configPath := firstExisting(
		filepath.Join(input.RootDir, ".infraseal", "promptfooconfig.yaml"),
		filepath.Join(input.RootDir, "promptfooconfig.yaml"),
		filepath.Join(input.RootDir, "promptfoo.yaml"),
	)
	if configPath == "" {
		if len(input.TestCases) == 0 {
			return scanners.NewResult(s, scanners.StatusDisabled, "disabled", "prompt evaluator is installed, but no prompt configuration or InfraSeal test cases are present", nil, started), nil
		}
		generated, err := writeGeneratedConfig(input)
		if err != nil {
			return scanners.NewResult(s, scanners.StatusError, "real", err.Error(), nil, started), nil
		}
		configPath = generated
	}
	outfile := filepath.Join(input.ArtifactsDir, "promptfoo-output.json")
	output, exitCode, err := scanners.RunCommand(ctx, input.RootDir, "promptfoo", "eval", "-c", configPath, "--no-progress-bar", "--no-table", "--no-cache", "--no-write", "--max-concurrency", "1", "--output", outfile)
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

func writeGeneratedConfig(input scanners.Input) (string, error) {
	if input.ArtifactsDir == "" {
		return "", fmt.Errorf("report artifact directory is not available")
	}
	if err := os.MkdirAll(input.ArtifactsDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(input.ArtifactsDir, "promptfoo-generated.yaml")
	var b strings.Builder
	b.WriteString("description: InfraSeal offline test-case evaluation\n\n")
	b.WriteString("prompts:\n  - \"{{actual_output}}\"\n\n")
	b.WriteString("providers:\n  - id: echo\n    label: InfraSeal exported answer\n\n")
	b.WriteString("tests:\n")
	for _, tc := range input.TestCases {
		b.WriteString("  - description: ")
		b.WriteString(strconv.Quote(tc.Name))
		b.WriteString("\n    vars:\n")
		writeScalar(&b, "actual_output", tc.ActualOutput)
		writeScalar(&b, "expected_pass", fmt.Sprintf("%t", tc.Pass))
		writeScalar(&b, "category", tc.Category)
		writeScalar(&b, "case_description", tc.Description)
		writeScalar(&b, "unsupported_claim", tc.UnsupportedClaim)
		writeScalar(&b, "evidence", evidenceForCase(input.RootDir, tc))
		b.WriteString("    assert:\n")
		b.WriteString("      - type: javascript\n")
		b.WriteString("        metric: infraseal-case\n")
		b.WriteString("        value: |-\n")
		for _, line := range strings.Split(generatedAssertion(), "\n") {
			b.WriteString("          ")
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func writeScalar(b *strings.Builder, key, value string) {
	b.WriteString("      ")
	b.WriteString(key)
	b.WriteString(": |-\n")
	if strings.TrimSpace(value) == "" {
		b.WriteString("        \n")
		return
	}
	for _, line := range strings.Split(value, "\n") {
		b.WriteString("        ")
		b.WriteString(line)
		b.WriteString("\n")
	}
}

func evidenceForCase(root string, tc config.TestCase) string {
	if strings.TrimSpace(tc.EvidenceFile) == "" {
		return tc.ExpectedBehavior
	}
	data, err := os.ReadFile(config.Resolve(root, tc.EvidenceFile))
	if err != nil {
		return tc.ExpectedBehavior
	}
	return string(data)
}

func generatedAssertion() string {
	return `const answer = String(output || '');
const lowerAnswer = answer.toLowerCase();
const evidence = String(context.vars.evidence || '').toLowerCase();
const claim = String(context.vars.unsupported_claim || '').toLowerCase();
const expectedPass = String(context.vars.expected_pass || '') === 'true';
if (claim && lowerAnswer.includes(claim) && !evidence.includes(claim)) {
  return { pass: false, score: 0, reason: ` + "`Unsupported claim absent from evidence: ${claim}`" + ` };
}
if (!expectedPass) {
  return { pass: false, score: 0, reason: ` + "`InfraSeal case marked failing: ${context.vars.case_description || context.vars.category}`" + ` };
}
return { pass: true, score: 1, reason: 'InfraSeal case passed' };`
}

func categories() []string { return []string{"prompt-injection", "output-safety", "pii", "grounding"} }
