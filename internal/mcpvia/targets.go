package mcpvia

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

var supportedChecks = []string{"prompt-injection", "pii", "output-safety", "hallucination", "grounding", "rag-quality", "agent-safety", "code-security", "dependency-risk", "runtime-security", "governance"}

func NormalizeChecks(values []string) ([]string, error) {
	seen := map[string]bool{}
	var checks []string
	for _, raw := range values {
		for _, item := range strings.Split(raw, ",") {
			value := normalizeCheck(item)
			if value == "" {
				continue
			}
			if value == "all" {
				return nil, nil
			}
			if !isSupportedCheck(value) {
				return nil, fmt.Errorf("unknown check %q; supported checks: %s", item, strings.Join(supportedChecks, ", "))
			}
			if !seen[value] {
				seen[value] = true
				checks = append(checks, value)
			}
		}
	}
	return checks, nil
}

func normalizeCheck(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "inject", "injection", "prompt-injection", "jailbreak":
		return "prompt-injection"
	case "privacy", "pii", "data-leakage":
		return "pii"
	case "unsafe", "safety", "unsafe-output", "output-safety":
		return "output-safety"
	case "hallucination", "hallucinations":
		return "hallucination"
	case "ground", "grounding", "evidence":
		return "grounding"
	case "rag", "rag-quality", "context-quality":
		return "rag-quality"
	case "agent", "agent-safety", "skills", "tool-safety":
		return "agent-safety"
	case "code", "code-security", "sast":
		return "code-security"
	case "dependencies", "dependency", "dependency-risk", "vulnerabilities":
		return "dependency-risk"
	case "runtime", "runtime-security", "infra", "infrastructure", "infrastructure-security", "terraform", "tf":
		return "runtime-security"
	case "governance", "iso42001", "oversight":
		return "governance"
	case "all":
		return "all"
	default:
		return value
	}
}

func isSupportedCheck(value string) bool {
	for _, item := range supportedChecks {
		if item == value {
			return true
		}
	}
	return false
}
func containsCheck(checks []string, value string) bool {
	for _, item := range checks {
		if item == value {
			return true
		}
	}
	return false
}

func categoriesMatch(categories, checks []string) bool {
	for _, category := range categories {
		category = normalizeCheck(category)
		for _, check := range checks {
			if category == check {
				return true
			}
			if check == "hallucination" && (category == "grounding" || category == "rag-quality") {
				return true
			}
			if check == "grounding" && (category == "hallucination" || category == "rag-quality") {
				return true
			}
			if check == "rag-quality" && (category == "grounding" || category == "hallucination") {
				return true
			}
			if check == "agent-safety" && strings.Contains(category, "agent") {
				return true
			}
			if check == "code-security" && (strings.Contains(category, "code") || strings.Contains(category, "supply")) {
				return true
			}
			if check == "dependency-risk" && strings.Contains(category, "vulnerab") {
				return true
			}
			if check == "runtime-security" && (strings.Contains(category, "runtime") || strings.Contains(category, "infra") || strings.Contains(category, "network") || strings.Contains(category, "iam")) {
				return true
			}
		}
	}
	return false
}

var emailPattern = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
var secretPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password)\s*[:=]\s*["']?[A-Za-z0-9_\-]{8,}`)

func nativeTargetFindings(root string, targets, checks, excludes []string) []schema.Finding {
	if len(targets) == 0 || len(checks) == 0 {
		return nil
	}
	files := targetFiles(root, targets, excludes)
	var findings []schema.Finding
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil || info.Size() > 2<<20 {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(data)
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if containsCheck(checks, "prompt-injection") {
			lower := strings.ToLower(text)
			for _, pattern := range []string{"ignore previous instructions", "reveal the system prompt", "override system", "developer message"} {
				if strings.Contains(lower, pattern) {
					findings = append(findings, targetedFinding("high", "prompt-injection", "Prompt-injection pattern detected in target", pattern, rel, "Treat this content as untrusted data and add a refusal regression case."))
					break
				}
			}
		}
		if containsCheck(checks, "pii") {
			if match := emailPattern.FindString(text); match != "" {
				findings = append(findings, targetedFinding("medium", "pii", "Email address detected in target", match, rel, "Redact or tokenize personal identifiers before model processing and report generation."))
			}
			if match := secretPattern.FindString(text); match != "" {
				findings = append(findings, targetedFinding("high", "credential-exposure", "Potential secret detected in target", redact(match), rel, "Remove the secret, rotate it if live, and add secret scanning before AI evaluation."))
			}
		}
		if containsCheck(checks, "output-safety") {
			lower := strings.ToLower(text)
			for _, pattern := range []string{"bypass verification", "disable audit", "exfiltrate", "ignore safety"} {
				if strings.Contains(lower, pattern) {
					findings = append(findings, targetedFinding("high", "output-safety", "Unsafe output pattern detected in target", pattern, rel, "Add a refusal boundary and retain the output as a blocking safety test."))
					break
				}
			}
		}
		if containsCheck(checks, "agent-safety") {
			lower := strings.ToLower(text)
			patterns := []string{
				"network: [\"*\"]",
				"network:\n    - \"*\"",
				"requires_human_approval: []",
				"data_exfiltration",
				"send_to_external",
				"credential_dump",
				"secrets: read",
				"aws:*",
				"disable approval",
			}
			for _, pattern := range patterns {
				if strings.Contains(lower, pattern) {
					findings = append(findings, targetedFinding("critical", "agent-safety", "Risky agent skill pattern detected in target", pattern, rel, "Restrict tool permissions, require human approval for external side effects, and document the agent boundary."))
					break
				}
			}
		}
		if containsCheck(checks, "code-security") {
			findings = append(findings, codeSecurityFindings(rel, text)...)
		}
	}
	return findings
}

func codeSecurityFindings(path, text string) []schema.Finding {
	lower := strings.ToLower(text)
	rules := []struct {
		needle string
		title  string
		action string
	}{
		{"shell=true", "Shell execution is enabled from application code", "Avoid shell execution for user-controlled values; call the intended binary directly and validate arguments."},
		{"eval(", "Dynamic evaluation is used in application code", "Remove dynamic evaluation or tightly constrain input before execution."},
		{"exec(", "Dynamic code execution is used in application code", "Replace dynamic execution with explicit handlers and record an approval exception if unavoidable."},
		{"ignore previous instructions", "Prompt-injection text is embedded in application code", "Treat injection strings as test fixtures only and keep them in evaluation cases, not runtime prompts."},
		{"reveal the system prompt", "System-prompt disclosure pattern is embedded in application code", "Move disclosure attempts into regression tests and keep runtime prompts focused on refusal behavior."},
		{"tenant_id = \"*\"", "Tenant isolation is bypassed in application code", "Require tenant-scoped queries and add a regression test for cross-tenant access."},
		{"where 1=1", "Broad database query pattern is present", "Replace broad query construction with parameterized, tenant-scoped access."},
	}
	var findings []schema.Finding
	for _, rule := range rules {
		if strings.Contains(lower, rule.needle) {
			findings = append(findings, targetedFinding("high", "code-security", rule.title, rule.needle, path, rule.action))
		}
	}
	if strings.Contains(lower, "openai_api_key") || strings.Contains(lower, "anthropic_api_key") || strings.Contains(lower, "api_key") {
		if match := secretPattern.FindString(text); match != "" {
			findings = append(findings, targetedFinding("high", "credential-exposure", "Hardcoded API credential pattern detected", redact(match), path, "Move model-provider credentials to a managed secret store and rotate exposed values."))
		}
	}
	if strings.EqualFold(filepath.Ext(path), ".go") && strings.Contains(lower, "os.readfile(") && strings.Contains(lower, "user") {
		findings = append(findings, targetedFinding("medium", "code-security", "Go file read appears tied to user-controlled input", "os.ReadFile", path, "Constrain file reads to approved directories and validate resolved paths."))
	}
	if strings.EqualFold(filepath.Ext(path), ".py") && strings.Contains(lower, "subprocess.") && strings.Contains(lower, "shell=true") {
		findings = append(findings, targetedFinding("high", "code-security", "Python subprocess call uses shell=True", "subprocess shell=True", path, "Use an argument list with shell disabled and validate user-provided values."))
	}
	return findings
}

func targetFiles(root string, targets, excludes []string) []string {
	var files []string
	for _, target := range targets {
		if config.ShouldExclude(root, target, excludes) {
			continue
		}
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			files = append(files, target)
			continue
		}
		_ = filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if config.ShouldExclude(root, path, excludes) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			files = append(files, path)
			return nil
		})
	}
	return files
}

func targetedFinding(severity, category, title, evidence, path, action string) schema.Finding {
	return schema.Finding{Severity: severity, Category: category, Title: title, Description: title, Evidence: evidence, Recommendation: action, FilePath: path, SourceTool: "mcpvia", ExecutionMode: "native"}
}

func redact(value string) string {
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return "[redacted]"
	}
	return parts[0] + "=[redacted]"
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}
