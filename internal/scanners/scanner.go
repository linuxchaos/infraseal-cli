package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

const (
	StatusAvailable         = "available"
	StatusMissingDependency = "missing_dependency"
	StatusMocked            = "mocked"
	StatusDisabled          = "disabled"
	StatusError             = "error"
)

type Input struct {
	RootDir      string
	ConfigPath   string
	Config       config.Config
	Profile      string
	ArtifactsDir string
	Evidence     []string
	TestCases    []config.TestCase
	TestSources  []string
	AgentSkills  []string
	Targets      []string
	Checks       []string
	Excludes     []string
}

type Scanner interface {
	Name() string
	DisplayName() string
	Profiles() []string
	IsAvailable(context.Context, config.Config) schema.ScannerStatus
	Scan(context.Context, Input) (schema.ToolResult, error)
}

func SupportsProfile(scanner Scanner, profile string) bool {
	for _, item := range scanner.Profiles() {
		if strings.EqualFold(item, profile) {
			return true
		}
	}
	return false
}

func CommandAvailable(name string) (string, bool) {
	path, err := exec.LookPath(name)
	return path, err == nil
}

func RunCommand(ctx context.Context, dir, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err == nil {
		return output.Bytes(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output.Bytes(), exitErr.ExitCode(), err
	}
	return output.Bytes(), -1, err
}

func WriteArtifact(input Input, name, suffix string, data []byte) string {
	if input.ArtifactsDir == "" {
		return ""
	}
	if err := os.MkdirAll(input.ArtifactsDir, 0o755); err != nil {
		return ""
	}
	path := filepath.Join(input.ArtifactsDir, name+"-"+suffix)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return ""
	}
	return path
}

func WriteJSONArtifact(input Input, name string, value any) string {
	data, _ := json.MarshalIndent(value, "", "  ")
	return WriteArtifact(input, name, "result.json", data)
}

func NewResult(scanner Scanner, status, mode, detail string, findings []schema.Finding, started time.Time) schema.ToolResult {
	for i := range findings {
		findings[i].SourceTool = scanner.Name()
		findings[i].ExecutionMode = mode
		if findings[i].Domain == "" {
			findings[i].Domain = DomainForCategory(findings[i].Category)
		}
	}
	return schema.ToolResult{
		Name: scanner.Name(), DisplayName: PublicName(scanner.Name()), Status: status, Mode: mode,
		Detail: PublicDetail(status, mode), InternalDetail: detail, Findings: findings, StartedAt: started, CompletedAt: time.Now().UTC(),
	}
}

func PublicName(name string) string {
	switch strings.ToLower(name) {
	case "promptfoo":
		return "Prompt & Red-Team Evaluator"
	case "giskard":
		return "Privacy & Regression Evaluator"
	case "ragas":
		return "RAG Quality Evaluator"
	case "deepeval":
		return "Response Quality Evaluator"
	case "hallbayes":
		return "Grounding Validator"
	case "skillspector":
		return "Agent Skill Analyzer"
	case "agent-governance-toolkit":
		return "Agent Policy Evaluator"
	case "guard0":
		return "AI Workload Security Analyzer"
	case "terraform-plan":
		return "Infrastructure Plan Analyzer"
	case "gosec":
		return "Source Security Analyzer"
	case "govulncheck":
		return "Dependency Risk Analyzer"
	default:
		return "Evaluation Adapter"
	}
}

func PublicDetail(status, mode string) string {
	switch mode {
	case "real":
		return "The configured evaluator ran against the selected workload inputs."
	case "mocked":
		return "A declared local fixture or deterministic offline backend was used."
	case "missing dependency":
		return "Optional enhanced coverage is unavailable; MCPvia native checks still run."
	case "disabled":
		return "This evaluator needs a compatible target or optional integration configuration."
	case "error":
		return "The evaluator returned an execution error; review local diagnostic artifacts."
	}
	if status == StatusAvailable {
		return "Evaluator is available."
	}
	return "Evaluator status recorded by MCPvia."
}

func DomainForCategory(category string) string {
	value := strings.ToLower(category)
	switch {
	case strings.Contains(value, "ground"), strings.Contains(value, "halluc"), strings.Contains(value, "rag"):
		return "Grounding"
	case strings.Contains(value, "govern"), strings.Contains(value, "owner"), strings.Contains(value, "approval"), strings.Contains(value, "oversight"), strings.Contains(value, "incident"), strings.Contains(value, "monitor"):
		return "Governance"
	case strings.Contains(value, "agent"), strings.Contains(value, "skill"), strings.Contains(value, "tool"):
		return "Agent Safety"
	case strings.Contains(value, "pii"), strings.Contains(value, "privacy"), strings.Contains(value, "data"):
		return "Privacy"
	case strings.Contains(value, "code"), strings.Contains(value, "vulnerab"), strings.Contains(value, "supply"), strings.Contains(value, "runtime"), strings.Contains(value, "infrastructure"), strings.Contains(value, "iam"), strings.Contains(value, "network"):
		return "Code Security"
	default:
		return "Security"
	}
}

func NormalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "crit":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "moderate", "warning", "warn":
		return "medium"
	case "low", "note":
		return "low"
	default:
		return "info"
	}
}

func TextValue(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := m[key]; ok {
			switch typed := value.(type) {
			case string:
				return typed
			case json.Number:
				return typed.String()
			case float64:
				return fmt.Sprintf("%.0f", typed)
			case bool:
				return fmt.Sprintf("%t", typed)
			}
		}
	}
	return ""
}

func IntValue(m map[string]any, keys ...string) int {
	for _, key := range keys {
		if value, ok := m[key]; ok {
			switch typed := value.(type) {
			case float64:
				return int(typed)
			case json.Number:
				v, _ := typed.Int64()
				return int(v)
			case string:
				var v int
				_, _ = fmt.Sscanf(typed, "%d", &v)
				return v
			}
		}
	}
	return 0
}

func DecodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	return value, decoder.Decode(&value)
}

func GoPackagePatterns(root string, targets, excludes []string) []string {
	seen := map[string]bool{}
	var patterns []string
	addDir := func(dir string) {
		if dir == "" || !dirHasGo(root, dir, excludes) {
			return
		}
		rel, err := filepath.Rel(root, dir)
		if err != nil || rel == "." {
			rel = "."
		}
		pattern := "./..."
		if rel != "." {
			pattern = "./" + filepath.ToSlash(rel) + "/..."
		}
		if !seen[pattern] {
			seen[pattern] = true
			patterns = append(patterns, pattern)
		}
	}
	if len(targets) == 0 {
		addDir(root)
		return patterns
	}
	for _, target := range targets {
		if config.ShouldExclude(root, target, excludes) {
			continue
		}
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		if info.IsDir() {
			addDir(target)
			continue
		}
		if strings.EqualFold(filepath.Ext(target), ".go") {
			addDir(filepath.Dir(target))
		}
	}
	if len(patterns) == 0 {
		addDir(root)
	}
	return patterns
}

func dirHasGo(root, dir string, excludes []string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if config.ShouldExclude(root, path, excludes) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".go") {
			found = true
		}
		return nil
	})
	return found
}

func PythonCommand() (string, bool) {
	if path, ok := CommandAvailable("python"); ok {
		return path, true
	}
	return CommandAvailable("python3")
}

func PythonModuleStatus(ctx context.Context, cfg config.Config, name, display, module, install string, categories []string) schema.ScannerStatus {
	if config.IsDisabled(cfg, name) {
		return schema.ScannerStatus{Name: name, DisplayName: display, Status: StatusDisabled, Detail: "disabled in configuration", Categories: categories}
	}
	python, ok := PythonCommand()
	if !ok {
		return schema.ScannerStatus{Name: name, DisplayName: display, Status: StatusMissingDependency, Detail: "Python was not found on PATH", InstallHint: install, Categories: categories}
	}
	probe := "import importlib.util,sys; found=importlib.util.find_spec('" + module + "') is not None; print('installed' if found else 'missing'); sys.exit(0 if found else 1)"
	out, _, err := RunCommand(ctx, "", python, "-c", probe)
	if err != nil {
		return schema.ScannerStatus{Name: name, DisplayName: display, Status: StatusMissingDependency, Detail: strings.TrimSpace(string(out)), InstallHint: install, Categories: categories}
	}
	return schema.ScannerStatus{Name: name, DisplayName: display, Status: StatusAvailable, Detail: strings.TrimSpace(string(out)), Categories: categories}
}
