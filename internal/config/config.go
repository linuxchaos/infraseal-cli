package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultPath = ".infraseal/infraseal.yaml"

type Config struct {
	Project      ProjectConfig    `yaml:"project"`
	ScanProfiles []string         `yaml:"scan_profiles"`
	Runtime      RuntimeConfig    `yaml:"runtime"`
	Inputs       InputsConfig     `yaml:"inputs"`
	Output       OutputConfig     `yaml:"output"`
	Settings     SettingsConfig   `yaml:"settings"`
	Governance   GovernanceConfig `yaml:"governance"`
	Scanners     ScannersConfig   `yaml:"scanners"`
}

type ProjectConfig struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Purpose string `yaml:"purpose"`
	Owner   string `yaml:"owner"`
}

type RuntimeConfig struct {
	Preferred string `yaml:"preferred"`
	Fallback  string `yaml:"fallback"`
}

type InputsConfig struct {
	Prompts           []string `yaml:"prompts"`
	Evidence          []string `yaml:"evidence"`
	TestCases         []string `yaml:"test_cases"`
	AgentSkills       []string `yaml:"agent_skills"`
	Targets           []string `yaml:"targets"`
	Include           []string `yaml:"include"`
	Exclude           []string `yaml:"exclude"`
	TerraformPlanJSON []string `yaml:"terraform_plan_json"`
}

type OutputConfig struct {
	Formats []string `yaml:"formats"`
}

type SettingsConfig struct {
	ShowToolDetails       bool `yaml:"show_tool_details"`
	BlockOnCritical       bool `yaml:"block_on_critical"`
	MinimumReadinessScore int  `yaml:"minimum_readiness_score"`
}

type GovernanceConfig struct {
	DataOwner               string `yaml:"data_owner"`
	ApprovalWorkflow        string `yaml:"approval_workflow"`
	HumanReviewRequired     bool   `yaml:"human_review_required"`
	EvaluationCadence       string `yaml:"evaluation_cadence"`
	ReevaluateOnChange      bool   `yaml:"reevaluate_on_change"`
	IncidentResponseRunbook string `yaml:"incident_response_runbook"`
	RemediationTracking     string `yaml:"remediation_tracking"`
	PolicyPath              string `yaml:"policy_path"`
	RiskRegister            string `yaml:"risk_register"`
	ImpactAssessment        string `yaml:"impact_assessment"`
	ModelCard               string `yaml:"model_card"`
	DataLineage             string `yaml:"data_lineage"`
	HumanOversightPlan      string `yaml:"human_oversight_plan"`
	MonitoringPlan          string `yaml:"monitoring_plan"`
	ChangeManagement        string `yaml:"change_management"`
	VendorReview            string `yaml:"vendor_review"`
	TrainingRecords         string `yaml:"training_records"`
	UserDisclosure          string `yaml:"user_disclosure"`
	AuditLog                string `yaml:"audit_log"`
}

type ScannersConfig struct {
	HallbayesBackend string            `yaml:"hallbayes_backend"`
	Disabled         []string          `yaml:"disabled"`
	Options          map[string]string `yaml:"options"`
}

type TestCase struct {
	Name             string `yaml:"name" json:"name"`
	Category         string `yaml:"category" json:"category"`
	Description      string `yaml:"description" json:"description"`
	Input            string `yaml:"input" json:"input"`
	ExpectedBehavior string `yaml:"expected_behavior" json:"expected_behavior"`
	ActualOutput     string `yaml:"actual_output" json:"actual_output"`
	Pass             bool   `yaml:"pass" json:"pass"`
	Severity         string `yaml:"severity" json:"severity"`
	EvidenceFile     string `yaml:"evidence_file" json:"evidence_file"`
	UnsupportedClaim string `yaml:"unsupported_claim" json:"unsupported_claim"`
}

func Default(projectName string) Config {
	if strings.TrimSpace(projectName) == "" {
		projectName = "my-ai-system"
	}
	return Config{
		Project:      ProjectConfig{Name: projectName, Type: "rag-agent", Purpose: "Customer support assistant grounded in approved product policy."},
		ScanProfiles: []string{"quick", "iso42001"},
		Runtime:      RuntimeConfig{Preferred: "local", Fallback: "local"},
		Inputs: InputsConfig{
			Prompts:           []string{"prompts/system.md"},
			Evidence:          []string{".infraseal/evidence/knowledge-base.md"},
			TestCases:         []string{".infraseal/test-cases/*.yaml"},
			AgentSkills:       []string{".infraseal/agent-skills/"},
			Targets:           []string{"prompts/", "app/", "src/", "cmd/", "internal/", "exports/", ".infraseal/agent-skills/"},
			Include:           []string{"prompts/", "app/", "src/", "cmd/", "internal/", "exports/", ".infraseal/agent-skills/", "infra/"},
			Exclude:           DefaultExcludes(),
			TerraformPlanJSON: []string{"infra/tfplan.json", "infra/terraform-plan.json", ".infraseal/evidence/tfplan.json"},
		},
		Output:   OutputConfig{Formats: []string{"json", "markdown", "html", "csv"}},
		Settings: SettingsConfig{BlockOnCritical: true, MinimumReadinessScore: 80},
		Governance: GovernanceConfig{
			ReevaluateOnChange:      true,
			PolicyPath:              ".infraseal/governance/ai-policy.md",
			RiskRegister:            ".infraseal/governance/risk-register.md",
			ImpactAssessment:        ".infraseal/governance/impact-assessment.md",
			ModelCard:               ".infraseal/governance/model-card.md",
			DataLineage:             ".infraseal/governance/data-lineage.md",
			HumanOversightPlan:      ".infraseal/governance/human-oversight-plan.md",
			MonitoringPlan:          ".infraseal/governance/monitoring-plan.md",
			ChangeManagement:        ".infraseal/governance/change-management.md",
			IncidentResponseRunbook: ".infraseal/governance/incident-response.md",
			VendorReview:            ".infraseal/governance/vendor-review.md",
			TrainingRecords:         ".infraseal/governance/training-records.md",
			UserDisclosure:          ".infraseal/governance/user-disclosure.md",
			AuditLog:                ".infraseal/governance/audit-log.md",
		},
		Scanners: ScannersConfig{HallbayesBackend: "dummy", Options: map[string]string{}},
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Project.Name == "" {
		return Config{}, errors.New("project.name is required")
	}
	if cfg.Runtime.Preferred == "" {
		cfg.Runtime.Preferred = "local"
	}
	if cfg.Runtime.Fallback == "" {
		cfg.Runtime.Fallback = "local"
	}
	if cfg.Settings.MinimumReadinessScore == 0 {
		cfg.Settings.MinimumReadinessScore = 80
	}
	if len(cfg.Output.Formats) == 0 {
		cfg.Output.Formats = []string{"json", "markdown", "html", "csv"}
	}
	if cfg.Inputs.Exclude == nil {
		cfg.Inputs.Exclude = DefaultExcludes()
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func Root(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "."
	}
	dir := filepath.Dir(abs)
	if filepath.Base(dir) == ".infraseal" {
		return filepath.Dir(dir)
	}
	return dir
}

func Resolve(root, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Join(root, filepath.FromSlash(value))
}

func Expand(root string, patterns []string) []string {
	return ExpandWithExcludes(root, patterns, nil)
}

func ExpandWithExcludes(root string, patterns, excludes []string) []string {
	seen := map[string]bool{}
	var paths []string
	for _, pattern := range patterns {
		matches := expandOne(root, pattern)
		for _, match := range matches {
			match = filepath.Clean(match)
			if !ShouldExclude(root, match, excludes) && !seen[match] {
				seen[match] = true
				paths = append(paths, match)
			}
		}
	}
	return paths
}

func DefaultExcludes() []string {
	return []string{
		".git/**",
		".github/**",
		".infraseal/reports/**",
		"node_modules/**",
		"vendor/**",
		"dist/**",
		"build/**",
		".next/**",
		".venv/**",
		"venv/**",
		"coverage/**",
		"tmp/**",
		"**/*.png",
		"**/*.jpg",
		"**/*.jpeg",
		"**/*.gif",
		"**/*.pdf",
		"**/*.zip",
		"**/*.exe",
		"**/*.dll",
	}
}

func MergeExcludes(configured, extra []string) []string {
	seen := map[string]bool{}
	var merged []string
	for _, list := range [][]string{configured, extra} {
		for _, item := range list {
			item = filepath.ToSlash(strings.TrimSpace(item))
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			merged = append(merged, item)
		}
	}
	return merged
}

func ShouldExclude(root, path string, excludes []string) bool {
	if len(excludes) == 0 {
		return false
	}
	rel := normalizeRel(root, path)
	for _, pattern := range excludes {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		pattern = strings.TrimPrefix(pattern, "./")
		if pattern == "" {
			continue
		}
		if matchGlob(pattern, rel) || matchGlob(pattern, filepath.Base(rel)) {
			return true
		}
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "/**")
			if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
				return true
			}
		}
	}
	return false
}

func LoadTestCases(root string, patterns []string) ([]TestCase, []string, error) {
	var cases []TestCase
	var sources []string
	for _, path := range Expand(root, patterns) {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		var tc TestCase
		if err := yaml.Unmarshal(data, &tc); err != nil {
			return nil, nil, fmt.Errorf("parse test case %s: %w", path, err)
		}
		if tc.Name == "" {
			tc.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		}
		if tc.Severity == "" {
			tc.Severity = "medium"
		}
		cases = append(cases, tc)
		rel, _ := filepath.Rel(root, path)
		sources = append(sources, filepath.ToSlash(rel))
	}
	return cases, sources, nil
}

func expandOne(root, pattern string) []string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	resolved := Resolve(root, pattern)
	if !hasGlob(pattern) {
		return []string{resolved}
	}
	if strings.Contains(pattern, "**") {
		var matches []string
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel := normalizeRel(root, path)
			if matchGlob(filepath.ToSlash(pattern), rel) {
				matches = append(matches, path)
			}
			return nil
		})
		return matches
	}
	matches, err := filepath.Glob(resolved)
	if err != nil || len(matches) == 0 {
		return []string{resolved}
	}
	return matches
}

func hasGlob(value string) bool {
	return strings.ContainsAny(value, "*?[")
}

func normalizeRel(root, path string) string {
	if path == "" {
		return ""
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if filepath.IsAbs(clean) {
		if rel, err := filepath.Rel(root, clean); err == nil {
			clean = rel
		}
	}
	clean = filepath.ToSlash(clean)
	clean = strings.TrimPrefix(clean, "./")
	return clean
}

func matchGlob(pattern, rel string) bool {
	pattern = filepath.ToSlash(strings.TrimPrefix(pattern, "./"))
	rel = filepath.ToSlash(strings.TrimPrefix(rel, "./"))
	if pattern == rel {
		return true
	}
	if ok, _ := filepath.Match(filepath.FromSlash(pattern), filepath.FromSlash(rel)); ok {
		return true
	}
	regex := globRegex(pattern)
	ok, _ := regexp.MatchString(regex, rel)
	return ok
}

func globRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if ch == '*' {
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
			continue
		}
		if ch == '?' {
			b.WriteString("[^/]")
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(ch)))
	}
	b.WriteString("$")
	return b.String()
}

func IsDisabled(cfg Config, name string) bool {
	for _, item := range cfg.Scanners.Disabled {
		if strings.EqualFold(item, name) {
			return true
		}
	}
	return false
}
