package mcpvia

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/compliance/benchmarks"
	"github.com/linuxchaos/infraseal-cli/internal/compliance/iso42001"
	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/recommendations"
	"github.com/linuxchaos/infraseal-cli/internal/reports"
	"github.com/linuxchaos/infraseal-cli/internal/runtime"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type Engine interface {
	RunScan(context.Context, schema.ScanRequest) (*schema.ScanResult, error)
	RunCompliancePack(context.Context, schema.ComplianceRequest) (*schema.ComplianceResult, error)
}

type Orchestrator struct {
	Adapters []scanners.Scanner
	Runtimes runtime.Resolver
	Reports  *reports.Service
}

type prepared struct {
	cfg         config.Config
	root        string
	cases       []config.TestCase
	testSources []string
	evidence    []string
	agentSkills []string
	excludes    []string
}

func New(adapters []scanners.Scanner, resolver runtime.Resolver, reportService *reports.Service) *Orchestrator {
	return &Orchestrator{Adapters: adapters, Runtimes: resolver, Reports: reportService}
}

func (e *Orchestrator) RunScan(ctx context.Context, request schema.ScanRequest) (*schema.ScanResult, error) {
	return e.runScan(ctx, request, true)
}

func (e *Orchestrator) runScan(ctx context.Context, request schema.ScanRequest, generateReports bool) (*schema.ScanResult, error) {
	started := time.Now().UTC()
	if !ValidProfile(request.Profile) {
		return nil, fmt.Errorf("unknown profile %q; expected quick, rag, agent, governance, or full", request.Profile)
	}
	input, err := prepare(request.ConfigPath)
	if err != nil {
		return nil, err
	}
	if request.ProjectRoot != "" {
		input.root = request.ProjectRoot
	}
	if request.ProjectName != "" {
		input.cfg.Project.Name = request.ProjectName
	}
	if request.ProjectType != "" {
		input.cfg.Project.Type = request.ProjectType
	}
	checks, err := NormalizeChecks(request.Checks)
	if err != nil {
		return nil, err
	}
	targetPatterns := request.Targets
	if len(targetPatterns) == 0 {
		if len(input.cfg.Inputs.Include) > 0 {
			targetPatterns = input.cfg.Inputs.Include
		} else {
			targetPatterns = input.cfg.Inputs.Targets
		}
	}
	excludes := config.MergeExcludes(input.cfg.Inputs.Exclude, request.Excludes)
	targets := existing(config.ExpandWithExcludes(input.root, targetPatterns, excludes))
	if len(targetPatterns) > 0 && len(targets) == 0 {
		return nil, fmt.Errorf("none of the requested scan targets exist: %s", strings.Join(targetPatterns, ", "))
	}

	preferred := request.Runtime
	if preferred == "" {
		preferred = input.cfg.Runtime.Preferred
	}
	provider, fellBack := e.Runtimes.Resolve(ctx, preferred, input.cfg.Runtime.Fallback)
	if provider == nil {
		return nil, fmt.Errorf("runtime %q is unavailable and fallback %q is not ready", preferred, input.cfg.Runtime.Fallback)
	}
	runtimeName := provider.Name()
	assessmentID := newID("scan")
	artifactDir := filepath.Join(input.root, ".infraseal", "reports", "artifacts", assessmentID)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return nil, err
	}

	selected := e.adaptersFor(ctx, input.cfg, request.Profile, checks)
	toolInput := scanners.Input{
		RootDir: input.root, ConfigPath: request.ConfigPath, Config: input.cfg, Profile: request.Profile,
		ArtifactsDir: artifactDir, Evidence: input.evidence, TestCases: input.cases,
		TestSources: input.testSources, AgentSkills: input.agentSkills, Targets: targets, Checks: checks,
		Excludes: excludes,
	}
	toolResults, err := provider.Execute(ctx, selected, toolInput)
	if err != nil {
		return nil, err
	}
	findings := nativeFindings(input, request.Profile, checks)
	findings = append(findings, nativeTargetFindings(input.root, targets, nativeTargetChecks(request.Profile, checks), excludes)...)
	for toolIndex := range toolResults {
		toolResults[toolIndex].Findings = filterFindings(input.root, toolResults[toolIndex].Findings, excludes)
		for _, finding := range toolResults[toolIndex].Findings {
			finding.HiddenByDefault = true
			findings = append(findings, finding)
		}
	}
	findings = correlate(findings)
	findings = benchmarks.Annotate(findings)
	domains, score := scoreFindings(findings)
	status := "pass"
	if score < input.cfg.Settings.MinimumReadinessScore || (input.cfg.Settings.BlockOnCritical && hasSeverity(findings, "critical")) {
		status = "fail"
	}
	runtimeDetail := runtimeName
	if fellBack {
		runtimeDetail += " (fallback from " + preferred + ")"
	}
	result := &schema.ScanResult{
		SchemaVersion: "1.0", AssessmentID: assessmentID, ProjectName: input.cfg.Project.Name,
		ProjectType: input.cfg.Project.Type, WorkloadClass: classify(input.cfg), Profile: request.Profile,
		Checks: checks, Targets: relativePaths(input.root, targets),
		Runtime: runtimeDetail, OverallScore: score, ReadinessScore: score, Status: status,
		Domains: domains, Findings: findings, Recommendations: recommendations.Build(findings), ToolResults: toolResults,
		EvidenceFiles: append([]string{}, append(append(input.testSources, relativePaths(input.root, input.evidence)...), relativePaths(input.root, targets)...)...),
		ReportPaths:   map[string]string{}, StartedAt: started, CompletedAt: time.Now().UTC(),
	}
	if generateReports && e.Reports != nil {
		paths, err := e.Reports.GenerateScan(input.root, result, outputFormats(input.cfg.Output.Formats, request.OutputFormats), request.IncludeToolDetails || input.cfg.Settings.ShowToolDetails)
		if err != nil {
			return nil, err
		}
		result.ReportPaths = paths
	}
	return result, nil
}

func (e *Orchestrator) RunCompliancePack(ctx context.Context, request schema.ComplianceRequest) (*schema.ComplianceResult, error) {
	framework := normalizeFramework(request.Framework)
	if framework == "" {
		framework = "iso42001"
	}
	if !validFramework(framework) {
		return nil, fmt.Errorf("unsupported compliance pack %q", request.Framework)
	}
	started := time.Now().UTC()
	input, err := prepare(request.ConfigPath)
	if err != nil {
		return nil, err
	}
	providerName := request.Runtime
	if providerName == "" {
		providerName = input.cfg.Runtime.Preferred
	}
	provider, fellBack := e.Runtimes.Resolve(ctx, providerName, input.cfg.Runtime.Fallback)
	if provider == nil {
		return nil, errors.New("no evaluation runtime is available")
	}
	if fellBack {
		providerName = provider.Name() + " (fallback from " + providerName + ")"
	} else {
		providerName = provider.Name()
	}

	excludes := input.cfg.Inputs.Exclude
	targetPatterns := input.cfg.Inputs.Include
	if len(targetPatterns) == 0 {
		targetPatterns = input.cfg.Inputs.Targets
	}
	targets := existing(config.ExpandWithExcludes(input.root, targetPatterns, excludes))

	selected := e.adaptersFor(ctx, input.cfg, "full", nil)
	assessmentID := newID(framework)
	artifactDir := filepath.Join(input.root, ".infraseal", "reports", "artifacts", assessmentID)
	toolResults, err := provider.Execute(ctx, selected, scanners.Input{
		RootDir: input.root, ConfigPath: request.ConfigPath, Config: input.cfg, Profile: "governance",
		ArtifactsDir: artifactDir, Evidence: input.evidence, TestCases: input.cases,
		TestSources: input.testSources, AgentSkills: input.agentSkills,
		Targets: targets, Excludes: excludes,
	})
	if err != nil {
		return nil, err
	}
	for index := range toolResults {
		toolResults[index].Findings = filterFindings(input.root, toolResults[index].Findings, excludes)
	}
	result := iso42001.AssessFramework(iso42001.Input{
		AssessmentID: assessmentID, RootDir: input.root, Runtime: providerName, Config: input.cfg,
		TestCases: input.cases, TestSources: input.testSources, Evidence: input.evidence, ToolResults: toolResults, StartedAt: started,
	}, framework)
	if e.Reports != nil {
		paths, err := e.Reports.GenerateCompliance(input.root, &result, outputFormats(input.cfg.Output.Formats, request.OutputFormats), request.IncludeToolDetails || input.cfg.Settings.ShowToolDetails)
		if err != nil {
			return nil, err
		}
		result.ReportPaths = paths
	}
	return &result, nil
}

func (e *Orchestrator) ScannerStatuses(ctx context.Context, cfg config.Config) []schema.ScannerStatus {
	statuses := make([]schema.ScannerStatus, 0, len(e.Adapters))
	for _, adapter := range e.Adapters {
		statuses = append(statuses, adapter.IsAvailable(ctx, cfg))
	}
	return statuses
}

func (e *Orchestrator) RuntimeStatuses(ctx context.Context) []runtime.Status {
	keys := make([]string, 0, len(e.Runtimes.Providers))
	for key := range e.Runtimes.Providers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	statuses := make([]runtime.Status, 0, len(keys))
	for _, key := range keys {
		statuses = append(statuses, e.Runtimes.Providers[key].Status(ctx))
	}
	return statuses
}

func (e *Orchestrator) adaptersFor(ctx context.Context, cfg config.Config, profile string, checks []string) []scanners.Scanner {
	var selected []scanners.Scanner
	for _, adapter := range e.Adapters {
		profileMatch := profile == "full" || scanners.SupportsProfile(adapter, profile)
		if len(checks) > 0 {
			profileMatch = categoriesMatch(adapter.IsAvailable(ctx, cfg).Categories, checks)
		}
		if profileMatch {
			selected = append(selected, adapter)
		}
	}
	return selected
}

func prepare(configPath string) (prepared, error) {
	if configPath == "" {
		configPath = config.DefaultPath
	}
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return prepared{}, err
	}
	cfg, err := config.Load(abs)
	if err != nil {
		return prepared{}, err
	}
	root := config.Root(abs)
	cases, sources, err := config.LoadTestCases(root, cfg.Inputs.TestCases)
	if err != nil {
		return prepared{}, err
	}
	return prepared{cfg: cfg, root: root, cases: cases, testSources: sources, evidence: existing(config.Expand(root, cfg.Inputs.Evidence)), agentSkills: existing(config.Expand(root, cfg.Inputs.AgentSkills)), excludes: cfg.Inputs.Exclude}, nil
}

func existing(paths []string) []string {
	var values []string
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			values = append(values, path)
		}
	}
	return values
}

func classify(cfg config.Config) string {
	if cfg.Project.Type != "" {
		return cfg.Project.Type
	}
	hasEvidence := len(cfg.Inputs.Evidence) > 0
	hasSkills := len(cfg.Inputs.AgentSkills) > 0
	if hasEvidence && hasSkills {
		return "rag-agent"
	}
	if hasSkills {
		return "agent"
	}
	if hasEvidence {
		return "rag"
	}
	return "ai-workload"
}

func nativeFindings(input prepared, profile string, checks []string) []schema.Finding {
	var findings []schema.Finding
	for index, tc := range input.cases {
		if tc.Pass || !caseSelected(tc.Category, profile, checks) {
			continue
		}
		source := ""
		if index < len(input.testSources) {
			source = input.testSources[index]
		}
		findings = append(findings, schema.Finding{
			Severity: scanners.NormalizeSeverity(tc.Severity), Domain: scanners.DomainForCategory(tc.Category), Category: tc.Category,
			Title: tc.Name + " failed", Description: tc.Description, Evidence: tc.ActualOutput,
			Recommendation: "Implement the expected behavior and retain this case as a blocking regression test.",
			SourceTool:     "mcpvia", FilePath: source, ExecutionMode: "native",
		})
	}
	if len(checks) == 0 && (profile == "governance" || profile == "full") || containsCheck(checks, "governance") {
		if strings.TrimSpace(input.cfg.Project.Owner) == "" {
			findings = append(findings, governanceFinding("high", "ai-ownership", "AI system owner is not defined", "Assign an accountable owner and add the system to an AI inventory."))
		}
		if strings.TrimSpace(input.cfg.Governance.ApprovalWorkflow) == "" {
			findings = append(findings, governanceFinding("high", "approval-workflow", "Deployment approval workflow is not defined", "Document approvers, required evidence, blocking conditions, and exception handling."))
		}
		if !input.cfg.Governance.HumanReviewRequired {
			findings = append(findings, governanceFinding("high", "human-oversight", "Human review is not required before deployment", "Require accountable human review before production deployment."))
		}
		if strings.TrimSpace(input.cfg.Governance.EvaluationCadence) == "" {
			findings = append(findings, governanceFinding("medium", "evaluation-cadence", "Continuous evaluation cadence is not defined", "Schedule recurring evaluation and rerun after material changes."))
		}
		if strings.TrimSpace(input.cfg.Governance.IncidentResponseRunbook) == "" {
			findings = append(findings, governanceFinding("medium", "incident-response", "AI incident response runbook is not documented", "Document containment, evidence preservation, notification, and re-approval steps."))
		}
	}
	return findings
}

func caseSelected(category, profile string, checks []string) bool {
	if len(checks) == 0 {
		return caseInProfile(category, profile)
	}
	return categoriesMatch([]string{category}, checks)
}

func governanceFinding(severity, category, title, action string) schema.Finding {
	return schema.Finding{Severity: severity, Domain: "Governance", Category: category, Title: title, Description: title, Evidence: ".infraseal/infraseal.yaml", Recommendation: action, SourceTool: "mcpvia", ExecutionMode: "native"}
}

func caseInProfile(category, profile string) bool {
	category = strings.ToLower(category)
	switch profile {
	case "quick":
		return strings.Contains(category, "inject") || strings.Contains(category, "pii") || strings.Contains(category, "safety")
	case "rag":
		return strings.Contains(category, "ground") || strings.Contains(category, "halluc") || strings.Contains(category, "context") || strings.Contains(category, "evidence")
	case "agent":
		return strings.Contains(category, "agent") || strings.Contains(category, "tool") || strings.Contains(category, "skill")
	case "governance":
		return strings.Contains(category, "govern") || strings.Contains(category, "approval") || strings.Contains(category, "oversight")
	case "full":
		return true
	default:
		return false
	}
}

func correlate(findings []schema.Finding) []schema.Finding {
	seen := map[string]int{}
	var result []schema.Finding
	for _, finding := range findings {
		if finding.Domain == "" {
			finding.Domain = scanners.DomainForCategory(finding.Category)
		}
		key := strings.ToLower(strings.TrimSpace(finding.Category) + "|" + strings.TrimSpace(finding.Title) + "|" + strings.TrimSpace(finding.FilePath))
		if index, ok := seen[key]; ok {
			if result[index].SourceTool != finding.SourceTool && finding.SourceTool != "" {
				result[index].SourceTool += "," + finding.SourceTool
			}
			continue
		}
		finding.ID = findingID(finding)
		seen[key] = len(result)
		result = append(result, finding)
	}
	sort.SliceStable(result, func(i, j int) bool { return severityWeight(result[i].Severity) > severityWeight(result[j].Severity) })
	return result
}

func scoreFindings(findings []schema.Finding) ([]schema.DomainScore, int) {
	names := []string{"Security", "Grounding", "Privacy", "Agent Safety", "Code Security", "Governance"}
	byDomain := map[string][]schema.Finding{}
	overall := 100
	for _, finding := range findings {
		byDomain[finding.Domain] = append(byDomain[finding.Domain], finding)
		overall -= severityWeight(finding.Severity)
	}
	if overall < 0 {
		overall = 0
	}
	var domains []schema.DomainScore
	for _, name := range names {
		score := 100
		for _, finding := range byDomain[name] {
			score -= severityWeight(finding.Severity)
		}
		if score < 0 {
			score = 0
		}
		status := "pass"
		if score < 80 {
			status = "needs-attention"
		}
		summary := "No blocking gaps detected in this domain."
		if len(byDomain[name]) > 0 {
			summary = fmt.Sprintf("%d correlated finding(s) require review.", len(byDomain[name]))
		}
		domains = append(domains, schema.DomainScore{Name: name, Score: score, Status: status, Summary: summary, FindingCount: len(byDomain[name])})
	}
	return domains, overall
}

func severityWeight(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 25
	case "high":
		return 15
	case "medium":
		return 8
	case "low":
		return 3
	default:
		return 1
	}
}

func hasSeverity(findings []schema.Finding, severity string) bool {
	for _, finding := range findings {
		if strings.EqualFold(finding.Severity, severity) {
			return true
		}
	}
	return false
}

func findingID(finding schema.Finding) string {
	digest := sha256.Sum256([]byte(strings.ToLower(finding.Category + "|" + finding.Title + "|" + finding.Evidence)))
	return "FND-" + strings.ToUpper(hex.EncodeToString(digest[:])[:10])
}

func newID(prefix string) string {
	buf := make([]byte, 5)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("%s-%s-%s", prefix, time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(buf))
}

func relativePaths(root string, paths []string) []string {
	var values []string
	for _, path := range paths {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		values = append(values, filepath.ToSlash(rel))
	}
	return values
}

func filterFindings(root string, findings []schema.Finding, excludes []string) []schema.Finding {
	if len(excludes) == 0 {
		return findings
	}
	var filtered []schema.Finding
	for _, finding := range findings {
		if finding.FilePath == "" || !config.ShouldExclude(root, finding.FilePath, excludes) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func outputFormats(configured, requested []string) []string {
	if len(requested) > 0 {
		return requested
	}
	return configured
}

func normalizeFramework(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	switch value {
	case "", "iso", "iso42001", "iso-42001", "iso/iec-42001":
		return "iso42001"
	case "nist", "nist-ai-rmf", "nistairmf", "ai-rmf":
		return "nist-ai-rmf"
	case "aiuc", "aiuc1", "aiuc-1":
		return "aiuc1"
	default:
		return value
	}
}

func validFramework(value string) bool {
	switch value {
	case "iso42001", "nist-ai-rmf", "aiuc1":
		return true
	default:
		return false
	}
}

func nativeTargetChecks(profile string, checks []string) []string {
	if len(checks) > 0 {
		return checks
	}
	switch profile {
	case "quick", "full":
		return []string{"prompt-injection", "pii", "output-safety"}
	case "agent":
		return []string{"prompt-injection", "pii", "output-safety", "agent-safety"}
	default:
		return nil
	}
}
