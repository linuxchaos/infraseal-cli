package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/mcpvia"
	"github.com/linuxchaos/infraseal-cli/internal/reports"
	"github.com/linuxchaos/infraseal-cli/internal/runtime"
	"github.com/linuxchaos/infraseal-cli/internal/runtime/local"
	"github.com/linuxchaos/infraseal-cli/internal/runtime/taubyte"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/scanners/registry"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

type app struct {
	version            string
	configPath         string
	includeToolDetails bool
	engine             *mcpvia.Orchestrator
	reports            *reports.Service
}

func New(version string) *cobra.Command {
	reportService := reports.New()
	engine := mcpvia.New(
		registry.Default(),
		runtime.Resolver{Providers: map[string]runtime.Provider{
			"local":   local.Provider{Workers: 4},
			"taubyte": taubyte.Provider{},
		}},
		reportService,
	)
	a := &app{version: version, engine: engine, reports: reportService}
	root := &cobra.Command{
		Use:           "infraseal",
		Short:         "Run AI safety, code, agent, and governance checks from your terminal",
		Long:          "InfraSeal evaluates, governs, and audits AI workloads before deployment. MCPvia coordinates evidence, evaluators, policy checks, scoring, recommendations, and ISO 42001, NIST AI RMF, and AIUC-1 readiness reports.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.configPath, "config", config.DefaultPath, "path to infraseal.yaml")
	root.PersistentFlags().BoolVar(&a.includeToolDetails, "include-tool-details", false, "show InfraSeal evaluation capabilities, execution modes, and coverage provenance")
	root.AddCommand(a.initCommand(), a.scanCommand(), a.complianceCommand(), a.doctorCommand(), a.scannersCommand(), a.reportCommand(), a.versionCommand())
	return root
}

func (a *app) initCommand() *cobra.Command {
	var force bool
	var path string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a local InfraSeal governance workspace",
		RunE: func(cmd *cobra.Command, _ []string) error {
			created, err := config.Initialize(path, force)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "InfraSeal workspace initialized")
			for _, item := range created {
				fmt.Fprintf(cmd.OutOrStdout(), "  CREATE  %s\n", relative(path, item))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\nNext:")
			fmt.Fprintln(cmd.OutOrStdout(), "  1. Review .infraseal/infraseal.yaml")
			fmt.Fprintln(cmd.OutOrStdout(), "  2. Replace the starter evidence and test cases")
			fmt.Fprintln(cmd.OutOrStdout(), "  3. Run: infraseal scan --profile quick")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite starter files")
	cmd.Flags().StringVar(&path, "path", ".", "project root to initialize")
	return cmd
}

func (a *app) scanCommand() *cobra.Command {
	var profile string
	var runtimeName string
	var failOnGate bool
	var checks []string
	var targets []string
	var excludes []string
	var outputFormats []string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run an MCPvia evaluation profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Minute)
			defer cancel()
			paths, err := resolveScanPaths(cmd, a.configPath, targets)
			if err != nil {
				return err
			}
			result, err := a.engine.RunScan(ctx, schema.ScanRequest{Profile: profile, Runtime: runtimeName, ConfigPath: paths.configPath, ProjectRoot: paths.projectRoot, IncludeToolDetails: a.includeToolDetails, Checks: checks, Targets: paths.targets, Excludes: excludes, OutputFormats: outputFormats})
			if err != nil {
				return err
			}
			printScan(cmd.OutOrStdout(), *result, a.includeToolDetails)
			if failOnGate && result.Status != "pass" {
				return fmt.Errorf("InfraSeal gate failed with trust score %d", result.OverallScore)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "quick", "scan profile: quick, rag, agent, governance, or full")
	cmd.Flags().StringVar(&runtimeName, "runtime", "", "evaluation runtime: local or taubyte")
	cmd.Flags().BoolVar(&failOnGate, "fail-on-gate", false, "return a non-zero exit code when the InfraSeal decision is fail")
	cmd.Flags().StringSliceVar(&checks, "check", nil, "specific checks to run, such as hallucination, pii, prompt-injection, agent-safety, or code-security")
	cmd.Flags().StringSliceVar(&targets, "target", nil, "specific file, directory, or glob to evaluate; may be repeated")
	cmd.Flags().StringSliceVar(&excludes, "exclude", nil, "file, directory, or glob to skip for this run; may be repeated")
	cmd.Flags().StringSliceVar(&outputFormats, "format", nil, "override report formats for this run: json, markdown, html, csv, or pdf")
	return cmd
}

func (a *app) complianceCommand() *cobra.Command {
	parent := &cobra.Command{Use: "compliance", Short: "Run an AI governance readiness pack"}
	parent.AddCommand(a.complianceFrameworkCommand("iso42001", "Assess ISO/IEC 42001 readiness without claiming certification"))
	parent.AddCommand(a.complianceFrameworkCommand("nist-ai-rmf", "Assess NIST AI RMF readiness across Govern, Map, Measure, and Manage"))
	parent.AddCommand(a.complianceFrameworkCommand("aiuc1", "Assess AIUC-1 principle readiness for AI agents and workloads"))
	return parent
}

func (a *app) complianceFrameworkCommand(framework, short string) *cobra.Command {
	var runtimeName string
	var failOnReadiness bool
	var outputFormats []string
	cmd := &cobra.Command{
		Use:     framework,
		Aliases: complianceAliases(framework),
		Short:   short,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Minute)
			defer cancel()
			result, err := a.engine.RunCompliancePack(ctx, schema.ComplianceRequest{Framework: framework, Runtime: runtimeName, ConfigPath: a.configPath, IncludeToolDetails: a.includeToolDetails, OutputFormats: outputFormats})
			if err != nil {
				return err
			}
			printCompliance(cmd.OutOrStdout(), *result, a.includeToolDetails)
			if failOnReadiness && result.Status != "ready" {
				return fmt.Errorf("%s readiness gate failed at %d%%", result.Framework, result.OverallReadiness)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runtimeName, "runtime", "", "evaluation runtime: local or taubyte")
	cmd.Flags().BoolVar(&failOnReadiness, "fail-on-readiness", false, "return a non-zero exit code below the configured readiness threshold")
	cmd.Flags().StringSliceVar(&outputFormats, "format", nil, "override report formats for this run: json, markdown, html, csv, or pdf")
	return cmd
}

func (a *app) doctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check configuration, inputs, evaluators, and runtimes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(a.configPath)
			if err != nil {
				return err
			}
			root := config.Root(a.configPath)
			fmt.Fprintln(cmd.OutOrStdout(), "InfraSeal Doctor")
			fmt.Fprintf(cmd.OutOrStdout(), "\nPASS  Config      %s\n", a.configPath)
			evidence := existingCount(config.Expand(root, cfg.Inputs.Evidence))
			if evidence > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "PASS  Evidence    %d source file(s)\n", evidence)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "WARN  Evidence    no configured evidence files found")
			}
			cases, _, caseErr := config.LoadTestCases(root, cfg.Inputs.TestCases)
			if caseErr != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "FAIL  Test cases  %v\n", caseErr)
			} else if len(cases) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "PASS  Test cases  %d case(s)\n", len(cases))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "WARN  Test cases  no test cases found")
			}
			if cfg.Project.Owner == "" {
				fmt.Fprintln(cmd.OutOrStdout(), "WARN  Governance  AI system owner is not defined")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "PASS  Governance  owner: %s\n", cfg.Project.Owner)
			}
			if cfg.Governance.ApprovalWorkflow == "" {
				fmt.Fprintln(cmd.OutOrStdout(), "WARN  Oversight   approval workflow is not defined")
			}
			if cfg.Governance.EvaluationCadence == "" {
				fmt.Fprintln(cmd.OutOrStdout(), "WARN  Monitoring  evaluation cadence is not defined")
			}
			printGovernanceEvidence(cmd.OutOrStdout(), root, cfg)

			fmt.Fprintln(cmd.OutOrStdout(), "\nEvaluators")
			for _, status := range a.engine.ScannerStatuses(cmd.Context(), cfg) {
				fmt.Fprintf(cmd.OutOrStdout(), "  %-30s %-22s %s\n", scanners.PublicName(status.Name), status.Status, publicStatusDetail(status.Status))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\nRuntimes")
			for _, status := range a.engine.RuntimeStatuses(cmd.Context()) {
				label := "unavailable"
				if status.Available {
					label = "available"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %-12s %-12s %s\n", status.Name, label, status.Detail)
			}
			return nil
		},
	}
}

func (a *app) scannersCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "scanners",
		Aliases: []string{"evaluators"},
		Short:   "Show evaluator availability and execution readiness",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(a.configPath)
			if err != nil {
				if !os.IsNotExist(unwrapPathError(err)) {
					return err
				}
				cfg = config.Default("uninitialized-project")
			}
			for _, status := range a.engine.ScannerStatuses(cmd.Context(), cfg) {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", scanners.PublicName(status.Name), status.Status)
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", publicStatusDetail(status.Status))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\nBackend integration setup: docs/scanner-integrations.md")
			return nil
		},
	}
}

func (a *app) reportCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Regenerate a report from the latest local assessment",
		RunE: func(cmd *cobra.Command, _ []string) error {
			root := config.Root(a.configPath)
			path, err := a.reports.Regenerate(root, format, a.includeToolDetails)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Report generated: %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "markdown", "report format: json, markdown, html, csv, or pdf")
	return cmd
}

func (a *app) versionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print the InfraSeal CLI version", Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "InfraSeal CLI %s\nPowered by MCPvia\n", a.version)
	}}
}

func complianceAliases(framework string) []string {
	switch framework {
	case "iso42001":
		return []string{"iso-42001", "iso", "isoiec42001"}
	case "nist-ai-rmf":
		return []string{"nist", "ai-rmf", "nistairmf"}
	case "aiuc1":
		return []string{"aiuc", "aiuc-1"}
	default:
		return nil
	}
}

func printScan(out io.Writer, result schema.ScanResult, includeTools bool) {
	fmt.Fprintln(out, "InfraSeal AI Assurance")
	fmt.Fprintf(out, "\nProject:      %s\n", result.ProjectName)
	fmt.Fprintf(out, "Workload:     %s\n", result.WorkloadClass)
	fmt.Fprintf(out, "Profile:      %s\n", result.Profile)
	if len(result.Checks) > 0 {
		fmt.Fprintf(out, "Checks:       %s\n", strings.Join(result.Checks, ", "))
	}
	if len(result.Targets) > 0 {
		fmt.Fprintf(out, "Targets:      %s\n", strings.Join(result.Targets, ", "))
	}
	fmt.Fprintf(out, "Runtime:      %s\n", result.Runtime)
	fmt.Fprintf(out, "Trust Score:  %d/100\n", result.OverallScore)
	fmt.Fprintf(out, "Decision:     %s\n", strings.ToUpper(result.Status))
	fmt.Fprintln(out, "\nAssurance Domains")
	for _, domain := range result.Domains {
		fmt.Fprintf(out, "  %-18s %3d%%  %-15s %s\n", domain.Name, domain.Score, strings.ToUpper(domain.Status), domain.Summary)
	}
	fmt.Fprintln(out, "\nFindings")
	if len(result.Findings) == 0 {
		fmt.Fprintln(out, "  No open findings detected for this profile.")
	}
	for _, finding := range result.Findings {
		fmt.Fprintf(out, "  %-8s %-16s %s\n", strings.ToUpper(finding.Severity), finding.Domain, finding.Title)
		if refs := benchmarkSummary(finding.Benchmarks); refs != "" {
			fmt.Fprintf(out, "           Benchmarks: %s\n", refs)
		}
		fmt.Fprintf(out, "           Action: %s\n", finding.Recommendation)
	}
	fmt.Fprintln(out, "\nTop Recommendations")
	for _, item := range result.Recommendations {
		fmt.Fprintf(out, "  %d. %s (%s)\n", item.Priority, item.Title, item.EstimatedEffort)
	}
	printCoverage(out, result.ToolResults)
	if includeTools {
		printTools(out, result.ToolResults)
	}
	printPaths(out, result.ReportPaths)
	fmt.Fprintln(out, "\nPowered by MCPvia")
}

func printCompliance(out io.Writer, result schema.ComplianceResult, includeTools bool) {
	fmt.Fprintln(out, "InfraSeal AI Governance Readiness")
	fmt.Fprintf(out, "\nOverall Readiness: %d%%\n", result.OverallReadiness)
	fmt.Fprintf(out, "Status: %s\n", strings.ToUpper(result.Status))
	for _, category := range result.Categories {
		fmt.Fprintf(out, "\n%s\n  %-5s %d%%\n", category.Name, category.Status, category.Score)
		fmt.Fprintf(out, "  %s\n", category.AssessmentSummary)
		for _, strength := range category.Strengths {
			fmt.Fprintf(out, "  PASS  %s\n", strength)
		}
		for _, gap := range category.Gaps {
			fmt.Fprintf(out, "  WARN  %s\n", gap)
		}
		fmt.Fprintln(out, "  Expected evidence:")
		for _, evidence := range category.ExpectedEvidence {
			fmt.Fprintf(out, "    - %s\n", evidence)
		}
		if len(category.Controls) > 0 {
			fmt.Fprintln(out, "  Control assessment:")
			for _, control := range category.Controls {
				fmt.Fprintf(out, "    - %-18s %-16s %s\n", strings.ToUpper(control.Status), control.Applicability, control.Name)
				if control.Summary != "" {
					fmt.Fprintf(out, "      %s\n", control.Summary)
				}
				for _, gap := range control.Gaps {
					fmt.Fprintf(out, "      Gap: %s\n", gap)
				}
			}
		}
		fmt.Fprintln(out, "  Benchmark mapping:")
		for _, reference := range category.ControlReferences {
			label := reference.Reference
			if reference.Framework != "" {
				label = reference.Framework + " " + reference.Reference
			}
			fmt.Fprintf(out, "    - %s: %s\n      %s\n", label, reference.Topic, reference.URL)
		}
	}
	fmt.Fprintln(out, "\nTop Recommendations:")
	for _, item := range result.Recommendations {
		fmt.Fprintf(out, "  %d. %s (%s)\n", item.Priority, item.Title, item.EstimatedEffort)
	}
	if includeTools {
		printComplianceEvidence(out, result.ToolResults)
	}
	printPaths(out, result.ReportPaths)
	fmt.Fprintln(out, "\nOfficial resources:")
	for _, reference := range result.References {
		fmt.Fprintf(out, "  - %s: %s\n", reference.Reference, reference.URL)
	}
	fmt.Fprintf(out, "\n%s\n", result.Disclaimer)
	fmt.Fprintln(out, "\nPowered by MCPvia")
}

func printCoverage(out io.Writer, tools []schema.ToolResult) {
	counts := map[string]int{}
	for _, tool := range tools {
		if tool.Status == scanners.StatusError {
			counts["error"]++
			continue
		}
		counts[tool.Mode]++
	}
	fmt.Fprintf(out, "\nEvaluation Coverage: MCPvia native active; %d real, %d native, %d missing, %d disabled, %d errors\n", counts["real"], counts["native"], counts["missing dependency"], counts["disabled"], counts["error"])
	fmt.Fprintln(out, "  Use --include-tool-details to inspect evaluator-level provenance.")
}

func printTools(out io.Writer, tools []schema.ToolResult) {
	fmt.Fprintln(out, "\nEvaluation Provenance")
	for _, tool := range tools {
		fmt.Fprintf(out, "  %-28s %-18s %-12s %s\n", tool.DisplayName, tool.Status, tool.Mode, oneLine(tool.Detail))
	}
}

func printComplianceEvidence(out io.Writer, tools []schema.ToolResult) {
	fmt.Fprintln(out, "\nReadiness Evidence Provenance")
	fmt.Fprintln(out, "  This command did not execute scanner adapters; entries below were loaded from the latest technical scan.")
	for _, tool := range tools {
		fmt.Fprintf(out, "  %-28s %-18s %-12s %s\n", tool.DisplayName, tool.Status, tool.Mode, oneLine(tool.Detail))
	}
}

func printPaths(out io.Writer, paths map[string]string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintln(out, "\nReports")
	for _, value := range reports.SortedPaths(paths) {
		fmt.Fprintf(out, "  %s\n", value)
	}
}

func benchmarkSummary(refs []schema.ControlReference) string {
	if len(refs) == 0 {
		return ""
	}
	var values []string
	for _, ref := range refs {
		label := strings.TrimSpace(ref.Framework)
		if label == "" {
			label = strings.TrimSpace(ref.Reference)
		} else if ref.Reference != "" {
			label += " " + ref.Reference
		}
		if label != "" {
			values = append(values, label)
		}
	}
	return strings.Join(values, "; ")
}

func existingCount(paths []string) int {
	count := 0
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			count++
		}
	}
	return count
}

func printGovernanceEvidence(out io.Writer, root string, cfg config.Config) {
	fmt.Fprintln(out, "\nGovernance Evidence")
	for _, doc := range governanceDocs(cfg) {
		if doc.path == "" {
			fmt.Fprintf(out, "WARN  %-18s not configured\n", doc.label)
			continue
		}
		path := config.Resolve(root, doc.path)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(out, "WARN  %-18s missing: %s\n", doc.label, doc.path)
			continue
		}
		text := strings.TrimSpace(string(data))
		lower := strings.ToLower(text)
		if len(text) < 120 || strings.Contains(lower, "todo:") || strings.Contains(lower, "tbd") || strings.Contains(lower, "replace this") {
			fmt.Fprintf(out, "WARN  %-18s starter or incomplete: %s\n", doc.label, doc.path)
			continue
		}
		fmt.Fprintf(out, "PASS  %-18s %s\n", doc.label, doc.path)
	}
}

type governanceDoc struct {
	label string
	path  string
}

func governanceDocs(cfg config.Config) []governanceDoc {
	return []governanceDoc{
		{"AI policy", cfg.Governance.PolicyPath},
		{"Risk register", cfg.Governance.RiskRegister},
		{"Impact assessment", cfg.Governance.ImpactAssessment},
		{"Model card", cfg.Governance.ModelCard},
		{"Data lineage", cfg.Governance.DataLineage},
		{"Oversight plan", cfg.Governance.HumanOversightPlan},
		{"Monitoring plan", cfg.Governance.MonitoringPlan},
		{"Change plan", cfg.Governance.ChangeManagement},
		{"Incident runbook", cfg.Governance.IncidentResponseRunbook},
		{"Vendor review", cfg.Governance.VendorReview},
		{"Training records", cfg.Governance.TrainingRecords},
		{"User disclosure", cfg.Governance.UserDisclosure},
		{"Audit log", cfg.Governance.AuditLog},
	}
}
func oneLine(value string) string { return strings.Join(strings.Fields(value), " ") }
func publicStatusDetail(status string) string {
	switch status {
	case scanners.StatusAvailable:
		return "enhanced local coverage is ready"
	case scanners.StatusMissingDependency, "missing_backend_key":
		return "optional enhanced coverage is not configured"
	case scanners.StatusDisabled:
		return "needs a compatible target or optional evaluator binding"
	case scanners.StatusError:
		return "availability check returned an error"
	default:
		return "status recorded by MCPvia"
	}
}
func relative(root, path string) string {
	abs, _ := filepath.Abs(root)
	rel, err := filepath.Rel(abs, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

func unwrapPathError(err error) error {
	for {
		if pathErr, ok := err.(*os.PathError); ok {
			return pathErr
		}
		type unwrapper interface{ Unwrap() error }
		if value, ok := err.(unwrapper); ok {
			err = value.Unwrap()
			continue
		}
		return err
	}
}

type scanPaths struct {
	configPath  string
	projectRoot string
	targets     []string
}

func resolveScanPaths(cmd *cobra.Command, configPath string, targets []string) (scanPaths, error) {
	if configPath == "" {
		configPath = config.DefaultPath
	}
	if _, err := os.Stat(configPath); err == nil {
		normalizedTargets := normalizeCLITargetsFromBase(targets, config.Root(configPath))
		return scanPaths{configPath: configPath, targets: normalizedTargets}, nil
	}
	if configFlagChanged(cmd) {
		return scanPaths{}, missingConfigMessage(configPath)
	}
	normalizedTargets := normalizeCLITargets(targets)
	if discovered, err := discoverConfigFromTargets(targets); err != nil {
		return scanPaths{}, err
	} else if discovered != "" {
		return scanPaths{configPath: discovered, targets: normalizedTargets}, nil
	}
	root := inferredProjectRoot(normalizedTargets)
	if root == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return scanPaths{}, err
		}
		root = cwd
	}
	return scanPaths{configPath: configPath, projectRoot: root, targets: normalizedTargets}, nil
}

func configFlagChanged(cmd *cobra.Command) bool {
	flag := cmd.Flag("config")
	return flag != nil && flag.Changed
}

func normalizeCLITargets(targets []string) []string {
	return normalizeCLITargetsFromBase(targets, "")
}

func normalizeCLITargetsFromBase(targets []string, base string) []string {
	var values []string
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if filepath.IsAbs(target) {
			values = append(values, filepath.Clean(target))
			continue
		}
		if hasGlobChars(target) {
			if base == "" {
				values = append(values, filepath.Clean(target))
			} else {
				values = append(values, filepath.ToSlash(filepath.Clean(target)))
			}
			continue
		}
		if base != "" {
			values = append(values, filepath.Join(base, filepath.FromSlash(target)))
			continue
		}
		abs, err := filepath.Abs(target)
		if err != nil {
			values = append(values, target)
			continue
		}
		values = append(values, abs)
	}
	return values
}

func discoverConfigFromTargets(targets []string) (string, error) {
	found := map[string]bool{}
	for _, target := range targets {
		start := staticTargetBase(strings.TrimSpace(target))
		if start == "" {
			continue
		}
		if cfg := nearestConfig(start); cfg != "" {
			found[cfg] = true
		}
	}
	if len(found) == 0 {
		return "", nil
	}
	if len(found) > 1 {
		var configs []string
		for path := range found {
			configs = append(configs, path)
		}
		return "", fmt.Errorf("multiple InfraSeal configs matched the selected targets: %s; pass --config to choose one", strings.Join(configs, ", "))
	}
	for path := range found {
		return path, nil
	}
	return "", nil
}

func staticTargetBase(target string) string {
	if target == "" {
		return ""
	}
	if hasGlobChars(target) {
		for {
			dir := filepath.Dir(target)
			if dir == target || !hasGlobChars(dir) {
				target = dir
				break
			}
			target = dir
		}
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return ""
	}
	info, err := os.Stat(abs)
	if err == nil && !info.IsDir() {
		return filepath.Dir(abs)
	}
	if err != nil {
		return filepath.Dir(abs)
	}
	return abs
}

func nearestConfig(start string) string {
	dir := filepath.Clean(start)
	for {
		candidate := filepath.Join(dir, filepath.FromSlash(config.DefaultPath))
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func inferredProjectRoot(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	var roots []string
	for _, target := range targets {
		if hasGlobChars(target) {
			continue
		}
		path := target
		if !filepath.IsAbs(path) {
			abs, err := filepath.Abs(path)
			if err != nil {
				continue
			}
			path = abs
		}
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			path = filepath.Dir(path)
		}
		roots = append(roots, filepath.Clean(path))
	}
	if len(roots) == 0 {
		return ""
	}
	root := roots[0]
	for _, next := range roots[1:] {
		root = commonAncestor(root, next)
	}
	return root
}

func commonAncestor(left, right string) string {
	leftParts := strings.Split(filepath.Clean(left), string(os.PathSeparator))
	rightParts := strings.Split(filepath.Clean(right), string(os.PathSeparator))
	limit := len(leftParts)
	if len(rightParts) < limit {
		limit = len(rightParts)
	}
	var parts []string
	for index := 0; index < limit; index++ {
		if !strings.EqualFold(leftParts[index], rightParts[index]) {
			break
		}
		parts = append(parts, leftParts[index])
	}
	if len(parts) == 0 {
		return left
	}
	return filepath.Clean(strings.Join(parts, string(os.PathSeparator)))
}

func hasGlobChars(value string) bool {
	return strings.ContainsAny(value, "*?[")
}

func missingConfigMessage(path string) error {
	return fmt.Errorf("InfraSeal config not found at %s; run `infraseal init` from the repository root, pass `--config path/to/.infraseal/infraseal.yaml`, or run `infraseal scan --profile full --target path/to/repo` for a first technical scan without a config", path)
}
