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
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Minute)
			defer cancel()
			result, err := a.engine.RunScan(ctx, schema.ScanRequest{Profile: profile, Runtime: runtimeName, ConfigPath: a.configPath, IncludeToolDetails: a.includeToolDetails, Checks: checks, Targets: targets, Excludes: excludes, OutputFormats: outputFormats})
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
		Use:   framework,
		Short: short,
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
		printTools(out, result.ToolResults)
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
		counts[tool.Mode]++
	}
	fmt.Fprintf(out, "\nEvaluation Coverage: MCPvia native active; %d real, %d mocked, %d missing, %d disabled, %d errors\n", counts["real"], counts["mocked"], counts["missing dependency"], counts["disabled"], counts["error"])
	fmt.Fprintln(out, "  Use --include-tool-details to inspect evaluator-level provenance.")
}

func printTools(out io.Writer, tools []schema.ToolResult) {
	fmt.Fprintln(out, "\nEvaluation Provenance")
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
	case scanners.StatusMocked:
		return "deterministic fixture-backed coverage is ready"
	case scanners.StatusMissingDependency, "missing_backend_key":
		return "optional enhanced coverage is not configured"
	case scanners.StatusDisabled:
		return "disabled by project configuration"
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
