package iso42001

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linuxchaos/infraseal-cli/internal/compliance/benchmarks"
	"github.com/linuxchaos/infraseal-cli/internal/config"
	"github.com/linuxchaos/infraseal-cli/internal/recommendations"
	"github.com/linuxchaos/infraseal-cli/internal/scanners"
	"github.com/linuxchaos/infraseal-cli/internal/schema"
)

const Disclaimer = "InfraSeal helps organizations prepare for and maintain AI governance programs aligned with ISO/IEC 42001. This readiness assessment is not certification and does not establish compliance."
const standardURL = "https://www.iso.org/standard/42001"
const explainerURL = "https://www.iso.org/home/insights-news/resources/iso-42001-explained-what-it-is.html"
const nistCoreURL = "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/"
const nistPlaybookURL = "https://airc.nist.gov/airmf-resources/playbook/"
const aiucURL = "https://aiuc.com/research/introducing-aiuc-1"

type Input struct {
	AssessmentID string
	RootDir      string
	Runtime      string
	Config       config.Config
	TestCases    []config.TestCase
	TestSources  []string
	Evidence     []string
	AgentSkills  []string
	ToolResults  []schema.ToolResult
	StartedAt    time.Time
}

func Assess(input Input) schema.ComplianceResult {
	return AssessFramework(input, "iso42001")
}

func AssessFramework(input Input, framework string) schema.ComplianceResult {
	framework = normalizeFramework(framework)
	var findings []schema.Finding
	var categories []schema.ReadinessCategory
	var weights map[string]int
	var references []schema.ControlReference
	title := "ISO/IEC 42001 Readiness"
	disclaimer := Disclaimer
	switch framework {
	case "nist-ai-rmf":
		title = "NIST AI RMF Readiness"
		disclaimer = "InfraSeal maps local evidence and evaluator findings to NIST AI RMF functions for readiness planning. This is not legal advice or a formal assurance attestation."
		categories = []schema.ReadinessCategory{
			nistGovern(input, &findings),
			nistMap(input, &findings),
			nistMeasure(input, &findings),
			nistManage(input, &findings),
		}
		weights = map[string]int{"GOVERN": 25, "MAP": 20, "MEASURE": 35, "MANAGE": 20}
		references = []schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "AI RMF Core", Topic: "Govern, Map, Measure, and Manage functions", URL: nistCoreURL},
			{Framework: "NIST AI RMF", Reference: "AI RMF Playbook", Topic: "Suggested actions aligned to AI RMF outcomes", URL: nistPlaybookURL},
		}
	case "aiuc1":
		title = "AIUC-1 Principles Readiness"
		disclaimer = "InfraSeal maps local evidence and evaluator findings to public AIUC-1 principle areas for internal readiness planning. This is not AIUC certification."
		categories = []schema.ReadinessCategory{
			aiucDataPrivacy(input, &findings),
			aiucSecurity(input, &findings),
			aiucSafety(input, &findings),
			aiucReliability(input, &findings),
			aiucAccountability(input, &findings),
			aiucSociety(input, &findings),
		}
		weights = map[string]int{"Data & Privacy": 20, "Security": 25, "Safety": 15, "Reliability": 20, "Accountability": 15, "Society": 5}
		references = []schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Public principles", Topic: "Data & Privacy, Security, Safety, Reliability, Accountability, and Society", URL: aiucURL},
		}
	default:
		categories = []schema.ReadinessCategory{
			isoClause4(input, &findings),
			isoClause5(input, &findings),
			isoClause6(input, &findings),
			isoClause7(input, &findings),
			isoClause8(input, &findings),
			isoClause9(input, &findings),
			isoClause10(input, &findings),
		}
		weights = map[string]int{"Clause 4 - Context": 15, "Clause 5 - Leadership": 15, "Clause 6 - Planning": 15, "Clause 7 - Support": 10, "Clause 8 - Operation": 20, "Clause 9 - Performance Evaluation": 15, "Clause 10 - Improvement": 10}
		references = []schema.ControlReference{
			{Framework: "ISO/IEC 42001", Reference: "ISO/IEC 42001:2023", Topic: "Official standard page and purchasing access", URL: standardURL},
			{Framework: "ISO/IEC 42001", Reference: "ISO 42001 explained", Topic: "Official overview of AI management system requirements", URL: explainerURL},
		}
	}
	categories = attachControlAssessments(framework, input, categories)
	findings = append(findings, toolFindings(input.ToolResults)...)
	findings = benchmarks.Annotate(findings)
	overall := 0
	for _, category := range categories {
		overall += category.Score * weights[category.Name]
	}
	overall /= 100
	status := "needs-attention"
	if overall >= input.Config.Settings.MinimumReadinessScore && !hasBlockingFinding(findings) {
		status = "ready"
	}
	assignIDs(findings, framework)
	return schema.ComplianceResult{
		SchemaVersion: "1.0", AssessmentID: input.AssessmentID, Framework: title,
		ProjectName: input.Config.Project.Name, Runtime: input.Runtime, OverallReadiness: overall, Status: status,
		Categories: categories, Findings: findings, Recommendations: recommendations.Build(findings),
		EvidenceFiles: evidenceFiles(input),
		ToolResults:   input.ToolResults,
		References:    references,
		ReportPaths:   map[string]string{}, Disclaimer: disclaimer,
		StartedAt: input.StartedAt, CompletedAt: time.Now().UTC(),
	}
}

func isoClause4(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Name != "" {
		score += 15
		strengths = append(strengths, "AI system is identified")
	} else {
		gaps = append(gaps, "AI system name is missing")
	}
	if input.Config.Project.Purpose != "" {
		score += 20
		strengths = append(strengths, "System purpose and intended use are documented")
	} else {
		gaps = append(gaps, "System purpose and intended use are missing")
		*findings = append(*findings, gap("high", "system-context", "ISO Clause 4 context is missing system purpose", "Document intended use, users, business objective, and operating boundaries."))
	}
	if input.Config.Project.Type != "" {
		score += 10
		strengths = append(strengths, "Workload type is declared")
	} else {
		gaps = append(gaps, "Workload type is not declared")
	}
	if len(input.Config.Inputs.Include) > 0 || len(input.Config.Inputs.Targets) > 0 {
		score += 15
		strengths = append(strengths, "Assessment scope is declared")
	} else {
		gaps = append(gaps, "Assessment scope is not declared")
	}
	if len(input.Config.Inputs.Exclude) > 0 {
		score += 10
		strengths = append(strengths, "Out-of-scope paths are documented")
	} else {
		gaps = append(gaps, "Exclusions are not documented")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI impact assessment", input.Config.Governance.ImpactAssessment, "impact-assessment", "high", "Document stakeholders, intended users, foreseeable misuse, harms, safeguards, and operating context.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Data lineage record", input.Config.Governance.DataLineage, "data-lineage", "medium", "Map data sources, retrieval inputs, logs, personal data, retention, and approved storage.")
	return enrich(category("Clause 4 - Context", score, strengths, gaps),
		"Checks whether the AI management system scope, use case, interested-party context, and operating boundaries are explicit enough to review.",
		[]string{"System inventory entry", "Purpose and intended use", "Assessment scope", "Exclusions", "Impact assessment", "Data lineage"},
		[]schema.ControlReference{{Framework: "ISO/IEC 42001", Reference: "Clause 4", Topic: "Context of the organization and AI management system scope", URL: standardURL}})
}

func isoClause5(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Owner != "" {
		score += 25
		strengths = append(strengths, "Accountable AI system owner is defined")
	} else {
		gaps = append(gaps, "Accountable AI system owner is missing")
		*findings = append(*findings, gap("high", "ai-ownership", "ISO Clause 5 leadership evidence is missing an accountable owner", "Assign an owner with authority over AI risk acceptance and release decisions."))
	}
	if input.Config.Governance.DataOwner != "" {
		score += 10
		strengths = append(strengths, "Data owner is defined")
	} else {
		gaps = append(gaps, "Data owner is missing")
	}
	if input.Config.Governance.ApprovalWorkflow != "" {
		score += 15
		strengths = append(strengths, "Approval workflow is documented")
	} else {
		gaps = append(gaps, "Approval workflow is missing")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 15
		strengths = append(strengths, "Human review is required before release")
	} else {
		gaps = append(gaps, "Human review requirement is missing")
		*findings = append(*findings, gap("high", "human-oversight", "ISO Clause 5 does not require human review", "Require accountable human review for production releases and high-impact agent actions."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI policy", input.Config.Governance.PolicyPath, "ai-policy", "high", "Maintain an approved AI policy covering permitted use, prohibited use, data handling, security, releases, and exceptions.")
	addDoc(input, &score, &strengths, &gaps, findings, 15, "Training and attestation records", input.Config.Governance.TrainingRecords, "training-attestation", "medium", "Track role-based AI policy training and reviewer attestation.")
	return enrich(category("Clause 5 - Leadership", score, strengths, gaps),
		"Checks accountability, policy, roles, review authority, and leadership-backed operating expectations.",
		[]string{"Named AI owner", "Data owner", "AI policy", "Approval workflow", "Human review requirement", "Training or attestation evidence"},
		[]schema.ControlReference{{Framework: "ISO/IEC 42001", Reference: "Clause 5", Topic: "Leadership, policy, roles, responsibilities, and authorities", URL: standardURL}})
}

func isoClause6(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	addDoc(input, &score, &strengths, &gaps, findings, 25, "AI risk register", input.Config.Governance.RiskRegister, "risk-register", "high", "Maintain a risk register with owner, likelihood, impact, treatment, due date, status, and residual risk.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI impact assessment", input.Config.Governance.ImpactAssessment, "impact-assessment", "high", "Document foreseeable misuse, harms, affected stakeholders, safeguards, and go/no-go decision.")
	if input.Config.Settings.MinimumReadinessScore > 0 {
		score += 15
		strengths = append(strengths, "Readiness threshold is configured")
	} else {
		gaps = append(gaps, "Readiness threshold is not configured")
	}
	if input.Config.Settings.BlockOnCritical {
		score += 15
		strengths = append(strengths, "Critical findings block release")
	} else {
		gaps = append(gaps, "Critical findings are not configured to block release")
	}
	if input.Config.Governance.RemediationTracking != "" {
		score += 15
		strengths = append(strengths, "Risk treatment and remediation tracking are documented")
	} else {
		gaps = append(gaps, "Risk treatment tracking is missing")
	}
	if input.Config.Governance.ReevaluateOnChange {
		score += 10
		strengths = append(strengths, "Material changes require re-evaluation")
	} else {
		gaps = append(gaps, "Change-triggered re-evaluation is missing")
	}
	return enrich(category("Clause 6 - Planning", score, strengths, gaps),
		"Checks planning evidence for AI risks, objectives, treatment decisions, release gates, and change-triggered reassessment.",
		[]string{"Risk register", "Impact assessment", "Risk treatment process", "Release threshold", "Critical-finding gate", "Re-evaluation trigger"},
		[]schema.ControlReference{{Framework: "ISO/IEC 42001", Reference: "Clause 6", Topic: "Planning for risks, opportunities, AI objectives, and changes", URL: standardURL}})
}

func isoClause7(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if len(input.Evidence) > 0 {
		score += 20
		strengths = append(strengths, fmt.Sprintf("%d evidence source(s) are traceable", len(input.Evidence)))
	} else {
		gaps = append(gaps, "Evidence source files are missing")
		*findings = append(*findings, gap("high", "documented-information", "ISO Clause 7 evidence sources are missing", "Version the approved policy, knowledge, evaluation, or operational evidence used by the AI system."))
	}
	if len(input.TestSources) > 0 {
		score += 15
		strengths = append(strengths, "Evaluation cases are traceable to files")
	} else {
		gaps = append(gaps, "Evaluation case files are missing")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Model card", input.Config.Governance.ModelCard, "model-card", "medium", "Document model/provider, version, intended use, limitations, evaluation summary, failure modes, and monitoring triggers.")
	addDoc(input, &score, &strengths, &gaps, findings, 15, "Data lineage record", input.Config.Governance.DataLineage, "data-lineage", "medium", "Document prompts, retrieval sources, logs, personal data, retention, storage, and access owners.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Vendor review", input.Config.Governance.VendorReview, "vendor-review", "medium", "Record provider dependencies, data sharing, retention terms, security review, contractual controls, and exit criteria.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Training and attestation records", input.Config.Governance.TrainingRecords, "training-attestation", "medium", "Track role-based AI training, security training, policy attestations, reviewers, and exceptions.")
	if len(input.Config.Output.Formats) > 0 {
		score += 10
		strengths = append(strengths, "Report formats are configured for evidence retention")
	}
	return enrich(category("Clause 7 - Support", score, strengths, gaps),
		"Checks support evidence for documented information, resources, competence, awareness, model context, and supplier dependencies.",
		[]string{"Evidence files", "Evaluation cases", "Model card", "Data lineage", "Vendor review", "Training records", "Report retention format"},
		[]schema.ControlReference{{Framework: "ISO/IEC 42001", Reference: "Clause 7", Topic: "Support, resources, competence, awareness, communication, and documented information", URL: standardURL}})
}

func isoClause8(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if len(input.Config.Inputs.Prompts) > 0 {
		score += 10
		strengths = append(strengths, "Prompt inputs are configured")
	} else {
		gaps = append(gaps, "Prompt inputs are not configured")
	}
	if len(input.TestCases) > 0 {
		score += 15
		strengths = append(strengths, "Operational evaluation cases are configured")
	} else {
		gaps = append(gaps, "Operational evaluation cases are missing")
	}
	for _, item := range []struct {
		category string
		points   int
		label    string
	}{
		{"prompt-injection", 10, "Prompt-injection validation is configured"},
		{"grounding", 10, "Grounding validation is configured"},
		{"pii", 10, "Privacy validation is configured"},
		{"output-safety", 10, "Unsafe-output validation is configured"},
		{"agent-safety", 10, "Agent safety validation is configured"},
	} {
		if hasAnyCategory(input.TestCases, item.category) {
			score += item.points
			strengths = append(strengths, item.label)
		} else {
			gaps = append(gaps, item.label+" missing")
		}
	}
	if len(input.Config.Inputs.TerraformPlanJSON) > 0 {
		score += 10
		strengths = append(strengths, "Runtime infrastructure plan evidence is configured")
	} else {
		gaps = append(gaps, "Runtime infrastructure plan evidence is not configured")
	}
	if !hasHighRiskFinding(input.ToolResults, "prompt-injection", "pii", "privacy", "credential", "output-safety", "grounding", "hallucination", "agent-safety", "runtime-security", "code-security", "dependency", "iam-policy") {
		score += 15
		strengths = append(strengths, "No high or critical operational findings are present in latest scan evidence")
	} else {
		gaps = append(gaps, "High or critical operational findings are present in latest scan evidence")
		*findings = append(*findings, gap("high", "technical-risk", "ISO Clause 8 operational controls have unresolved technical findings", "Close high and critical findings or record accountable risk acceptance before release."))
	}
	return enrich(category("Clause 8 - Operation", score, strengths, gaps),
		"Checks whether operational AI controls are configured and whether latest scan evidence shows unresolved high-risk behavior.",
		[]string{"Prompt inputs", "Evaluation test cases", "Agent skill scope", "Terraform plan evidence", "Latest technical scan report", "Release blocking findings"},
		[]schema.ControlReference{{Framework: "ISO/IEC 42001", Reference: "Clause 8", Topic: "Operational planning and control for AI systems", URL: standardURL}})
}

func isoClause9(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if len(input.ToolResults) > 0 {
		score += 25
		strengths = append(strengths, "Latest scan evidence is available for performance review")
	} else {
		gaps = append(gaps, "No latest scan evidence was found; run `infraseal scan` before final readiness review")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 25, "Monitoring plan", input.Config.Governance.MonitoringPlan, "monitoring-plan", "medium", "Define metrics, sampling, alert thresholds, owner, monitoring cadence, and evidence retention.")
	if input.Config.Governance.EvaluationCadence != "" {
		score += 15
		strengths = append(strengths, "Evaluation cadence is defined")
	} else {
		gaps = append(gaps, "Evaluation cadence is not defined")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 15, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Record release decisions, scan reports, approvers, exceptions, incidents, and risk acceptance decisions.")
	if !hasHighRiskFinding(input.ToolResults, "prompt-injection", "pii", "privacy", "credential", "output-safety", "grounding", "hallucination", "agent-safety", "runtime-security", "code-security", "dependency", "iam-policy") {
		score += 20
		strengths = append(strengths, "Latest scan evidence has no high or critical measurement findings")
	} else {
		gaps = append(gaps, "Latest scan evidence contains high or critical measurement findings")
		*findings = append(*findings, gap("high", "performance-evaluation", "ISO Clause 9 performance review found unresolved high-risk findings", "Review scan evidence, assign owners, and rerun focused checks after remediation."))
	}
	return enrich(category("Clause 9 - Performance Evaluation", score, strengths, gaps),
		"Checks monitoring, measurement, analysis, review evidence, and whether recent scan findings are suitable for release review.",
		[]string{"Latest scan report", "Monitoring plan", "Evaluation cadence", "Audit log", "Measurement findings", "Review evidence"},
		[]schema.ControlReference{{Framework: "ISO/IEC 42001", Reference: "Clause 9", Topic: "Performance evaluation, monitoring, measurement, analysis, internal review, and management review", URL: standardURL}})
}

func isoClause10(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Change-management plan", input.Config.Governance.ChangeManagement, "change-management", "medium", "Define changes that require re-evaluation, reviewer approval, and release evidence.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI incident response runbook", input.Config.Governance.IncidentResponseRunbook, "incident-response", "medium", "Document triage, containment, evidence preservation, notification, remediation, re-approval, and post-incident review.")
	if input.Config.Governance.RemediationTracking != "" {
		score += 20
		strengths = append(strengths, "Corrective-action tracking is documented")
	} else {
		gaps = append(gaps, "Corrective-action tracking is missing")
	}
	if input.Config.Governance.ReevaluateOnChange {
		score += 15
		strengths = append(strengths, "Material changes require re-evaluation")
	} else {
		gaps = append(gaps, "Material changes do not require re-evaluation")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 15, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Maintain release decisions, exceptions, incidents, corrective actions, and closure evidence.")
	if !hasCriticalFinding(input.ToolResults) {
		score += 10
		strengths = append(strengths, "No critical findings are present in latest scan evidence")
	} else {
		gaps = append(gaps, "Critical findings remain open in latest scan evidence")
	}
	return enrich(category("Clause 10 - Improvement", score, strengths, gaps),
		"Checks whether nonconformities, incidents, corrective actions, changes, and continual improvement are tracked in an actionable way.",
		[]string{"Change-management plan", "Incident response runbook", "Corrective-action tracker", "Re-evaluation trigger", "Audit log", "Closure evidence"},
		[]schema.ControlReference{{Framework: "ISO/IEC 42001", Reference: "Clause 10", Topic: "Improvement, nonconformity, corrective action, and continual improvement", URL: standardURL}})
}

func technical(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if len(input.TestCases) > 0 {
		score += 20
		strengths = append(strengths, "Evaluation test cases are defined")
	} else {
		gaps = append(gaps, "No evaluation test cases are configured")
		*findings = append(*findings, gap("high", "output-validation", "No AI evaluation test cases are configured", "Add prompt injection, PII, output safety, grounding, and agent workflow cases."))
	}
	if hasCategory(input.TestCases, "prompt-injection") {
		score += 10
		strengths = append(strengths, "Prompt-injection validation is configured")
	} else {
		gaps = append(gaps, "Prompt-injection validation is missing")
	}
	if hasCategory(input.TestCases, "grounding") || hasCategory(input.TestCases, "hallucination") {
		score += 10
		strengths = append(strengths, "Grounding and hallucination validation are configured")
	} else {
		gaps = append(gaps, "Grounding validation is missing")
		*findings = append(*findings, gap("high", "grounding", "Grounding validation is not configured", "Add RAG evidence and unsupported-claim test cases."))
	}
	if realCoverage(input.ToolResults) > 0 {
		score += 20
		strengths = append(strengths, fmt.Sprintf("%d real evaluator(s) produced technical evidence", realCoverage(input.ToolResults)))
	} else {
		gaps = append(gaps, "No real evaluator produced technical evidence")
	}
	if allPassing(input.TestCases) && len(input.TestCases) > 0 {
		score += 10
		strengths = append(strengths, "Configured technical cases currently pass")
	} else if len(input.TestCases) > 0 {
		gaps = append(gaps, "One or more technical controls are failing")
	}
	if !hasHighRiskFinding(input.ToolResults, "prompt-injection", "pii", "privacy", "credential", "output-safety", "grounding", "hallucination", "agent-safety", "runtime-security", "code-security", "dependency", "iam-policy") {
		score += 30
		strengths = append(strengths, "No high or critical technical findings are open")
	} else {
		gaps = append(gaps, "High or critical technical findings are open")
		*findings = append(*findings, gap("high", "technical-risk", "High or critical technical scan findings are open", "Close high and critical scan findings or record accountable risk acceptance before release."))
	}
	return enrich(category("Technical Controls", score, strengths, gaps),
		"Evaluates whether repeatable technical tests exist for prompt attacks, privacy, unsafe output, grounding, and AI workload behavior.",
		[]string{"Versioned evaluation cases", "Prompt and model configuration", "Grounding evidence", "Evaluation results and regression history"},
		[]schema.ControlReference{
			{Reference: "Clause 8", Topic: "Operational planning and control for the AI management system", URL: standardURL},
			{Reference: "Clause 9", Topic: "Performance evaluation, monitoring, measurement, analysis, and review", URL: standardURL},
			{Reference: "Annex A.6 and A.7 control families", Topic: "AI system lifecycle and data for AI systems", URL: standardURL},
		})
}

func governance(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Name != "" {
		score += 15
		strengths = append(strengths, "AI system is identified")
	}
	if input.Config.Project.Purpose != "" {
		score += 20
		strengths = append(strengths, "System purpose is documented")
	} else {
		gaps = append(gaps, "AI system purpose is not documented")
	}
	if input.Config.Project.Owner != "" {
		score += 25
		strengths = append(strengths, "Accountable AI system owner is defined")
	} else {
		gaps = append(gaps, "Missing AI Ownership Register")
		*findings = append(*findings, gap("high", "ai-ownership", "AI system owner is not defined", "Assign an accountable owner and record the system in an AI inventory."))
	}
	if input.Config.Governance.DataOwner != "" {
		score += 20
		strengths = append(strengths, "Data access ownership is documented")
	} else {
		gaps = append(gaps, "Data access owner is not documented")
		*findings = append(*findings, gap("medium", "data-governance", "Data ownership is not documented", "Identify the owner responsible for source data and access decisions."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI policy", input.Config.Governance.PolicyPath, "ai-policy", "high", "Create an approved AI policy covering acceptable use, prohibited use, data handling, security, release criteria, and exceptions.")
	return enrich(category("Governance", score, strengths, gaps),
		"Evaluates whether the AI system, purpose, accountable owner, data ownership, and governing AI policy are explicitly documented.",
		[]string{"AI system inventory", "Approved purpose and scope", "Named accountable owner", "Data ownership and access responsibility", "Approved AI policy"},
		[]schema.ControlReference{
			{Reference: "Clauses 4-6", Topic: "Organizational context, leadership, policy, roles, objectives, risks, and planning", URL: standardURL},
			{Reference: "Annex A.2 and A.3 control families", Topic: "AI-related policy and internal organization", URL: standardURL},
			{Reference: "Annex A.5 control family", Topic: "AI system impact assessment", URL: standardURL},
		})
}

func riskImpactManagement(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	addDoc(input, &score, &strengths, &gaps, findings, 30, "AI risk register", input.Config.Governance.RiskRegister, "risk-register", "high", "Maintain a risk register with owner, likelihood, impact, treatment, due date, residual risk, and acceptance status.")
	addDoc(input, &score, &strengths, &gaps, findings, 30, "AI impact assessment", input.Config.Governance.ImpactAssessment, "impact-assessment", "high", "Document intended users, affected stakeholders, foreseeable misuse, harms, safeguards, and go/no-go decision.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Model card", input.Config.Governance.ModelCard, "model-card", "medium", "Document model/provider, version, intended use, limitations, evaluation results, known failure modes, and monitoring triggers.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Data lineage record", input.Config.Governance.DataLineage, "data-lineage", "medium", "Document prompts, retrieval sources, logs, personal data, retention rules, access owners, and approved storage locations.")
	return enrich(category("Risk & Impact Management", score, strengths, gaps),
		"Evaluates whether non-technical risk, impact, model, and data-lineage evidence exists before deployment decisions are made.",
		[]string{"Risk register", "Impact assessment", "Model card", "Data lineage and retention record"},
		[]schema.ControlReference{
			{Framework: "ISO/IEC 42001", Reference: "Clauses 6 and 8", Topic: "Risk and opportunity planning plus operational control", URL: standardURL},
			{Framework: "ISO/IEC 42001", Reference: "Annex A.5", Topic: "AI system impact assessment", URL: standardURL},
			{Framework: "NIST AI RMF", Reference: "MAP", Topic: "Context, risks, benefits, and impacts are identified", URL: nistCoreURL},
			{Framework: "AIUC-1", Reference: "Data & Privacy/Accountability", Topic: "Data safeguards, risk ownership, and defensible decision records", URL: aiucURL},
		})
}

func humanOversight(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Governance.ApprovalWorkflow != "" {
		score += 30
		strengths = append(strengths, "Approval workflow is documented")
	} else {
		gaps = append(gaps, "No documented approval process")
		*findings = append(*findings, gap("high", "approval-workflow", "Deployment approval workflow is not defined", "Document who approves AI changes, the evidence required, and blocking conditions."))
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 25
		strengths = append(strengths, "Human review is required for deployment")
	} else {
		gaps = append(gaps, "Human review is not required before deployment")
		*findings = append(*findings, gap("high", "human-oversight", "Human review gate is not required", "Require accountable human review before production deployment or high-impact agent actions."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 25, "Human oversight plan", input.Config.Governance.HumanOversightPlan, "human-oversight", "high", "Define review checkpoints, escalation criteria, blocked actions, approver role, and exception handling.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Record release decisions, approvers, exceptions, incident links, and risk acceptance decisions.")
	return enrich(category("Human Oversight", score, strengths, gaps),
		"Evaluates whether production deployment and high-impact AI actions require accountable human review and recorded approval.",
		[]string{"Approval workflow", "Named approver or role", "Human review criteria", "Approval and exception records"},
		[]schema.ControlReference{
			{Reference: "Clause 5", Topic: "Leadership, accountability, roles, responsibilities, and authorities", URL: standardURL},
			{Reference: "Annex A.3 and A.9 control families", Topic: "Internal organization and responsible use of AI systems", URL: standardURL},
			{Reference: "Annex A.8 control family", Topic: "Information for interested parties", URL: standardURL},
		})
}

func operationalMonitoring(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Governance.EvaluationCadence != "" {
		score += 25
		strengths = append(strengths, "Evaluation cadence is defined")
	} else {
		gaps = append(gaps, "Evaluation cadence not defined")
		*findings = append(*findings, gap("medium", "evaluation-cadence", "Continuous evaluation cadence is not defined", "Schedule a recurring evaluation and record the owner and evidence retention period."))
	}
	if input.Config.Governance.ReevaluateOnChange {
		score += 20
		strengths = append(strengths, "Re-evaluation is required after material changes")
	} else {
		gaps = append(gaps, "Re-evaluation after model or prompt changes is not required")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 25, "AI incident response runbook", input.Config.Governance.IncidentResponseRunbook, "incident-response", "medium", "Document containment, evidence preservation, notification, remediation, re-approval, and post-incident review.")
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Monitoring plan", input.Config.Governance.MonitoringPlan, "monitoring-plan", "medium", "Define metrics, sampling, alert thresholds, owner, monitoring cadence, and evidence retention.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Change-management plan", input.Config.Governance.ChangeManagement, "change-management", "medium", "Define changes that require re-evaluation, reviewer approval, and release evidence.")
	return enrich(category("Operational Monitoring", score, strengths, gaps),
		"Evaluates recurring assessment, re-evaluation after change, monitoring, change management, and response procedures for unsafe or materially incorrect AI behavior.",
		[]string{"Evaluation schedule", "Change-triggered reassessment policy", "Monitoring plan/results", "AI incident response runbook", "Change-management records", "Corrective action records"},
		[]schema.ControlReference{
			{Reference: "Clauses 9-10", Topic: "Performance evaluation, internal review, nonconformity, corrective action, and continual improvement", URL: standardURL},
			{Reference: "Annex A.6 control family", Topic: "AI system lifecycle management", URL: standardURL},
		})
}

func evidenceReadiness(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	existing := 0
	for _, path := range input.Evidence {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			existing++
		}
	}
	if existing > 0 {
		score += 35
		strengths = append(strengths, fmt.Sprintf("%d evidence source(s) are traceable", existing))
	} else {
		gaps = append(gaps, "No evidence source files are available")
		*findings = append(*findings, gap("high", "evidence-readiness", "Evidence sources are not available", "Add and version the knowledge, policy, or evaluation evidence used by the AI system."))
	}
	if len(input.TestSources) > 0 {
		score += 25
		strengths = append(strengths, "Evaluation cases are traceable to files")
	}
	reportsDir := filepath.Join(input.RootDir, ".infraseal", "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err == nil {
		score += 20
		strengths = append(strengths, "Local evidence report repository is available")
	}
	if input.Config.Governance.RemediationTracking != "" {
		score += 20
		strengths = append(strengths, "Remediation tracking method is documented")
	} else {
		gaps = append(gaps, "Remediation tracking method is not documented")
		*findings = append(*findings, gap("low", "risk-management", "Remediation tracking is not defined", "Document where findings, owners, due dates, and closure evidence are tracked."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Maintain an audit log linking scan outputs, approval records, exceptions, and closure evidence.")
	return enrich(category("Evidence Readiness", score, strengths, gaps),
		"Evaluates whether source evidence, test cases, reports, and remediation records are traceable and available for review.",
		[]string{"Controlled policies and evidence sources", "Traceable test cases", "Assessment reports", "Finding owners and due dates", "Closure evidence"},
		[]schema.ControlReference{
			{Reference: "Clause 7.5", Topic: "Documented information and control of records", URL: standardURL},
			{Reference: "Clause 9.1", Topic: "Monitoring, measurement, analysis, and evaluation evidence", URL: standardURL},
			{Reference: "Annex A.5, A.6, and A.8 control families", Topic: "Impact assessment, lifecycle evidence, and information for interested parties", URL: standardURL},
		})
}

func transparencyTraining(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	addDoc(input, &score, &strengths, &gaps, findings, 35, "User disclosure", input.Config.Governance.UserDisclosure, "transparency", "medium", "Document user-facing AI disclosure, limitations, escalation paths, appeal/redress channel, and provenance language.")
	addDoc(input, &score, &strengths, &gaps, findings, 35, "Training and attestation records", input.Config.Governance.TrainingRecords, "training-attestation", "medium", "Track role-based AI usage/security training, policy attestations, reviewers, and exceptions.")
	addDoc(input, &score, &strengths, &gaps, findings, 30, "Vendor review", input.Config.Governance.VendorReview, "vendor-review", "medium", "Record provider dependencies, data sharing, retention terms, security review, contractual controls, and exit criteria.")
	return enrich(category("Transparency & Training", score, strengths, gaps),
		"Evaluates practical non-technical controls for user transparency, staff readiness, and third-party AI dependencies.",
		[]string{"User disclosure", "Training and policy attestation evidence", "AI vendor/provider review"},
		[]schema.ControlReference{
			{Framework: "ISO/IEC 42001", Reference: "Clause 7; Annex A.8/A.10", Topic: "Awareness, documented information, interested-party information, and third-party controls", URL: standardURL},
			{Framework: "NIST AI RMF", Reference: "GOVERN/MAP", Topic: "Organizational roles, communication, and stakeholder context", URL: nistCoreURL},
			{Framework: "AIUC-1", Reference: "Society/Accountability", Topic: "Responsible deployment, transparency, and auditable control ownership", URL: aiucURL},
		})
}

func category(name string, score int, strengths, gaps []string) schema.ReadinessCategory {
	if score > 100 {
		score = 100
	}
	status := "WARN"
	if score >= 80 {
		status = "PASS"
	} else if score < 50 {
		status = "FAIL"
	}
	return schema.ReadinessCategory{Name: name, Score: score, Status: status, Strengths: strengths, Gaps: gaps}
}

func enrich(category schema.ReadinessCategory, summary string, expected []string, references []schema.ControlReference) schema.ReadinessCategory {
	category.AssessmentSummary = summary
	category.ExpectedEvidence = expected
	category.ControlReferences = references
	return category
}

func gap(severity, categoryName, title, action string) schema.Finding {
	return schema.Finding{Severity: severity, Domain: "Governance", Category: categoryName, Title: title, Description: title, Evidence: "infraseal.yaml readiness control", Recommendation: action, SourceTool: "mcpvia", ExecutionMode: "native"}
}

func gapEvidence(severity, categoryName, title, evidence, action string) schema.Finding {
	return schema.Finding{Severity: severity, Domain: "Governance", Category: categoryName, Title: title, Description: title, Evidence: evidence, Recommendation: action, SourceTool: "mcpvia", ExecutionMode: "native"}
}

func addDoc(input Input, score *int, strengths, gaps *[]string, findings *[]schema.Finding, points int, label, path, categoryName, severity, action string) {
	rel, complete, reason := documentStatus(input, path)
	if complete {
		*score += points
		*strengths = append(*strengths, fmt.Sprintf("%s complete (%s)", label, rel))
		return
	}
	message := fmt.Sprintf("%s is %s", label, reason)
	*gaps = append(*gaps, message)
	evidence := "infraseal.yaml governance field"
	if rel != "" {
		evidence = rel
	}
	*findings = append(*findings, gapEvidence(severity, categoryName, message, evidence, action))
}

func documentStatus(input Input, path string) (string, bool, string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false, "not configured"
	}
	resolved := config.Resolve(input.RootDir, path)
	rel, err := filepath.Rel(input.RootDir, resolved)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		return rel, false, "configured but missing"
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return rel, false, "configured but unreadable"
	}
	text := strings.TrimSpace(string(data))
	lower := strings.ToLower(text)
	if len(text) < 120 || strings.Contains(lower, "todo:") || strings.Contains(lower, "tbd") || strings.Contains(lower, "replace this") {
		return rel, false, "a starter template or incomplete"
	}
	if missing := missingDocumentEvidence(rel, lower); len(missing) > 0 {
		return rel, false, "missing expected content: " + strings.Join(missing, ", ")
	}
	return rel, true, ""
}

func attachControlAssessments(framework string, input Input, categories []schema.ReadinessCategory) []schema.ReadinessCategory {
	if framework != "iso42001" {
		return categories
	}
	for index := range categories {
		categories[index].Controls = isoControls(input, categories[index].Name)
		if categories[index].Status == "PASS" && controlsNeedAttention(categories[index].Controls) {
			categories[index].Status = "WARN"
		}
	}
	return categories
}

func controlsNeedAttention(controls []schema.ControlAssessment) bool {
	for _, control := range controls {
		switch control.Status {
		case "needs-evidence", "needs-remediation":
			return true
		}
	}
	return false
}

func isoControls(input Input, category string) []schema.ControlAssessment {
	switch category {
	case "Clause 4 - Context":
		return []schema.ControlAssessment{
			metadataControl("AI system identity and intended-use context", "applicable", input.Config.Project.Name != "" && input.Config.Project.Purpose != "" && input.Config.Project.Type != "", []string{"project.name", "project.type", "project.purpose"}, "Project metadata identifies the AI system, workload class, and intended purpose.", "Add project name, workload type, intended users, business purpose, and operating boundaries."),
			metadataControl("Assessment scope and exclusions", "applicable", (len(input.Config.Inputs.Include) > 0 || len(input.Config.Inputs.Targets) > 0) && len(input.Config.Inputs.Exclude) > 0, []string{"inputs.include", "inputs.targets", "inputs.exclude"}, "Configured scan scope and exclusions define what InfraSeal reviewed.", "Declare included paths and excluded/generated paths in `.infraseal/infraseal.yaml`."),
			documentControl(input, "Impact assessment process", "applicable", input.Config.Governance.ImpactAssessment, "impact assessment should identify stakeholders, intended users, foreseeable misuse, harms, safeguards, and a go/no-go decision"),
			documentControl(input, "Data lineage and evidence boundary", "applicable", input.Config.Governance.DataLineage, "data lineage should map prompts, retrieval sources, logs, personal data, retention, storage, and access ownership"),
		}
	case "Clause 5 - Leadership":
		return []schema.ControlAssessment{
			metadataControl("Accountability and ownership", "applicable", input.Config.Project.Owner != "" && input.Config.Governance.DataOwner != "", []string{"project.owner", "governance.data_owner"}, "Accountable AI and data ownership are declared for release review.", "Assign an AI system owner and data owner with authority over risk acceptance."),
			metadataControl("Approval authority and human review", "applicable", input.Config.Governance.ApprovalWorkflow != "" && input.Config.Governance.HumanReviewRequired, []string{"governance.approval_workflow", "governance.human_review_required"}, "Release approval and human review requirements are represented in configuration.", "Document who approves release, what evidence is required, and which actions require human review."),
			documentControl(input, "AI policy process", "applicable", input.Config.Governance.PolicyPath, "policy should cover permitted use, prohibited use, data handling, security expectations, release criteria, and exceptions"),
			documentControl(input, "Training and attestation process", "applicable", input.Config.Governance.TrainingRecords, "training records should identify roles, training completion, policy attestation, reviewers, and exceptions"),
		}
	case "Clause 6 - Planning":
		return []schema.ControlAssessment{
			documentControl(input, "AI risk register process", "applicable", input.Config.Governance.RiskRegister, "risk register should include owners, likelihood or impact, treatment, status, due dates, and residual risk"),
			documentControl(input, "Impact and safeguards planning", "applicable", input.Config.Governance.ImpactAssessment, "impact assessment should connect foreseeable misuse and harms to safeguards and release decisions"),
			metadataControl("Release gates and risk treatment settings", "applicable", input.Config.Settings.MinimumReadinessScore > 0 && input.Config.Settings.BlockOnCritical && input.Config.Governance.RemediationTracking != "", []string{"settings.minimum_readiness_score", "settings.block_on_critical", "governance.remediation_tracking"}, "Readiness threshold, critical-finding gate, and remediation tracker are configured.", "Set a readiness threshold, block critical findings, and define where finding owners, due dates, and closure evidence are tracked."),
			metadataControl("Change-triggered reassessment", "applicable", input.Config.Governance.ReevaluateOnChange, []string{"governance.reevaluate_on_change"}, "Material changes are configured to require re-evaluation.", "Require re-evaluation after prompt, model, data, dependency, tool, or infrastructure changes."),
		}
	case "Clause 7 - Support":
		return []schema.ControlAssessment{
			metadataControl("Traceable evaluation evidence", "applicable", len(input.Evidence) > 0 && len(input.TestSources) > 0 && len(input.Config.Output.Formats) > 0, []string{"inputs.evidence", "inputs.test_cases", "output.formats"}, "Evidence files, test cases, and retained report formats are configured.", "Add versioned evidence, test cases, and retained report outputs."),
			documentControl(input, "Model or workload card", "applicable", input.Config.Governance.ModelCard, "model card should include model/provider identity, intended use, limitations, evaluation summary, failure modes, and monitoring triggers"),
			documentControl(input, "Supplier and provider review", "conditional", input.Config.Governance.VendorReview, "vendor review should describe provider dependencies, data sharing, retention terms, security review, contractual controls, and exit criteria"),
			documentControl(input, "Competence and awareness evidence", "applicable", input.Config.Governance.TrainingRecords, "training records should show role-based AI and security awareness for operators, reviewers, and owners"),
		}
	case "Clause 8 - Operation":
		return []schema.ControlAssessment{
			metadataControl("Operational test coverage", "applicable", len(input.Config.Inputs.Prompts) > 0 && len(input.TestCases) > 0, []string{"inputs.prompts", "inputs.test_cases"}, "Prompt inputs and operational test cases are configured.", "Add prompt templates and regression cases for the AI workload."),
			testCaseControl(input, "Prompt-injection and jailbreak coverage", "applicable", "prompt-injection", "Add prompt-injection and jailbreak cases that must block release on failure."),
			testCaseControl(input, "Grounding and hallucination coverage", "applicable", "grounding", "Add grounding or hallucination cases tied to approved evidence."),
			testCaseControl(input, "Privacy and unsafe-output coverage", "applicable", "pii", "Add PII, credential leakage, unsafe output, and refusal-boundary cases."),
			agentControl(input),
			terraformControl(input),
			latestScanControl(input, "Operational findings gate", "applicable", "prompt-injection", "pii", "privacy", "credential", "output-safety", "grounding", "hallucination", "agent-safety", "runtime-security", "code-security", "dependency", "iam-policy"),
		}
	case "Clause 9 - Performance Evaluation":
		return []schema.ControlAssessment{
			metadataControl("Latest scan evidence for measurement", "applicable", len(input.ToolResults) > 0, []string{".infraseal/reports/latest-scan.json"}, "Readiness uses the latest local scan report as measurement evidence.", "Run `infraseal scan --profile full` before readiness review."),
			documentControl(input, "Monitoring and metrics process", "applicable", input.Config.Governance.MonitoringPlan, "monitoring plan should include metrics, cadence, owner, thresholds, issue tracking, and evidence retention"),
			metadataControl("Evaluation cadence", "applicable", input.Config.Governance.EvaluationCadence != "", []string{"governance.evaluation_cadence"}, "Recurring evaluation cadence is configured.", "Define when scans run, who reviews them, and what blocks deployment."),
			documentControl(input, "Decision and review audit trail", "applicable", input.Config.Governance.AuditLog, "audit log should link decisions, approvals or exceptions, reports, incidents, changes, releases, and closure evidence"),
			latestScanControl(input, "High-risk measurement findings", "applicable", "prompt-injection", "pii", "privacy", "credential", "output-safety", "grounding", "hallucination", "agent-safety", "runtime-security", "code-security", "dependency", "iam-policy"),
		}
	case "Clause 10 - Improvement":
		return []schema.ControlAssessment{
			documentControl(input, "Change-management process", "applicable", input.Config.Governance.ChangeManagement, "change management should define changes that require reassessment, approval, and release evidence"),
			documentControl(input, "Incident and nonconformity response", "applicable", input.Config.Governance.IncidentResponseRunbook, "incident runbook should define triage, containment, evidence preservation, notification, remediation, re-approval, and post-incident review"),
			metadataControl("Corrective-action tracking", "applicable", input.Config.Governance.RemediationTracking != "", []string{"governance.remediation_tracking"}, "Finding ownership, due dates, and closure evidence have a configured tracker.", "Define a tracker for findings, corrective actions, owners, due dates, and acceptance decisions."),
			metadataControl("Continual improvement trigger", "applicable", input.Config.Governance.ReevaluateOnChange, []string{"governance.reevaluate_on_change"}, "Material changes trigger re-evaluation.", "Use release and incident outcomes to update tests, policies, prompts, retrieval evidence, tools, and infrastructure."),
			criticalClosureControl(input),
		}
	default:
		return nil
	}
}

func metadataControl(name, applicability string, pass bool, evidence []string, summary, next string) schema.ControlAssessment {
	status := "pass"
	var gaps, steps []string
	if !pass {
		status = "needs-evidence"
		gaps = append(gaps, summary)
		steps = append(steps, next)
	} else if next != "" {
		steps = append(steps, "Confirm the documented process is followed in operating records.")
	}
	return schema.ControlAssessment{
		Name: name, Applicability: applicability, Status: status, ReviewMethod: "configuration and repository evidence",
		Summary: summary, Evidence: evidence, Gaps: gaps, NextSteps: steps,
	}
}

func documentControl(input Input, name, applicability, path, expectation string) schema.ControlAssessment {
	rel, complete, reason := documentStatus(input, path)
	evidence := []string{rel}
	if rel == "" {
		evidence = []string{"governance YAML field"}
	}
	status := "pass"
	summary := "Documentation contains expected process signals: " + expectation + "."
	var gaps, next []string
	if !complete {
		status = "needs-evidence"
		summary = "Documentation is " + reason + "; expected " + expectation + "."
		gaps = append(gaps, reason)
		next = append(next, "Add real owners, process steps, thresholds, evidence links, review cadence, and approval or exception handling.")
	} else {
		next = append(next, "Manual review should confirm the process is approved, current, and followed.")
	}
	return schema.ControlAssessment{
		Name: name, Applicability: applicability, Status: status, ReviewMethod: "document content check plus manual review",
		Summary: summary, Evidence: evidence, Gaps: gaps, NextSteps: next,
	}
}

func testCaseControl(input Input, name, applicability, categoryName, next string) schema.ControlAssessment {
	status := "pass"
	summary := "Matching evaluation cases are configured."
	var gaps, steps []string
	if categoryName == "grounding" {
		if !hasAnyCategory(input.TestCases, "grounding", "hallucination") {
			status = "needs-evidence"
		}
	} else if categoryName == "pii" {
		if !hasAnyCategory(input.TestCases, "pii", "output-safety") {
			status = "needs-evidence"
		}
	} else if !hasAnyCategory(input.TestCases, categoryName) {
		status = "needs-evidence"
	}
	if status != "pass" {
		summary = "No matching evaluation case was found."
		gaps = append(gaps, "missing evaluation case")
		steps = append(steps, next)
	}
	return schema.ControlAssessment{
		Name: name, Applicability: applicability, Status: status, ReviewMethod: "test-case inventory",
		Summary: summary, Evidence: input.TestSources, Gaps: gaps, NextSteps: steps,
	}
}

func agentControl(input Input) schema.ControlAssessment {
	applicable := strings.Contains(strings.ToLower(input.Config.Project.Type), "agent") || len(input.AgentSkills) > 0
	if !applicable {
		return schema.ControlAssessment{
			Name: "Agent skill and tool-use controls", Applicability: "conditional", Status: "not-applicable", ReviewMethod: "configuration and target discovery",
			Summary: "No agent workload type or agent skill path was found.", NextSteps: []string{"If the system can call tools or take actions, add agent skill manifests or tool configuration to the scan scope."},
		}
	}
	status := "pass"
	summary := "Agent skill paths or agent-safety test cases are configured."
	var gaps, next []string
	if len(input.AgentSkills) == 0 && !hasAnyCategory(input.TestCases, "agent-safety") {
		status = "needs-evidence"
		summary = "The workload appears agentic, but no agent skill evidence or agent-safety case was found."
		gaps = append(gaps, "missing agent skill evidence")
		next = append(next, "Add agent tool manifests, permission files, or agent-safety test cases.")
	}
	return schema.ControlAssessment{Name: "Agent skill and tool-use controls", Applicability: "conditional", Status: status, ReviewMethod: "configuration and file discovery", Summary: summary, Evidence: relativePaths(input.RootDir, input.AgentSkills), Gaps: gaps, NextSteps: next}
}

func terraformControl(input Input) schema.ControlAssessment {
	files := existingRelativePaths(input.RootDir, config.Expand(input.RootDir, input.Config.Inputs.TerraformPlanJSON))
	if len(files) == 0 {
		return schema.ControlAssessment{
			Name: "Infrastructure and runtime plan controls", Applicability: "conditional", Status: "needs-evidence", ReviewMethod: "Terraform plan JSON discovery",
			Summary: "No Terraform plan JSON was found in configured inputs.", Evidence: input.Config.Inputs.TerraformPlanJSON,
			Gaps: []string{"missing Terraform plan JSON"}, NextSteps: []string{"When infrastructure is managed by Terraform, run `terraform show -json` and add the plan JSON path to the scan."},
		}
	}
	return schema.ControlAssessment{Name: "Infrastructure and runtime plan controls", Applicability: "conditional", Status: "pass", ReviewMethod: "Terraform plan JSON scan", Summary: "Terraform plan JSON is available for runtime, IAM, network, storage, database, and secret exposure checks.", Evidence: files, NextSteps: []string{"Manual review should confirm whether any public access or broad permissions are approved exceptions."}}
}

func existingRelativePaths(root string, paths []string) []string {
	var values []string
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			values = append(values, filepath.ToSlash(rel))
		}
	}
	return values
}

func latestScanControl(input Input, name, applicability string, categories ...string) schema.ControlAssessment {
	if len(input.ToolResults) == 0 {
		return schema.ControlAssessment{Name: name, Applicability: applicability, Status: "needs-evidence", ReviewMethod: "latest technical scan", Summary: "No latest scan evidence was found.", Evidence: []string{".infraseal/reports/latest-scan.json"}, Gaps: []string{"missing latest scan evidence"}, NextSteps: []string{"Run `infraseal scan --profile full` before compliance readiness."}}
	}
	if hasHighRiskFinding(input.ToolResults, categories...) {
		return schema.ControlAssessment{Name: name, Applicability: applicability, Status: "needs-remediation", ReviewMethod: "latest technical scan", Summary: "Latest scan evidence contains high or critical findings relevant to this control.", Evidence: []string{".infraseal/reports/latest-scan.json"}, Gaps: []string{"high or critical findings remain open"}, NextSteps: []string{"Remediate findings, record risk acceptance if needed, and rerun focused checks."}}
	}
	return schema.ControlAssessment{Name: name, Applicability: applicability, Status: "pass", ReviewMethod: "latest technical scan", Summary: "No high or critical findings matched this control in the latest scan evidence.", Evidence: []string{".infraseal/reports/latest-scan.json"}}
}

func criticalClosureControl(input Input) schema.ControlAssessment {
	if len(input.ToolResults) == 0 {
		return schema.ControlAssessment{Name: "Critical finding closure", Applicability: "applicable", Status: "needs-evidence", ReviewMethod: "latest technical scan", Summary: "No latest scan evidence was found.", Evidence: []string{".infraseal/reports/latest-scan.json"}, Gaps: []string{"missing latest scan evidence"}, NextSteps: []string{"Run a full scan and review critical findings before release."}}
	}
	if hasCriticalFinding(input.ToolResults) {
		return schema.ControlAssessment{Name: "Critical finding closure", Applicability: "applicable", Status: "needs-remediation", ReviewMethod: "latest technical scan plus manual closure review", Summary: "Critical findings remain open in the latest scan evidence.", Evidence: []string{".infraseal/reports/latest-scan.json"}, Gaps: []string{"open critical findings"}, NextSteps: []string{"Close critical findings or document accountable risk acceptance before release."}}
	}
	return schema.ControlAssessment{Name: "Critical finding closure", Applicability: "applicable", Status: "pass", ReviewMethod: "latest technical scan", Summary: "No critical findings are present in the latest scan evidence.", Evidence: []string{".infraseal/reports/latest-scan.json"}}
}

func missingDocumentEvidence(path, text string) []string {
	type requirement struct {
		label    string
		keywords []string
	}
	requirementsByFile := map[string][]requirement{
		"ai-policy.md": {
			{"approved or permitted use", []string{"approved", "permitted", "acceptable"}},
			{"prohibited use", []string{"prohibited", "must not", "decline", "refuse"}},
			{"data handling", []string{"data", "privacy", "personal", "sensitive"}},
			{"release criteria", []string{"release", "approval", "exception"}},
		},
		"risk-register.md": {
			{"risk", []string{"risk"}},
			{"owner", []string{"owner"}},
			{"severity", []string{"severity", "impact", "likelihood"}},
			{"treatment", []string{"treatment", "mitigation", "control"}},
			{"status", []string{"status", "open", "closed", "accepted"}},
		},
		"impact-assessment.md": {
			{"stakeholders", []string{"stakeholder", "customer", "user"}},
			{"misuse or harms", []string{"misuse", "harm", "unsafe"}},
			{"safeguards", []string{"safeguard", "control", "mitigation"}},
			{"decision boundary", []string{"decision", "approved", "not approved", "must not"}},
		},
		"model-card.md": {
			{"model identity", []string{"model", "provider", "version"}},
			{"intended use", []string{"intended", "approved", "use"}},
			{"limitations", []string{"limitation", "known", "failure"}},
			{"evaluation", []string{"evaluation", "test", "monitoring"}},
		},
		"data-lineage.md": {
			{"data sources", []string{"prompt", "retrieval", "source", "logs"}},
			{"personal or sensitive data", []string{"personal", "sensitive", "customer"}},
			{"retention or storage", []string{"retention", "storage", "stored"}},
			{"access ownership", []string{"access", "owner", "approved"}},
		},
		"human-oversight-plan.md": {
			{"review", []string{"review", "reviewer"}},
			{"approval", []string{"approval", "approve"}},
			{"escalation", []string{"escalation", "escalate"}},
			{"exception or blocked action", []string{"exception", "blocked", "must not"}},
		},
		"monitoring-plan.md": {
			{"metrics", []string{"metric", "rate", "threshold"}},
			{"cadence", []string{"weekly", "daily", "cadence", "recurring"}},
			{"owner or issue tracking", []string{"owner", "issue", "reviewer"}},
			{"evidence retention", []string{"evidence", "report", "retention"}},
		},
		"change-management.md": {
			{"change triggers", []string{"prompt", "model", "dependency", "terraform", "infrastructure"}},
			{"re-evaluation", []string{"re-evaluation", "reevaluation", "reassess"}},
			{"approval", []string{"approval", "reviewer", "release"}},
		},
		"incident-response.md": {
			{"triage", []string{"triage", "first responder", "investigation"}},
			{"containment", []string{"containment", "disable", "rollback", "revoke"}},
			{"evidence preservation", []string{"evidence", "preserve", "logs"}},
			{"remediation", []string{"remediation", "root-cause", "re-approval"}},
		},
		"vendor-review.md": {
			{"provider dependency", []string{"provider", "vendor"}},
			{"data sharing", []string{"data", "sharing", "retention"}},
			{"security review", []string{"security", "contract", "terms"}},
			{"exit criteria", []string{"exit", "criteria", "termination"}},
		},
		"training-records.md": {
			{"training", []string{"training"}},
			{"attestation", []string{"attestation", "acknowledge"}},
			{"roles", []string{"role", "reviewer", "engineer", "owner"}},
			{"policy", []string{"policy"}},
		},
		"user-disclosure.md": {
			{"AI disclosure", []string{"disclosure", "interacting", "ai"}},
			{"limitations", []string{"limitation", "imperfect", "not final"}},
			{"escalation", []string{"escalation", "escalate", "support"}},
			{"redress or appeal", []string{"redress", "appeal", "review"}},
		},
		"audit-log.md": {
			{"decision", []string{"decision"}},
			{"approval or exception", []string{"approval", "exception", "accepted"}},
			{"report evidence", []string{"report", "evidence", "scan"}},
			{"incident or change", []string{"incident", "change", "release"}},
		},
	}
	items := requirementsByFile[strings.ToLower(filepath.Base(path))]
	var missing []string
	for _, item := range items {
		if !containsAny(text, item.keywords...) {
			missing = append(missing, item.label)
		}
	}
	return missing
}

func containsAny(text string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(text, strings.ToLower(value)) {
			return true
		}
	}
	return false
}

func hasCategory(cases []config.TestCase, value string) bool {
	for _, tc := range cases {
		if strings.EqualFold(tc.Category, value) {
			return true
		}
	}
	return false
}

func allPassing(cases []config.TestCase) bool {
	for _, tc := range cases {
		if !tc.Pass {
			return false
		}
	}
	return true
}

func nistGovern(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Owner != "" {
		score += 15
		strengths = append(strengths, "Accountable AI owner is defined")
	} else {
		gaps = append(gaps, "AI ownership is not assigned")
		*findings = append(*findings, gap("high", "ai-ownership", "NIST GOVERN evidence is missing an accountable owner", "Assign an owner with authority over AI risk acceptance and release decisions."))
	}
	if input.Config.Governance.ApprovalWorkflow != "" {
		score += 15
		strengths = append(strengths, "Approval workflow is documented")
	} else {
		gaps = append(gaps, "Approval workflow is not documented")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 15
		strengths = append(strengths, "Human review is required before release")
	} else {
		gaps = append(gaps, "Human review gate is not required")
	}
	if input.Config.Governance.RemediationTracking != "" {
		score += 15
		strengths = append(strengths, "Remediation tracking is defined")
	} else {
		gaps = append(gaps, "Risk treatment and remediation tracking are not defined")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI policy", input.Config.Governance.PolicyPath, "ai-policy", "high", "Approve and publish an AI policy that defines permitted use, prohibited use, roles, release criteria, and exceptions.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Training and attestation records", input.Config.Governance.TrainingRecords, "training-attestation", "medium", "Track role-based AI usage/security training and policy attestations.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Link release decisions, risk acceptances, exceptions, and scan reports in a maintained audit log.")
	return enrich(category("GOVERN", score, strengths, gaps),
		"Evaluates organization-level accountability, policies, roles, oversight, risk ownership, and corrective-action tracking.",
		[]string{"AI owner", "Risk acceptance policy", "Human review workflow", "Remediation tracker", "Release approval evidence"},
		[]schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "GOVERN", Topic: "Policies, processes, procedures, and practices are in place across the AI lifecycle", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clauses 5-6", Topic: "Leadership, roles, responsibilities, objectives, risk and opportunity planning", URL: standardURL},
			{Framework: "AIUC-1", Reference: "Accountability", Topic: "Ownership, oversight, and decision traceability for AI agents", URL: aiucURL},
		})
}

func nistMap(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Purpose != "" {
		score += 15
		strengths = append(strengths, "AI system purpose is documented")
	} else {
		gaps = append(gaps, "AI system purpose is missing")
	}
	if input.Config.Project.Type != "" {
		score += 10
		strengths = append(strengths, "Workload class is declared")
	}
	if input.Config.Governance.DataOwner != "" {
		score += 15
		strengths = append(strengths, "Data owner is identified")
	} else {
		gaps = append(gaps, "Data owner is not identified")
	}
	if len(input.Evidence) > 0 {
		score += 15
		strengths = append(strengths, "Evidence sources are configured")
	} else {
		gaps = append(gaps, "Evidence sources are not configured")
		*findings = append(*findings, gap("high", "evidence-readiness", "NIST MAP evidence sources are missing", "Map the model, prompts, data sources, retrieved context, and expected operating boundary."))
	}
	if len(input.Config.Inputs.Targets) > 0 || len(input.Config.Inputs.Include) > 0 {
		score += 10
		strengths = append(strengths, "Scan scope is declared in configuration")
	} else {
		gaps = append(gaps, "Scan scope is not declared")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 15, "AI impact assessment", input.Config.Governance.ImpactAssessment, "impact-assessment", "high", "Document stakeholders, foreseeable misuse, expected benefits, harms, safeguards, and release decision.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Model card", input.Config.Governance.ModelCard, "model-card", "medium", "Document model/provider, version, intended use, limitations, evaluation results, and known failure modes.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Data lineage record", input.Config.Governance.DataLineage, "data-lineage", "medium", "Map prompts, retrieval sources, logs, personal data, retention, and approved storage.")
	return enrich(category("MAP", score, strengths, gaps),
		"Evaluates whether the system context, intended purpose, data ownership, evidence sources, and scan scope are mapped before risk measurement.",
		[]string{"System purpose", "Workload class", "Data lineage", "Evidence inventory", "Included and excluded scan scope"},
		[]schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "MAP", Topic: "Context is established and risks are identified", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clause 4; Annex A.5", Topic: "Organizational context and AI system impact assessment", URL: standardURL},
			{Framework: "AIUC-1", Reference: "Data & Privacy", Topic: "Data policies, access controls, and safeguards against leakage", URL: aiucURL},
		})
}

func nistMeasure(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if len(input.TestCases) > 0 {
		score += 20
		strengths = append(strengths, "Evaluation cases are versioned")
	} else {
		gaps = append(gaps, "Evaluation cases are missing")
	}
	if hasAnyCategory(input.TestCases, "prompt-injection", "pii", "output-safety") {
		score += 20
		strengths = append(strengths, "Security, privacy, or safety cases are configured")
	} else {
		gaps = append(gaps, "Security, privacy, and safety evaluation cases are missing")
	}
	if hasAnyCategory(input.TestCases, "grounding", "hallucination") {
		score += 20
		strengths = append(strengths, "Grounding or hallucination cases are configured")
	} else {
		gaps = append(gaps, "Reliability and grounding cases are missing")
	}
	if realCoverage(input.ToolResults) > 0 {
		score += 20
		strengths = append(strengths, fmt.Sprintf("%d real evaluator(s) produced evidence", realCoverage(input.ToolResults)))
	} else {
		gaps = append(gaps, "No external evaluator produced real evidence")
	}
	if !hasHighRiskFinding(input.ToolResults, "prompt-injection", "pii", "credential", "grounding", "hallucination", "runtime-security", "code-security", "dependency") {
		score += 20
		strengths = append(strengths, "No high-severity measurement findings are open")
	} else {
		gaps = append(gaps, "High-severity measurement findings are open")
		*findings = append(*findings, gap("high", "risk-measurement", "NIST MEASURE found high-risk technical evidence", "Treat high and critical findings as release blockers or document risk acceptance."))
	}
	return enrich(category("MEASURE", score, strengths, gaps),
		"Evaluates prompt attack resistance, privacy, safety, grounding, code, dependency, agent, and infrastructure evidence.",
		[]string{"Evaluation results", "Scanner artifacts", "Hallucination/grounding evidence", "Code and dependency findings", "Terraform plan findings"},
		[]schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "MEASURE", Topic: "AI risks and trustworthiness characteristics are assessed and analyzed", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clauses 8-9; Annex A.6/A.7", Topic: "Operational control, lifecycle evidence, data controls, and evaluation", URL: standardURL},
			{Framework: "AIUC-1", Reference: "Security/Safety/Reliability", Topic: "Agent security, harmful output prevention, and reliability testing", URL: aiucURL},
		})
}

func nistManage(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Settings.BlockOnCritical {
		score += 20
		strengths = append(strengths, "Critical findings block release gates")
	} else {
		gaps = append(gaps, "Critical findings are not configured to block release")
	}
	if input.Config.Governance.ReevaluateOnChange {
		score += 20
		strengths = append(strengths, "Material changes require re-evaluation")
	} else {
		gaps = append(gaps, "Change-triggered re-evaluation is missing")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI incident response runbook", input.Config.Governance.IncidentResponseRunbook, "incident-response", "medium", "Document containment, evidence preservation, notification, remediation, re-approval, and post-incident review.")
	if input.Config.Governance.EvaluationCadence != "" {
		score += 15
		strengths = append(strengths, "Recurring evaluation cadence is defined")
	} else {
		gaps = append(gaps, "Recurring evaluation cadence is not defined")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 15, "Monitoring plan", input.Config.Governance.MonitoringPlan, "monitoring-plan", "medium", "Define metrics, sampling, alert thresholds, owner, monitoring cadence, and evidence retention.")
	addDoc(input, &score, &strengths, &gaps, findings, 10, "Change-management plan", input.Config.Governance.ChangeManagement, "change-management", "medium", "Define changes that require re-evaluation, reviewer approval, and release evidence.")
	return enrich(category("MANAGE", score, strengths, gaps),
		"Evaluates whether measured risks drive release gates, reassessment, incident response, and ongoing risk treatment.",
		[]string{"Release gate policy", "Risk treatment plan", "Change-management trigger", "Incident response runbook", "Monitoring cadence"},
		[]schema.ControlReference{
			{Framework: "NIST AI RMF", Reference: "MANAGE", Topic: "Risks are prioritized, responded to, and monitored", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clause 10", Topic: "Corrective action and continual improvement", URL: standardURL},
			{Framework: "AIUC-1", Reference: "Accountability", Topic: "Decision traceability and controlled risk acceptance", URL: aiucURL},
		})
}

func aiucDataPrivacy(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Governance.DataOwner != "" {
		score += 20
		strengths = append(strengths, "Data owner is defined")
	} else {
		gaps = append(gaps, "Data owner is missing")
	}
	if hasAnyCategory(input.TestCases, "pii", "privacy") {
		score += 25
		strengths = append(strengths, "PII/privacy evaluation cases are configured")
	} else {
		gaps = append(gaps, "PII/privacy evaluation is missing")
	}
	if !hasHighRiskFinding(input.ToolResults, "pii", "privacy", "credential", "data-exfiltration") {
		score += 30
		strengths = append(strengths, "No high-risk privacy findings are open")
	} else {
		gaps = append(gaps, "High-risk privacy findings are open")
		*findings = append(*findings, gap("high", "privacy-risk", "AIUC-1 Data & Privacy evidence found high-risk issues", "Fix or formally accept privacy, credential, and data-leakage risks before release."))
	}
	addDoc(input, &score, &strengths, &gaps, findings, 25, "Data lineage record", input.Config.Governance.DataLineage, "data-lineage", "medium", "Map the data used by prompts, retrieval, logs, storage, retention, and model-provider calls.")
	return enrich(category("Data & Privacy", score, strengths, gaps),
		"Evaluates protection against customer-data leakage, IP leakage, credentials in prompts/plans, and unauthorized data handling.",
		[]string{"Data owner", "PII regression cases", "Secret scanning output", "Data leakage findings", "Approved evidence sources"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Data & Privacy", Topic: "Customer data policies, access controls, and safeguards", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MEASURE 2", Topic: "Privacy-enhanced trustworthy AI characteristics", URL: nistPlaybookURL},
			{Framework: "ISO/IEC 42001", Reference: "Annex A.7", Topic: "Data for AI systems", URL: standardURL},
		})
}

func aiucSecurity(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if hasAnyCategory(input.TestCases, "prompt-injection") {
		score += 25
		strengths = append(strengths, "Prompt-injection cases are configured")
	} else {
		gaps = append(gaps, "Prompt-injection testing is missing")
	}
	if len(input.Config.Inputs.AgentSkills) > 0 || len(input.Config.Inputs.Targets) > 0 || len(input.Config.Inputs.Include) > 0 {
		score += 20
		strengths = append(strengths, "Agent/source scan scope is configured")
	}
	if realCoverage(input.ToolResults) > 0 {
		score += 15
		strengths = append(strengths, "Real scanner evidence is available")
	} else {
		gaps = append(gaps, "No real scanner evidence is available")
	}
	if !hasHighRiskFinding(input.ToolResults, "prompt-injection", "agent-safety", "runtime-security", "code-security", "dependency", "iam-policy") {
		score += 40
		strengths = append(strengths, "No high-risk security findings are open")
	} else {
		gaps = append(gaps, "High-risk security findings are open")
	}
	return enrich(category("Security", score, strengths, gaps),
		"Evaluates adversarial prompt resistance, tool authorization, source-code risk, dependency risk, and infrastructure exposure.",
		[]string{"Prompt attack tests", "Agent skill manifests", "Code scan results", "Dependency scan results", "Terraform plan findings"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Security", Topic: "Jailbreaks, prompt injection, unauthorized tool calls, and exploitable agent behavior", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MEASURE/MANAGE", Topic: "Secure and resilient assessment plus risk response", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clause 8; Annex A.6", Topic: "Operational controls and AI lifecycle management", URL: standardURL},
		})
}

func aiucSafety(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if hasAnyCategory(input.TestCases, "output-safety") {
		score += 35
		strengths = append(strengths, "Unsafe-output evaluation cases are configured")
	} else {
		gaps = append(gaps, "Unsafe-output testing is missing")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 20
		strengths = append(strengths, "Human review is required for release")
	} else {
		gaps = append(gaps, "Human review is not required")
	}
	if !hasHighRiskFinding(input.ToolResults, "output-safety", "unsafe") {
		score += 25
		strengths = append(strengths, "No high-risk safety findings are open")
	} else {
		gaps = append(gaps, "High-risk safety findings are open")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "Human oversight plan", input.Config.Governance.HumanOversightPlan, "human-oversight", "high", "Define review checkpoints, blocked actions, escalation, exception handling, and approver roles.")
	return enrich(category("Safety", score, strengths, gaps),
		"Evaluates safeguards against harmful output, brand risk, unsafe instructions, and missing human review.",
		[]string{"Safety test cases", "Refusal behavior evidence", "Human review workflow", "Safety findings and closure evidence"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Safety", Topic: "Prevention of harmful AI outputs and brand risk", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MEASURE 2", Topic: "Safe trustworthy AI characteristics", URL: nistPlaybookURL},
			{Framework: "ISO/IEC 42001", Reference: "Annex A.9", Topic: "Responsible use of AI systems", URL: standardURL},
		})
}

func aiucReliability(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if hasAnyCategory(input.TestCases, "grounding", "hallucination") {
		score += 40
		strengths = append(strengths, "Grounding/hallucination cases are configured")
	} else {
		gaps = append(gaps, "Grounding and hallucination testing is missing")
	}
	if len(input.Evidence) > 0 {
		score += 25
		strengths = append(strengths, "Evidence sources are configured")
	} else {
		gaps = append(gaps, "Evidence sources are missing")
	}
	if !hasHighRiskFinding(input.ToolResults, "grounding", "hallucination", "rag", "context") {
		score += 35
		strengths = append(strengths, "No high-risk reliability findings are open")
	} else {
		gaps = append(gaps, "High-risk reliability findings are open")
		*findings = append(*findings, gap("high", "reliability-risk", "AIUC-1 Reliability evidence found unsupported answers", "Require cited evidence spans and convert unsupported responses into regression cases."))
	}
	return enrich(category("Reliability", score, strengths, gaps),
		"Evaluates hallucination resistance, grounded answers, dependable retrieval context, and tool-call reliability.",
		[]string{"Knowledge/evidence files", "Grounding cases", "Exported chatbot outputs", "Verifier results", "Reliability regression history"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Reliability", Topic: "Hallucination prevention and reliable tool calls to business systems", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MEASURE 2", Topic: "Valid and reliable trustworthy AI characteristics", URL: nistPlaybookURL},
			{Framework: "ISO/IEC 42001", Reference: "Clause 9", Topic: "Monitoring, measurement, analysis, and evaluation", URL: standardURL},
		})
}

func aiucAccountability(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Owner != "" {
		score += 15
		strengths = append(strengths, "Accountable owner is defined")
	} else {
		gaps = append(gaps, "Accountable owner is missing")
	}
	if input.Config.Governance.ApprovalWorkflow != "" {
		score += 15
		strengths = append(strengths, "Approval workflow is documented")
	} else {
		gaps = append(gaps, "Approval workflow is missing")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 15
		strengths = append(strengths, "Human review is required")
	} else {
		gaps = append(gaps, "Human review is not required")
	}
	if input.Config.Governance.RemediationTracking != "" {
		score += 15
		strengths = append(strengths, "Remediation tracking is documented")
	} else {
		gaps = append(gaps, "Remediation tracking is missing")
	}
	if len(input.TestSources) > 0 {
		score += 10
		strengths = append(strengths, "Evaluation cases are traceable")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 15, "AI risk register", input.Config.Governance.RiskRegister, "risk-register", "high", "Maintain a risk register with owner, treatment status, residual risk, and acceptance evidence.")
	addDoc(input, &score, &strengths, &gaps, findings, 15, "Decision audit log", input.Config.Governance.AuditLog, "decision-trail", "medium", "Link approvals, exceptions, scan reports, and risk acceptances in a maintained audit log.")
	return enrich(category("Accountability", score, strengths, gaps),
		"Evaluates release ownership, human approval, traceability, remediation, and evidence needed to explain deployment decisions.",
		[]string{"System owner", "Approval workflow", "Human review records", "Decision trail", "Remediation closure evidence"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Accountability", Topic: "Agent ownership, oversight, auditability, and risk decisions", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "GOVERN", Topic: "Accountability and policies across the AI lifecycle", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Clauses 5, 7.5, 10", Topic: "Roles, documented information, and continual improvement", URL: standardURL},
		})
}

func aiucSociety(input Input, findings *[]schema.Finding) schema.ReadinessCategory {
	score := 0
	var strengths, gaps []string
	if input.Config.Project.Purpose != "" {
		score += 20
		strengths = append(strengths, "Use-case purpose is documented")
	} else {
		gaps = append(gaps, "Use-case purpose is missing")
	}
	if input.Config.Governance.HumanReviewRequired {
		score += 15
		strengths = append(strengths, "Human oversight is part of the release decision")
	}
	if input.Config.Governance.EvaluationCadence != "" {
		score += 15
		strengths = append(strengths, "Recurring evaluation supports ongoing impact review")
	} else {
		gaps = append(gaps, "Recurring impact review cadence is missing")
	}
	addDoc(input, &score, &strengths, &gaps, findings, 20, "AI impact assessment", input.Config.Governance.ImpactAssessment, "impact-assessment", "medium", "Review intended users, affected stakeholders, foreseeable misuse, harms, safeguards, and residual impact.")
	addDoc(input, &score, &strengths, &gaps, findings, 15, "User disclosure", input.Config.Governance.UserDisclosure, "transparency", "medium", "Document user-facing AI disclosure, limitations, escalation paths, appeal/redress, and provenance language.")
	addDoc(input, &score, &strengths, &gaps, findings, 15, "AI incident response runbook", input.Config.Governance.IncidentResponseRunbook, "incident-response", "medium", "Document an incident path for harmful, misleading, or materially incorrect AI behavior.")
	return enrich(category("Society", score, strengths, gaps),
		"Evaluates whether use-case purpose, oversight, recurring review, and incident handling support responsible deployment.",
		[]string{"Use-case purpose", "Impact review notes", "Human oversight criteria", "Monitoring cadence", "Incident handling route"},
		[]schema.ControlReference{
			{Framework: "AIUC-1", Reference: "Society", Topic: "Responsible deployment and broader misuse-risk consideration", URL: aiucURL},
			{Framework: "NIST AI RMF", Reference: "MAP/MANAGE", Topic: "Contextual impacts and risk response", URL: nistCoreURL},
			{Framework: "ISO/IEC 42001", Reference: "Annex A.5/A.8", Topic: "AI system impact assessment and interested-party information", URL: standardURL},
		})
}

func assignIDs(findings []schema.Finding, framework string) {
	prefix := "ISO"
	if framework == "nist-ai-rmf" {
		prefix = "NIST"
	}
	if framework == "aiuc1" {
		prefix = "AIUC"
	}
	for i := range findings {
		findings[i].ID = fmt.Sprintf("%s-%03d", prefix, i+1)
	}
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

func evidenceFiles(input Input) []string {
	seen := map[string]bool{}
	var values []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		values = append(values, path)
	}
	for _, path := range input.TestSources {
		add(path)
	}
	for _, path := range relativePaths(input.RootDir, input.Evidence) {
		add(path)
	}
	for _, path := range relativePaths(input.RootDir, config.Expand(input.RootDir, input.Config.Inputs.TerraformPlanJSON)) {
		add(path)
	}
	for _, path := range governanceDocumentPaths(input.Config.Governance) {
		rel, _, _ := documentStatus(input, path)
		add(rel)
	}
	return values
}

func governanceDocumentPaths(g config.GovernanceConfig) []string {
	return []string{
		g.PolicyPath,
		g.RiskRegister,
		g.ImpactAssessment,
		g.ModelCard,
		g.DataLineage,
		g.HumanOversightPlan,
		g.MonitoringPlan,
		g.ChangeManagement,
		g.IncidentResponseRunbook,
		g.VendorReview,
		g.TrainingRecords,
		g.UserDisclosure,
		g.AuditLog,
	}
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

func toolFindings(results []schema.ToolResult) []schema.Finding {
	var findings []schema.Finding
	for _, result := range results {
		for _, finding := range result.Findings {
			if finding.Domain == "" {
				finding.Domain = scanners.DomainForCategory(finding.Category)
			}
			if finding.SourceTool == "" {
				finding.SourceTool = result.Name
			}
			if finding.ExecutionMode == "" {
				finding.ExecutionMode = result.Mode
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

func hasAnyCategory(cases []config.TestCase, values ...string) bool {
	for _, tc := range cases {
		for _, value := range values {
			if strings.EqualFold(tc.Category, value) {
				return true
			}
		}
	}
	return false
}

func hasHighRiskFinding(results []schema.ToolResult, categories ...string) bool {
	for _, result := range results {
		for _, finding := range result.Findings {
			severity := strings.ToLower(finding.Severity)
			if severity != "high" && severity != "critical" {
				continue
			}
			value := strings.ToLower(finding.Category + " " + finding.Domain + " " + finding.Title)
			for _, category := range categories {
				if strings.Contains(value, strings.ToLower(category)) {
					return true
				}
			}
		}
	}
	return false
}

func hasCriticalFinding(results []schema.ToolResult) bool {
	for _, result := range results {
		for _, finding := range result.Findings {
			if strings.EqualFold(finding.Severity, "critical") {
				return true
			}
		}
	}
	return false
}

func hasBlockingFinding(findings []schema.Finding) bool {
	for _, finding := range findings {
		severity := strings.ToLower(finding.Severity)
		if severity == "critical" || severity == "high" {
			return true
		}
	}
	return false
}

func realCoverage(results []schema.ToolResult) int {
	count := 0
	for _, result := range results {
		if result.Mode == "real" && result.Status == "available" {
			count++
		}
	}
	return count
}
